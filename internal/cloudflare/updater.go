package cloudflare

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/diepkhoa/openwrt-cf-edge/internal/config"
	"github.com/diepkhoa/openwrt-cf-edge/internal/ipwatch"
	"github.com/diepkhoa/openwrt-cf-edge/internal/notify"
	"github.com/diepkhoa/openwrt-cf-edge/internal/state"
)

const (
	defaultTTL              = 60
	defaultCooldown         = 10 * time.Second
	defaultAPIRetries       = 3
	defaultAPIRetryDelay    = 5 * time.Second
	defaultGlobalMaxRounds  = 3
	defaultGlobalRetryDelay = 15 * time.Second
)

// ErrShielded indicates DDNS updates are blocked because /etc/cf-edge/shield.lock exists.
var ErrShielded = errors.New("DDNS update skipped: shield lock is active")

// SyncOptions controls DDNS synchronization behavior.
type SyncOptions struct {
	Force      bool
	Subdomains []string
}

type syncTask struct {
	Record   config.RecordConfig
	Type     string // "A" or "AAAA"
	TargetIP string
}

// Updater serializes Cloudflare DNS record updates, cleanup, retries, and state persistence.
type Updater struct {
	cfg            *config.Config
	api            API
	store          *state.Store
	notifier       notify.Notifier
	shieldLockPath string
	logger         *slog.Logger

	mu               sync.Mutex
	lastNormalSync   time.Time
	cooldown         time.Duration
	apiRetries       int
	apiRetryDelay    time.Duration
	globalMaxRounds  int
	globalRetryDelay time.Duration
}

// UpdaterOption customizes an Updater instance.
type UpdaterOption func(*Updater)

// WithTiming overrides cooldown and retry timings (primarily for unit tests).
func WithTiming(cooldown, apiRetryDelay, globalRetryDelay time.Duration, apiRetries, globalMaxRounds int) UpdaterOption {
	return func(u *Updater) {
		if cooldown >= 0 {
			u.cooldown = cooldown
		}
		if apiRetryDelay >= 0 {
			u.apiRetryDelay = apiRetryDelay
		}
		if globalRetryDelay >= 0 {
			u.globalRetryDelay = globalRetryDelay
		}
		if apiRetries >= 0 {
			u.apiRetries = apiRetries
		}
		if globalMaxRounds > 0 {
			u.globalMaxRounds = globalMaxRounds
		}
	}
}

// NewUpdater creates a serialized DDNS Updater.
func NewUpdater(
	cfg *config.Config,
	api API,
	store *state.Store,
	notifier notify.Notifier,
	shieldLockPath string,
	logger *slog.Logger,
	opts ...UpdaterOption,
) *Updater {
	if logger == nil {
		logger = slog.Default()
	}
	if shieldLockPath == "" {
		shieldLockPath = state.DefaultShieldLockPath
	}
	u := &Updater{
		cfg:              cfg,
		api:              api,
		store:            store,
		notifier:         notifier,
		shieldLockPath:   shieldLockPath,
		logger:           logger,
		cooldown:         defaultCooldown,
		apiRetries:       defaultAPIRetries,
		apiRetryDelay:    defaultAPIRetryDelay,
		globalMaxRounds:  defaultGlobalMaxRounds,
		globalRetryDelay: defaultGlobalRetryDelay,
	}
	for _, opt := range opts {
		opt(u)
	}
	return u
}

// Sync synchronizes configured Cloudflare DNS records to snap.
func (u *Updater) Sync(ctx context.Context, snap ipwatch.Snapshot, opts SyncOptions) error {
	u.mu.Lock()
	defer u.mu.Unlock()

	if !u.cfg.Cloudflare.Enabled {
		return nil
	}
	if state.IsShielded(u.shieldLockPath) {
		return ErrShielded
	}

	tasks := u.buildTasks(snap, opts.Subdomains)
	if len(tasks) == 0 {
		u.logger.Info("no matching DNS tasks for available WAN IPs")
		return nil
	}

	currentState := u.store.Get()
	if !opts.Force && u.allTasksSynced(currentState, tasks) {
		u.logger.Debug("all DNS records already match state", "ipv4", snap.IPv4, "ipv6", snap.IPv6)
		if len(currentState.PendingNotify) > 0 && u.notifier != nil {
			u.flushDDNSNotification(ctx, snap, nil)
		}
		return nil
	}

	if !opts.Force && !u.lastNormalSync.IsZero() && u.cooldown > 0 {
		elapsed := time.Since(u.lastNormalSync)
		if elapsed < u.cooldown {
			if err := sleepCtx(ctx, u.cooldown-elapsed); err != nil {
				return err
			}
			if state.IsShielded(u.shieldLockPath) {
				return ErrShielded
			}
		}
	}

	pending := tasks
	var updatedLabels []string
	var lastErr error

	for round := 1; round <= u.globalMaxRounds; round++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if state.IsShielded(u.shieldLockPath) {
			return ErrShielded
		}

		st := u.store.Get()
		var nextPending []syncTask
		stateDirty := false

		for _, task := range pending {
			changed, dirty, err := u.syncTask(ctx, &st, task, opts.Force)
			if dirty {
				stateDirty = true
			}
			if err != nil {
				lastErr = err
				u.logger.Warn("record sync failed", "subdomain", task.Record.Subdomain, "type", task.Type, "round", round, "err", err)
				nextPending = append(nextPending, task)
				continue
			}
			if changed {
				updatedLabels = append(updatedLabels, fmt.Sprintf("%s (%s)", task.Record.Subdomain, task.Type))
			}
		}

		if stateDirty {
			if snap.IPv4 != "" {
				st.LastIPv4 = snap.IPv4
			}
			if snap.IPv6 != "" {
				st.LastIPv6 = snap.IPv6
			}
			st.LastUpdated = time.Now().UTC()
			if saveErr := u.persistState(st); saveErr != nil {
				u.logger.Error("failed to persist state", "err", saveErr)
			}
		}

		if len(nextPending) == 0 {
			lastErr = nil
			break
		}
		pending = nextPending
		if round < u.globalMaxRounds && u.globalRetryDelay > 0 {
			if err := sleepCtx(ctx, u.globalRetryDelay); err != nil {
				return err
			}
		}
	}

	if !opts.Force {
		u.lastNormalSync = time.Now()
	}

	if (len(updatedLabels) > 0 || len(u.store.Get().PendingNotify) > 0) && u.notifier != nil {
		u.flushDDNSNotification(ctx, snap, updatedLabels)
	}

	return lastErr
}


