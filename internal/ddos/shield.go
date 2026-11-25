package ddos

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/diepkhoa/openwrt-cf-edge/internal/config"
	"github.com/diepkhoa/openwrt-cf-edge/internal/netutil"
	"github.com/diepkhoa/openwrt-cf-edge/internal/notify"
	"github.com/diepkhoa/openwrt-cf-edge/internal/state"
	"github.com/diepkhoa/openwrt-cf-edge/internal/ubus"
)

const (
	defaultBRASFlushWait    = 20 * time.Second
	defaultReconnectTimeout = 120 * time.Second
	defaultReconnectPoll    = 3 * time.Second
	defaultPingTimeout      = 2 * time.Second
)

// EnterOptions configures shield activation behavior.
type EnterOptions struct {
	Manual   bool
	NoRedial bool
}

// DiscoverIPv4Func resolves the router's public WAN IPv4 address.
type DiscoverIPv4Func func(ctx context.Context) (string, error)

// SyncForceFunc executes `update --force` after leaving shield mode.
type SyncForceFunc func(ctx context.Context) error

// ShieldManager coordinates DDoS detection, nftables ingress shielding, WAN redialing, and Worker recovery polling.
type ShieldManager struct {
	cfg             *config.Config
	ubus            ubus.Client
	pinger          netutil.Pinger
	reader          SampleReader
	firewall        Firewall
	worker          WorkerAPI
	store           *state.Store
	notifier        notify.Notifier
	discoverIPv4Fn  DiscoverIPv4Func
	syncForceFn     SyncForceFunc
	redialHook      func(active bool)
	shieldLockPath  string
	logger          *slog.Logger
	mu              sync.Mutex
	nowFn           func() time.Time
	brasFlushWait   time.Duration
	reconnectMax    time.Duration
	reconnectPoll   time.Duration
	lastRateLimitAt time.Time
}

// Option customizes a ShieldManager instance.
type Option func(*ShieldManager)

// WithTimings overrides redial sleep and reconnect timeouts (used in unit tests).
func WithTimings(brasFlush, reconnectMax, reconnectPoll time.Duration) Option {
	return func(m *ShieldManager) {
		if brasFlush >= 0 {
			m.brasFlushWait = brasFlush
		}
		if reconnectMax >= 0 {
			m.reconnectMax = reconnectMax
		}
		if reconnectPoll > 0 {
			m.reconnectPoll = reconnectPoll
		}
	}
}

// WithRedialHook registers a callback invoked before/after intentional redials (to pause PPPoE Guard).
func WithRedialHook(hook func(active bool)) Option {
	return func(m *ShieldManager) {
		m.redialHook = hook
	}
}

// WithClock overrides time.Now (used in unit tests).
func WithClock(fn func() time.Time) Option {
	return func(m *ShieldManager) {
		if fn != nil {
			m.nowFn = fn
		}
	}
}

// NewShieldManager constructs a ShieldManager.
func NewShieldManager(
	cfg *config.Config,
	ubusClient ubus.Client,
	pinger netutil.Pinger,
	reader SampleReader,
	firewall Firewall,
	worker WorkerAPI,
	store *state.Store,
	notifier notify.Notifier,
	discoverIPv4Fn DiscoverIPv4Func,
	syncForceFn SyncForceFunc,
	shieldLockPath string,
	logger *slog.Logger,
	opts ...Option,
) *ShieldManager {
	if logger == nil {
		logger = slog.Default()
	}
	if shieldLockPath == "" {
		shieldLockPath = state.DefaultShieldLockPath
	}
	m := &ShieldManager{
		cfg:            cfg,
		ubus:           ubusClient,
		pinger:         pinger,
		reader:         reader,
		firewall:       firewall,
		worker:         worker,
		store:          store,
		notifier:       notifier,
		discoverIPv4Fn: discoverIPv4Fn,
		syncForceFn:    syncForceFn,
		shieldLockPath: shieldLockPath,
		logger:         logger,
		nowFn:          time.Now,
		brasFlushWait:  defaultBRASFlushWait,
		reconnectMax:   defaultReconnectTimeout,
		reconnectPoll:  defaultReconnectPoll,
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// EnterShield locks DDNS, blocks wan_ingress_port via nftables, redials WAN (unless rate-limited/NoRedial),
// reports the new IP to the Cloudflare Worker, and notifies Telegram.
func (m *ShieldManager) EnterShield(ctx context.Context, reason string, opts EnterOptions) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var curState state.RuntimeState
	if m.store != nil {
		curState = m.store.Get()
	}

	lockData := state.ShieldLock{
		Active:         true,
		NodeName:       m.cfg.NodeName,
		Reason:         reason,
		Manual:         opts.Manual,
		WANIngressPort: m.cfg.DDoSShield.WANIngressPort,
		ShieldedIPv4:   curState.LastIPv4,
		ShieldedIPv6:   curState.LastIPv6,
		EnteredAt:      m.nowFn().UTC(),
	}
	if err := state.WriteShieldLock(m.shieldLockPath, lockData); err != nil {
		return fmt.Errorf("write shield lock: %w", err)
	}

	wanDevs := m.resolveWANDevices(ctx)
	if err := m.firewall.ApplyShield(ctx, wanDevs, m.cfg.DDoSShield.WANIngressPort); err != nil {
		return fmt.Errorf("apply nft shield: %w", err)
	}

	redialSkipped := opts.NoRedial
	redialNote := "redial skipped (--no-redial)"
	if !opts.NoRedial {
		allowed, count := m.consumeRedialQuota()
		if !allowed {
			redialSkipped = true
			redialNote = fmt.Sprintf("redial skipped (hourly limit %d/%d reached)", count, m.cfg.DDoSShield.MaxRedialsPerHour)
			m.logger.Warn("max_redials_per_hour exceeded; keeping shield.lock + nft without redialing", "count", count)
		} else {
			redialNote = m.performRedial(ctx)
			_ = m.firewall.ApplyShield(ctx, m.resolveWANDevices(ctx), m.cfg.DDoSShield.WANIngressPort)
		}
	}

	newIP := ""
	if m.discoverIPv4Fn != nil {
		if ip, err := m.discoverIPv4Fn(ctx); err == nil {
			newIP = ip
		}
	}

	workerStatus := "not configured"
	if m.worker != nil && m.cfg.DDoSShield.WorkerURL != "" {
		if err := m.worker.ReportDDoS(ctx, newIP, reason); err != nil {
			workerStatus = "error: " + err.Error()
			m.logger.Error("worker /edge/ddos notification failed", "err", err)
		} else {
			workerStatus = "notified OK"
		}
	}

	if m.notifier != nil && (!redialSkipped || m.shouldSendRateLimitNotice()) {
		detail := fmt.Sprintf("%s (%s)", workerStatus, redialNote)
		msg := notify.FormatShieldEntered(m.cfg.NodeName, reason, newIP, detail)
		if err := m.notifier.Send(ctx, msg); err != nil {
			m.logger.Warn("telegram shield-enter notification failed", "err", err)
		}
	}
	return nil
}

// ExitShield removes the nftables ingress block, removes shield.lock, and optionally runs update --force.
func (m *ShieldManager) ExitShield(ctx context.Context, syncForce bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.firewall.RemoveShield(ctx); err != nil {
		return fmt.Errorf("remove nft shield: %w", err)
	}
	if err := state.RemoveShieldLock(m.shieldLockPath); err != nil {
		return fmt.Errorf("remove shield lock: %w", err)
	}

	detail := "Shield lock & nft rule removed"
	if syncForce && m.syncForceFn != nil {
		if err := m.syncForceFn(ctx); err != nil {
			detail = "Shield exited; DNS force-sync error: " + err.Error()
			m.logger.Error("force sync after shield exit failed", "err", err)
		} else {
			detail = "Shield exited & DNS force-synced"
		}
	}

	if m.notifier != nil {
		msg := notify.FormatShieldExited(m.cfg.NodeName, detail)
		_ = m.notifier.Send(ctx, msg)
	}
	return nil
}


