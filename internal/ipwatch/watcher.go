package ipwatch

import (
	"context"
	"log/slog"

	"github.com/diepkhoa/openwrt-cf-edge/internal/config"
	"github.com/diepkhoa/openwrt-cf-edge/internal/state"
	"github.com/diepkhoa/openwrt-cf-edge/internal/ubus"
)

// SyncFunc pushes discovered WAN IPs to DNS.
type SyncFunc func(ctx context.Context, snap Snapshot, force bool) error

// Watcher reacts to ubus WAN interface events and triggers preemptible DDNS updates.
type Watcher struct {
	cfg            *config.Config
	discoverer     *Discoverer
	listener       *ubus.Listener
	syncFn         SyncFunc
	shieldLockPath string
	logger         *slog.Logger
}

// NewWatcher constructs an event-driven WAN IP Watcher.
func NewWatcher(cfg *config.Config, discoverer *Discoverer, listener *ubus.Listener, syncFn SyncFunc, shieldLockPath string, logger *slog.Logger) *Watcher {
	if logger == nil {
		logger = slog.Default()
	}
	if shieldLockPath == "" {
		shieldLockPath = state.DefaultShieldLockPath
	}
	return &Watcher{
		cfg:            cfg,
		discoverer:     discoverer,
		listener:       listener,
		syncFn:         syncFn,
		shieldLockPath: shieldLockPath,
		logger:         logger,
	}
}

// Run subscribes to ubus events, runs an initial check, and preempts stale updates on new events.
func (w *Watcher) Run(ctx context.Context) {
	events, unsubscribe := w.listener.Subscribe(16)
	defer unsubscribe()

	var (
		activeCancel context.CancelFunc
		activeDone   chan struct{}
	)

	stopActive := func() {
		if activeCancel != nil {
			activeCancel()
			<-activeDone
			activeCancel = nil
			activeDone = nil
		}
	}
	defer stopActive()

	startUpdate := func(reason string) {
		if state.IsShielded(w.shieldLockPath) {
			w.logger.Info("shield lock active, skipping DDNS trigger", "reason", reason)
			return
		}
		stopActive()

		childCtx, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		activeCancel = cancel
		activeDone = done

		go func() {
			defer close(done)
			defer cancel()
			snap, err := w.discoverer.Discover(childCtx)
			if childCtx.Err() != nil {
				return
			}
			if err != nil {
				w.logger.Warn("WAN IP discovery failed", "reason", reason, "err", err)
				return
			}
			if state.IsShielded(w.shieldLockPath) {
				w.logger.Info("shield lock appeared during discovery, aborting DDNS sync")
				return
			}
			if err := w.syncFn(childCtx, snap, false); err != nil && childCtx.Err() == nil {
				w.logger.Error("DDNS sync failed", "reason", reason, "err", err)
			}
		}()
	}

	startUpdate("startup")

	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-events:
			if !ok {
				return
			}
			if w.matchesWANEvent(ev) {
				w.logger.Info("WAN ubus event received", "action", ev.Action, "interface", ev.Interface)
				startUpdate(ev.Action + ":" + ev.Interface)
			}
		}
	}
}

func (w *Watcher) matchesWANEvent(ev ubus.Event) bool {
	if ev.Action != "ifup" && ev.Action != "ifupdate" {
		return false
	}
	if ev.Interface == w.cfg.WAN.IfaceV4 {
		return true
	}
	if w.cfg.WAN.IfaceV6 != "" && ev.Interface == w.cfg.WAN.IfaceV6 {
		return true
	}
	return false
}
