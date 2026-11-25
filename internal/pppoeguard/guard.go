package pppoeguard

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/diepkhoa/openwrt-cf-edge/internal/config"
	"github.com/diepkhoa/openwrt-cf-edge/internal/netutil"
	"github.com/diepkhoa/openwrt-cf-edge/internal/notify"
	"github.com/diepkhoa/openwrt-cf-edge/internal/state"
	"github.com/diepkhoa/openwrt-cf-edge/internal/ubus"
)

const (
	defaultAuthDownWait    = 10 * time.Second
	defaultPendingDownWait = 15 * time.Second
	defaultFastInterval    = 60 * time.Second
	defaultSlowInterval    = 120 * time.Second
	maxPendingCycles       = 3
)

// Guard monitors WAN PPPoE stability via ubus events and recovers stuck netifd states.
type Guard struct {
	cfg      *config.Config
	ubus     ubus.Client
	listener *ubus.Listener
	health   *HealthChecker
	store    *state.Store
	notifier notify.Notifier
	logger   *slog.Logger

	externalRedial atomic.Bool

	bootGrace       time.Duration
	initialWait     time.Duration
	authDownWait    time.Duration
	pendingDownWait time.Duration
	fastInterval    time.Duration
	slowInterval    time.Duration
}

// Option customizes a Guard instance.
type Option func(*Guard)

// WithTimings overrides guard timers (used in unit tests).
func WithTimings(bootGrace, initialWait, authDownWait, pendingDownWait, fastInterval, slowInterval time.Duration) Option {
	return func(g *Guard) {
		if bootGrace >= 0 {
			g.bootGrace = bootGrace
		}
		if initialWait >= 0 {
			g.initialWait = initialWait
		}
		if authDownWait >= 0 {
			g.authDownWait = authDownWait
		}
		if pendingDownWait >= 0 {
			g.pendingDownWait = pendingDownWait
		}
		if fastInterval >= 0 {
			g.fastInterval = fastInterval
		}
		if slowInterval >= 0 {
			g.slowInterval = slowInterval
		}
	}
}

// NewGuard constructs an event-driven PPPoE Guard.
func NewGuard(
	cfg *config.Config,
	ubusClient ubus.Client,
	listener *ubus.Listener,
	pinger netutil.Pinger,
	store *state.Store,
	notifier notify.Notifier,
	logger *slog.Logger,
	opts ...Option,
) *Guard {
	if logger == nil {
		logger = slog.Default()
	}
	g := &Guard{
		cfg:             cfg,
		ubus:            ubusClient,
		listener:        listener,
		health:          NewHealthChecker(cfg, ubusClient, pinger),
		store:           store,
		notifier:        notifier,
		logger:          logger,
		bootGrace:       cfg.PPPoEGuard.BootGrace.Std(),
		initialWait:     cfg.PPPoEGuard.InitialWait.Std(),
		authDownWait:    defaultAuthDownWait,
		pendingDownWait: defaultPendingDownWait,
		fastInterval:    defaultFastInterval,
		slowInterval:    defaultSlowInterval,
	}
	for _, opt := range opts {
		opt(g)
	}
	return g
}

// SetExternalRedialing marks whether DDoS Shield is intentionally redialing WAN.
func (g *Guard) SetExternalRedialing(active bool) {
	g.externalRedial.Store(active)
}

// Run monitors boot grace and ubus events until ctx is cancelled.
func (g *Guard) Run(ctx context.Context) {
	if !g.cfg.PPPoEGuard.Enabled {
		return
	}

	events, unsubscribe := g.listener.Subscribe(16)
	defer unsubscribe()

	if g.bootGrace > 0 {
		if !g.waitDrainEvents(ctx, g.bootGrace, events) {
			return
		}
	}

	if !g.externalRedial.Load() {
		report := g.health.Check(ctx)
		if ctx.Err() != nil {
			return
		}
		if report.IsHealthy() {
			g.recordStatus("healthy", "")
		} else {
			g.logger.Warn("WAN unhealthy after boot grace, starting PPPoE recovery")
			g.recoverLoop(ctx, events)
		}
	}

	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-events:
			if !ok {
				return
			}
			if g.externalRedial.Load() || ev.Interface != g.cfg.WAN.IfaceV4 {
				continue
			}
			if ev.Action == "ifdown" || ev.Action == "ifup-failed" {
				g.logger.Warn("PPPoE Guard triggered by ubus event", "action", ev.Action, "interface", ev.Interface)
				g.recoverLoop(ctx, events)
			}
		}
	}
}
