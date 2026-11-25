package reconcile

import (
	"context"
	"log/slog"
	"net/netip"
	"time"

	"github.com/diepkhoa/openwrt-cf-edge/internal/cloudflare"
	"github.com/diepkhoa/openwrt-cf-edge/internal/config"
	"github.com/diepkhoa/openwrt-cf-edge/internal/ipwatch"
	"github.com/diepkhoa/openwrt-cf-edge/internal/state"
)

const defaultStartupDelay = 15 * time.Second

// DiscoverFunc resolves the router's current public WAN IPv4/IPv6 snapshot.
type DiscoverFunc func(ctx context.Context) (ipwatch.Snapshot, error)

// SyncFunc forces a Cloudflare DDNS synchronization with specific options.
type SyncFunc func(ctx context.Context, snap ipwatch.Snapshot, opts cloudflare.SyncOptions) error

// Reconciler periodically verifies non-proxied DNS records against external resolvers.
type Reconciler struct {
	cfg            *config.Config
	store          *state.Store
	resolver       Resolver
	cfIPs          *CFProxyCatalog
	discoverFn     DiscoverFunc
	syncFn         SyncFunc
	shieldLockPath string
	startupDelay   time.Duration
	logger         *slog.Logger
}

// Option customizes a Reconciler instance.
type Option func(*Reconciler)

// WithStartupDelay overrides the 15s initial delay (used in unit tests).
func WithStartupDelay(d time.Duration) Option {
	return func(r *Reconciler) {
		r.startupDelay = d
	}
}

// NewReconciler constructs a periodic DNS Reconciler.
func NewReconciler(
	cfg *config.Config,
	store *state.Store,
	resolver Resolver,
	cfIPs *CFProxyCatalog,
	discoverFn DiscoverFunc,
	syncFn SyncFunc,
	shieldLockPath string,
	logger *slog.Logger,
	opts ...Option,
) *Reconciler {
	if logger == nil {
		logger = slog.Default()
	}
	if shieldLockPath == "" {
		shieldLockPath = state.DefaultShieldLockPath
	}
	r := &Reconciler{
		cfg:            cfg,
		store:          store,
		resolver:       resolver,
		cfIPs:          cfIPs,
		discoverFn:     discoverFn,
		syncFn:         syncFn,
		shieldLockPath: shieldLockPath,
		startupDelay:   defaultStartupDelay,
		logger:         logger,
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// Run waits for the initial startup delay, then reconciles DNS every reconcile.interval.
func (r *Reconciler) Run(ctx context.Context) {
	if !r.cfg.Reconcile.Enabled {
		return
	}

	if r.startupDelay > 0 {
		timer := time.NewTimer(r.startupDelay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}

	r.runTick(ctx)

	ticker := time.NewTicker(r.cfg.Reconcile.Interval.Std())
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.runTick(ctx)
		}
	}
}

func (r *Reconciler) runTick(ctx context.Context) {
	if err := r.ReconcileOnce(ctx); err != nil && ctx.Err() == nil {
		r.logger.Warn("DNS reconcile tick encountered errors", "err", err)
	}
}

// ReconcileOnce inspects each non-proxied record and forces an update for mismatched subdomains.
func (r *Reconciler) ReconcileOnce(ctx context.Context) error {
	if state.IsShielded(r.shieldLockPath) {
		r.logger.Debug("shield lock active, skipping DNS reconcile")
		return nil
	}

	st := r.store.Get()
	var dirtySubdomains []string

	for _, rec := range r.cfg.Cloudflare.Records {
		if rec.Proxied {
			continue
		}
		needsSync := false

		if rec.IPv4 {
			expected := expectedRecordIP(st, rec.Subdomain, "A", st.LastIPv4)
			if r.checkRecordMismatch(ctx, rec.Subdomain, "A", expected) {
				needsSync = true
			}
		}
		if !needsSync && rec.IPv6 {
			expected := expectedRecordIP(st, rec.Subdomain, "AAAA", st.LastIPv6)
			if r.checkRecordMismatch(ctx, rec.Subdomain, "AAAA", expected) {
				needsSync = true
			}
		}

		if needsSync {
			dirtySubdomains = append(dirtySubdomains, rec.Subdomain)
		}
	}

	if len(dirtySubdomains) == 0 {
		return nil
	}

	snap, err := r.discoverFn(ctx)
	if err != nil {
		return err
	}
	if state.IsShielded(r.shieldLockPath) {
		return nil
	}

	for _, sub := range dirtySubdomains {
		r.logger.Info("reconcile triggering force update", "subdomain", sub)
		if syncErr := r.syncFn(ctx, snap, cloudflare.SyncOptions{
			Force:      true,
			Subdomains: []string{sub},
		}); syncErr != nil {
			err = syncErr
		}
	}
	return err
}

func expectedRecordIP(st state.RuntimeState, subdomain, recordType, fallback string) string {
	if entry, ok := st.Records[state.RecordKey(subdomain, recordType)]; ok && entry.IP != "" {
		return entry.IP
	}
	return fallback
}

func (r *Reconciler) checkRecordMismatch(ctx context.Context, subdomain, recordType, expectedIP string) bool {
	res := r.resolver.Query(ctx, subdomain, recordType)
	switch res.Outcome {
	case OutcomeNetError:
		r.logger.Debug("reconcile DNS query classified as NET_ERROR, skipping", "subdomain", subdomain, "type", recordType, "err", res.Err)
		return false
	case OutcomeNXDOMAIN, OutcomeNODATA:
		r.logger.Info("reconcile detected missing DNS record", "subdomain", subdomain, "type", recordType, "outcome", res.Outcome)
		return true
	case OutcomeOK:
		for _, ip := range res.IPs {
			if r.cfIPs != nil && r.cfIPs.IsProxyIP(ctx, ip) {
				r.logger.Warn("reconcile detected Cloudflare Proxy IP on non-proxied subdomain", "subdomain", subdomain, "ip", ip.String())
				return true
			}
		}
		if expectedIP == "" {
			return false
		}
		expectedAddr, err := netip.ParseAddr(expectedIP)
		if err != nil {
			return false
		}
		if len(res.IPs) != 1 || res.IPs[0] != expectedAddr {
			r.logger.Info("reconcile detected DNS IP drift", "subdomain", subdomain, "type", recordType, "dns", res.IPs, "expected", expectedIP)
			return true
		}
		return false
	default:
		return false
	}
}
