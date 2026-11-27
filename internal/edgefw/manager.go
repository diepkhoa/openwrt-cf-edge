package edgefw

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/diepkhoa/openwrt-cf-edge/internal/config"
	"github.com/diepkhoa/openwrt-cf-edge/internal/notify"
	"github.com/diepkhoa/openwrt-cf-edge/internal/ubus"
)

// ApplyOptions controls CLI or daemon firewall application behavior.
type ApplyOptions struct {
	ForceRefresh    bool
	WANDevOverride  []string
	NotifyOnFailure bool
}

// RuntimeStatus summarizes current `edge_firewall` state for `cf-edge status` and CLI inspection.
type RuntimeStatus struct {
	Enabled        bool      `json:"enabled"`
	NftActive      bool      `json:"nft_active"`
	WANDevices     []string  `json:"wan_devices,omitempty"`
	RuleCount      int       `json:"rule_count"`
	GeoIPv4Count   int       `json:"geoip_v4_count"`
	GeoIPv6Count   int       `json:"geoip_v6_count"`
	CacheUpdatedAt time.Time `json:"cache_updated_at,omitempty"`
	RolledBack     bool      `json:"rolled_back,omitempty"`
	LastError      string    `json:"last_error,omitempty"`
}

// Manager orchestrates GeoIP loading, fw4-native nftables rendering, connectivity checks, and automatic rollback.
type Manager struct {
	cfg        *config.Config
	ubusClient ubus.Client
	listener   *ubus.Listener
	catalog    *Catalog
	prober     HealthChecker
	nft        NftRunner
	notifier   notify.Notifier
	logger     *slog.Logger

	mu           sync.Mutex
	rolledHash   string
	lastWANDevs  []string
	lastError    string
	lastRollBack bool
}

// NewManager constructs an edgefw Manager.
func NewManager(
	cfg *config.Config,
	ubusClient ubus.Client,
	listener *ubus.Listener,
	catalog *Catalog,
	prober HealthChecker,
	nft NftRunner,
	notifier notify.Notifier,
	logger *slog.Logger,
) *Manager {
	if catalog == nil {
		catalog = NewCatalog(nil)
	}
	if prober == nil {
		prober = NewConnectivityProber()
	}
	if nft == nil {
		nft = ExecNftRunner{}
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Manager{
		cfg:        cfg,
		ubusClient: ubusClient,
		listener:   listener,
		catalog:    catalog,
		prober:     prober,
		nft:        nft,
		notifier:   notifier,
		logger:     logger,
	}
}

// SetListener attaches a ubus.Listener before launching Run in daemon mode.
func (m *Manager) SetListener(l *ubus.Listener) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.listener = l
}

// Render builds and returns the nftables script for inspection or dry-run.
func (m *Manager) Render(ctx context.Context, opts ApplyOptions) (string, []string, GeoIPCache, error) {
	wanDevs, err := ResolveWANDevices(ctx, m.cfg, m.ubusClient, opts.WANDevOverride)
	if err != nil {
		return "", nil, GeoIPCache{}, err
	}
	var cache GeoIPCache
	if NeedsGeoIPSets(m.cfg.EdgeFirewall) {
		var cacheErr error
		cache, cacheErr = m.catalog.EnsureSets(ctx, m.cfg.EdgeFirewall, opts.ForceRefresh)
		if cacheErr != nil {
			if len(cache.IPv4CIDRs) == 0 && len(cache.IPv6CIDRs) == 0 {
				return "", nil, GeoIPCache{}, cacheErr
			}
			m.logger.Warn("using fallback GeoIP cache after refresh error", "err", cacheErr)
		}
	}
	script, err := BuildScript(m.cfg, wanDevs, cache.IPv4CIDRs, cache.IPv6CIDRs)
	if err != nil {
		return "", nil, GeoIPCache{}, err
	}
	return script, wanDevs, cache, nil
}

// Apply renders, dry-runs (`nft -c`), snapshots baseline connectivity, applies rules, and rolls back on regression.
func (m *Manager) Apply(ctx context.Context, opts ApplyOptions) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	script, wanDevs, cache, err := m.Render(ctx, opts)
	if err != nil {
		m.recordFailure(err, false)
		return err
	}
	if _, err := m.nft.Run(ctx, script, "-c", "-f", "-"); err != nil {
		err = fmt.Errorf("nft syntax check failed: %w", err)
		m.recordFailure(err, false)
		return err
	}

	hadPrev, prevDump := snapshotTable(ctx, m.nft)
	var base Baseline
	if m.cfg.EdgeFirewall.RollbackOnCheckFail {
		base = m.prober.SnapshotBaseline(ctx, m.cfg.EdgeFirewall)
	}

	if _, err := m.nft.Run(ctx, script, "-f", "-"); err != nil {
		rollbackTable(ctx, m.nft, hadPrev, prevDump)
		err = fmt.Errorf("apply nftables rules: %w", err)
		m.recordFailure(err, true)
		m.alert(ctx, opts.NotifyOnFailure, "APPLY FAILED (ROLLED BACK)", err.Error())
		return err
	}

	if m.cfg.EdgeFirewall.RollbackOnCheckFail {
		if verifyErr := m.prober.Verify(ctx, m.cfg.EdgeFirewall, base); verifyErr != nil {
			rollbackTable(ctx, m.nft, hadPrev, prevDump)
			m.rolledHash = m.configDigest()
			m.recordFailure(verifyErr, true)
			m.logger.Error("edge firewall rolled back after connectivity check failure", "err", verifyErr)
			m.alert(ctx, opts.NotifyOnFailure, "AUTO-ROLLBACK TRIGGERED", verifyErr.Error())
			return verifyErr
		}
	}

	m.rolledHash = ""
	m.lastWANDevs = wanDevs
	m.lastError = ""
	m.lastRollBack = false
	m.logger.Info("edge firewall applied",
		"wan_devs", strings.Join(wanDevs, ","),
		"rules", len(m.cfg.EdgeFirewall.Rules),
		"geoip_v4", len(cache.IPv4CIDRs),
		"geoip_v6", len(cache.IPv6CIDRs),
	)
	return nil
}

// Remove deletes `table inet cf_edge_fw` if present.
func (m *Manager) Remove(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !isTableActive(ctx, m.nft) {
		return nil
	}
	_, err := m.nft.Run(ctx, "", "delete", "table", "inet", TableName)
	return err
}

// Status returns live kernel table state and GeoIP cache metadata.
func (m *Manager) Status(ctx context.Context) RuntimeStatus {
	m.mu.Lock()
	st := RuntimeStatus{
		Enabled:    m.cfg.EdgeFirewall.Enabled,
		NftActive:  isTableActive(ctx, m.nft),
		WANDevices: append([]string(nil), m.lastWANDevs...),
		RuleCount:  len(m.cfg.EdgeFirewall.Rules),
		RolledBack: m.lastRollBack,
		LastError:  m.lastError,
	}
	m.mu.Unlock()

	if cache, err := LoadGeoIPCache(m.cfg.EdgeFirewall.CachePath); err == nil {
		st.GeoIPv4Count = len(cache.IPv4CIDRs)
		st.GeoIPv6Count = len(cache.IPv6CIDRs)
		st.CacheUpdatedAt = cache.FetchedAt
	}
	return st
}

// Run maintains `table inet cf_edge_fw` across boot, WAN interface changes, and weekly GeoIP refreshes.
func (m *Manager) Run(ctx context.Context) {
	if !m.cfg.EdgeFirewall.Enabled {
		return
	}
	m.mu.Lock()
	l := m.listener
	m.mu.Unlock()

	var events <-chan ubus.Event
	var unsub func()
	if l != nil {
		events, unsub = l.Subscribe(16)
		defer unsub()
	}

	m.applyWithBootRetry(ctx)

	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-events:
			if (ev.Action == "ifup" || ev.Action == "ifupdate") &&
				(ev.Interface == m.cfg.WAN.IfaceV4 || (m.cfg.WAN.IfaceV6 != "" && ev.Interface == m.cfg.WAN.IfaceV6)) {
				if err := m.applyIfAllowed(ctx, false); err != nil {
					m.logger.Warn("edge firewall sync on WAN event failed", "iface", ev.Interface, "err", err)
				}
			}
		case <-ticker.C:
			if m.isCacheDueForRefresh() || !isTableActive(ctx, m.nft) {
				if err := m.applyIfAllowed(ctx, false); err != nil {
					m.logger.Warn("edge firewall periodic sync failed", "err", err)
				}
			}
		}
	}
}

func (m *Manager) applyWithBootRetry(ctx context.Context) {
	for attempt := 0; attempt < 6; attempt++ {
		if err := m.applyIfAllowed(ctx, true); err == nil {
			return
		} else {
			m.logger.Warn("initial edge firewall apply deferred", "attempt", attempt+1, "err", err)
		}
		if attempt < 5 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
		}
	}
}

func (m *Manager) applyIfAllowed(ctx context.Context, notifyOnFail bool) error {
	m.mu.Lock()
	rolledHash := m.rolledHash
	m.mu.Unlock()
	if rolledHash != "" && rolledHash == m.configDigest() {
		return fmt.Errorf("skipping auto-apply after rollback for current configuration")
	}
	applyCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	return m.Apply(applyCtx, ApplyOptions{NotifyOnFailure: notifyOnFail})
}

func (m *Manager) isCacheDueForRefresh() bool {
	if !NeedsGeoIPSets(m.cfg.EdgeFirewall) {
		return false
	}
	cache, err := LoadGeoIPCache(m.cfg.EdgeFirewall.CachePath)
	if err != nil {
		return true
	}
	return time.Since(cache.FetchedAt) >= m.cfg.EdgeFirewall.RefreshInterval.Std()
}

func (m *Manager) recordFailure(err error, rolled bool) {
	m.lastError = err.Error()
	m.lastRollBack = rolled
}

func (m *Manager) alert(ctx context.Context, send bool, action, detail string) {
	if !send || m.notifier == nil {
		return
	}
	_ = m.notifier.Send(ctx, notify.FormatFirewallAlert(m.cfg.NodeName, action, detail))
}

func (m *Manager) configDigest() string {
	raw, _ := json.Marshal(m.cfg.EdgeFirewall)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:8])
}
