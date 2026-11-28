package metrics

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/diepkhoa/openwrt-cf-edge/internal/config"
	"github.com/diepkhoa/openwrt-cf-edge/internal/ddos"
	"github.com/diepkhoa/openwrt-cf-edge/internal/edgefw"
	"github.com/diepkhoa/openwrt-cf-edge/internal/platform"
	"github.com/diepkhoa/openwrt-cf-edge/internal/state"
	"github.com/diepkhoa/openwrt-cf-edge/internal/ubus"
)

// PeerSample allows optional mesh watchdog metrics to be exported cleanly on /metrics.
type PeerSample struct {
	Name  string
	IP    string
	Site  string
	Up    bool
	RTTMs float64
}

// PeerMetricsProvider optionally returns live mesh peer health samples.
type PeerMetricsProvider interface {
	SnapshotPeers() []PeerSample
}

// Collector gathers router, firewall, PPPoE, and DDNS metrics cleanly in Prometheus text format.
type Collector struct {
	cfg        *config.Config
	env        platform.Env
	version    string
	ubusClient ubus.Client
	store      *state.Store
	procReader ddos.SampleReader
	nft        edgefw.NftRunner
	lockPath   string
	wanDevFn   func(context.Context) string
	peerProv   PeerMetricsProvider

	mu             sync.Mutex
	prevRaw        ddos.RawCounters
	hasPrevRaw     bool
	lastRates      ddos.RateSnapshot
	nftCacheAt     time.Time
	nftCacheActive bool
	nftCacheRules  []RuleCounter
}

// NewCollector builds a Prometheus text Collector.
func NewCollector(
	cfg *config.Config,
	env platform.Env,
	version string,
	ubusClient ubus.Client,
	store *state.Store,
	procReader ddos.SampleReader,
	nft edgefw.NftRunner,
	wanDevFn func(context.Context) string,
	lockPath string,
) *Collector {
	if procReader == nil {
		procReader = ddos.NewProcSysReader()
	}
	if nft == nil {
		nft = edgefw.ExecNftRunner{}
	}
	if lockPath == "" {
		lockPath = state.DefaultShieldLockPath
	}
	return &Collector{
		cfg:        cfg,
		env:        env,
		version:    version,
		ubusClient: ubusClient,
		store:      store,
		procReader: procReader,
		nft:        nft,
		lockPath:   lockPath,
		wanDevFn:   wanDevFn,
	}
}

// SetPeerProvider attaches an optional mesh peer metrics provider.
func (c *Collector) SetPeerProvider(p PeerMetricsProvider) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.peerProv = p
}

// WritePrometheus writes all metrics in Prometheus exposition format 0.0.4.
func (c *Collector) WritePrometheus(ctx context.Context, w io.Writer) {
	plat := "linux"
	if c.env.HasUbus {
		plat = "openwrt"
	}
	fmt.Fprintf(w, "# HELP cf_edge_info Static metadata about running cf-edge instance.\n# TYPE cf_edge_info gauge\n")
	fmt.Fprintf(w, "cf_edge_info{version=%q,node=%q,platform=%q} 1\n", c.version, c.cfg.NodeName, plat)

	c.writeNetworkMetrics(ctx, w)
	c.writeFirewallMetrics(ctx, w)
	c.writePPPoEAndDDNSMetrics(ctx, w)
	c.writePeerMetrics(w)
}

func (c *Collector) writeNetworkMetrics(ctx context.Context, w io.Writer) {
	wanDev := c.resolveWANDev(ctx)
	ovDev := c.cfg.WAN.EffectiveOverlayDevice()
	lanDev := c.cfg.WAN.EffectiveLANDevice()

	raw, err := c.procReader.Read(wanDev, ovDev, lanDev)
	if err == nil {
		c.mu.Lock()
		if c.hasPrevRaw {
			if rates := ddos.ComputeRates(c.prevRaw, raw); rates.Valid {
				c.lastRates = rates
			}
		}
		c.prevRaw = raw
		c.hasPrevRaw = true
		rates := c.lastRates
		c.mu.Unlock()

		fmt.Fprintf(w, "# HELP cf_edge_wan_rx_bytes_total Total received bytes on WAN device.\n# TYPE cf_edge_wan_rx_bytes_total counter\n")
		fmt.Fprintf(w, "cf_edge_wan_rx_bytes_total{device=%q} %d\n", wanDev, raw.WANRxBytes)
		fmt.Fprintf(w, "# HELP cf_edge_wan_rx_packets_total Total received packets on WAN device.\n# TYPE cf_edge_wan_rx_packets_total counter\n")
		fmt.Fprintf(w, "cf_edge_wan_rx_packets_total{device=%q} %d\n", wanDev, raw.WANRxPackets)
		if ovDev != "" {
			fmt.Fprintf(w, "# HELP cf_edge_overlay_tx_bytes_total Total transmitted bytes on overlay device.\n# TYPE cf_edge_overlay_tx_bytes_total counter\n")
			fmt.Fprintf(w, "cf_edge_overlay_tx_bytes_total{device=%q} %d\n", ovDev, raw.OverlayTxBytes)
		}
		if lanDev != "" {
			fmt.Fprintf(w, "# HELP cf_edge_lan_tx_bytes_total Total transmitted bytes on LAN device.\n# TYPE cf_edge_lan_tx_bytes_total counter\n")
			fmt.Fprintf(w, "cf_edge_lan_tx_bytes_total{device=%q} %d\n", lanDev, raw.LANTxBytes)
		}
		fmt.Fprintf(w, "# HELP cf_edge_conntrack_entries Current active nf_conntrack entries.\n# TYPE cf_edge_conntrack_entries gauge\n")
		fmt.Fprintf(w, "cf_edge_conntrack_entries %d\n", raw.Conntrack)
		if rates.Valid {
			fmt.Fprintf(w, "# HELP cf_edge_junk_mbps Estimated non-forwarded inbound WAN Mbps.\n# TYPE cf_edge_junk_mbps gauge\n")
			fmt.Fprintf(w, "cf_edge_junk_mbps %.3f\n", rates.JunkMbps)
		}
	}

	shieldVal := 0
	if state.IsShielded(c.lockPath) {
		shieldVal = 1
	}
	fmt.Fprintf(w, "# HELP cf_edge_ddos_shield_active 1 when DDoS shield lock is active.\n# TYPE cf_edge_ddos_shield_active gauge\n")
	fmt.Fprintf(w, "cf_edge_ddos_shield_active %d\n", shieldVal)
}

func (c *Collector) writeFirewallMetrics(ctx context.Context, w io.Writer) {
	active, rules := c.cachedNftCounters(ctx)
	actVal := 0
	if active {
		actVal = 1
	}
	fmt.Fprintf(w, "# HELP cf_edge_fw_active 1 when table inet cf_edge_fw is loaded.\n# TYPE cf_edge_fw_active gauge\n")
	fmt.Fprintf(w, "cf_edge_fw_active %d\n", actVal)

	if cache, err := edgefw.LoadGeoIPCache(c.cfg.EdgeFirewall.CachePath); err == nil {
		fmt.Fprintf(w, "# HELP cf_edge_fw_geoip_cidrs Number of merged GeoIP/Cloudflare CIDRs in cache.\n# TYPE cf_edge_fw_geoip_cidrs gauge\n")
		fmt.Fprintf(w, "cf_edge_fw_geoip_cidrs{family=\"ipv4\"} %d\n", len(cache.IPv4CIDRs))
		fmt.Fprintf(w, "cf_edge_fw_geoip_cidrs{family=\"ipv6\"} %d\n", len(cache.IPv6CIDRs))
	}

	if c.cfg.Metrics.IncludeNftCounters && len(rules) > 0 {
		fmt.Fprintf(w, "# HELP cf_edge_fw_rule_packets_total Packets matched by cf_edge_fw nftables rules.\n# TYPE cf_edge_fw_rule_packets_total counter\n")
		for _, r := range rules {
			fmt.Fprintf(w, "cf_edge_fw_rule_packets_total{chain=%q,rule=%q,verdict=%q} %d\n", r.Chain, r.Rule, r.Verdict, r.Packets)
		}
		fmt.Fprintf(w, "# HELP cf_edge_fw_rule_bytes_total Bytes matched by cf_edge_fw nftables rules.\n# TYPE cf_edge_fw_rule_bytes_total counter\n")
		for _, r := range rules {
			fmt.Fprintf(w, "cf_edge_fw_rule_bytes_total{chain=%q,rule=%q,verdict=%q} %d\n", r.Chain, r.Rule, r.Verdict, r.Bytes)
		}
	}
}

func (c *Collector) writePPPoEAndDDNSMetrics(ctx context.Context, w io.Writer) {
	if c.env.HasUbus && c.ubusClient != nil {
		if st, err := c.ubusClient.Status(ctx, c.cfg.WAN.IfaceV4); err == nil {
			upVal := 0
			if st.Up {
				upVal = 1
			}
			fmt.Fprintf(w, "# HELP cf_edge_pppoe_up 1 when WAN interface is up via ubus.\n# TYPE cf_edge_pppoe_up gauge\n")
			fmt.Fprintf(w, "cf_edge_pppoe_up{iface=%q} %d\n", c.cfg.WAN.IfaceV4, upVal)
			fmt.Fprintf(w, "# HELP cf_edge_pppoe_uptime_seconds WAN interface uptime reported by ubus.\n# TYPE cf_edge_pppoe_uptime_seconds gauge\n")
			fmt.Fprintf(w, "cf_edge_pppoe_uptime_seconds{iface=%q} %d\n", c.cfg.WAN.IfaceV4, st.Uptime)
		}
	}
	if c.store == nil {
		return
	}
	st := c.store.Get()
	if st.PPPoEStatus != nil {
		fmt.Fprintf(w, "# HELP cf_edge_pppoe_redials_total PPPoE Guard redial attempts tracked in runtime state.\n# TYPE cf_edge_pppoe_redials_total counter\n")
		fmt.Fprintf(w, "cf_edge_pppoe_redials_total %d\n", st.PPPoEStatus.RedialCount)
	}
	if c.cfg.Cloudflare.Enabled && !st.LastUpdated.IsZero() {
		fmt.Fprintf(w, "# HELP cf_edge_ddns_last_sync_timestamp_seconds Unix timestamp of last Cloudflare DDNS sync.\n# TYPE cf_edge_ddns_last_sync_timestamp_seconds gauge\n")
		fmt.Fprintf(w, "cf_edge_ddns_last_sync_timestamp_seconds %d\n", st.LastUpdated.Unix())
	}
}

func (c *Collector) writePeerMetrics(w io.Writer) {
	c.mu.Lock()
	prov := c.peerProv
	c.mu.Unlock()
	if prov == nil {
		return
	}
	peers := prov.SnapshotPeers()
	if len(peers) == 0 {
		return
	}
	fmt.Fprintf(w, "# HELP cf_edge_mesh_peer_up 1 when NetBird mesh peer responds to ICMP probe.\n# TYPE cf_edge_mesh_peer_up gauge\n")
	for _, p := range peers {
		up := 0
		if p.Up {
			up = 1
		}
		fmt.Fprintf(w, "cf_edge_mesh_peer_up{name=%q,ip=%q,site=%q} %d\n", p.Name, p.IP, p.Site, up)
	}
	fmt.Fprintf(w, "# HELP cf_edge_mesh_peer_rtt_ms Last observed ICMP RTT in milliseconds over overlay.\n# TYPE cf_edge_mesh_peer_rtt_ms gauge\n")
	for _, p := range peers {
		if p.Up {
			fmt.Fprintf(w, "cf_edge_mesh_peer_rtt_ms{name=%q,ip=%q,site=%q} %.2f\n", p.Name, p.IP, p.Site, p.RTTMs)
		}
	}
}

func (c *Collector) resolveWANDev(ctx context.Context) string {
	if c.cfg.WAN.WANDeviceV4 != "" {
		return c.cfg.WAN.WANDeviceV4
	}
	if c.env.HasUbus && c.ubusClient != nil {
		if st, err := c.ubusClient.Status(ctx, c.cfg.WAN.IfaceV4); err == nil {
			if dev := st.EffectiveL3Device(); dev != "" {
				return dev
			}
		}
	}
	if c.wanDevFn != nil {
		if dev := strings.TrimSpace(c.wanDevFn(ctx)); dev != "" {
			return dev
		}
	}
	return "pppoe-wan"
}

func (c *Collector) cachedNftCounters(ctx context.Context) (bool, []RuleCounter) {
	c.mu.Lock()
	if !c.nftCacheAt.IsZero() && time.Since(c.nftCacheAt) < 5*time.Second {
		act, rules := c.nftCacheActive, c.nftCacheRules
		c.mu.Unlock()
		return act, rules
	}
	c.mu.Unlock()

	callCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	out, err := c.nft.Run(callCtx, "", "-j", "list", "table", "inet", edgefw.TableName)
	active := err == nil
	var rules []RuleCounter
	if active && c.cfg.Metrics.IncludeNftCounters {
		if parsed, pErr := ParseNftCounters(out); pErr == nil {
			rules = parsed
		}
	}

	c.mu.Lock()
	c.nftCacheAt = time.Now()
	c.nftCacheActive = active
	c.nftCacheRules = rules
	c.mu.Unlock()
	return active, rules
}
