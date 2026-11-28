package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration wraps time.Duration to support human-readable YAML duration strings.
type Duration time.Duration

// UnmarshalYAML parses a YAML scalar duration string such as "10m" or "90s".
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.ScalarNode {
		return fmt.Errorf("duration must be a scalar string, got kind %d", value.Kind)
	}
	raw := strings.TrimSpace(value.Value)
	if raw == "" {
		*d = 0
		return nil
	}
	parsed, err := time.ParseDuration(raw)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", raw, err)
	}
	*d = Duration(parsed)
	return nil
}

// MarshalYAML serializes Duration as a standard Go duration string.
func (d Duration) MarshalYAML() (any, error) {
	return time.Duration(d).String(), nil
}

// Std returns the underlying time.Duration value.
func (d Duration) Std() time.Duration {
	return time.Duration(d)
}

// String implements fmt.Stringer.
func (d Duration) String() string {
	return time.Duration(d).String()
}

// Config represents the read-only configuration loaded from /etc/cf-edge/config.yaml.
type Config struct {
	NodeName     string             `yaml:"node_name"`
	WAN          WANConfig          `yaml:"wan"`
	Cloudflare   CloudflareConfig   `yaml:"cloudflare"`
	Reconcile    ReconcileConfig    `yaml:"reconcile"`
	PPPoEGuard   PPPoEGuardConfig   `yaml:"pppoe_guard"`
	DDoSShield   DDoSShieldConfig   `yaml:"ddos_shield"`
	EdgeFirewall EdgeFirewallConfig `yaml:"edge_firewall"`
	AutoUpdate   AutoUpdateConfig   `yaml:"auto_update"`
	Telegram     TelegramConfig     `yaml:"telegram"`
}

// EdgeFirewallConfig configures the OpenWrt fw4-native GeoIP & rate-limit nftables module.
type EdgeFirewallConfig struct {
	Enabled                bool                 `yaml:"enabled"`
	RefreshInterval        Duration             `yaml:"refresh_interval"`
	CachePath              string               `yaml:"cache_path"`
	WANDevices             []string             `yaml:"wan_devices"`
	GeoIPCountries         []string             `yaml:"geoip_countries"`
	IncludeCloudflare      bool                 `yaml:"include_cloudflare"`
	AllowCIDRs             []string             `yaml:"allow_cidrs"`
	DropInvalidTCP         bool                 `yaml:"drop_invalid_tcp"`
	DropIPOptionsTCP       bool                 `yaml:"drop_ip_options_tcp"`
	AllowSSHPort           bool                 `yaml:"allow_ssh_port"`
	RollbackOnCheckFail    bool                 `yaml:"rollback_on_check_fail"`
	HealthCheckTCP         []string             `yaml:"health_check_tcp"`
	HealthCheckUDP         []string             `yaml:"health_check_udp"`
	HealthCheckInternalTCP []string             `yaml:"health_check_internal_tcp"`
	Rules                  []FirewallRuleConfig `yaml:"rules"`
}

// FirewallRuleConfig configures ingress protection rules for a protocol and set of destination ports.
type FirewallRuleConfig struct {
	Name          string `yaml:"name"`
	Chain         string `yaml:"chain"` // "input" or "forward"
	Proto         string `yaml:"proto"` // "tcp" or "udp"
	Ports         []int  `yaml:"ports"`
	GeoIPEnforce  bool   `yaml:"geoip_enforce"`
	GlobalPPS     int    `yaml:"global_pps"`
	GlobalBurst   int    `yaml:"global_burst"`
	PerIPPPS      int    `yaml:"per_ip_pps"`
	PerIPBurst    int    `yaml:"per_ip_burst"`
	MaxConnsPerIP int    `yaml:"max_conns_per_ip"`
	SynRatePerIP  int    `yaml:"syn_rate_per_ip"`
	SynBurst      int    `yaml:"syn_burst"`
}

// AutoUpdateConfig configures scheduled daily self-updates from GitHub Releases.
type AutoUpdateConfig struct {
	Enabled bool   `yaml:"enabled"`
	Time    string `yaml:"time"`    // Daily local wall-clock time in 24h "HH:MM" format (default "03:30").
	Restart bool   `yaml:"restart"` // Restart /etc/init.d/cf-edge after updating binary (default true).
}

// WANConfig defines the OpenWrt logical WAN interfaces and Linux kernel L3 device names.
type WANConfig struct {
	IfaceV4       string `yaml:"iface_v4"`       // OpenWrt logical interface for IPv4 (ubus)
	IfaceV6       string `yaml:"iface_v6"`       // OpenWrt logical interface for IPv6 (ubus)
	WANDeviceV4   string `yaml:"wan_device_v4"`  // Optional Linux L3 device override (e.g. pppoe-wan, eth1.11, eth0)
	OverlayDevice string `yaml:"overlay_device"` // Linux L3 device for NetBird/WireGuard (e.g. wt0)
	LANDevice     string `yaml:"lan_device"`     // Linux L3 device for LAN bridge (e.g. br-lan, br-lan.50)
	OverlayIface  string `yaml:"overlay_iface"`  // Deprecated alias for overlay_device
	LANIface      string `yaml:"lan_iface"`      // Deprecated alias for lan_device
}

// EffectiveOverlayDevice returns the configured overlay L3 device (overlay_device or legacy overlay_iface).
func (w WANConfig) EffectiveOverlayDevice() string {
	if w.OverlayDevice != "" {
		return w.OverlayDevice
	}
	return w.OverlayIface
}

// EffectiveLANDevice returns the configured LAN L3 device (lan_device or legacy lan_iface).
func (w WANConfig) EffectiveLANDevice() string {
	if w.LANDevice != "" {
		return w.LANDevice
	}
	return w.LANIface
}

// CloudflareConfig defines Cloudflare DNS zone credentials and managed subdomains.
type CloudflareConfig struct {
	Enabled  bool           `yaml:"enabled"`
	ZoneID   string         `yaml:"zone_id"`
	APIToken string         `yaml:"api_token"`
	Records  []RecordConfig `yaml:"records"`
}

// RecordConfig configures DDNS synchronization for a single subdomain.
type RecordConfig struct {
	Subdomain string `yaml:"subdomain"`
	IPv4      bool   `yaml:"ipv4"`
	IPv6      bool   `yaml:"ipv6"`
	Proxied   bool   `yaml:"proxied"`
}

// ReconcileConfig configures periodic direct DNS verification bypassing local cache.
type ReconcileConfig struct {
	Enabled   bool     `yaml:"enabled"`
	Interval  Duration `yaml:"interval"`
	Resolvers []string `yaml:"resolvers"`
}

// PPPoEGuardConfig configures optional PPPoE recovery against netifd lockouts.
type PPPoEGuardConfig struct {
	Enabled     bool     `yaml:"enabled"`
	BootGrace   Duration `yaml:"boot_grace"`
	InitialWait Duration `yaml:"initial_wait"`
	PingTargets []string `yaml:"ping_targets"`
}

// DDoSShieldConfig configures optional edge DDoS detection, firewall shielding, and Worker sync.
type DDoSShieldConfig struct {
	Enabled            bool     `yaml:"enabled"`
	WorkerURL          string   `yaml:"worker_url"`
	WorkerToken        string   `yaml:"worker_token"`
	WANIngressPort     int      `yaml:"wan_ingress_port"`
	CheckInterval      Duration `yaml:"check_interval"`
	SustainDuration    Duration `yaml:"sustain_duration"`
	ConntrackThreshold int64    `yaml:"conntrack_threshold"`
	JunkMbpsThreshold  float64  `yaml:"junk_mbps_threshold"`
	RXPPSThreshold     float64  `yaml:"rx_pps_threshold"`
	MaxRedialsPerHour  int      `yaml:"max_redials_per_hour"`
	StatusPollInterval Duration `yaml:"status_poll_interval"`
}

// TelegramConfig configures Telegram Bot notifications.
type TelegramConfig struct {
	Enabled  bool   `yaml:"enabled"`
	BotToken string `yaml:"bot_token"`
	ChatID   string `yaml:"chat_id"`
}

// NeedsIPv6 returns true when Cloudflare DDNS is enabled and at least one record uses IPv6.
func (c *Config) NeedsIPv6() bool {
	if !c.Cloudflare.Enabled {
		return false
	}
	for _, rec := range c.Cloudflare.Records {
		if rec.IPv6 {
			return true
		}
	}
	return false
}

// Load reads, parses, applies defaults, and validates a YAML configuration file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	return Parse(data)
}

// Parse decodes YAML bytes, applies defaults, and validates the resulting Config.
func Parse(data []byte) (*Config, error) {
	cfg := defaultConfig()
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config yaml: %w", err)
	}
	if err := cfg.normalizeAndValidate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}
