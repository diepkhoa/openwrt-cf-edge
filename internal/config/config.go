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
	NodeName   string           `yaml:"node_name"`
	WAN        WANConfig        `yaml:"wan"`
	Cloudflare CloudflareConfig `yaml:"cloudflare"`
	Reconcile  ReconcileConfig  `yaml:"reconcile"`
	PPPoEGuard PPPoEGuardConfig `yaml:"pppoe_guard"`
	DDoSShield DDoSShieldConfig `yaml:"ddos_shield"`
	Telegram   TelegramConfig   `yaml:"telegram"`
}

// WANConfig defines the WAN and overlay/LAN network interfaces on OpenWrt.
type WANConfig struct {
	IfaceV4      string `yaml:"iface_v4"`
	IfaceV6      string `yaml:"iface_v6"`
	OverlayIface string `yaml:"overlay_iface"`
	LANIface     string `yaml:"lan_iface"`
}

// CloudflareConfig defines Cloudflare DNS zone credentials and managed subdomains.
type CloudflareConfig struct {
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

// NeedsIPv6 returns true when at least one configured DNS record has IPv6 enabled.
func (c *Config) NeedsIPv6() bool {
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
