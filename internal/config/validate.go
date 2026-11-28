package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

func defaultConfig() Config {
	return Config{
		WAN: WANConfig{
			IfaceV4: "wan",
		},
		Cloudflare: CloudflareConfig{
			Enabled: true,
		},
		Reconcile: ReconcileConfig{
			Enabled:   true,
			Interval:  Duration(10 * time.Minute),
			Resolvers: []string{"1.1.1.1:53", "8.8.8.8:53", "1.0.0.1:53"},
		},
		PPPoEGuard: PPPoEGuardConfig{
			Enabled:     false,
			BootGrace:   Duration(90 * time.Second),
			InitialWait: Duration(45 * time.Second),
			PingTargets: []string{"1.1.1.1", "8.8.8.8", "203.162.4.190"},
		},
		DDoSShield: DDoSShieldConfig{
			Enabled:            false,
			WANIngressPort:     443,
			CheckInterval:      Duration(5 * time.Second),
			SustainDuration:    Duration(25 * time.Second),
			ConntrackThreshold: 5000,
			JunkMbpsThreshold:  300,
			RXPPSThreshold:     80000,
			MaxRedialsPerHour:  3,
			StatusPollInterval: Duration(2 * time.Minute),
		},
		EdgeFirewall: defaultEdgeFirewallConfig(),
		Metrics: MetricsConfig{
			Enabled:            false,
			Port:               9108,
			IncludeNftCounters: true,
		},
		MeshWatchdog: defaultMeshWatchdogConfig(),
		AutoUpdate: AutoUpdateConfig{
			Enabled: false,
			Time:    "03:30",
			Restart: true,
		},
	}
}

func (c *Config) normalizeAndValidate() error {
	c.NodeName = strings.TrimSpace(c.NodeName)
	if c.NodeName == "" {
		host, err := os.Hostname()
		if err != nil || strings.TrimSpace(host) == "" {
			c.NodeName = "openwrt"
		} else {
			c.NodeName = strings.TrimSpace(host)
		}
	}

	c.WAN.IfaceV4 = strings.TrimSpace(c.WAN.IfaceV4)
	c.WAN.IfaceV6 = strings.TrimSpace(c.WAN.IfaceV6)
	c.WAN.WANDeviceV4 = strings.TrimSpace(c.WAN.WANDeviceV4)
	c.WAN.OverlayDevice = strings.TrimSpace(c.WAN.OverlayDevice)
	c.WAN.LANDevice = strings.TrimSpace(c.WAN.LANDevice)
	c.WAN.OverlayIface = strings.TrimSpace(c.WAN.OverlayIface)
	c.WAN.LANIface = strings.TrimSpace(c.WAN.LANIface)
	if c.WAN.OverlayDevice == "" {
		c.WAN.OverlayDevice = c.WAN.OverlayIface
	}
	if c.WAN.LANDevice == "" {
		c.WAN.LANDevice = c.WAN.LANIface
	}
	c.WAN.OverlayIface = c.WAN.OverlayDevice
	c.WAN.LANIface = c.WAN.LANDevice
	if c.WAN.IfaceV4 == "" {
		c.WAN.IfaceV4 = "wan"
	}

	for _, fn := range []func() error{
		c.validateCloudflare,
		c.validateReconcile,
		c.validatePPPoEGuard,
		c.validateDDoSShield,
		c.validateEdgeFirewall,
		c.validateMetrics,
		c.validateMeshWatchdog,
		c.validateAutoUpdate,
		c.validateTelegram,
	} {
		if err := fn(); err != nil {
			return err
		}
	}
	return nil
}

func (c *Config) validateCloudflare() error {
	c.Cloudflare.ZoneID = strings.TrimSpace(c.Cloudflare.ZoneID)
	c.Cloudflare.APIToken = strings.TrimSpace(c.Cloudflare.APIToken)
	if !c.Cloudflare.Enabled {
		c.Reconcile.Enabled = false
		return nil
	}
	if c.Cloudflare.ZoneID == "" {
		return errors.New("cloudflare.zone_id must not be empty")
	}
	if c.Cloudflare.APIToken == "" {
		return errors.New("cloudflare.api_token must not be empty")
	}
	if len(c.Cloudflare.Records) == 0 {
		return errors.New("cloudflare.records must contain at least one record")
	}

	seen := make(map[string]struct{}, len(c.Cloudflare.Records))
	for i := range c.Cloudflare.Records {
		rec := &c.Cloudflare.Records[i]
		rec.Subdomain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(rec.Subdomain)), ".")
		if rec.Subdomain == "" {
			return fmt.Errorf("cloudflare.records[%d].subdomain must not be empty", i)
		}
		if !rec.IPv4 && !rec.IPv6 {
			return fmt.Errorf("cloudflare.records[%d] (%s) must enable ipv4 or ipv6", i, rec.Subdomain)
		}
		if _, dup := seen[rec.Subdomain]; dup {
			return fmt.Errorf("duplicate cloudflare record subdomain %q", rec.Subdomain)
		}
		seen[rec.Subdomain] = struct{}{}
	}
	return nil
}

func (c *Config) validateReconcile() error {
	if !c.Cloudflare.Enabled {
		c.Reconcile.Enabled = false
		return nil
	}
	if !c.Reconcile.Enabled {
		return nil
	}
	if c.Reconcile.Interval.Std() <= 0 {
		return errors.New("reconcile.interval must be positive")
	}
	if len(c.Reconcile.Resolvers) == 0 {
		return errors.New("reconcile.resolvers must not be empty when reconcile is enabled")
	}
	for i, r := range c.Reconcile.Resolvers {
		normalized, err := normalizeResolverAddr(r)
		if err != nil {
			return fmt.Errorf("reconcile.resolvers[%d]: %w", i, err)
		}
		c.Reconcile.Resolvers[i] = normalized
	}
	return nil
}

func normalizeResolverAddr(raw string) (string, error) {
	addr := strings.TrimSpace(raw)
	if addr == "" {
		return "", errors.New("empty resolver address")
	}
	if !strings.Contains(addr, ":") || net.ParseIP(addr) != nil {
		addr = net.JoinHostPort(addr, "53")
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("invalid resolver %q: %w", raw, err)
	}
	if host == "" {
		return "", fmt.Errorf("empty host in resolver %q", raw)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", fmt.Errorf("invalid port in resolver %q", raw)
	}
	return net.JoinHostPort(host, portStr), nil
}

func (c *Config) validatePPPoEGuard() error {
	if !c.PPPoEGuard.Enabled {
		return nil
	}
	if c.PPPoEGuard.BootGrace.Std() < 0 {
		return errors.New("pppoe_guard.boot_grace must be non-negative")
	}
	if c.PPPoEGuard.InitialWait.Std() <= 0 {
		return errors.New("pppoe_guard.initial_wait must be positive")
	}
	if len(c.PPPoEGuard.PingTargets) == 0 {
		return errors.New("pppoe_guard.ping_targets must not be empty when pppoe_guard is enabled")
	}
	for i, target := range c.PPPoEGuard.PingTargets {
		t := strings.TrimSpace(target)
		if t == "" {
			return fmt.Errorf("pppoe_guard.ping_targets[%d] must not be empty", i)
		}
		c.PPPoEGuard.PingTargets[i] = t
	}
	return nil
}

func (c *Config) validateDDoSShield() error {
	if c.DDoSShield.WANIngressPort == 0 && !c.DDoSShield.Enabled {
		c.DDoSShield.WANIngressPort = 443
	}
	if c.DDoSShield.WANIngressPort < 1 || c.DDoSShield.WANIngressPort > 65535 {
		return errors.New("ddos_shield.wan_ingress_port must be between 1 and 65535")
	}
	c.DDoSShield.WorkerURL = strings.TrimRight(strings.TrimSpace(c.DDoSShield.WorkerURL), "/")
	c.DDoSShield.WorkerToken = strings.TrimSpace(c.DDoSShield.WorkerToken)

	if !c.DDoSShield.Enabled {
		return nil
	}
	if c.WAN.EffectiveOverlayDevice() == "" {
		return errors.New("wan.overlay_device (or overlay_iface) must not be empty when ddos_shield is enabled")
	}
	if c.DDoSShield.WorkerURL == "" {
		return errors.New("ddos_shield.worker_url must not be empty when ddos_shield is enabled")
	}
	u, err := url.ParseRequestURI(c.DDoSShield.WorkerURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("ddos_shield.worker_url %q is not a valid http/https URL", c.DDoSShield.WorkerURL)
	}
	if c.DDoSShield.WorkerToken == "" {
		return errors.New("ddos_shield.worker_token must not be empty when ddos_shield is enabled")
	}
	if c.DDoSShield.CheckInterval.Std() <= 0 || c.DDoSShield.SustainDuration.Std() <= 0 || c.DDoSShield.StatusPollInterval.Std() <= 0 {
		return errors.New("ddos_shield check_interval, sustain_duration, and status_poll_interval must be positive")
	}
	if c.DDoSShield.ConntrackThreshold <= 0 || c.DDoSShield.JunkMbpsThreshold <= 0 || c.DDoSShield.RXPPSThreshold <= 0 {
		return errors.New("ddos_shield thresholds must be positive")
	}
	if c.DDoSShield.MaxRedialsPerHour <= 0 {
		return errors.New("ddos_shield.max_redials_per_hour must be positive")
	}
	return nil
}

func (c *Config) validateMetrics() error {
	c.Metrics.BindDevice = strings.TrimSpace(c.Metrics.BindDevice)
	if c.Metrics.Port == 0 {
		c.Metrics.Port = 9108
	}
	if c.Metrics.Port < 1 || c.Metrics.Port > 65535 {
		return errors.New("metrics.port must be between 1 and 65535")
	}
	if !c.Metrics.Enabled {
		return nil
	}
	if c.Metrics.BindDevice == "" {
		c.Metrics.BindDevice = c.WAN.EffectiveOverlayDevice()
	}
	if c.Metrics.BindDevice == "" {
		return errors.New("metrics.bind_device (or wan.overlay_device) must not be empty when metrics is enabled")
	}
	switch strings.ToLower(c.Metrics.BindDevice) {
	case "0.0.0.0", "::", "*", "any":
		return fmt.Errorf("metrics.bind_device %q must name a specific network device (e.g. wt0), never wildcard", c.Metrics.BindDevice)
	}
	return nil
}

func (c *Config) validateTelegram() error {
	c.Telegram.BotToken = strings.TrimSpace(c.Telegram.BotToken)
	c.Telegram.ChatID = strings.TrimSpace(c.Telegram.ChatID)
	if !c.Telegram.Enabled {
		return nil
	}
	if c.Telegram.BotToken == "" || c.Telegram.ChatID == "" {
		return errors.New("telegram.bot_token and telegram.chat_id are required when telegram is enabled")
	}
	return nil
}

// ParseDailyTime parses a 24-hour "HH:MM" wall-clock string.
func ParseDailyTime(raw string) (int, int, error) {
	s := strings.TrimSpace(raw)
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("auto_update.time %q must use HH:MM 24h format", raw)
	}
	hour, errH := strconv.Atoi(parts[0])
	min, errM := strconv.Atoi(parts[1])
	if errH != nil || errM != nil || hour < 0 || hour > 23 || min < 0 || min > 59 {
		return 0, 0, fmt.Errorf("auto_update.time %q out of range (expected 00:00..23:59)", raw)
	}
	return hour, min, nil
}

func (c *Config) validateAutoUpdate() error {
	if strings.TrimSpace(c.AutoUpdate.Time) == "" {
		c.AutoUpdate.Time = "03:30"
	}
	hour, min, err := ParseDailyTime(c.AutoUpdate.Time)
	if err != nil {
		return err
	}
	c.AutoUpdate.Time = fmt.Sprintf("%02d:%02d", hour, min)
	return nil
}
