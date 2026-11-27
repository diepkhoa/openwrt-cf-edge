package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const DefaultGeoIPCachePath = "/etc/cf-edge/geoip-cache.json"

var (
	countryCodeRe = regexp.MustCompile(`^[a-z]{2}$`)
	ruleNameRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9_]*$`)
)

func defaultEdgeFirewallConfig() EdgeFirewallConfig {
	return EdgeFirewallConfig{
		Enabled:             false,
		RefreshInterval:     Duration(7 * 24 * time.Hour),
		CachePath:           DefaultGeoIPCachePath,
		GeoIPCountries:      []string{"vn"},
		IncludeCloudflare:   true,
		DropInvalidTCP:      true,
		DropIPOptionsTCP:    false,
		AllowSSHPort:        false,
		RollbackOnCheckFail: true,
		HealthCheckTCP:      []string{"1.1.1.1:443", "8.8.8.8:443"},
		HealthCheckUDP:      []string{"1.1.1.1:53", "8.8.8.8:53"},
	}
}

// IsForbiddenWANDevice returns true if dev matches a local, bridge, LAN, or overlay interface
// that must never be placed into WAN ingress filtering sets.
func IsForbiddenWANDevice(dev string, lanIface, overlayIface string) bool {
	d := strings.ToLower(strings.TrimSpace(dev))
	if d == "" || d == "lo" {
		return true
	}
	if lan := strings.ToLower(strings.TrimSpace(lanIface)); lan != "" && d == lan {
		return true
	}
	if ov := strings.ToLower(strings.TrimSpace(overlayIface)); ov != "" && d == ov {
		return true
	}
	for _, prefix := range []string{"br-", "lan", "wg", "wt", "tailscale", "tun", "tap", "docker", "virbr", "veth", "warp"} {
		if strings.HasPrefix(d, prefix) {
			return true
		}
	}
	return false
}

func (c *Config) validateEdgeFirewall() error {
	ef := &c.EdgeFirewall
	ef.CachePath = strings.TrimSpace(ef.CachePath)
	if ef.CachePath == "" {
		ef.CachePath = DefaultGeoIPCachePath
	}
	if ef.RefreshInterval.Std() <= 0 {
		return errors.New("edge_firewall.refresh_interval must be positive")
	}

	if err := c.validateEdgeFirewallTargets(ef); err != nil {
		return err
	}
	if err := validateEdgeFirewallLists(ef); err != nil {
		return err
	}

	seenRules := make(map[string]struct{}, len(ef.Rules))
	for i := range ef.Rules {
		if err := validateFirewallRule(&ef.Rules[i], i, ef.AllowSSHPort, seenRules); err != nil {
			return err
		}
	}
	if ef.Enabled && len(ef.Rules) == 0 && !ef.DropIPOptionsTCP {
		return errors.New("edge_firewall.rules must contain at least one rule when edge_firewall is enabled")
	}
	return nil
}

func (c *Config) validateEdgeFirewallTargets(ef *EdgeFirewallConfig) error {
	for i, dev := range ef.WANDevices {
		trimmed := strings.TrimSpace(dev)
		if trimmed == "" {
			return fmt.Errorf("edge_firewall.wan_devices[%d] must not be empty", i)
		}
		if IsForbiddenWANDevice(trimmed, c.WAN.LANIface, c.WAN.OverlayIface) {
			return fmt.Errorf("edge_firewall.wan_devices[%d] (%q) cannot reference loopback, LAN, bridge, or overlay interface", i, trimmed)
		}
		ef.WANDevices[i] = trimmed
	}
	for i, hp := range ef.HealthCheckTCP {
		norm, err := validateHostPort(hp, "443")
		if err != nil {
			return fmt.Errorf("edge_firewall.health_check_tcp[%d]: %w", i, err)
		}
		ef.HealthCheckTCP[i] = norm
	}
	for i, hp := range ef.HealthCheckUDP {
		norm, err := validateHostPort(hp, "53")
		if err != nil {
			return fmt.Errorf("edge_firewall.health_check_udp[%d]: %w", i, err)
		}
		ef.HealthCheckUDP[i] = norm
	}
	for i, hp := range ef.HealthCheckInternalTCP {
		norm, err := validateHostPort(hp, "")
		if err != nil {
			return fmt.Errorf("edge_firewall.health_check_internal_tcp[%d]: %w", i, err)
		}
		ef.HealthCheckInternalTCP[i] = norm
	}
	return nil
}

func validateEdgeFirewallLists(ef *EdgeFirewallConfig) error {
	seenCountries := make(map[string]struct{}, len(ef.GeoIPCountries))
	var cleanCountries []string
	for i, raw := range ef.GeoIPCountries {
		cc := strings.ToLower(strings.TrimSpace(raw))
		if !countryCodeRe.MatchString(cc) {
			return fmt.Errorf("edge_firewall.geoip_countries[%d] (%q) must be an ISO-3166 alpha-2 code (e.g. \"vn\")", i, raw)
		}
		if _, ok := seenCountries[cc]; !ok {
			seenCountries[cc] = struct{}{}
			cleanCountries = append(cleanCountries, cc)
		}
	}
	ef.GeoIPCountries = cleanCountries

	for i, raw := range ef.AllowCIDRs {
		p, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil {
			return fmt.Errorf("edge_firewall.allow_cidrs[%d] (%q): %w", i, raw, err)
		}
		ef.AllowCIDRs[i] = p.Masked().String()
	}
	return nil
}

func validateFirewallRule(r *FirewallRuleConfig, idx int, allowSSH bool, seen map[string]struct{}) error {
	r.Name = strings.ToLower(strings.TrimSpace(r.Name))
	if r.Name == "" {
		r.Name = fmt.Sprintf("rule_%d", idx)
	}
	if !ruleNameRe.MatchString(r.Name) || len(r.Name) > 32 {
		return fmt.Errorf("edge_firewall.rules[%d].name (%q) must match ^[a-z0-9][a-z0-9_]*$ (max 32 chars)", idx, r.Name)
	}
	if _, dup := seen[r.Name]; dup {
		return fmt.Errorf("duplicate edge_firewall rule name %q", r.Name)
	}
	seen[r.Name] = struct{}{}

	r.Chain = strings.ToLower(strings.TrimSpace(r.Chain))
	if r.Chain != "input" && r.Chain != "forward" {
		return fmt.Errorf("edge_firewall.rules[%s].chain %q must be \"input\" or \"forward\"", r.Name, r.Chain)
	}
	r.Proto = strings.ToLower(strings.TrimSpace(r.Proto))
	if r.Proto != "tcp" && r.Proto != "udp" {
		return fmt.Errorf("edge_firewall.rules[%s].proto %q must be \"tcp\" or \"udp\"", r.Name, r.Proto)
	}
	if len(r.Ports) == 0 {
		return fmt.Errorf("edge_firewall.rules[%s].ports must not be empty", r.Name)
	}
	for _, p := range r.Ports {
		if p < 1 || p > 65535 {
			return fmt.Errorf("edge_firewall.rules[%s] invalid port %d (must be 1..65535)", r.Name, p)
		}
		if p == 22 && !allowSSH {
			return fmt.Errorf("edge_firewall.rules[%s] targets SSH port 22 (set edge_firewall.allow_ssh_port: true to allow)", r.Name)
		}
	}
	for _, val := range []int{r.GlobalPPS, r.GlobalBurst, r.PerIPPPS, r.PerIPBurst, r.MaxConnsPerIP, r.SynRatePerIP, r.SynBurst} {
		if val < 0 {
			return fmt.Errorf("edge_firewall.rules[%s] limits must be non-negative", r.Name)
		}
	}
	if r.Proto == "udp" && (r.MaxConnsPerIP > 0 || r.SynRatePerIP > 0) {
		return fmt.Errorf("edge_firewall.rules[%s] max_conns_per_ip and syn_rate_per_ip only apply to tcp", r.Name)
	}
	return nil
}

func validateHostPort(raw, defaultPort string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", errors.New("empty host:port target")
	}
	if defaultPort != "" && (!strings.Contains(s, ":") || net.ParseIP(s) != nil) {
		s = net.JoinHostPort(s, defaultPort)
	}
	host, portStr, err := net.SplitHostPort(s)
	if err != nil || strings.TrimSpace(host) == "" {
		return "", fmt.Errorf("invalid host:port %q", raw)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", fmt.Errorf("invalid port in %q", raw)
	}
	return net.JoinHostPort(host, portStr), nil
}
