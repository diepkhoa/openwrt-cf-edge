package edgefw

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/diepkhoa/openwrt-cf-edge/internal/config"
	"github.com/diepkhoa/openwrt-cf-edge/internal/ubus"
)

const TableName = "cf_edge_fw"

// NeedsGeoIPSets returns true when at least one rule enforces GeoIP filtering.
func NeedsGeoIPSets(cfg config.EdgeFirewallConfig) bool {
	for _, r := range cfg.Rules {
		if r.GeoIPEnforce {
			return true
		}
	}
	return false
}

// ResolveWANDevices resolves the active L3 WAN devices safe for ingress matching,
// rejecting loopback, LAN, bridge, and overlay interfaces.
func ResolveWANDevices(ctx context.Context, cfg *config.Config, ubusClient ubus.Client, override []string) ([]string, error) {
	var raw []string
	switch {
	case len(override) > 0:
		raw = override
	case len(cfg.EdgeFirewall.WANDevices) > 0:
		raw = cfg.EdgeFirewall.WANDevices
	default:
		if ubusClient == nil {
			return nil, errors.New("ubus client unavailable to resolve WAN devices")
		}
		for _, iface := range []string{cfg.WAN.IfaceV4, cfg.WAN.IfaceV6} {
			if strings.TrimSpace(iface) == "" {
				continue
			}
			st, err := ubusClient.Status(ctx, iface)
			if err != nil {
				continue
			}
			if dev := st.EffectiveL3Device(); dev != "" {
				raw = append(raw, dev)
			}
		}
	}

	seen := make(map[string]struct{}, len(raw))
	var out []string
	for _, dev := range raw {
		d := strings.TrimSpace(dev)
		if d == "" {
			continue
		}
		if config.IsForbiddenWANDevice(d, cfg.WAN.LANIface, cfg.WAN.OverlayIface) {
			return nil, fmt.Errorf("refusing forbidden internal/overlay interface %q in WAN firewall scope", d)
		}
		if _, ok := seen[d]; !ok {
			seen[d] = struct{}{}
			out = append(out, d)
		}
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil, errors.New("no active WAN L3 device resolved via ubus")
	}
	return out, nil
}

// BuildScript builds an OpenWrt 25.12 fw4-compatible nftables ruleset using interval sets and named dynamic sets.
func BuildScript(cfg *config.Config, wanDevs, v4CIDRs, v6CIDRs []string) (string, error) {
	if len(wanDevs) == 0 {
		return "", errors.New("cannot render nftables script without WAN devices")
	}
	for _, d := range wanDevs {
		if config.IsForbiddenWANDevice(d, cfg.WAN.LANIface, cfg.WAN.OverlayIface) {
			return "", fmt.Errorf("forbidden internal/overlay device %q in WAN match list", d)
		}
	}

	ef := cfg.EdgeFirewall
	needsGeo := NeedsGeoIPSets(ef)
	if needsGeo && len(v4CIDRs) == 0 && len(v6CIDRs) == 0 {
		return "", errors.New("geoip_enforce enabled but GeoIP CIDR sets are empty")
	}

	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s\n", TableName)
	fmt.Fprintf(&b, "delete table inet %s\n", TableName)
	fmt.Fprintf(&b, "table inet %s {\n", TableName)

	if needsGeo {
		writeIntervalSet(&b, "allowed_geoip_v4", "ipv4_addr", v4CIDRs)
		writeIntervalSet(&b, "allowed_geoip_v6", "ipv6_addr", v6CIDRs)
	}
	writeDynamicSets(&b, ef.Rules)

	wanSet := formatQuotedSet(wanDevs)
	writePreroutingChain(&b, wanSet, ef)
	writeRuleSubchains(&b, ef)
	writeHookDispatcher(&b, "input_protect", "input", "filter - 10", wanSet, filterRulesByChain(ef.Rules, "input"))
	writeHookDispatcher(&b, "forward_protect", "forward", "filter - 5", wanSet, filterRulesByChain(ef.Rules, "forward"))

	b.WriteString("}\n")
	return b.String(), nil
}

func writeIntervalSet(b *strings.Builder, name, addrType string, cidrs []string) {
	fmt.Fprintf(b, "  set %s {\n", name)
	fmt.Fprintf(b, "    type %s\n", addrType)
	b.WriteString("    flags interval\n")
	b.WriteString("    auto-merge\n")
	if len(cidrs) > 0 {
		b.WriteString("    elements = {\n")
		for _, c := range cidrs {
			fmt.Fprintf(b, "      %s,\n", c)
		}
		b.WriteString("    }\n")
	}
	b.WriteString("  }\n")
}

func writeDynamicSets(b *strings.Builder, rules []config.FirewallRuleConfig) {
	for _, r := range rules {
		if r.PerIPPPS > 0 {
			writeDynamicRateSet(b, "pps_v4_"+r.Name, "ipv4_addr")
			writeDynamicRateSet(b, "pps_v6_"+r.Name, "ipv6_addr")
		}
		if r.Proto == "tcp" && r.MaxConnsPerIP > 0 {
			writeDynamicConnSet(b, "conn_v4_"+r.Name, "ipv4_addr")
			writeDynamicConnSet(b, "conn_v6_"+r.Name, "ipv6_addr")
		}
		if r.Proto == "tcp" && r.SynRatePerIP > 0 {
			writeDynamicRateSet(b, "syn_v4_"+r.Name, "ipv4_addr")
			writeDynamicRateSet(b, "syn_v6_"+r.Name, "ipv6_addr")
		}
	}
}

func writeDynamicRateSet(b *strings.Builder, name, addrType string) {
	fmt.Fprintf(b, "  set %s {\n    type %s\n    size 65535\n    flags dynamic, timeout\n    timeout 1m\n  }\n", name, addrType)
}

func writeDynamicConnSet(b *strings.Builder, name, addrType string) {
	// Omit timeout on ct count sets so kernel conntrack GC frees entries cleanly when count hits zero.
	fmt.Fprintf(b, "  set %s {\n    type %s\n    size 65535\n    flags dynamic\n  }\n", name, addrType)
}

func writePreroutingChain(b *strings.Builder, wanSet string, ef config.EdgeFirewallConfig) {
	if !NeedsGeoIPSets(ef) && !ef.DropIPOptionsTCP {
		return
	}
	b.WriteString("  chain prerouting_raw {\n")
	b.WriteString("    type filter hook prerouting priority raw; policy accept;\n")
	fmt.Fprintf(b, "    iifname != %s return\n", wanSet)
	if ef.DropIPOptionsTCP {
		b.WriteString("    ip protocol tcp ip hdrlength > 5 counter drop comment \"drop tcp ip options\"\n")
	}
	for _, r := range ef.Rules {
		if !r.GeoIPEnforce {
			continue
		}
		ports := formatPortSet(r.Ports)
		fmt.Fprintf(b, "    %s dport %s meta nfproto ipv4 ip saddr != @allowed_geoip_v4 counter drop comment \"geoip_%s_v4\"\n", r.Proto, ports, r.Name)
		fmt.Fprintf(b, "    %s dport %s meta nfproto ipv6 ip6 saddr != @allowed_geoip_v6 counter drop comment \"geoip_%s_v6\"\n", r.Proto, ports, r.Name)
	}
	b.WriteString("  }\n")
}

func writeRuleSubchains(b *strings.Builder, ef config.EdgeFirewallConfig) {
	for _, r := range ef.Rules {
		fmt.Fprintf(b, "  chain %s {\n", subchainName(r))
		if ef.DropInvalidTCP && r.Proto == "tcp" {
			b.WriteString("    ct state invalid counter drop\n")
			b.WriteString("    tcp flags & (fin | syn | rst | psh | ack | urg) == 0 counter drop\n")
			b.WriteString("    tcp flags & (fin | psh | urg) == fin | psh | urg counter drop\n")
			b.WriteString("    tcp flags & (fin | syn) == fin | syn counter drop\n")
			b.WriteString("    tcp flags & (syn | rst) == syn | rst counter drop\n")
		}
		if r.GlobalPPS > 0 {
			burst := defaultBurst(r.GlobalBurst, r.GlobalPPS)
			fmt.Fprintf(b, "    limit rate over %d/second burst %d packets counter drop\n", r.GlobalPPS, burst)
		}
		if r.PerIPPPS > 0 {
			burst := defaultBurst(r.PerIPBurst, r.PerIPPPS)
			fmt.Fprintf(b, "    meta nfproto ipv4 update @pps_v4_%s { ip saddr limit rate over %d/second burst %d packets } counter drop\n", r.Name, r.PerIPPPS, burst)
			fmt.Fprintf(b, "    meta nfproto ipv6 update @pps_v6_%s { ip6 saddr limit rate over %d/second burst %d packets } counter drop\n", r.Name, r.PerIPPPS, burst)
		}
		b.WriteString("    ct state { established, related } accept\n")
		if r.Proto == "tcp" && r.MaxConnsPerIP > 0 {
			fmt.Fprintf(b, "    meta nfproto ipv4 ct state new add @conn_v4_%s { ip saddr ct count over %d } counter drop\n", r.Name, r.MaxConnsPerIP)
			fmt.Fprintf(b, "    meta nfproto ipv6 ct state new add @conn_v6_%s { ip6 saddr ct count over %d } counter drop\n", r.Name, r.MaxConnsPerIP)
		}
		if r.Proto == "tcp" && r.SynRatePerIP > 0 {
			burst := defaultBurst(r.SynBurst, r.SynRatePerIP)
			fmt.Fprintf(b, "    meta nfproto ipv4 tcp flags & (fin | syn | rst | ack) == syn update @syn_v4_%s { ip saddr limit rate over %d/second burst %d packets } counter drop\n", r.Name, r.SynRatePerIP, burst)
			fmt.Fprintf(b, "    meta nfproto ipv6 tcp flags & (fin | syn | rst | ack) == syn update @syn_v6_%s { ip6 saddr limit rate over %d/second burst %d packets } counter drop\n", r.Name, r.SynRatePerIP, burst)
		}
		b.WriteString("    counter return\n")
		b.WriteString("  }\n")
	}
}

func writeHookDispatcher(b *strings.Builder, chainName, hook, prio, wanSet string, rules []config.FirewallRuleConfig) {
	if len(rules) == 0 {
		return
	}
	fmt.Fprintf(b, "  chain %s {\n", chainName)
	fmt.Fprintf(b, "    type filter hook %s priority %s; policy accept;\n", hook, prio)
	fmt.Fprintf(b, "    iifname != %s return\n", wanSet)
	for _, r := range rules {
		fmt.Fprintf(b, "    %s dport %s jump %s\n", r.Proto, formatPortSet(r.Ports), subchainName(r))
	}
	b.WriteString("  }\n")
}

func subchainName(r config.FirewallRuleConfig) string {
	prefix := "in"
	if r.Chain == "forward" {
		prefix = "fwd"
	}
	return fmt.Sprintf("rule_%s_%s", prefix, r.Name)
}

func filterRulesByChain(rules []config.FirewallRuleConfig, chain string) []config.FirewallRuleConfig {
	var out []config.FirewallRuleConfig
	for _, r := range rules {
		if r.Chain == chain {
			out = append(out, r)
		}
	}
	return out
}

func defaultBurst(burst, rate int) int {
	if burst > 0 {
		return burst
	}
	if b := rate / 5; b >= 10 {
		return b
	}
	return 10
}

func formatQuotedSet(items []string) string {
	quoted := make([]string, len(items))
	for i, item := range items {
		quoted[i] = fmt.Sprintf("%q", item)
	}
	return "{ " + strings.Join(quoted, ", ") + " }"
}

func formatPortSet(ports []int) string {
	if len(ports) == 1 {
		return strconv.Itoa(ports[0])
	}
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = strconv.Itoa(p)
	}
	return "{ " + strings.Join(parts, ", ") + " }"
}
