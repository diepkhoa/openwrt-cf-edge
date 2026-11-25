package netutil

import (
	"context"
	"net/netip"
	"sort"
	"strings"
	"time"
)

var (
	privateAndSpecialV4 = []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("100.64.0.0/10"),  // CGNAT (RFC 6598)
		netip.MustParsePrefix("127.0.0.0/8"),    // Loopback
		netip.MustParsePrefix("169.254.0.0/16"), // Link-local
		netip.MustParsePrefix("0.0.0.0/8"),      // Unspecified
		netip.MustParsePrefix("224.0.0.0/4"),    // Multicast
		netip.MustParsePrefix("240.0.0.0/4"),    // Reserved
	}
	globalUnicastV6 = netip.MustParsePrefix("2000::/3")
)

// IPv6AddrInfo describes an IPv6 address discovered on an interface.
type IPv6AddrInfo struct {
	Addr         netip.Addr
	Deprecated   bool
	Temporary    bool
	PreferredLFT uint32
}

// NetInspector queries OS routing tables and interface IPv6 addresses.
type NetInspector interface {
	DefaultRouteIPv4(ctx context.Context) (iface string, ip string, err error)
	GlobalIPv6Addrs(ctx context.Context, devName string) ([]IPv6AddrInfo, error)
}

// Pinger performs bound ICMP reachability checks out of a specific network device.
type Pinger interface {
	Ping(ctx context.Context, target string, iface string, timeout time.Duration) error
}

// IsPrivateOrSpecialIPv4 returns true if ip is not a globally routable unicast IPv4 address.
func IsPrivateOrSpecialIPv4(ip netip.Addr) bool {
	if !ip.Is4() {
		return true
	}
	for _, p := range privateAndSpecialV4 {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// ParsePublicIPv4 parses raw as a valid public IPv4 address.
func ParsePublicIPv4(raw string) (string, bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil || !addr.Is4() || IsPrivateOrSpecialIPv4(addr) {
		return "", false
	}
	return addr.String(), true
}

// IsPublicGUAIPv6 returns true when ip belongs to Global Unicast 2000::/3.
func IsPublicGUAIPv6(ip netip.Addr) bool {
	return ip.Is6() && !ip.Is4In6() && globalUnicastV6.Contains(ip)
}

// ParsePublicIPv6 parses raw as a valid IPv6 Global Unicast Address (2000::/3).
func ParsePublicIPv6(raw string) (string, bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil || !IsPublicGUAIPv6(addr) {
		return "", false
	}
	return addr.String(), true
}

// ShouldExcludeRouteIface excludes loopback and tunnel/overlay interfaces from WAN route fallback.
func ShouldExcludeRouteIface(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" || n == "lo" {
		return true
	}
	for _, prefix := range []string{"wg", "wt", "warp", "tun"} {
		if strings.HasPrefix(n, prefix) {
			return true
		}
	}
	return false
}

// SelectBestIPv6 picks the preferred non-deprecated Global Unicast IPv6 address.
func SelectBestIPv6(addrs []IPv6AddrInfo) string {
	candidates := make([]IPv6AddrInfo, 0, len(addrs))
	for _, a := range addrs {
		if !IsPublicGUAIPv6(a.Addr) || a.Deprecated || a.PreferredLFT == 0 {
			continue
		}
		candidates = append(candidates, a)
	}
	if len(candidates) == 0 {
		return ""
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Temporary != candidates[j].Temporary {
			return !candidates[i].Temporary
		}
		if candidates[i].PreferredLFT != candidates[j].PreferredLFT {
			return candidates[i].PreferredLFT > candidates[j].PreferredLFT
		}
		return candidates[i].Addr.String() < candidates[j].Addr.String()
	})
	return candidates[0].Addr.String()
}

// ParseCIDRs converts CIDR strings into parsed netip.Prefix entries, ignoring invalid items.
func ParseCIDRs(cidrs []string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(strings.TrimSpace(c))
		if err == nil {
			out = append(out, p)
		}
	}
	return out
}

// ContainsIP checks whether ip falls within any prefix in prefixes.
func ContainsIP(prefixes []netip.Prefix, ip netip.Addr) bool {
	for _, p := range prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}
