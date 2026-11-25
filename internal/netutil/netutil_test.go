package netutil

import (
	"net/netip"
	"testing"
)

func TestIPv4Classification(t *testing.T) {
	cases := []struct {
		ip     string
		public bool
	}{
		{"1.1.1.1", true},
		{"203.162.4.190", true},
		{"10.0.0.1", false},
		{"172.16.5.10", false},
		{"172.31.255.254", false},
		{"172.32.0.1", true},
		{"192.168.1.1", false},
		{"100.64.0.1", false},
		{"100.127.255.254", false},
		{"100.128.0.1", true},
		{"127.0.0.1", false},
		{"169.254.1.2", false},
		{"2001:db8::1", false},
		{"invalid", false},
	}

	for _, tc := range cases {
		got, ok := ParsePublicIPv4(tc.ip)
		if ok != tc.public {
			t.Errorf("ParsePublicIPv4(%q) ok = %v (got=%q), want %v", tc.ip, ok, got, tc.public)
		}
	}
}

func TestIPv6SelectionExcludesDeprecatedAndLocal(t *testing.T) {
	addrs := []IPv6AddrInfo{
		{Addr: netip.MustParseAddr("fe80::1"), PreferredLFT: 1000},
		{Addr: netip.MustParseAddr("fd00::1"), PreferredLFT: 1000},
		{Addr: netip.MustParseAddr("2001:db8::10"), Deprecated: true, PreferredLFT: 0},
		{Addr: netip.MustParseAddr("2001:db8::20"), Deprecated: true, PreferredLFT: 500},
		{Addr: netip.MustParseAddr("2001:db8::30"), Temporary: true, PreferredLFT: 7200},
		{Addr: netip.MustParseAddr("2001:db8::40"), Temporary: false, PreferredLFT: 3600},
	}

	best := SelectBestIPv6(addrs)
	if best != "2001:db8::40" {
		t.Fatalf("SelectBestIPv6 = %q, want 2001:db8::40", best)
	}

	onlyDeprecated := []IPv6AddrInfo{
		{Addr: netip.MustParseAddr("2001:db8::10"), Deprecated: true, PreferredLFT: 0},
		{Addr: netip.MustParseAddr("fe80::1"), PreferredLFT: 1000},
	}
	if got := SelectBestIPv6(onlyDeprecated); got != "" {
		t.Fatalf("expected empty when only deprecated/link-local exist, got %q", got)
	}
}

func TestExcludeRouteIfaceAndCIDRMatch(t *testing.T) {
	for _, excluded := range []string{"lo", "wg0", "wt0", "warp1", "tun0"} {
		if !ShouldExcludeRouteIface(excluded) {
			t.Errorf("expected %s to be excluded", excluded)
		}
	}
	for _, kept := range []string{"pppoe-wan", "eth1", "eth0.35"} {
		if ShouldExcludeRouteIface(kept) {
			t.Errorf("expected %s not to be excluded", kept)
		}
	}

	prefixes := ParseCIDRs([]string{"104.16.0.0/12", "2606:4700::/32"})
	if !ContainsIP(prefixes, netip.MustParseAddr("104.21.10.5")) {
		t.Fatal("expected Cloudflare IPv4 to match")
	}
	if ContainsIP(prefixes, netip.MustParseAddr("1.1.1.1")) {
		t.Fatal("did not expect 1.1.1.1 to match proxy prefix")
	}
}
