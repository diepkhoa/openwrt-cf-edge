package edgefw

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/diepkhoa/openwrt-cf-edge/internal/config"
	"github.com/diepkhoa/openwrt-cf-edge/internal/ubus"
)

func TestSplitAndMergeCIDRsCoalescesOverlaps(t *testing.T) {
	raw := []string{
		"# comment",
		"",
		"192.0.2.0/25",
		"192.0.2.128/25", // adjacent -> 192.0.2.0/24
		"192.0.2.10/32",  // contained
		"198.51.100.1/24",
		"2001:db8::/49",
		"2001:db8:0:8000::/49", // adjacent -> 2001:db8::/48
		"not-a-cidr",
	}
	v4, v6, invalid := SplitAndMergeCIDRs(raw)
	if len(invalid) != 1 || invalid[0] != "not-a-cidr" {
		t.Fatalf("unexpected invalid CIDRs: %v", invalid)
	}
	if len(v4) != 2 || v4[0] != "192.0.2.0/24" || v4[1] != "198.51.100.0/24" {
		t.Fatalf("unexpected merged IPv4 CIDRs: %v", v4)
	}
	if len(v6) != 1 || v6[0] != "2001:db8::/48" {
		t.Fatalf("unexpected merged IPv6 CIDRs: %v", v6)
	}
}

func TestCatalogEnsureSetsIntegrityCacheAndFallback(t *testing.T) {
	var hits int
	var failUpstream bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if failUpstream {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		switch r.URL.Path {
		case "/v4/vn.zone":
			for i := 1; i <= 12; i++ {
				fmt.Fprintf(w, "103.%d.0.0/24\n", i*2)
			}
		case "/v6/vn.zone":
			for i := 1; i <= 6; i++ {
				fmt.Fprintf(w, "2405:48%02x::/32\n", i*2)
			}
		case "/cf/ips":
			_, _ = w.Write([]byte(`{"success":true,"result":{"ipv4_cidrs":["173.245.48.0/20","103.21.244.0/22","104.16.0.0/13","172.64.0.0/13","131.0.72.0/22"],"ipv6_cidrs":["2400:cb00::/32","2606:4700::/32","2803:f800::/32"]}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	cat := NewCatalog(srv.Client())
	cat.v4ZoneURLTpl = srv.URL + "/v4/%s.zone"
	cat.v6ZoneURLTpl = srv.URL + "/v6/%s.zone"
	cat.cfAPIURL = srv.URL + "/cf/ips"

	cfg := config.EdgeFirewallConfig{
		RefreshInterval:   config.Duration(7 * 24 * time.Hour),
		CachePath:         filepath.Join(t.TempDir(), "geoip-cache.json"),
		GeoIPCountries:    []string{"vn"},
		IncludeCloudflare: true,
		AllowCIDRs:        []string{"203.0.113.0/24"},
	}

	got1, err := cat.EnsureSets(context.Background(), cfg, false)
	if err != nil {
		t.Fatalf("first EnsureSets failed: %v", err)
	}
	if len(got1.IPv4CIDRs) < 18 || len(got1.IPv6CIDRs) < 9 {
		t.Fatalf("unexpected CIDR counts v4=%d v6=%d", len(got1.IPv4CIDRs), len(got1.IPv6CIDRs))
	}
	hitsAfterFirst := hits

	// Second call within RefreshInterval must use disk cache without hitting upstream.
	got2, err := cat.EnsureSets(context.Background(), cfg, false)
	if err != nil || hits != hitsAfterFirst || len(got2.IPv4CIDRs) != len(got1.IPv4CIDRs) {
		t.Fatalf("expected cache hit with 0 HTTP requests, hits=%d->%d err=%v", hitsAfterFirst, hits, err)
	}

	// Simulate expired cache + upstream failure: should fall back to cached sets.
	got2.FetchedAt = time.Now().Add(-10 * 24 * time.Hour)
	if err := SaveGeoIPCache(cfg.CachePath, got2); err != nil {
		t.Fatal(err)
	}
	failUpstream = true
	gotFallback, err := cat.EnsureSets(context.Background(), cfg, false)
	if err == nil || len(gotFallback.IPv4CIDRs) == 0 {
		t.Fatalf("expected non-empty fallback cache alongside refresh error, got len=%d err=%v", len(gotFallback.IPv4CIDRs), err)
	}
}

func TestBuildScriptUsesFw4DynamicSetsAndExcludesInternalIfaces(t *testing.T) {
	cfg := &config.Config{
		WAN: config.WANConfig{IfaceV4: "wan", LANIface: "br-lan", OverlayIface: "wt0"},
		EdgeFirewall: config.EdgeFirewallConfig{
			DropInvalidTCP: true,
			Rules: []config.FirewallRuleConfig{
				{
					Name:          "haproxy_https",
					Chain:         "input",
					Proto:         "tcp",
					Ports:         []int{443},
					GeoIPEnforce:  true,
					GlobalPPS:     30000,
					GlobalBurst:   5000,
					PerIPPPS:      26000,
					PerIPBurst:    5000,
					MaxConnsPerIP: 80,
					SynRatePerIP:  25,
					SynBurst:      100,
				},
				{
					Name:         "livekit_webrtc",
					Chain:        "forward",
					Proto:        "udp",
					Ports:        []int{50044},
					GeoIPEnforce: true,
					GlobalPPS:    15000,
					GlobalBurst:  2000,
					PerIPPPS:     5000,
					PerIPBurst:   800,
				},
			},
		},
	}

	if _, err := BuildScript(cfg, []string{"wt0"}, []string{"1.1.1.0/24"}, []string{"2405::/32"}); err == nil {
		t.Fatal("expected internal/overlay device wt0 to be rejected")
	}

	script, err := BuildScript(cfg, []string{"pppoe-wan"}, []string{"1.1.1.0/24"}, []string{"2405::/32"})
	if err != nil {
		t.Fatalf("BuildScript failed: %v", err)
	}

	for _, want := range []string{
		"flags interval\n    auto-merge",
		"flags dynamic, timeout\n    timeout 1m",
		"flags dynamic\n  }", // ct count dynamic set without timeout
		`iifname != { "pppoe-wan" } return`,
		"tcp flags & (fin | syn | rst | psh | ack | urg) == 0 counter drop",
		"update @pps_v4_haproxy_https",
		"ct state new add @conn_v4_haproxy_https { ip saddr ct count over 80 } counter drop",
		"udp dport 50044 jump rule_fwd_livekit_webrtc",
		"type filter hook forward priority filter - 5",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("rendered script missing %q:\n%s", want, script)
		}
	}
	if strings.Contains(script, "meter ") || strings.Contains(script, "hook output") || strings.Contains(script, "br-lan") {
		t.Fatalf("script must not contain deprecated meter, output hook, or internal ifaces:\n%s", script)
	}
}

type fakeUbus struct {
	dev string
}

func (f fakeUbus) Status(_ context.Context, iface string) (ubus.InterfaceStatus, error) {
	return ubus.InterfaceStatus{Up: true, L3Device: f.dev}, nil
}
func (fakeUbus) Down(context.Context, string) error { return nil }
func (fakeUbus) Up(context.Context, string) error   { return nil }

type fakeNft struct {
	mu          sync.Mutex
	activeTable string
	commands    []string
}

func (n *fakeNft) Run(_ context.Context, stdin string, args ...string) ([]byte, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	cmd := strings.Join(args, " ")
	n.commands = append(n.commands, cmd)

	switch cmd {
	case "list table inet cf_edge_fw":
		if n.activeTable == "" {
			return nil, errors.New("no such table")
		}
		return []byte(n.activeTable), nil
	case "delete table inet cf_edge_fw":
		n.activeTable = ""
		return nil, nil
	case "-c -f -":
		return nil, nil
	case "-f -":
		n.activeTable = stdin
		return nil, nil
	default:
		return nil, fmt.Errorf("unexpected nft call: %s", cmd)
	}
}

type fakeNotifier struct {
	mu   sync.Mutex
	msgs []string
}

func (f *fakeNotifier) Send(_ context.Context, msg string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.msgs = append(f.msgs, msg)
	return nil
}

func TestManagerApplyAutomaticRollbackOnUDPDrop(t *testing.T) {
	nft := &fakeNft{activeTable: "table inet cf_edge_fw { chain old { } }"}
	notifier := &fakeNotifier{}

	// Simulate UDP working in baseline, then breaking right after nft -f - is applied.
	prober := &ConnectivityProber{
		tcpDial: func(context.Context, string) error { return nil },
		udpProbe: func(context.Context, string) error {
			nft.mu.Lock()
			broken := strings.Contains(nft.activeTable, "input_protect")
			nft.mu.Unlock()
			if broken {
				return errors.New("udp i/o timeout")
			}
			return nil
		},
	}

	cfg := &config.Config{
		NodeName: "x96air-edge",
		WAN:      config.WANConfig{IfaceV4: "wan", LANIface: "br-lan", OverlayIface: "wt0"},
		EdgeFirewall: config.EdgeFirewallConfig{
			Enabled:             true,
			RefreshInterval:     config.Duration(168 * time.Hour),
			CachePath:           filepath.Join(t.TempDir(), "missing.json"),
			RollbackOnCheckFail: true,
			HealthCheckTCP:      []string{"1.1.1.1:443"},
			HealthCheckUDP:      []string{"1.1.1.1:53"},
			Rules: []config.FirewallRuleConfig{
				{
					Name:         "test_port",
					Chain:        "input",
					Proto:        "tcp",
					Ports:        []int{443},
					GeoIPEnforce: false,
					GlobalPPS:    1000,
				},
			},
		},
	}

	mgr := NewManager(cfg, fakeUbus{dev: "pppoe-wan"}, nil, nil, prober, nft, notifier, nil)
	err := mgr.Apply(context.Background(), ApplyOptions{NotifyOnFailure: true})
	if err == nil || !strings.Contains(err.Error(), "outbound UDP") {
		t.Fatalf("expected outbound UDP regression error, got: %v", err)
	}
	if !strings.Contains(nft.activeTable, "chain old") {
		t.Fatalf("expected previous nftables table snapshot restored, got:\n%s", nft.activeTable)
	}
	if len(notifier.msgs) != 1 || !strings.Contains(notifier.msgs[0], "AUTO-ROLLBACK TRIGGERED") {
		t.Fatalf("expected Telegram rollback notification, got: %v", notifier.msgs)
	}
	if err := mgr.applyIfAllowed(context.Background(), false); err == nil || !strings.Contains(err.Error(), "skipping auto-apply") {
		t.Fatalf("expected anti-loop skip after rollback, got: %v", err)
	}
}
