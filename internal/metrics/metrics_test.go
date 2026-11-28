package metrics

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/diepkhoa/openwrt-cf-edge/internal/config"
	"github.com/diepkhoa/openwrt-cf-edge/internal/ddos"
	"github.com/diepkhoa/openwrt-cf-edge/internal/edgefw"
	"github.com/diepkhoa/openwrt-cf-edge/internal/platform"
	"github.com/diepkhoa/openwrt-cf-edge/internal/state"
	"github.com/diepkhoa/openwrt-cf-edge/internal/ubus"
)

func TestParseNftCountersHandlesCommentsAndUnnamedRules(t *testing.T) {
	sample := []byte(`{
		"nftables": [
			{"metainfo": {"version": "1.1.6"}},
			{"rule": {"chain": "prerouting_raw", "comment": "geoip_haproxy_https_v4", "expr": [
				{"match": {}},
				{"counter": {"packets": 1234, "bytes": 98765}},
				{"drop": null}
			]}},
			{"rule": {"chain": "rule_in_haproxy_https", "expr": [
				{"match": {"right": {"set": "invalid"}}},
				{"counter": {"packets": 12, "bytes": 480}},
				{"drop": null}
			]}},
			{"rule": {"chain": "rule_in_haproxy_https", "expr": [
				{"meter": "@pps_v4_haproxy_https"},
				{"counter": {"packets": 500, "bytes": 20000}},
				{"drop": null}
			]}},
			{"rule": {"chain": "rule_in_haproxy_https", "expr": [
				{"counter": {"packets": 99, "bytes": 5500}},
				{"return": null}
			]}}
		]
	}`)

	got, err := ParseNftCounters(sample)
	if err != nil {
		t.Fatalf("ParseNftCounters failed: %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("got %d rules, want 4: %+v", len(got), got)
	}
	if got[0].Rule != "geoip_haproxy_https_v4" || got[0].Verdict != "drop" || got[0].Packets != 1234 {
		t.Fatalf("unexpected first counter: %+v", got[0])
	}
	if got[1].Rule != "ct_invalid" || got[2].Rule != "per_ip_pps_v4" || got[3].Rule != "passed_to_fw4" {
		t.Fatalf("unexpected derived rule labels: %+v", got)
	}
}

type fakeProcReader struct{ samples []ddos.RawCounters; i int }

func (f *fakeProcReader) Read(string, string, string) (ddos.RawCounters, error) {
	s := f.samples[f.i]
	if f.i < len(f.samples)-1 {
		f.i++
	}
	return s, nil
}

type fakeNft struct{}

func (fakeNft) Run(context.Context, string, ...string) ([]byte, error) {
	return []byte(`{"nftables":[{"rule":{"chain":"prerouting_raw","comment":"geoip_haproxy_https_v4","expr":[{"counter":{"packets":42,"bytes":2520}},{"drop":null}]}}]}`), nil
}

type fakeUbus struct{}

func (fakeUbus) Status(context.Context, string) (ubus.InterfaceStatus, error) {
	return ubus.InterfaceStatus{Up: true, L3Device: "pppoe-wan", Uptime: 3600}, nil
}
func (fakeUbus) Down(context.Context, string) error { return nil }
func (fakeUbus) Up(context.Context, string) error   { return nil }

type fakePeerProv struct{}

func (fakePeerProv) SnapshotPeers() []PeerSample {
	return []PeerSample{{Name: "proxmox", IP: "100.123.0.10", Site: "site-b", Up: true, RTTMs: 4.5}}
}

func TestCollectorAndServerHTTPOutput(t *testing.T) {
	dir := t.TempDir()
	cachePath := filepath.Join(dir, "geoip.json")
	if err := edgefw.SaveGeoIPCache(cachePath, edgefw.GeoIPCache{
		IPv4CIDRs: []string{"1.1.1.0/24", "103.1.0.0/16"},
		IPv6CIDRs: []string{"2405::/32"},
	}); err != nil {
		t.Fatal(err)
	}

	store := state.NewStore(filepath.Join(dir, "state.json"))
	_ = store.Update(func(st *state.RuntimeState) error {
		st.LastUpdated = time.Unix(1700000000, 0)
		st.PPPoEStatus = &state.PPPoERuntimeInfo{RedialCount: 2}
		return nil
	})

	cfg := &config.Config{
		NodeName:   "x96air",
		WAN:        config.WANConfig{IfaceV4: "wan", OverlayDevice: "wt0", LANDevice: "br-lan"},
		Cloudflare: config.CloudflareConfig{Enabled: true},
		EdgeFirewall: config.EdgeFirewallConfig{
			CachePath: cachePath,
		},
		Metrics: config.MetricsConfig{
			Enabled:            true,
			BindDevice:         "wt0",
			Port:               9108,
			IncludeNftCounters: true,
		},
	}

	t0 := time.Unix(1000, 0)
	proc := &fakeProcReader{samples: []ddos.RawCounters{
		{Timestamp: t0, Conntrack: 100, WANRxBytes: 1000, WANRxPackets: 50, OverlayTxBytes: 500, LANTxBytes: 100},
		{Timestamp: t0.Add(time.Second), Conntrack: 120, WANRxBytes: 26_001_000, WANRxPackets: 5050, OverlayTxBytes: 1_000_500, LANTxBytes: 100},
	}}

	col := NewCollector(cfg, platform.Env{HasUbus: true}, "v0.1.12", fakeUbus{}, store, proc, fakeNft{}, nil, filepath.Join(dir, "missing.lock"))
	col.SetPeerProvider(fakePeerProv{})

	// First scrape initializes baseline counters; second scrape produces valid junk_mbps.
	var discard bytes.Buffer
	col.WritePrometheus(context.Background(), &discard)

	srv := NewServer(cfg.Metrics, col, nil)
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /metrics = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		`cf_edge_info{version="v0.1.12",node="x96air",platform="openwrt"} 1`,
		`cf_edge_junk_mbps 200.000`,
		`cf_edge_fw_active 1`,
		`cf_edge_fw_geoip_cidrs{family="ipv4"} 2`,
		`cf_edge_fw_rule_packets_total{chain="prerouting_raw",rule="geoip_haproxy_https_v4",verdict="drop"} 42`,
		`cf_edge_pppoe_up{iface="wan"} 1`,
		`cf_edge_pppoe_redials_total 2`,
		`cf_edge_mesh_peer_up{name="proxmox",ip="100.123.0.10",site="site-b"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("metrics output missing %q:\n%s", want, body)
		}
	}
}
