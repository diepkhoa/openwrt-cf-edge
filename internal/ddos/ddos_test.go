package ddos

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/diepkhoa/openwrt-cf-edge/internal/config"
	"github.com/diepkhoa/openwrt-cf-edge/internal/state"
	"github.com/diepkhoa/openwrt-cf-edge/internal/ubus"
)

func TestComputeRatesSubtractsOverlayAndLAN(t *testing.T) {
	t0 := time.Unix(1000, 0)
	prev := RawCounters{
		Timestamp:      t0,
		Conntrack:      200,
		WANRxBytes:     1000,
		WANRxPackets:   100,
		OverlayTxBytes: 500,
		LANTxBytes:     200,
	}
	// +1s: WAN RX = 500 Mbps (62,500,000 bytes), Overlay TX = 100 Mbps, LAN TX = 300 Mbps => Junk = 100 Mbps
	cur := RawCounters{
		Timestamp:      t0.Add(time.Second),
		Conntrack:      350,
		WANRxBytes:     1000 + 62_500_000,
		WANRxPackets:   100 + 85_000,
		OverlayTxBytes: 500 + 12_500_000,
		LANTxBytes:     200 + 37_500_000,
	}

	r := ComputeRates(prev, cur)
	if !r.Valid {
		t.Fatal("expected valid rates")
	}
	if r.RXWANMbps != 500 || r.TXOverlayMbps != 100 || r.TXLANMbps != 300 || r.JunkMbps != 100 {
		t.Fatalf("unexpected Mbps rates: %+v", r)
	}
	if r.RXPPS != 85_000 {
		t.Fatalf("RXPPS = %v, want 85000", r.RXPPS)
	}

	// Counter wrap/reset should mark sample invalid instead of overflowing.
	wrapped := ComputeRates(cur, RawCounters{Timestamp: t0.Add(2 * time.Second), WANRxBytes: 10})
	if wrapped.Valid {
		t.Fatalf("expected invalid rate on counter reset, got %+v", wrapped)
	}
}

func TestBuildShieldScriptUsesIifnameAndIngressOnly(t *testing.T) {
	script := BuildShieldScript([]string{"pppoe-wan", "eth1.35", "pppoe-wan"}, 443)
	if !strings.Contains(script, `iifname { "eth1.35", "pppoe-wan" }`) {
		t.Fatalf("expected iifname with deduplicated sorted interfaces, got:\n%s", script)
	}
	if strings.Contains(script, " iif ") || strings.Contains(script, "hook output") {
		t.Fatalf("script must not use iif or touch outbound traffic:\n%s", script)
	}
	if !strings.Contains(script, "tcp dport 443 drop") || !strings.Contains(script, "udp dport 443 drop") {
		t.Fatalf("missing tcp/udp dport 443 drop rules:\n%s", script)
	}
}

type fakeUbus struct {
	downs atomic.Int32
	ups   atomic.Int32
}

func (f *fakeUbus) Status(_ context.Context, iface string) (ubus.InterfaceStatus, error) {
	return ubus.InterfaceStatus{
		Up:          true,
		Device:      "eth1",
		L3Device:    "pppoe-" + iface,
		IPv4Address: []ubus.IPv4Address{{Address: "198.51.100.77"}},
	}, nil
}
func (f *fakeUbus) Down(context.Context, string) error { f.downs.Add(1); return nil }
func (f *fakeUbus) Up(context.Context, string) error   { f.ups.Add(1); return nil }

type fakeFirewall struct {
	mu      sync.Mutex
	active  bool
	applies int
	removes int
}

func (f *fakeFirewall) ApplyShield(context.Context, []string, int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.active = true
	f.applies++
	return nil
}
func (f *fakeFirewall) RemoveShield(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.active = false
	f.removes++
	return nil
}
func (f *fakeFirewall) IsActive(context.Context) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.active, nil
}

type fakePinger struct{ fail bool }

func (p fakePinger) Ping(context.Context, string, string, time.Duration) error {
	if p.fail {
		return errors.New("timeout")
	}
	return nil
}

type fakeReader struct {
	mu      sync.Mutex
	samples []RawCounters
	idx     int
}

func (r *fakeReader) Read(string, string, string) (RawCounters, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.samples[r.idx]
	if r.idx < len(r.samples)-1 {
		r.idx++
	}
	return s, nil
}

func TestShieldManagerEnterRateLimitAndWorkerResume(t *testing.T) {
	var reportedIP, reportedReason string
	workerAction := "hold"
	var mu sync.Mutex

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer w-tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/edge/ddos":
			var p struct {
				NewIP  string `json:"new_ip"`
				Reason string `json:"reason"`
			}
			_ = json.NewDecoder(r.Body).Decode(&p)
			mu.Lock()
			reportedIP = p.NewIP
			reportedReason = p.Reason
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
		case "/edge/status":
			mu.Lock()
			act := workerAction
			mu.Unlock()
			_, _ = w.Write([]byte(`{"action":"` + act + `"}`))
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	lockPath := filepath.Join(dir, "shield.lock")
	store := state.NewStore(filepath.Join(dir, "state.json"))
	ub := &fakeUbus{}
	fw := &fakeFirewall{}

	cfg := &config.Config{
		NodeName: "x96air",
		WAN:      config.WANConfig{IfaceV4: "wan", IfaceV6: "wan6", OverlayIface: "wt0", LANIface: "br-lan"},
		DDoSShield: config.DDoSShieldConfig{
			Enabled:            true,
			WorkerURL:          srv.URL,
			WorkerToken:        "w-tok",
			WANIngressPort:     443,
			CheckInterval:      config.Duration(5 * time.Millisecond),
			SustainDuration:    config.Duration(10 * time.Millisecond),
			ConntrackThreshold: 5000,
			JunkMbpsThreshold:  300,
			RXPPSThreshold:     80000,
			MaxRedialsPerHour:  1,
			StatusPollInterval: config.Duration(10 * time.Millisecond),
		},
	}

	t0 := time.Unix(2000, 0)
	reader := &fakeReader{
		samples: []RawCounters{
			{Timestamp: t0, Conntrack: 6000, WANRxBytes: 1000, WANRxPackets: 10},
			{Timestamp: t0.Add(time.Second), Conntrack: 6000, WANRxBytes: 2000, WANRxPackets: 20},
		},
	}
	var synced atomic.Int32
	var hooked atomic.Int32

	mgr := NewShieldManager(
		cfg, ub, fakePinger{}, reader, fw,
		NewHTTPWorkerClient(srv.URL, "w-tok", 0),
		store, nil,
		func(context.Context) (string, error) { return "198.51.100.77", nil },
		func(context.Context) error { synced.Add(1); return nil },
		lockPath, nil,
		WithTimings(time.Millisecond, 50*time.Millisecond, 2*time.Millisecond),
		WithRedialHook(func(active bool) {
			if active {
				hooked.Add(1)
			}
		}),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		mgr.Run(ctx)
	}()

	// Wait for detection + EnterShield (including redial + worker /edge/ddos report).
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		gotRep := reportedIP
		mu.Unlock()
		if state.IsShielded(lockPath) && ub.ups.Load() >= 2 && gotRep != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !state.IsShielded(lockPath) {
		t.Fatal("expected shield.lock to be created after sustained conntrack breach")
	}
	if ub.downs.Load() != 2 || ub.ups.Load() != 2 || hooked.Load() == 0 {
		t.Fatalf("expected wan+wan6 redial and redialHook called, got downs=%d ups=%d hooked=%d", ub.downs.Load(), ub.ups.Load(), hooked.Load())
	}

	mu.Lock()
	if reportedIP != "198.51.100.77" || !strings.Contains(reportedReason, "conntrack") {
		mu.Unlock()
		t.Fatalf("unexpected worker report: ip=%q reason=%q", reportedIP, reportedReason)
	}
	workerAction = "resume"
	mu.Unlock()

	// Wait for recovery poll to trigger ExitShield + force sync.
	deadline = time.Now().Add(time.Second)
	for time.Now().Before(deadline) && (state.IsShielded(lockPath) || synced.Load() == 0) {
		time.Sleep(10 * time.Millisecond)
	}
	if state.IsShielded(lockPath) || synced.Load() == 0 {
		t.Fatalf("expected shield removed and syncForce>=1, shielded=%v synced=%d", state.IsShielded(lockPath), synced.Load())
	}

	// Stop background detector loop before testing direct EnterShield rate limit cleanly.
	cancel()
	<-runDone

	// Second EnterShield within 1 hour should hit MaxRedialsPerHour=1 and skip redial while still locking + applying nft.
	if err := mgr.EnterShield(context.Background(), "second attack", EnterOptions{}); err != nil {
		t.Fatalf("second EnterShield failed: %v", err)
	}
	if ub.downs.Load() != 2 {
		t.Fatalf("expected redial skipped due to hourly quota, downs=%d", ub.downs.Load())
	}
	if !state.IsShielded(lockPath) {
		t.Fatal("expected shield.lock written even when redial skipped")
	}
}

func TestEvaluateBreachMatrix(t *testing.T) {
	cfg := &config.Config{
		PPPoEGuard: config.PPPoEGuardConfig{PingTargets: []string{"1.1.1.1"}},
		DDoSShield: config.DDoSShieldConfig{
			ConntrackThreshold: 5000,
			JunkMbpsThreshold:  300,
			RXPPSThreshold:     80000,
		},
	}

	// Normal high-bandwidth download with healthy ping & PPS <= 80000: must NOT breach.
	mgrOK := NewShieldManager(cfg, &fakeUbus{}, fakePinger{fail: false}, nil, &fakeFirewall{}, nil, nil, nil, nil, nil, "", nil)
	if r := mgrOK.evaluateBreach(context.Background(), "pppoe-wan", RateSnapshot{
		Valid: true, Conntrack: 500, JunkMbps: 450, RXPPS: 40000,
	}); r != "" {
		t.Fatalf("expected no breach on healthy ping & PPS<=80000, got %q", r)
	}

	// ISP outage (RX_WAN == 0, ping fails): must NOT breach.
	mgrOutage := NewShieldManager(cfg, &fakeUbus{}, fakePinger{fail: true}, nil, &fakeFirewall{}, nil, nil, nil, nil, nil, "", nil)
	if r := mgrOutage.evaluateBreach(context.Background(), "pppoe-wan", RateSnapshot{
		Valid: true, Conntrack: 10, JunkMbps: 0, RXPPS: 0,
	}); r != "" {
		t.Fatalf("expected no breach during ISP outage, got %q", r)
	}

	// Junk > 300 Mbps + RX_PPS > 80000: must breach.
	if r := mgrOK.evaluateBreach(context.Background(), "pppoe-wan", RateSnapshot{
		Valid: true, Conntrack: 100, JunkMbps: 350, RXPPS: 95000,
	}); !strings.Contains(r, "rx_pps") {
		t.Fatalf("expected rx_pps breach, got %q", r)
	}

	// Junk > 300 Mbps + ping fail: must breach.
	if r := mgrOutage.evaluateBreach(context.Background(), "pppoe-wan", RateSnapshot{
		Valid: true, Conntrack: 100, JunkMbps: 350, RXPPS: 20000,
	}); !strings.Contains(r, "ping_loss") {
		t.Fatalf("expected ping_loss breach, got %q", r)
	}
}

type fakeNotifier struct {
	mu   sync.Mutex
	msgs []string
}

func (n *fakeNotifier) Send(_ context.Context, msg string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.msgs = append(n.msgs, msg)
	return nil
}

func (n *fakeNotifier) Count() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.msgs)
}

func TestEnterShieldNoRedialAlwaysNotifiesWhileRateLimitThrottles(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, "shield.lock")
	store := state.NewStore(filepath.Join(dir, "state.json"))
	ub := &fakeUbus{}
	fw := &fakeFirewall{}
	notifier := &fakeNotifier{}

	now := time.Unix(5000, 0)
	cfg := &config.Config{
		NodeName: "edge-test",
		WAN:      config.WANConfig{IfaceV4: "wan", OverlayIface: "wt0"},
		DDoSShield: config.DDoSShieldConfig{
			Enabled:           true,
			WANIngressPort:    443,
			MaxRedialsPerHour: 1,
		},
	}

	mgr := NewShieldManager(
		cfg, ub, fakePinger{}, nil, fw, nil, store, notifier,
		func(context.Context) (string, error) { return "198.51.100.88", nil },
		nil, lockPath, nil,
		WithTimings(0, 50*time.Millisecond, time.Millisecond),
		WithClock(func() time.Time { return now }),
	)

	// Two consecutive manual --no-redial calls within seconds must BOTH send Telegram notifications
	// and must not touch the hourly rate-limit notice window.
	if err := mgr.EnterShield(context.Background(), "manual test 1", EnterOptions{Manual: true, NoRedial: true}); err != nil {
		t.Fatalf("first --no-redial EnterShield failed: %v", err)
	}
	now = now.Add(5 * time.Second)
	if err := mgr.EnterShield(context.Background(), "manual test 2", EnterOptions{Manual: true, NoRedial: true}); err != nil {
		t.Fatalf("second --no-redial EnterShield failed: %v", err)
	}
	if notifier.Count() != 2 {
		t.Fatalf("expected 2 Telegram notifications for consecutive --no-redial calls, got %d", notifier.Count())
	}
	if ub.downs.Load() != 0 {
		t.Fatalf("expected no redials with --no-redial, got %d", ub.downs.Load())
	}

	// Exhaust MaxRedialsPerHour=1 via a normal redial, then trigger 2 rate-limited entries <10m apart.
	if err := mgr.EnterShield(context.Background(), "auto attack 1", EnterOptions{}); err != nil {
		t.Fatalf("auto EnterShield 1 failed: %v", err)
	}
	if err := mgr.EnterShield(context.Background(), "auto attack 2 (rate-limited)", EnterOptions{}); err != nil {
		t.Fatalf("auto EnterShield 2 failed: %v", err)
	}
	now = now.Add(30 * time.Second)
	if err := mgr.EnterShield(context.Background(), "auto attack 3 (throttled)", EnterOptions{}); err != nil {
		t.Fatalf("auto EnterShield 3 failed: %v", err)
	}

	// Expected total: 2 (--no-redial) + 1 (auto redial 1) + 1 (first rate-limit notice) = 4.
	if notifier.Count() != 4 {
		t.Fatalf("expected rate-limit notice to be throttled after 10m window check, got total=%d", notifier.Count())
	}
}
