package ipwatch

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/diepkhoa/openwrt-cf-edge/internal/config"
	"github.com/diepkhoa/openwrt-cf-edge/internal/netutil"
	"github.com/diepkhoa/openwrt-cf-edge/internal/ubus"
)

type fakeUbus struct {
	statuses map[string]ubus.InterfaceStatus
	err      error
}

func (f *fakeUbus) Status(_ context.Context, iface string) (ubus.InterfaceStatus, error) {
	if f.err != nil {
		return ubus.InterfaceStatus{}, f.err
	}
	st, ok := f.statuses[iface]
	if !ok {
		return ubus.InterfaceStatus{}, errors.New("not found")
	}
	return st, nil
}
func (f *fakeUbus) Down(context.Context, string) error { return nil }
func (f *fakeUbus) Up(context.Context, string) error   { return nil }

type fakeNet struct {
	routeIface string
	routeIP    string
	routeErr   error
	v6Addrs    map[string][]netutil.IPv6AddrInfo
	v6Err      error
}

func (f *fakeNet) DefaultRouteIPv4(context.Context) (string, string, error) {
	return f.routeIface, f.routeIP, f.routeErr
}
func (f *fakeNet) GlobalIPv6Addrs(_ context.Context, dev string) ([]netutil.IPv6AddrInfo, error) {
	if f.v6Err != nil {
		return nil, f.v6Err
	}
	return f.v6Addrs[dev], nil
}

func testConfig(ipv6 bool) *config.Config {
	return &config.Config{
		NodeName: "test",
		WAN: config.WANConfig{
			IfaceV4: "wan",
			IfaceV6: "wan6",
		},
		Cloudflare: config.CloudflareConfig{
			Records: []config.RecordConfig{{
				Subdomain: "node.example.com",
				IPv4:      true,
				IPv6:      ipv6,
			}},
		},
	}
}

func TestDiscoverPublicIPv4AndSkipIPv6(t *testing.T) {
	ub := &fakeUbus{
		statuses: map[string]ubus.InterfaceStatus{
			"wan": {
				Up:          true,
				L3Device:    "pppoe-wan",
				IPv4Address: []ubus.IPv4Address{{Address: "203.162.4.190", Mask: 32}},
			},
		},
	}
	ni := &fakeNet{v6Err: errors.New("should not be called")}
	d := NewDiscoverer(testConfig(false), ub, ni, nil, WithRetryPolicy(1, 0))

	snap, err := d.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover failed: %v", err)
	}
	if snap.IPv4 != "203.162.4.190" || snap.IPv6 != "" || snap.L3DeviceV4 != "pppoe-wan" {
		t.Fatalf("unexpected snapshot: %+v", snap)
	}
}

func TestDiscoverBehindCGNATUsesTraceAndRejectsPrivateFallback(t *testing.T) {
	traceSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("fl=1\nip=198.51.100.42\nloc=VN\n"))
	}))
	defer traceSrv.Close()

	ub := &fakeUbus{
		statuses: map[string]ubus.InterfaceStatus{
			"wan": {
				Up:          true,
				L3Device:    "eth1",
				IPv4Address: []ubus.IPv4Address{{Address: "100.64.12.34", Mask: 10}},
			},
		},
	}
	d := NewDiscoverer(
		testConfig(false),
		ub,
		&fakeNet{},
		nil,
		WithProbeURLs(traceSrv.URL, traceSrv.URL, ""),
		WithHTTPClientFactory(func(_, _ string, timeout time.Duration) *http.Client {
			return &http.Client{Timeout: timeout}
		}),
		WithRetryPolicy(1, 0),
	)

	snap, err := d.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover behind CGNAT failed: %v", err)
	}
	if snap.IPv4 != "198.51.100.42" {
		t.Fatalf("got %q, want 198.51.100.42", snap.IPv4)
	}

	// If probe fails or returns private IP, private IP must NEVER leak.
	badSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("192.168.1.50"))
	}))
	defer badSrv.Close()

	dFail := NewDiscoverer(
		testConfig(false),
		ub,
		&fakeNet{},
		nil,
		WithProbeURLs(badSrv.URL, badSrv.URL, ""),
		WithHTTPClientFactory(func(_, _ string, timeout time.Duration) *http.Client {
			return &http.Client{Timeout: timeout}
		}),
		WithRetryPolicy(2, time.Millisecond),
	)
	if snapFail, err := dFail.Discover(context.Background()); err == nil || snapFail.IPv4 != "" {
		t.Fatalf("expected error and empty IPv4 when probe returns private IP, got snap=%+v err=%v", snapFail, err)
	}
}

func TestDiscoverIPv6FiltersDeprecated(t *testing.T) {
	ub := &fakeUbus{
		statuses: map[string]ubus.InterfaceStatus{
			"wan":  {Up: true, L3Device: "pppoe-wan", IPv4Address: []ubus.IPv4Address{{Address: "198.51.100.9"}}},
			"wan6": {Up: true, L3Device: "pppoe-wan"},
		},
	}
	ni := &fakeNet{
		v6Addrs: map[string][]netutil.IPv6AddrInfo{
			"pppoe-wan": {
				{Addr: netip.MustParseAddr("fe80::1"), PreferredLFT: 9999},
				{Addr: netip.MustParseAddr("2001:db8::dead"), Deprecated: true, PreferredLFT: 0},
				{Addr: netip.MustParseAddr("2001:db8::beef"), Deprecated: false, PreferredLFT: 3600},
			},
		},
	}
	d := NewDiscoverer(testConfig(true), ub, ni, nil, WithRetryPolicy(1, 0))

	snap, err := d.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover failed: %v", err)
	}
	if snap.IPv6 != "2001:db8::beef" {
		t.Fatalf("IPv6 = %q, want 2001:db8::beef", snap.IPv6)
	}
}

type channelStreamOpener struct {
	lines chan string
}

func (c *channelStreamOpener) Open(ctx context.Context) (io.ReadCloser, func() error, error) {
	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		for {
			select {
			case <-ctx.Done():
				return
			case line, ok := <-c.lines:
				if !ok {
					return
				}
				_, _ = pw.Write([]byte(line + "\n"))
			}
		}
	}()
	return pr, nil, nil
}

func TestWatcherPreemptsAndRespectsShieldLock(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, "shield.lock")

	var attempts atomic.Int32
	ub := &fakeUbus{
		statuses: map[string]ubus.InterfaceStatus{
			"wan": {Up: true, L3Device: "pppoe-wan", IPv4Address: []ubus.IPv4Address{{Address: "198.51.100.10"}}},
		},
	}
	// First attempt succeeds only after slow discovery; let's verify preemption cancels old context.
	stream := &channelStreamOpener{lines: make(chan string, 4)}
	listener := ubus.NewListener(stream, nil)

	var mu sync.Mutex
	var syncCalls int
	startedCh := make(chan struct{}, 4)

	d := NewDiscoverer(testConfig(false), ub, &fakeNet{}, nil, WithRetryPolicy(6, 50*time.Millisecond))
	w := NewWatcher(testConfig(false), d, listener, func(ctx context.Context, snap Snapshot, force bool) error {
		attempts.Add(1)
		startedCh <- struct{}{}
		// Simulate slow API call that honors ctx cancellation.
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(120 * time.Millisecond):
		}
		mu.Lock()
		syncCalls++
		mu.Unlock()
		return nil
	}, lockPath, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go listener.Run(ctx)
	go w.Run(ctx)

	// Wait for startup sync to enter slow API call, then preempt with a new ifup event.
	<-startedCh
	stream.lines <- `{"network.interface":{"action":"ifup","interface":"wan"}}`
	<-startedCh
	time.Sleep(180 * time.Millisecond)

	mu.Lock()
	completed := syncCalls
	mu.Unlock()
	if completed != 1 {
		t.Fatalf("expected exactly 1 completed sync after preemption, got %d (started=%d)", completed, attempts.Load())
	}

	// Write shield.lock and verify further ubus events are ignored.
	if err := os.WriteFile(lockPath, []byte(`{"active":true}`), 0644); err != nil {
		t.Fatal(err)
	}
	before := attempts.Load()
	stream.lines <- `{"network.interface":{"action":"ifupdate","interface":"wan"}}`
	time.Sleep(60 * time.Millisecond)
	if attempts.Load() != before {
		t.Fatalf("expected no sync triggers while shield.lock exists")
	}
}

func TestDiscoverIPv6PrefixDelegationFallbackToLANIface(t *testing.T) {
	cfg := testConfig(true)
	cfg.WAN.LANIface = "br-lan"

	ub := &fakeUbus{
		statuses: map[string]ubus.InterfaceStatus{
			"wan":  {Up: true, L3Device: "pppoe-wan", IPv4Address: []ubus.IPv4Address{{Address: "198.51.100.10"}}},
			"wan6": {Up: true, L3Device: "pppoe-wan"},
		},
	}
	// pppoe-wan only has link-local fe80::1 while PD assigns GUA onto br-lan.
	ni := &fakeNet{
		v6Addrs: map[string][]netutil.IPv6AddrInfo{
			"pppoe-wan": {{Addr: netip.MustParseAddr("fe80::1"), PreferredLFT: 9999}},
			"br-lan":    {{Addr: netip.MustParseAddr("2001:db8:cafe::1"), Deprecated: false, PreferredLFT: 3600}},
		},
	}
	failSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer failSrv.Close()

	d := NewDiscoverer(
		cfg, ub, ni, nil,
		WithProbeURLs("", "", failSrv.URL),
		WithHTTPClientFactory(func(_, _ string, timeout time.Duration) *http.Client {
			return &http.Client{Timeout: timeout}
		}),
		WithRetryPolicy(1, 0),
	)

	ip6, err := d.DiscoverIPv6(context.Background())
	if err != nil {
		t.Fatalf("DiscoverIPv6 failed: %v", err)
	}
	if ip6 != "2001:db8:cafe::1" {
		t.Fatalf("IPv6 = %q, want 2001:db8:cafe::1", ip6)
	}
}
