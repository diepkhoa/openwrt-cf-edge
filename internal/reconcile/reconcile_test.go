package reconcile

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/diepkhoa/openwrt-cf-edge/internal/cloudflare"
	"github.com/diepkhoa/openwrt-cf-edge/internal/config"
	"github.com/diepkhoa/openwrt-cf-edge/internal/ipwatch"
	"github.com/diepkhoa/openwrt-cf-edge/internal/state"
	"golang.org/x/net/dns/dnsmessage"
)

func startMockUDPServer(t *testing.T, handler func(dnsmessage.Question) (dnsmessage.RCode, []net.IP)) (string, func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 2048)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var req dnsmessage.Message
			if err := req.Unpack(buf[:n]); err != nil || len(req.Questions) == 0 {
				continue
			}
			q := req.Questions[0]
			rcode, ips := handler(q)

			resp := dnsmessage.Message{
				Header: dnsmessage.Header{
					ID:            req.ID,
					Response:      true,
					RCode:         rcode,
					Authoritative: true,
				},
				Questions: req.Questions,
			}
			for _, ip := range ips {
				if v4 := ip.To4(); v4 != nil && q.Type == dnsmessage.TypeA {
					var arr [4]byte
					copy(arr[:], v4)
					resp.Answers = append(resp.Answers, dnsmessage.Resource{
						Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
						Body:   &dnsmessage.AResource{A: arr},
					})
				}
			}
			wire, err := resp.Pack()
			if err == nil {
				_, _ = pc.WriteTo(wire, addr)
			}
		}
	}()
	return pc.LocalAddr().String(), func() {
		_ = pc.Close()
		<-done
	}
}

func TestDirectResolverOutcomes(t *testing.T) {
	addr, stop := startMockUDPServer(t, func(q dnsmessage.Question) (dnsmessage.RCode, []net.IP) {
		switch q.Name.String() {
		case "nx.example.com.":
			return dnsmessage.RCodeNameError, nil
		case "nodata.example.com.":
			return dnsmessage.RCodeSuccess, nil
		case "ok.example.com.":
			return dnsmessage.RCodeSuccess, []net.IP{net.ParseIP("203.0.113.55")}
		default:
			return dnsmessage.RCodeServerFailure, nil
		}
	})
	defer stop()

	res := NewDirectResolver([]string{addr}, time.Second)

	if got := res.Query(context.Background(), "nx.example.com", "A"); got.Outcome != OutcomeNXDOMAIN {
		t.Fatalf("expected NXDOMAIN, got %+v", got)
	}
	if got := res.Query(context.Background(), "nodata.example.com", "A"); got.Outcome != OutcomeNODATA {
		t.Fatalf("expected NODATA, got %+v", got)
	}
	if got := res.Query(context.Background(), "ok.example.com", "A"); got.Outcome != OutcomeOK || len(got.IPs) != 1 || got.IPs[0].String() != "203.0.113.55" {
		t.Fatalf("expected OK 203.0.113.55, got %+v", got)
	}
	if got := res.Query(context.Background(), "servfail.example.com", "A"); got.Outcome != OutcomeNetError {
		t.Fatalf("expected NET_ERROR on SERVFAIL, got %+v", got)
	}
}

func TestReconcilerBehavior(t *testing.T) {
	addr, stop := startMockUDPServer(t, func(q dnsmessage.Question) (dnsmessage.RCode, []net.IP) {
		switch q.Name.String() {
		case "proxied.example.com.":
			return dnsmessage.RCodeNameError, nil // Should be skipped because proxied=true
		case "healthy.example.com.":
			return dnsmessage.RCodeSuccess, []net.IP{net.ParseIP("203.0.113.10")}
		case "cfproxy.example.com.":
			return dnsmessage.RCodeSuccess, []net.IP{net.ParseIP("104.21.5.5")} // Cloudflare proxy IP
		case "drifted.example.com.":
			return dnsmessage.RCodeSuccess, []net.IP{net.ParseIP("198.51.100.1")}
		default:
			return dnsmessage.RCodeNameError, nil
		}
	})
	defer stop()

	cfIPSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"result":{"ipv4_cidrs":["104.16.0.0/13"],"ipv6_cidrs":[]}}`))
	}))
	defer cfIPSrv.Close()

	dir := t.TempDir()
	store := state.NewStore(filepath.Join(dir, "state.json"))
	_ = store.Update(func(st *state.RuntimeState) error {
		st.LastIPv4 = "203.0.113.10"
		return nil
	})

	cfg := &config.Config{
		NodeName: "x96air",
		Cloudflare: config.CloudflareConfig{
			Records: []config.RecordConfig{
				{Subdomain: "proxied.example.com", IPv4: true, Proxied: true},
				{Subdomain: "healthy.example.com", IPv4: true, Proxied: false},
				{Subdomain: "cfproxy.example.com", IPv4: true, Proxied: false},
				{Subdomain: "drifted.example.com", IPv4: true, Proxied: false},
			},
		},
		Reconcile: config.ReconcileConfig{
			Enabled:   true,
			Interval:  config.Duration(time.Minute),
			Resolvers: []string{addr},
		},
	}

	var mu sync.Mutex
	var synced []string
	rec := NewReconciler(
		cfg,
		store,
		NewDirectResolver([]string{addr}, time.Second),
		NewCFProxyCatalog(store, cfIPSrv.URL),
		func(context.Context) (ipwatch.Snapshot, error) {
			return ipwatch.Snapshot{IPv4: "203.0.113.10"}, nil
		},
		func(_ context.Context, _ ipwatch.Snapshot, opts cloudflare.SyncOptions) error {
			mu.Lock()
			defer mu.Unlock()
			if !opts.Force {
				t.Errorf("expected Force=true from reconcile")
			}
			synced = append(synced, opts.Subdomains...)
			return nil
		},
		filepath.Join(dir, "shield.lock"),
		nil,
	)

	if err := rec.ReconcileOnce(context.Background()); err != nil {
		t.Fatalf("ReconcileOnce failed: %v", err)
	}
	if len(synced) != 2 || synced[0] != "cfproxy.example.com" || synced[1] != "drifted.example.com" {
		t.Fatalf("unexpected synced subdomains: %v", synced)
	}

	// Verify NET_ERROR does NOT trigger sync.
	synced = nil
	recErr := NewReconciler(
		cfg,
		store,
		NewDirectResolver([]string{"127.0.0.1:1"}, 50*time.Millisecond),
		NewCFProxyCatalog(store, cfIPSrv.URL),
		func(context.Context) (ipwatch.Snapshot, error) {
			t.Fatal("discover should not be called on NET_ERROR")
			return ipwatch.Snapshot{}, nil
		},
		func(context.Context, ipwatch.Snapshot, cloudflare.SyncOptions) error {
			t.Fatal("sync should not be called on NET_ERROR")
			return nil
		},
		filepath.Join(dir, "shield.lock"),
		nil,
	)
	if err := recErr.ReconcileOnce(context.Background()); err != nil {
		t.Fatalf("ReconcileOnce NET_ERROR failed: %v", err)
	}
}
