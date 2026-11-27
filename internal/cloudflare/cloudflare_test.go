package cloudflare

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
	"github.com/diepkhoa/openwrt-cf-edge/internal/ipwatch"
	"github.com/diepkhoa/openwrt-cf-edge/internal/notify"
	"github.com/diepkhoa/openwrt-cf-edge/internal/state"
)

type spyNotifier struct {
	mu   sync.Mutex
	msgs []string
}

func (s *spyNotifier) Send(_ context.Context, msg string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.msgs = append(s.msgs, msg)
	return nil
}

func newTestConfig() *config.Config {
	return &config.Config{
		NodeName: "x96air",
		Cloudflare: config.CloudflareConfig{
			Enabled:  true,
			ZoneID:   "zone-1",
			APIToken: "secret",
			Records: []config.RecordConfig{
				{Subdomain: "wg.example.com", IPv4: true, IPv6: true, Proxied: false},
			},
		},
	}
}

func TestUpdaterDedupAndSkipPutWhenAlreadyMatching(t *testing.T) {
	var putCount, postCount, deleteCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_, _ = w.Write([]byte(`{
				"success": true,
				"result": [
					{"id": "rec-stale", "type": "A", "name": "wg.example.com", "content": "9.9.9.9", "ttl": 60, "proxied": false},
					{"id": "rec-good", "type": "A", "name": "wg.example.com", "content": "203.0.113.1", "ttl": 60, "proxied": false},
					{"id": "rec-dup", "type": "A", "name": "wg.example.com", "content": "203.0.113.1", "ttl": 60, "proxied": false}
				]
			}`))
		case http.MethodDelete:
			deleteCount.Add(1)
			_, _ = w.Write([]byte(`{"success": true, "result": {}}`))
		case http.MethodPut:
			putCount.Add(1)
		case http.MethodPost:
			postCount.Add(1)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	store := state.NewStore(filepath.Join(dir, "state.json"))
	api := NewHTTPClient("secret", WithBaseURL(srv.URL))
	spy := &spyNotifier{}
	cfg := newTestConfig()
	cfg.Cloudflare.Records[0].IPv6 = false

	upd := NewUpdater(cfg, api, store, spy, filepath.Join(dir, "shield.lock"), nil,
		WithTiming(0, 0, 0, 1, 1),
	)

	err := upd.Sync(context.Background(), ipwatch.Snapshot{IPv4: "203.0.113.1"}, SyncOptions{})
	if err != nil {
		t.Fatalf("Sync failed: %v", err)
	}
	if deleteCount.Load() != 2 {
		t.Fatalf("expected 2 DELETE calls (1 stale + 1 dup), got %d", deleteCount.Load())
	}
	if putCount.Load() != 0 || postCount.Load() != 0 {
		t.Fatalf("expected 0 PUT/POST when matched IP exists, got put=%d post=%d", putCount.Load(), postCount.Load())
	}
	got := store.Get().Records[state.RecordKey("wg.example.com", "A")]
	if got.RecordID != "rec-good" {
		t.Fatalf("saved RecordID = %q, want rec-good", got.RecordID)
	}
}

func TestUpdaterFallbackFromStaleIDToPostAndCooldown(t *testing.T) {
	var postCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPut:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":81044,"message":"Record does not exist."}]}`))
		case http.MethodPost:
			postCount.Add(1)
			var body DNSRecord
			_ = json.NewDecoder(r.Body).Decode(&body)
			body.ID = "new-rec-123"
			resp := map[string]any{"success": true, "result": body}
			_ = json.NewEncoder(w).Encode(resp)
		default:
			_, _ = w.Write([]byte(`{"success": true, "result": []}`))
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	store := state.NewStore(filepath.Join(dir, "state.json"))
	_ = store.Update(func(st *state.RuntimeState) error {
		st.Records[state.RecordKey("wg.example.com", "A")] = state.RecordState{
			RecordID:  "deleted-id",
			Subdomain: "wg.example.com",
			Type:      "A",
			IP:        "1.1.1.1",
		}
		return nil
	})

	cfg := newTestConfig()
	cfg.Cloudflare.Records[0].IPv6 = false
	api := NewHTTPClient("secret", WithBaseURL(srv.URL))
	var notifier notify.Notifier = &spyNotifier{}

	upd := NewUpdater(cfg, api, store, notifier, filepath.Join(dir, "shield.lock"), nil,
		WithTiming(50*time.Millisecond, 0, 0, 1, 1),
	)

	if err := upd.Sync(context.Background(), ipwatch.Snapshot{IPv4: "198.51.100.7"}, SyncOptions{}); err != nil {
		t.Fatalf("Sync failed: %v", err)
	}
	if postCount.Load() != 1 {
		t.Fatalf("expected 1 POST fallback, got %d", postCount.Load())
	}
	saved := store.Get().Records[state.RecordKey("wg.example.com", "A")]
	if saved.RecordID != "new-rec-123" || saved.IP != "198.51.100.7" {
		t.Fatalf("unexpected saved record: %+v", saved)
	}

	// Normal sync within cooldown with new IP should wait cooldown then succeed;
	// force sync bypasses cooldown immediately.
	start := time.Now()
	if err := upd.Sync(context.Background(), ipwatch.Snapshot{IPv4: "198.51.100.8"}, SyncOptions{Force: true}); err != nil {
		t.Fatalf("Force sync failed: %v", err)
	}
	if time.Since(start) >= 45*time.Millisecond {
		t.Fatalf("Force sync waited for cooldown unexpectedly")
	}
}

func TestUpdaterGlobalRetryAndShieldBlock(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempts.Add(1)
		if n <= 2 {
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":502,"message":"bad gateway"}]}`))
			return
		}
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"success":true,"result":[]}`))
			return
		}
		_, _ = w.Write([]byte(`{"success":true,"result":{"id":"id-ok","type":"A","name":"wg.example.com","content":"203.0.113.9","ttl":60}}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	lockPath := filepath.Join(dir, "shield.lock")
	store := state.NewStore(filepath.Join(dir, "state.json"))
	cfg := newTestConfig()
	cfg.Cloudflare.Records[0].IPv6 = false
	api := NewHTTPClient("secret", WithBaseURL(srv.URL))

	upd := NewUpdater(cfg, api, store, nil, lockPath, nil,
		WithTiming(0, time.Millisecond, time.Millisecond, 0, 3),
	)
	if err := upd.Sync(context.Background(), ipwatch.Snapshot{IPv4: "203.0.113.9"}, SyncOptions{}); err != nil {
		t.Fatalf("expected global retry round 3 to succeed, got %v", err)
	}

	if err := state.WriteShieldLock(lockPath, state.ShieldLock{Reason: "test"}); err != nil {
		t.Fatal(err)
	}
	err := upd.Sync(context.Background(), ipwatch.Snapshot{IPv4: "203.0.113.10"}, SyncOptions{Force: true})
	if !errors.Is(err, ErrShielded) {
		t.Fatalf("expected ErrShielded, got %v", err)
	}
	if !strings.Contains(err.Error(), "shield") {
		t.Fatalf("unexpected error string: %v", err)
	}
}

type flakyNotifier struct {
	failNext atomic.Bool
	mu       sync.Mutex
	msgs     []string
}

func (f *flakyNotifier) Send(_ context.Context, msg string) error {
	if f.failNext.Load() {
		return errors.New("temporary DNS error")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.msgs = append(f.msgs, msg)
	return nil
}

func TestUpdaterFlushesPendingNotifyWhenIPv6ArrivesLater(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_, _ = w.Write([]byte(`{"success":true,"result":[]}`))
		case http.MethodPost:
			var body DNSRecord
			_ = json.NewDecoder(r.Body).Decode(&body)
			body.ID = "id-" + body.Type
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": body})
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	store := state.NewStore(filepath.Join(dir, "state.json"))
	cfg := newTestConfig()
	cfg.NodeName = "knr3053"
	cfg.Cloudflare.Records[0].Subdomain = "test.com"
	api := NewHTTPClient("secret", WithBaseURL(srv.URL))

	flaky := &flakyNotifier{}
	flaky.failNext.Store(true)

	upd := NewUpdater(cfg, api, store, flaky, filepath.Join(dir, "shield.lock"), nil,
		WithTiming(0, 0, 0, 1, 1),
	)

	// Pass 1 (boot): only IPv4 available, A record updates on CF, Telegram send fails.
	if err := upd.Sync(context.Background(), ipwatch.Snapshot{IPv4: "42.118.213.53"}, SyncOptions{}); err != nil {
		t.Fatalf("Pass 1 sync failed: %v", err)
	}
	if got := store.Get().PendingNotify; len(got) != 1 || got[0] != "test.com (A)" {
		t.Fatalf("expected PendingNotify=[test.com (A)], got %v", got)
	}

	// Pass 2 (3 minutes later): IPv6 comes up, Telegram recovers and must merge A + AAAA cleanly.
	flaky.failNext.Store(false)
	if err := upd.Sync(context.Background(), ipwatch.Snapshot{IPv4: "42.118.213.53", IPv6: "2405:4803::1"}, SyncOptions{}); err != nil {
		t.Fatalf("Pass 2 sync failed: %v", err)
	}
	if got := store.Get().PendingNotify; len(got) != 0 {
		t.Fatalf("expected PendingNotify cleared after send, got %v", got)
	}
	if len(flaky.msgs) != 1 {
		t.Fatalf("expected 1 combined Telegram message, got %d", len(flaky.msgs))
	}
	msg := flaky.msgs[0]
	if !strings.Contains(msg, "42.118.213.53") || !strings.Contains(msg, "2405:4803::1") || !strings.Contains(msg, "test.com (A, AAAA)") {
		t.Fatalf("expected combined IPv4 + IPv6 + grouped host (A, AAAA), got:\n%s", msg)
	}
}
