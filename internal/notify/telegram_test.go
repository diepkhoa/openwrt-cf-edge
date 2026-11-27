package notify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/diepkhoa/openwrt-cf-edge/internal/config"
)

func TestTelegramDisabledIsNoop(t *testing.T) {
	c := NewTelegramClient(config.TelegramConfig{Enabled: false})
	if err := c.Send(context.Background(), "hello"); err != nil {
		t.Fatalf("disabled client returned error: %v", err)
	}
}

func TestTelegramSendSuccess(t *testing.T) {
	var gotPath string
	var gotPayload sendMessagePayload
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		if err := json.NewDecoder(r.Body).Decode(&gotPayload); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true,"result":{"message_id":42}}`))
	}))
	defer srv.Close()

	c := NewTelegramClient(config.TelegramConfig{
		Enabled:  true,
		BotToken: "123:ABC",
		ChatID:   "-100999",
	}, WithBaseURL(srv.URL))

	msg := FormatDDNSUpdate("node<1>", "1.2.3.4", "2001:db8::1", []string{"wg.example.com (A)"})
	if err := c.Send(context.Background(), msg); err != nil {
		t.Fatalf("Send failed: %v", err)
	}
	if gotPath != "/bot123:ABC/sendMessage" {
		t.Fatalf("path = %q", gotPath)
	}
	if gotPayload.ChatID != "-100999" || gotPayload.ParseMode != "HTML" {
		t.Fatalf("unexpected payload: %+v", gotPayload)
	}
	if !strings.Contains(gotPayload.Text, "node&lt;1&gt;") {
		t.Fatalf("expected HTML-escaped node name, got %q", gotPayload.Text)
	}
}

func TestTelegramSendFailures(t *testing.T) {
	t.Run("ok_false_with_200", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"ok":false,"description":"chat not found"}`))
		}))
		defer srv.Close()

		c := NewTelegramClient(config.TelegramConfig{Enabled: true, BotToken: "t", ChatID: "c"}, WithBaseURL(srv.URL))
		err := c.Send(context.Background(), "hi")
		if err == nil || !strings.Contains(err.Error(), "ok=false") {
			t.Fatalf("expected ok=false error, got %v", err)
		}
	})

	t.Run("http_500", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`internal error`))
		}))
		defer srv.Close()

		c := NewTelegramClient(config.TelegramConfig{Enabled: true, BotToken: "t", ChatID: "c"}, WithBaseURL(srv.URL), WithRetryDelay(0))
		err := c.Send(context.Background(), "hi")
		if err == nil || !strings.Contains(err.Error(), "HTTP 500") {
			t.Fatalf("expected HTTP 500 error, got %v", err)
		}
	})
}

func TestTelegramSendRedactsTokenOnTransportError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	deadURL := srv.URL
	srv.Close() // closed port forces immediate connection refused *url.Error

	const secretToken = "99887766:SUPER_SECRET_BOT_TOKEN"
	c := NewTelegramClient(
		config.TelegramConfig{Enabled: true, BotToken: secretToken, ChatID: "c"},
		WithBaseURL(deadURL),
		WithRetryDelay(0),
	)
	err := c.Send(context.Background(), "hello")
	if err == nil {
		t.Fatal("expected error against closed server")
	}
	if strings.Contains(err.Error(), secretToken) {
		t.Fatalf("error must not leak bot_token, got: %v", err)
	}
	if !strings.Contains(err.Error(), "/bot***/sendMessage") {
		t.Fatalf("expected redacted bot path in error, got: %v", err)
	}
}

func TestTelegramSendRetriesTransientErrors(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if attempts.Add(1) < 3 {
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte("bad gateway"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	c := NewTelegramClient(
		config.TelegramConfig{Enabled: true, BotToken: "tok", ChatID: "chat"},
		WithBaseURL(srv.URL),
		WithRetryDelay(0),
	)
	if err := c.Send(context.Background(), "hello"); err != nil {
		t.Fatalf("expected retry recovery on 3rd attempt, got: %v", err)
	}
	if attempts.Load() != 3 {
		t.Fatalf("attempts = %d, want 3", attempts.Load())
	}
}

func TestFormatDDNSUpdateGroupsHostsAndSortsTypes(t *testing.T) {
	single := FormatDDNSUpdate("knr3053", "42.118.213.53", "2405:4803::1", []string{
		"test.com (AAAA)",
		"test.com (A)",
		"test.com (A)",
	})
	if !strings.Contains(single, "• <b>Host:</b> <code>test.com (A, AAAA)</code>") {
		t.Fatalf("expected grouped single host line, got:\n%s", single)
	}
	if strings.Count(single, "test.com") != 1 {
		t.Fatalf("expected test.com mentioned only once, got:\n%s", single)
	}

	multi := FormatDDNSUpdate("knr3053", "42.118.213.53", "", []string{
		"test.com (A)",
		"wg.com (AAAA)",
		"test.com (AAAA)",
	})
	if !strings.Contains(multi, "• <b>Hosts:</b>") ||
		!strings.Contains(multi, "<code>test.com (A, AAAA)</code>") ||
		!strings.Contains(multi, "<code>wg.com (AAAA)</code>") {
		t.Fatalf("unexpected multi-host formatting:\n%s", multi)
	}
}
