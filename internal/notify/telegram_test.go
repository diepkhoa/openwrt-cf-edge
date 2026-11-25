package notify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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

		c := NewTelegramClient(config.TelegramConfig{Enabled: true, BotToken: "t", ChatID: "c"}, WithBaseURL(srv.URL))
		err := c.Send(context.Background(), "hi")
		if err == nil || !strings.Contains(err.Error(), "HTTP 500") {
			t.Fatalf("expected HTTP 500 error, got %v", err)
		}
	})
}
