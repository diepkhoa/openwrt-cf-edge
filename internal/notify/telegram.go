package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/diepkhoa/openwrt-cf-edge/internal/config"
)

const defaultTelegramBaseURL = "https://api.telegram.org"

// Notifier delivers alert messages to an external notification channel.
type Notifier interface {
	Send(ctx context.Context, htmlMessage string) error
}

// TelegramClient sends HTML-formatted notifications via the Telegram Bot API.
type TelegramClient struct {
	enabled    bool
	botToken   string
	chatID     string
	baseURL    string
	httpClient *http.Client
}

// Option customizes a TelegramClient instance.
type Option func(*TelegramClient)

// WithBaseURL overrides the Telegram API base URL (used in unit tests).
func WithBaseURL(baseURL string) Option {
	return func(c *TelegramClient) {
		c.baseURL = strings.TrimRight(baseURL, "/")
	}
}

// WithHTTPClient overrides the underlying HTTP client.
func WithHTTPClient(client *http.Client) Option {
	return func(c *TelegramClient) {
		if client != nil {
			c.httpClient = client
		}
	}
}

// NewTelegramClient constructs a TelegramClient from configuration.
func NewTelegramClient(cfg config.TelegramConfig, opts ...Option) *TelegramClient {
	c := &TelegramClient{
		enabled:  cfg.Enabled,
		botToken: cfg.BotToken,
		chatID:   cfg.ChatID,
		baseURL:  defaultTelegramBaseURL,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

type sendMessagePayload struct {
	ChatID                string `json:"chat_id"`
	Text                  string `json:"text"`
	ParseMode             string `json:"parse_mode"`
	DisableWebPagePreview bool   `json:"disable_web_page_preview"`
}

type telegramResponse struct {
	OK          bool   `json:"ok"`
	Description string `json:"description"`
}

// Send posts a message to Telegram and verifies both HTTP 200 and JSON `"ok": true`.
func (c *TelegramClient) Send(ctx context.Context, htmlMessage string) error {
	if !c.enabled {
		return nil
	}
	payload := sendMessagePayload{
		ChatID:                c.chatID,
		Text:                  htmlMessage,
		ParseMode:             "HTML",
		DisableWebPagePreview: true,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal telegram payload: %w", err)
	}

	endpoint := fmt.Sprintf("%s/bot%s/sendMessage", c.baseURL, c.botToken)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build telegram request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("send telegram request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return fmt.Errorf("read telegram response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("telegram HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var tgResp telegramResponse
	if err := json.Unmarshal(respBody, &tgResp); err != nil {
		return fmt.Errorf("decode telegram JSON: %w", err)
	}
	if !tgResp.OK {
		return fmt.Errorf("telegram API ok=false: %s", tgResp.Description)
	}
	return nil
}

// FormatDDNSUpdate builds an HTML alert for updated Cloudflare DNS records.
func FormatDDNSUpdate(nodeName, ipv4, ipv6 string, updated []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "<b>[cf-edge] DDNS Updated</b> — <code>%s</code>\n", html.EscapeString(nodeName))
	if ipv4 != "" {
		fmt.Fprintf(&b, "• IPv4: <code>%s</code>\n", html.EscapeString(ipv4))
	}
	if ipv6 != "" {
		fmt.Fprintf(&b, "• IPv6: <code>%s</code>\n", html.EscapeString(ipv6))
	}
	if len(updated) > 0 {
		fmt.Fprintf(&b, "• Records: <code>%s</code>", html.EscapeString(strings.Join(updated, ", ")))
	}
	return b.String()
}

// FormatPPPoEAction builds an HTML alert for PPPoE Guard recovery events.
func FormatPPPoEAction(nodeName, action, detail string) string {
	return fmt.Sprintf(
		"<b>[cf-edge] PPPoE Guard</b> — <code>%s</code>\n• Action: <code>%s</code>\n• Detail: %s",
		html.EscapeString(nodeName),
		html.EscapeString(action),
		html.EscapeString(detail),
	)
}

// FormatShieldEntered builds an HTML alert when entering DDoS Shield mode.
func FormatShieldEntered(nodeName, reason, newIP, workerStatus string) string {
	return fmt.Sprintf(
		"<b>[cf-edge] DDoS SHIELD ENTERED</b> — <code>%s</code>\n• Reason: <code>%s</code>\n• New WAN IP: <code>%s</code>\n• Worker: %s",
		html.EscapeString(nodeName),
		html.EscapeString(reason),
		html.EscapeString(newIP),
		html.EscapeString(workerStatus),
	)
}

// FormatShieldExited builds an HTML alert when exiting DDoS Shield mode.
func FormatShieldExited(nodeName, detail string) string {
	return fmt.Sprintf(
		"<b>[cf-edge] DDoS Shield Exited</b> — <code>%s</code>\n• Status: %s",
		html.EscapeString(nodeName),
		html.EscapeString(detail),
	)
}
