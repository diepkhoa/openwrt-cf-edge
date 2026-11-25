package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	defaultAPIBaseURL = "https://api.cloudflare.com/client/v4"
	defaultAPITimeout = 10 * time.Second
)

// DNSRecord models a Cloudflare DNS record returned or sent via REST v4.
type DNSRecord struct {
	ID      string `json:"id,omitempty"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied bool   `json:"proxied"`
}

// APIError represents an error returned by the Cloudflare REST API.
type APIError struct {
	StatusCode int
	Code       int
	Message    string
}

// Error implements error.
func (e *APIError) Error() string {
	return fmt.Sprintf("cloudflare API HTTP %d (code %d): %s", e.StatusCode, e.Code, e.Message)
}

// IsNotFoundError reports whether err indicates a missing or invalid Cloudflare record ID.
func IsNotFoundError(err error) bool {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	if apiErr.StatusCode == http.StatusNotFound || apiErr.Code == 81044 || apiErr.Code == 1001 {
		return true
	}
	msg := strings.ToLower(apiErr.Message)
	return strings.Contains(msg, "not found") ||
		strings.Contains(msg, "not a valid") ||
		strings.Contains(msg, "does not exist")
}

// IsRetryableError reports whether err is a transient network, 5xx, or 429 rate-limit failure.
func IsRetryableError(err error) bool {
	if err == nil {
		return false
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode >= 500 || apiErr.StatusCode == http.StatusTooManyRequests
	}
	return !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded)
}

// API defines the Cloudflare DNS record operations used by Updater.
type API interface {
	ListRecords(ctx context.Context, zoneID, recordType, name string) ([]DNSRecord, error)
	CreateRecord(ctx context.Context, zoneID string, rec DNSRecord) (DNSRecord, error)
	UpdateRecord(ctx context.Context, zoneID, recordID string, rec DNSRecord) (DNSRecord, error)
	DeleteRecord(ctx context.Context, zoneID, recordID string) error
}

// ClientOption configures an HTTPClient.
type ClientOption func(*HTTPClient)

// WithBaseURL overrides the Cloudflare API base URL (used in tests).
func WithBaseURL(baseURL string) ClientOption {
	return func(c *HTTPClient) {
		c.baseURL = strings.TrimRight(baseURL, "/")
	}
}

// WithHTTPClient overrides the HTTP client (used in tests).
func WithHTTPClient(hc *http.Client) ClientOption {
	return func(c *HTTPClient) {
		if hc != nil {
			c.httpClient = hc
		}
	}
}

// HTTPClient implements API against the Cloudflare v4 REST endpoint.
type HTTPClient struct {
	apiToken   string
	baseURL    string
	httpClient *http.Client
}

// NewHTTPClient creates an authenticated Cloudflare DNS API client.
func NewHTTPClient(apiToken string, opts ...ClientOption) *HTTPClient {
	c := &HTTPClient{
		apiToken: apiToken,
		baseURL:  defaultAPIBaseURL,
		httpClient: &http.Client{
			Timeout: defaultAPITimeout,
		},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

type cfEnvelope[T any] struct {
	Success bool `json:"success"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	Result T `json:"result"`
}

// ListRecords calls GET /zones/{zone_id}/dns_records?type={type}&name={name}.
func (c *HTTPClient) ListRecords(ctx context.Context, zoneID, recordType, name string) ([]DNSRecord, error) {
	q := url.Values{}
	q.Set("type", recordType)
	q.Set("name", name)
	q.Set("per_page", "100")

	endpoint := fmt.Sprintf("%s/zones/%s/dns_records?%s", c.baseURL, url.PathEscape(zoneID), q.Encode())
	var out cfEnvelope[[]DNSRecord]
	if err := c.doJSON(ctx, http.MethodGet, endpoint, nil, &out); err != nil {
		return nil, err
	}
	return out.Result, nil
}

// CreateRecord calls POST /zones/{zone_id}/dns_records.
func (c *HTTPClient) CreateRecord(ctx context.Context, zoneID string, rec DNSRecord) (DNSRecord, error) {
	endpoint := fmt.Sprintf("%s/zones/%s/dns_records", c.baseURL, url.PathEscape(zoneID))
	var out cfEnvelope[DNSRecord]
	if err := c.doJSON(ctx, http.MethodPost, endpoint, rec, &out); err != nil {
		return DNSRecord{}, err
	}
	return out.Result, nil
}

// UpdateRecord calls PUT /zones/{zone_id}/dns_records/{record_id}.
func (c *HTTPClient) UpdateRecord(ctx context.Context, zoneID, recordID string, rec DNSRecord) (DNSRecord, error) {
	endpoint := fmt.Sprintf("%s/zones/%s/dns_records/%s", c.baseURL, url.PathEscape(zoneID), url.PathEscape(recordID))
	var out cfEnvelope[DNSRecord]
	if err := c.doJSON(ctx, http.MethodPut, endpoint, rec, &out); err != nil {
		return DNSRecord{}, err
	}
	return out.Result, nil
}

// DeleteRecord calls DELETE /zones/{zone_id}/dns_records/{record_id}.
func (c *HTTPClient) DeleteRecord(ctx context.Context, zoneID, recordID string) error {
	endpoint := fmt.Sprintf("%s/zones/%s/dns_records/%s", c.baseURL, url.PathEscape(zoneID), url.PathEscape(recordID))
	var out cfEnvelope[json.RawMessage]
	return c.doJSON(ctx, http.MethodDelete, endpoint, nil, &out)
}

func (c *HTTPClient) doJSON(ctx context.Context, method, endpoint string, bodyObj any, dest any) error {
	var bodyReader io.Reader
	if bodyObj != nil {
		raw, err := json.Marshal(bodyObj)
		if err != nil {
			return fmt.Errorf("marshal request: %w", err)
		}
		bodyReader = bytes.NewReader(raw)
	}

	req, err := http.NewRequestWithContext(ctx, method, endpoint, bodyReader)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	rawResp, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	var envelope struct {
		Success bool `json:"success"`
		Errors  []struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}
	_ = json.Unmarshal(rawResp, &envelope)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 || !envelope.Success {
		apiErr := &APIError{
			StatusCode: resp.StatusCode,
			Message:    strings.TrimSpace(string(rawResp)),
		}
		if len(envelope.Errors) > 0 {
			apiErr.Code = envelope.Errors[0].Code
			apiErr.Message = envelope.Errors[0].Message
		}
		if retryAfter := resp.Header.Get("Retry-After"); retryAfter != "" {
			if secs, convErr := strconv.Atoi(retryAfter); convErr == nil && secs > 0 {
				apiErr.Message = fmt.Sprintf("%s (retry-after %ds)", apiErr.Message, secs)
			}
		}
		return apiErr
	}

	if dest != nil {
		if err := json.Unmarshal(rawResp, dest); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}
