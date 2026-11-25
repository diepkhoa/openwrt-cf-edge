package ddos

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	defaultWorkerTimeout    = 8 * time.Second
	defaultWorkerMaxRetries = 5
	defaultWorkerRetryDelay = 3 * time.Second
)

// WorkerAPI communicates with the Cloudflare Maintenance Worker.
type WorkerAPI interface {
	ReportDDoS(ctx context.Context, newIP, reason string) error
	PollStatus(ctx context.Context) (string, error)
}

// HTTPWorkerClient implements WorkerAPI over HTTPS with Bearer token authentication.
type HTTPWorkerClient struct {
	baseURL    string
	token      string
	httpClient *http.Client
	maxRetries int
	retryDelay time.Duration
}

// NewHTTPWorkerClient creates a Cloudflare Worker API client.
func NewHTTPWorkerClient(workerURL, token string, retryDelay time.Duration) *HTTPWorkerClient {
	if retryDelay < 0 {
		retryDelay = defaultWorkerRetryDelay
	}
	return &HTTPWorkerClient{
		baseURL: strings.TrimRight(workerURL, "/"),
		token:   token,
		httpClient: &http.Client{
			Timeout: defaultWorkerTimeout,
		},
		maxRetries: defaultWorkerMaxRetries,
		retryDelay: retryDelay,
	}
}

type ddosReportPayload struct {
	NewIP  string `json:"new_ip"`
	Reason string `json:"reason"`
}

type workerStatusResponse struct {
	Action string `json:"action"`
}

// ReportDDoS sends POST <worker_url>/edge/ddos with up to 5 attempts.
func (c *HTTPWorkerClient) ReportDDoS(ctx context.Context, newIP, reason string) error {
	if c.baseURL == "" {
		return nil
	}
	body, err := json.Marshal(ddosReportPayload{
		NewIP:  newIP,
		Reason: reason,
	})
	if err != nil {
		return err
	}

	endpoint := c.baseURL + "/edge/ddos"
	var lastErr error
	for attempt := 1; attempt <= c.maxRetries; attempt++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		lastErr = c.postOnce(ctx, endpoint, body)
		if lastErr == nil {
			return nil
		}
		if attempt < c.maxRetries && c.retryDelay > 0 {
			timer := time.NewTimer(c.retryDelay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
	}
	return lastErr
}

func (c *HTTPWorkerClient) postOnce(ctx context.Context, endpoint string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("worker POST /edge/ddos HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	return nil
}

// PollStatus queries GET <worker_url>/edge/status and returns "hold" or "resume".
func (c *HTTPWorkerClient) PollStatus(ctx context.Context) (string, error) {
	if c.baseURL == "" {
		return "hold", nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/edge/status", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("worker GET /edge/status HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	var status workerStatusResponse
	if err := json.Unmarshal(respBody, &status); err != nil {
		return "", fmt.Errorf("decode worker status: %w", err)
	}
	return strings.ToLower(strings.TrimSpace(status.Action)), nil
}
