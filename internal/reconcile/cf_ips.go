package reconcile

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/diepkhoa/openwrt-cf-edge/internal/netutil"
	"github.com/diepkhoa/openwrt-cf-edge/internal/state"
)

const (
	defaultCFIPsURL = "https://api.cloudflare.com/client/v4/ips"
	cfIPCacheTTL    = 24 * time.Hour
)

var staticCloudflareCIDRs = []string{
	"173.245.48.0/20",
	"103.21.244.0/22",
	"103.22.200.0/22",
	"103.31.4.0/22",
	"141.101.64.0/18",
	"108.162.192.0/18",
	"190.93.240.0/20",
	"188.114.96.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
	"162.158.0.0/15",
	"104.16.0.0/13",
	"104.24.0.0/14",
	"172.64.0.0/13",
	"131.0.72.0/22",
	"2400:cb00::/32",
	"2606:4700::/32",
	"2803:f800::/32",
	"2405:b500::/32",
	"2405:8100::/32",
	"2a06:98c0::/29",
	"2c0f:f248::/32",
}

// CFProxyCatalog detects whether an IP belongs to Cloudflare's Proxy edge ranges.
type CFProxyCatalog struct {
	store      *state.Store
	ipsURL     string
	httpClient *http.Client
	mu         sync.Mutex
	prefixes   []netip.Prefix
	loadedAt   time.Time
}

// NewCFProxyCatalog constructs a CFProxyCatalog backed by state cache and static fallback.
func NewCFProxyCatalog(store *state.Store, ipsURL string) *CFProxyCatalog {
	if ipsURL == "" {
		ipsURL = defaultCFIPsURL
	}
	return &CFProxyCatalog{
		store:  store,
		ipsURL: ipsURL,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// IsProxyIP returns true if ip matches Cloudflare's cached or fallback Proxy CIDR ranges.
func (c *CFProxyCatalog) IsProxyIP(ctx context.Context, ip netip.Addr) bool {
	prefixes := c.getPrefixes(ctx)
	return netutil.ContainsIP(prefixes, ip)
}

func (c *CFProxyCatalog) getPrefixes(ctx context.Context) []netip.Prefix {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.prefixes) > 0 && time.Since(c.loadedAt) < cfIPCacheTTL {
		return c.prefixes
	}

	if c.store != nil {
		if cached := c.store.Get().CFProxyCache; cached != nil && time.Since(cached.FetchedAt) < cfIPCacheTTL {
			combined := append(append([]string(nil), cached.IPv4CIDRs...), cached.IPv6CIDRs...)
			if parsed := netutil.ParseCIDRs(combined); len(parsed) > 0 {
				c.prefixes = parsed
				c.loadedAt = cached.FetchedAt
				return c.prefixes
			}
		}
	}

	v4, v6, err := c.fetchCloudflareIPs(ctx)
	if err == nil && (len(v4) > 0 || len(v6) > 0) {
		now := time.Now().UTC()
		if c.store != nil {
			_ = c.store.Update(func(st *state.RuntimeState) error {
				st.CFProxyCache = &state.CFProxyIPCache{
					IPv4CIDRs: v4,
					IPv6CIDRs: v6,
					FetchedAt: now,
				}
				return nil
			})
		}
		combined := append(append([]string(nil), v4...), v6...)
		c.prefixes = netutil.ParseCIDRs(combined)
		c.loadedAt = now
		return c.prefixes
	}

	// Fallback to expired cache if available, otherwise static CIDRs.
	if c.store != nil {
		if cached := c.store.Get().CFProxyCache; cached != nil {
			combined := append(append([]string(nil), cached.IPv4CIDRs...), cached.IPv6CIDRs...)
			if parsed := netutil.ParseCIDRs(combined); len(parsed) > 0 {
				c.prefixes = parsed
				c.loadedAt = time.Now().Add(-cfIPCacheTTL + 5*time.Minute)
				return c.prefixes
			}
		}
	}
	c.prefixes = netutil.ParseCIDRs(staticCloudflareCIDRs)
	c.loadedAt = time.Now().Add(-cfIPCacheTTL + 5*time.Minute)
	return c.prefixes
}

// StaticCloudflareCIDRs returns copies of the built-in Cloudflare IPv4 and IPv6 CIDR lists.
func StaticCloudflareCIDRs() (v4 []string, v6 []string) {
	for _, raw := range staticCloudflareCIDRs {
		if stringsContainsColon(raw) {
			v6 = append(v6, raw)
		} else {
			v4 = append(v4, raw)
		}
	}
	return v4, v6
}

func stringsContainsColon(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			return true
		}
	}
	return false
}

// FetchCloudflareIPs retrieves official Cloudflare IPv4 and IPv6 CIDR ranges from Cloudflare's API.
func FetchCloudflareIPs(ctx context.Context, client *http.Client, ipsURL string) ([]string, []string, error) {
	if ipsURL == "" {
		ipsURL = defaultCFIPsURL
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ipsURL, nil)
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, io.ErrUnexpectedEOF
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
	if err != nil {
		return nil, nil, err
	}
	var payload struct {
		Success bool `json:"success"`
		Result  struct {
			IPv4CIDRs []string `json:"ipv4_cidrs"`
			IPv6CIDRs []string `yaml:"ipv6_cidrs" json:"ipv6_cidrs"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &payload); err != nil || !payload.Success {
		return nil, nil, io.ErrUnexpectedEOF
	}
	return payload.Result.IPv4CIDRs, payload.Result.IPv6CIDRs, nil
}

func (c *CFProxyCatalog) fetchCloudflareIPs(ctx context.Context) ([]string, []string, error) {
	return FetchCloudflareIPs(ctx, c.httpClient, c.ipsURL)
}
