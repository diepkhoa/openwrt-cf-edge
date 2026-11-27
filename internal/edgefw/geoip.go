package edgefw

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/diepkhoa/openwrt-cf-edge/internal/config"
	"github.com/diepkhoa/openwrt-cf-edge/internal/reconcile"
)

const (
	defaultV4ZoneURLTpl = "https://www.ipdeny.com/ipblocks/data/countries/%s.zone"
	defaultV6ZoneURLTpl = "https://www.ipdeny.com/ipv6/ipaddresses/blocks/%s.zone"
	defaultCFPlainV4URL = "https://www.cloudflare.com/ips-v4"
	defaultCFPlainV6URL = "https://www.cloudflare.com/ips-v6"
	minCountryV4CIDRs   = 10
	minCountryV6CIDRs   = 5
	maxZoneBodyBytes    = 4 * 1024 * 1024
)

// GeoIPCache stores validated, merged IPv4 and IPv6 allowlist CIDRs on disk.
type GeoIPCache struct {
	FetchedAt         time.Time `json:"fetched_at"`
	Countries         []string  `json:"countries"`
	IncludeCloudflare bool      `json:"include_cloudflare"`
	AllowCIDRs        []string  `json:"allow_cidrs,omitempty"`
	IPv4CIDRs         []string  `json:"ipv4_cidrs"`
	IPv6CIDRs         []string  `json:"ipv6_cidrs"`
}

// Catalog fetches, validates, merges, and persists GeoIP and Cloudflare CIDR sets.
type Catalog struct {
	httpClient   *http.Client
	v4ZoneURLTpl string
	v6ZoneURLTpl string
	cfAPIURL     string
	cfPlainV4URL string
	cfPlainV6URL string
}

// NewCatalog builds a GeoIP Catalog with sensible defaults.
func NewCatalog(client *http.Client) *Catalog {
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	return &Catalog{
		httpClient:   client,
		v4ZoneURLTpl: defaultV4ZoneURLTpl,
		v6ZoneURLTpl: defaultV6ZoneURLTpl,
		cfAPIURL:     "",
		cfPlainV4URL: defaultCFPlainV4URL,
		cfPlainV6URL: defaultCFPlainV6URL,
	}
}

// EnsureSets returns cached CIDR sets if fresh and config-compatible, or refreshes from upstream sources.
// When refresh fails on an expired cache, the existing matching cache is returned alongside the refresh error.
func (c *Catalog) EnsureSets(ctx context.Context, cfg config.EdgeFirewallConfig, forceRefresh bool) (GeoIPCache, error) {
	cached, cacheErr := LoadGeoIPCache(cfg.CachePath)
	matches := cacheErr == nil && cacheMatchesConfig(cached, cfg)
	if !forceRefresh && matches && time.Since(cached.FetchedAt) < cfg.RefreshInterval.Std() {
		return cached, nil
	}

	fresh, err := c.Refresh(ctx, cfg)
	if err == nil {
		return fresh, nil
	}
	if matches && !forceRefresh && (len(cached.IPv4CIDRs) > 0 || len(cached.IPv6CIDRs) > 0) {
		return cached, fmt.Errorf("geoip refresh failed (using cached fallback): %w", err)
	}
	return GeoIPCache{}, err
}

// Refresh downloads all configured country zones and Cloudflare IP ranges, validates integrity, merges CIDRs, and saves cache.
func (c *Catalog) Refresh(ctx context.Context, cfg config.EdgeFirewallConfig) (GeoIPCache, error) {
	var rawAll []string
	rawAll = append(rawAll, cfg.AllowCIDRs...)

	for _, cc := range cfg.GeoIPCountries {
		v4Lines, err := c.fetchLines(ctx, fmt.Sprintf(c.v4ZoneURLTpl, cc))
		if err != nil {
			return GeoIPCache{}, fmt.Errorf("download %s IPv4 zone: %w", cc, err)
		}
		v4Raw, _ := parseFamilyCIDRs(v4Lines, false)
		if len(v4Raw) < minCountryV4CIDRs {
			return GeoIPCache{}, fmt.Errorf("%s IPv4 zone failed integrity check (%d CIDRs < %d)", cc, len(v4Raw), minCountryV4CIDRs)
		}

		v6Lines, err := c.fetchLines(ctx, fmt.Sprintf(c.v6ZoneURLTpl, cc))
		if err != nil {
			return GeoIPCache{}, fmt.Errorf("download %s IPv6 zone: %w", cc, err)
		}
		_, v6Raw := parseFamilyCIDRs(v6Lines, true)
		if len(v6Raw) < minCountryV6CIDRs {
			return GeoIPCache{}, fmt.Errorf("%s IPv6 zone failed integrity check (%d CIDRs < %d)", cc, len(v6Raw), minCountryV6CIDRs)
		}

		rawAll = append(rawAll, v4Raw...)
		rawAll = append(rawAll, v6Raw...)
	}

	if cfg.IncludeCloudflare {
		cfV4, cfV6 := c.fetchCloudflareWithFallback(ctx)
		rawAll = append(rawAll, cfV4...)
		rawAll = append(rawAll, cfV6...)
	}

	mergedV4, mergedV6, _ := SplitAndMergeCIDRs(rawAll)
	cache := GeoIPCache{
		FetchedAt:         time.Now().UTC(),
		Countries:         append([]string(nil), cfg.GeoIPCountries...),
		IncludeCloudflare: cfg.IncludeCloudflare,
		AllowCIDRs:        append([]string(nil), cfg.AllowCIDRs...),
		IPv4CIDRs:         mergedV4,
		IPv6CIDRs:         mergedV6,
	}
	if err := SaveGeoIPCache(cfg.CachePath, cache); err != nil {
		return GeoIPCache{}, err
	}
	return cache, nil
}

func (c *Catalog) fetchCloudflareWithFallback(ctx context.Context) ([]string, []string) {
	if v4, v6, err := reconcile.FetchCloudflareIPs(ctx, c.httpClient, c.cfAPIURL); err == nil && len(v4) >= 5 && len(v6) >= 3 {
		return v4, v6
	}
	if v4Lines, err4 := c.fetchLines(ctx, c.cfPlainV4URL); err4 == nil {
		if v6Lines, err6 := c.fetchLines(ctx, c.cfPlainV6URL); err6 == nil {
			v4, _, _ := SplitAndMergeCIDRs(v4Lines)
			_, v6, _ := SplitAndMergeCIDRs(v6Lines)
			if len(v4) >= 5 && len(v6) >= 3 {
				return v4, v6
			}
		}
	}
	return reconcile.StaticCloudflareCIDRs()
}

func (c *Catalog) fetchLines(ctx context.Context, url string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxZoneBodyBytes))
	if err != nil {
		return nil, err
	}
	return strings.Split(string(body), "\n"), nil
}

// LoadGeoIPCache reads and decodes the persisted GeoIP JSON cache.
func LoadGeoIPCache(path string) (GeoIPCache, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return GeoIPCache{}, err
	}
	var cache GeoIPCache
	if err := json.Unmarshal(data, &cache); err != nil {
		return GeoIPCache{}, fmt.Errorf("decode geoip cache %s: %w", path, err)
	}
	return cache, nil
}

// SaveGeoIPCache atomically writes the GeoIP cache file via temp file + rename.
func SaveGeoIPCache(path string, cache GeoIPCache) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create geoip cache dir: %w", err)
	}
	data, err := json.Marshal(cache)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".geoip-cache-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	_ = tmp.Chmod(0600)
	_ = tmp.Sync()
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func cacheMatchesConfig(cache GeoIPCache, cfg config.EdgeFirewallConfig) bool {
	if cache.IncludeCloudflare != cfg.IncludeCloudflare {
		return false
	}
	c1 := sortedCopy(cache.Countries)
	c2 := sortedCopy(cfg.GeoIPCountries)
	if !reflect.DeepEqual(c1, c2) {
		return false
	}
	a1 := sortedCopy(cache.AllowCIDRs)
	a2 := sortedCopy(cfg.AllowCIDRs)
	return reflect.DeepEqual(a1, a2)
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}
