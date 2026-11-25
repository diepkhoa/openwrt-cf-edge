package ipwatch

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/diepkhoa/openwrt-cf-edge/internal/config"
	"github.com/diepkhoa/openwrt-cf-edge/internal/netutil"
	"github.com/diepkhoa/openwrt-cf-edge/internal/ubus"
)

const (
	defaultMaxAttempts = 6
	defaultRetryDelay  = 5 * time.Second
)

// Snapshot contains the discovered public WAN IPv4/IPv6 addresses.
type Snapshot struct {
	IPv4       string
	IPv6       string
	L3DeviceV4 string
}

// HTTPClientFactory constructs an HTTP client bound to a network family and L3 device.
type HTTPClientFactory func(network, l3Device string, timeout time.Duration) *http.Client

// Discoverer resolves the router's public WAN IPv4 and IPv6 addresses.
type Discoverer struct {
	cfg               *config.Config
	ubus              ubus.Client
	net               netutil.NetInspector
	logger            *slog.Logger
	traceURL          string
	ipifyV4URL        string
	ipifyV6URL        string
	maxAttempts       int
	retryDelay        time.Duration
	httpClientFactory HTTPClientFactory
}

// Option customizes a Discoverer instance.
type Option func(*Discoverer)

// WithProbeURLs overrides the HTTP fallback endpoints (used in unit tests).
func WithProbeURLs(traceURL, ipifyV4URL, ipifyV6URL string) Option {
	return func(d *Discoverer) {
		if traceURL != "" {
			d.traceURL = traceURL
		}
		if ipifyV4URL != "" {
			d.ipifyV4URL = ipifyV4URL
		}
		if ipifyV6URL != "" {
			d.ipifyV6URL = ipifyV6URL
		}
	}
}

// WithRetryPolicy overrides discovery attempts and delay (used in unit tests).
func WithRetryPolicy(attempts int, delay time.Duration) Option {
	return func(d *Discoverer) {
		if attempts > 0 {
			d.maxAttempts = attempts
		}
		if delay >= 0 {
			d.retryDelay = delay
		}
	}
}

// WithHTTPClientFactory overrides HTTP client construction (used in unit tests).
func WithHTTPClientFactory(fn HTTPClientFactory) Option {
	return func(d *Discoverer) {
		d.httpClientFactory = fn
	}
}

// NewDiscoverer constructs a Discoverer for the router's WAN interfaces.
func NewDiscoverer(cfg *config.Config, ubusClient ubus.Client, netInsp netutil.NetInspector, logger *slog.Logger, opts ...Option) *Discoverer {
	if logger == nil {
		logger = slog.Default()
	}
	d := &Discoverer{
		cfg:         cfg,
		ubus:        ubusClient,
		net:         netInsp,
		logger:      logger,
		traceURL:    defaultTraceURL,
		ipifyV4URL:  defaultIpifyV4URL,
		ipifyV6URL:  defaultIpifyV6URL,
		maxAttempts: defaultMaxAttempts,
		retryDelay:  defaultRetryDelay,
	}
	for _, opt := range opts {
		opt(d)
	}
	return d
}

// Discover resolves IPv4 and (when needed by config) IPv6 in parallel with retries.
func (d *Discoverer) Discover(ctx context.Context) (Snapshot, error) {
	needsV4 := d.needsIPv4()
	needsV6 := d.cfg.NeedsIPv6()

	var (
		wg   sync.WaitGroup
		snap Snapshot
		err4 error
		err6 error
	)

	if needsV4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err4 = d.retryLoop(ctx, "ipv4", func(attemptCtx context.Context) error {
				ip, l3, err := d.DiscoverIPv4(attemptCtx)
				if l3 != "" {
					snap.L3DeviceV4 = l3
				}
				if err != nil {
					return err
				}
				snap.IPv4 = ip
				return nil
			})
		}()
	}

	if needsV6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err6 = d.retryLoop(ctx, "ipv6", func(attemptCtx context.Context) error {
				ip, err := d.DiscoverIPv6(attemptCtx)
				if err != nil {
					return err
				}
				snap.IPv6 = ip
				return nil
			})
		}()
	}

	wg.Wait()
	if ctx.Err() != nil {
		return snap, ctx.Err()
	}
	if snap.IPv4 == "" && snap.IPv6 == "" {
		return snap, errors.Join(err4, err6)
	}
	if err4 != nil {
		d.logger.Warn("IPv4 discovery exhausted retries", "err", err4)
	}
	if err6 != nil {
		d.logger.Warn("IPv6 discovery exhausted retries", "err", err6)
	}
	return snap, nil
}

func (d *Discoverer) needsIPv4() bool {
	for _, r := range d.cfg.Cloudflare.Records {
		if r.IPv4 {
			return true
		}
	}
	return false
}

func (d *Discoverer) retryLoop(ctx context.Context, family string, fn func(context.Context) error) error {
	var lastErr error
	for attempt := 1; attempt <= d.maxAttempts; attempt++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := fn(ctx); err == nil {
			return nil
		} else {
			lastErr = err
		}
		if attempt == d.maxAttempts {
			break
		}
		d.logger.Debug("ip discovery retry scheduled", "family", family, "attempt", attempt, "err", lastErr)
		if d.retryDelay > 0 {
			timer := time.NewTimer(d.retryDelay)
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
