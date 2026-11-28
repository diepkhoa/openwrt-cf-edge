package ipwatch

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/diepkhoa/openwrt-cf-edge/internal/netutil"
)

const (
	defaultTraceURL   = "https://1.1.1.1/cdn-cgi/trace"
	defaultIpifyV4URL = "https://api.ipify.org"
	defaultIpifyV6URL = "https://api64.ipify.org"
	probeTimeout      = 3 * time.Second
)

// DiscoverIPv4 resolves the router's public WAN IPv4 address and L3 device name.
// It never returns a private or CGNAT address.
func (d *Discoverer) DiscoverIPv4(ctx context.Context) (ip string, l3Device string, err error) {
	candidate := ""
	if d.ubus != nil {
		if st, ubusErr := d.ubus.Status(ctx, d.cfg.WAN.IfaceV4); ubusErr == nil {
			l3Device = st.EffectiveL3Device()
			candidate = st.PrimaryIPv4()
		}
	}

	if candidate == "" {
		routeIface, routeIP, routeErr := d.net.DefaultRouteIPv4(ctx)
		if routeErr == nil {
			if l3Device == "" {
				l3Device = routeIface
			}
			candidate = routeIP
		}
	}
	if l3Device == "" && d.cfg.WAN.WANDeviceV4 != "" {
		l3Device = d.cfg.WAN.WANDeviceV4
	}

	if candidate == "" {
		return "", l3Device, errors.New("no WAN IPv4 candidate found via ubus or default route")
	}

	addr, parseErr := netip.ParseAddr(strings.TrimSpace(candidate))
	if parseErr != nil || !addr.Is4() {
		return "", l3Device, fmt.Errorf("invalid IPv4 candidate %q", candidate)
	}

	if !netutil.IsPrivateOrSpecialIPv4(addr) {
		return addr.String(), l3Device, nil
	}

	// Behind NAT/CGNAT: probe public IPv4 over WAN device.
	pubIP, probeErr := d.probePublicIPv4(ctx, l3Device)
	if probeErr != nil {
		return "", l3Device, fmt.Errorf("behind NAT (%s), public IPv4 probe failed: %w", addr.String(), probeErr)
	}
	return pubIP, l3Device, nil
}

func (d *Discoverer) probePublicIPv4(ctx context.Context, l3Device string) (string, error) {
	client := d.buildHTTPClient("tcp4", l3Device, probeTimeout)

	if body, err := fetchText(ctx, client, d.traceURL); err == nil {
		if ip := parseCloudflareTraceIP(body); ip != "" {
			if valid, ok := netutil.ParsePublicIPv4(ip); ok {
				return valid, nil
			}
		}
	}

	body, err := fetchText(ctx, client, d.ipifyV4URL)
	if err != nil {
		return "", err
	}
	valid, ok := netutil.ParsePublicIPv4(body)
	if !ok {
		return "", fmt.Errorf("ipify returned non-public IPv4 %q", strings.TrimSpace(body))
	}
	return valid, nil
}

func parseCloudflareTraceIP(body string) string {
	scanner := bufio.NewScanner(strings.NewReader(body))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if val, ok := strings.CutPrefix(line, "ip="); ok {
			return strings.TrimSpace(val)
		}
	}
	return ""
}

func (d *Discoverer) buildHTTPClient(network, l3Device string, timeout time.Duration) *http.Client {
	if d.httpClientFactory != nil {
		return d.httpClientFactory(network, l3Device, timeout)
	}
	dialer := &net.Dialer{
		Timeout: timeout,
		Control: netutil.BindDeviceControl(l3Device),
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr)
		},
		DisableKeepAlives: true,
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}
}

func fetchText(ctx context.Context, client *http.Client, rawURL string) (string, error) {
	reqCtx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d from %s", resp.StatusCode, rawURL)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8*1024))
	if err != nil {
		return "", err
	}
	return string(data), nil
}
