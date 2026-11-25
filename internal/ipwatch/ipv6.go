package ipwatch

import (
	"context"
	"fmt"
	"strings"

	"github.com/diepkhoa/openwrt-cf-edge/internal/netutil"
)

// DiscoverIPv6 resolves the router's non-deprecated Global Unicast IPv6 address (2000::/3).
func (d *Discoverer) DiscoverIPv6(ctx context.Context) (string, error) {
	l3Device := d.resolveIPv6L3Device(ctx)

	if l3Device != "" {
		addrs, err := d.net.GlobalIPv6Addrs(ctx, l3Device)
		if err == nil {
			if best := netutil.SelectBestIPv6(addrs); best != "" {
				return best, nil
			}
		}
	}

	client := d.buildHTTPClient("tcp6", l3Device, probeTimeout)
	body, err := fetchText(ctx, client, d.ipifyV6URL)
	if err != nil {
		return "", fmt.Errorf("ipv6 discovery failed on %q and fallback probe: %w", l3Device, err)
	}
	valid, ok := netutil.ParsePublicIPv6(body)
	if !ok {
		return "", fmt.Errorf("api64 fallback returned non-GUA IPv6 %q", strings.TrimSpace(body))
	}
	return valid, nil
}

func (d *Discoverer) resolveIPv6L3Device(ctx context.Context) string {
	if d.cfg.WAN.IfaceV6 != "" {
		if st, err := d.ubus.Status(ctx, d.cfg.WAN.IfaceV6); err == nil {
			if dev := st.EffectiveL3Device(); dev != "" {
				return dev
			}
		}
	}
	if st, err := d.ubus.Status(ctx, d.cfg.WAN.IfaceV4); err == nil {
		if dev := st.EffectiveL3Device(); dev != "" {
			return dev
		}
	}
	if iface, _, err := d.net.DefaultRouteIPv4(ctx); err == nil {
		return iface
	}
	return ""
}
