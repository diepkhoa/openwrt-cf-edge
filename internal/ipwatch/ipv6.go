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
		if best := d.lookupNetlinkIPv6(ctx, l3Device); best != "" {
			return best, nil
		}
	}

	client := d.buildHTTPClient("tcp6", l3Device, probeTimeout)
	body, err := fetchText(ctx, client, d.ipifyV6URL)
	if err == nil {
		valid, ok := netutil.ParsePublicIPv6(body)
		if !ok {
			return "", fmt.Errorf("api64 fallback returned non-GUA IPv6 %q", strings.TrimSpace(body))
		}
		return valid, nil
	}

	// Prefix-Delegation setups may assign GUA only on lan_iface (e.g. br-lan) while pppoe-wan only holds link-local.
	if lanIface := strings.TrimSpace(d.cfg.WAN.LANIface); lanIface != "" && lanIface != l3Device {
		if best := d.lookupNetlinkIPv6(ctx, lanIface); best != "" {
			return best, nil
		}
	}
	return "", fmt.Errorf("ipv6 discovery failed on %q and fallback probe: %w", l3Device, err)
}

func (d *Discoverer) lookupNetlinkIPv6(ctx context.Context, iface string) string {
	addrs, err := d.net.GlobalIPv6Addrs(ctx, iface)
	if err != nil {
		return ""
	}
	return netutil.SelectBestIPv6(addrs)
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
