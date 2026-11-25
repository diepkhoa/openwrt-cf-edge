package pppoeguard

import (
	"context"
	"time"

	"github.com/diepkhoa/openwrt-cf-edge/internal/config"
	"github.com/diepkhoa/openwrt-cf-edge/internal/netutil"
	"github.com/diepkhoa/openwrt-cf-edge/internal/ubus"
)

const defaultPingTimeout = 2 * time.Second

// HealthReport captures the result of inspecting WAN PPPoE status and ICMP reachability.
type HealthReport struct {
	Up        bool
	Pending   bool
	L3Device  string
	IPv4      string
	Reachable bool
	Err       error
}

// IsHealthy returns true when WAN is up, has an IPv4 address, and passed at least one ping target.
func (h HealthReport) IsHealthy() bool {
	return h.Up && h.IPv4 != "" && h.L3Device != "" && h.Reachable
}

// HealthChecker verifies WAN interface readiness and external ICMP reachability via l3_device.
type HealthChecker struct {
	cfg    *config.Config
	ubus   ubus.Client
	pinger netutil.Pinger
}

// NewHealthChecker constructs a HealthChecker.
func NewHealthChecker(cfg *config.Config, ubusClient ubus.Client, pinger netutil.Pinger) *HealthChecker {
	return &HealthChecker{
		cfg:    cfg,
		ubus:   ubusClient,
		pinger: pinger,
	}
}

// Check queries ubus status for iface_v4 and pings ping_targets bound to l3_device.
func (hc *HealthChecker) Check(ctx context.Context) HealthReport {
	st, err := hc.ubus.Status(ctx, hc.cfg.WAN.IfaceV4)
	if err != nil {
		return HealthReport{Err: err}
	}

	report := HealthReport{
		Up:       st.Up,
		Pending:  st.Pending,
		L3Device: st.EffectiveL3Device(),
		IPv4:     st.PrimaryIPv4(),
	}
	if !report.Up || report.IPv4 == "" || report.L3Device == "" {
		return report
	}

	for _, target := range hc.cfg.PPPoEGuard.PingTargets {
		if ctx.Err() != nil {
			report.Err = ctx.Err()
			return report
		}
		if err := hc.pinger.Ping(ctx, target, report.L3Device, defaultPingTimeout); err == nil {
			report.Reachable = true
			return report
		}
	}
	return report
}
