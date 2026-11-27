package edgefw

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/diepkhoa/openwrt-cf-edge/internal/config"
	"github.com/diepkhoa/openwrt-cf-edge/internal/reconcile"
)

const probeTimeout = 3 * time.Second

// Baseline records pre-apply connectivity so post-apply checks only fail on newly broken paths.
type Baseline struct {
	TCPHealthy      bool
	UDPHealthy      bool
	InternalHealthy map[string]bool
}

// HealthChecker probes outbound TCP, outbound UDP, and internal targets before and after applying nftables rules.
type HealthChecker interface {
	SnapshotBaseline(ctx context.Context, cfg config.EdgeFirewallConfig) Baseline
	Verify(ctx context.Context, cfg config.EdgeFirewallConfig, base Baseline) error
}

// ConnectivityProber executes real TCP dials and direct DNS UDP round-trip queries.
type ConnectivityProber struct {
	tcpDial  func(ctx context.Context, addr string) error
	udpProbe func(ctx context.Context, addr string) error
}

// NewConnectivityProber constructs a default ConnectivityProber.
func NewConnectivityProber() *ConnectivityProber {
	return &ConnectivityProber{
		tcpDial: func(ctx context.Context, addr string) error {
			dialer := net.Dialer{Timeout: probeTimeout}
			conn, err := dialer.DialContext(ctx, "tcp", addr)
			if err != nil {
				return err
			}
			_ = conn.Close()
			return nil
		},
		udpProbe: func(ctx context.Context, addr string) error {
			res := reconcile.NewDirectResolver([]string{addr}, probeTimeout).Query(ctx, "cloudflare.com", "A")
			if res.Outcome == reconcile.OutcomeNetError {
				if res.Err != nil {
					return res.Err
				}
				return fmt.Errorf("udp dns net error to %s", addr)
			}
			return nil
		},
	}
}

// SnapshotBaseline measures current TCP, UDP, and internal connectivity prior to modifying nftables.
func (p *ConnectivityProber) SnapshotBaseline(ctx context.Context, cfg config.EdgeFirewallConfig) Baseline {
	base := Baseline{
		TCPHealthy:      p.anyPass(ctx, cfg.HealthCheckTCP, p.tcpDial),
		UDPHealthy:      p.anyPass(ctx, cfg.HealthCheckUDP, p.udpProbe),
		InternalHealthy: make(map[string]bool, len(cfg.HealthCheckInternalTCP)),
	}
	for _, target := range cfg.HealthCheckInternalTCP {
		if p.tcpDial(ctx, target) == nil {
			base.InternalHealthy[target] = true
		}
	}
	return base
}

// Verify re-tests all paths that were healthy in baseline after applying firewall rules.
func (p *ConnectivityProber) Verify(ctx context.Context, cfg config.EdgeFirewallConfig, base Baseline) error {
	var failures []string

	if base.TCPHealthy && !p.anyPassWithRetry(ctx, cfg.HealthCheckTCP, p.tcpDial) {
		failures = append(failures, fmt.Sprintf("outbound TCP (%s)", strings.Join(cfg.HealthCheckTCP, ", ")))
	}
	if base.UDPHealthy && !p.anyPassWithRetry(ctx, cfg.HealthCheckUDP, p.udpProbe) {
		failures = append(failures, fmt.Sprintf("outbound UDP (%s)", strings.Join(cfg.HealthCheckUDP, ", ")))
	}
	for target, wasOK := range base.InternalHealthy {
		if !wasOK {
			continue
		}
		if !p.anyPassWithRetry(ctx, []string{target}, p.tcpDial) {
			failures = append(failures, fmt.Sprintf("internal TCP (%s)", target))
		}
	}

	if len(failures) > 0 {
		return fmt.Errorf("post-apply connectivity regression detected: %s", strings.Join(failures, "; "))
	}
	return nil
}

func (p *ConnectivityProber) anyPassWithRetry(ctx context.Context, targets []string, fn func(context.Context, string) error) bool {
	if p.anyPass(ctx, targets, fn) {
		return true
	}
	select {
	case <-ctx.Done():
		return false
	case <-time.After(400 * time.Millisecond):
	}
	return p.anyPass(ctx, targets, fn)
}

func (p *ConnectivityProber) anyPass(ctx context.Context, targets []string, fn func(context.Context, string) error) bool {
	for _, t := range targets {
		if ctx.Err() != nil {
			return false
		}
		if fn(ctx, t) == nil {
			return true
		}
	}
	return false
}
