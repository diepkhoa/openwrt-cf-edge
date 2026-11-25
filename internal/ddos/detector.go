package ddos

import (
	"context"
	"fmt"
	"time"

	"github.com/diepkhoa/openwrt-cf-edge/internal/state"
)

// Run supervises DDoS detection and persistent shield recovery across reboots.
func (m *ShieldManager) Run(ctx context.Context) {
	if !m.cfg.DDoSShield.Enabled && !state.IsShielded(m.shieldLockPath) {
		return
	}

	if state.IsShielded(m.shieldLockPath) {
		m.logger.Warn("persistent shield.lock detected at startup, re-applying firewall block")
		m.ensureFirewall(ctx)
	}

	var (
		prevSample  RawCounters
		breachStart time.Time
		lastPollAt  time.Time
	)

	tickDur := m.cfg.DDoSShield.CheckInterval.Std()
	if tickDur <= 0 {
		tickDur = 5 * time.Second
	}
	ticker := time.NewTicker(tickDur)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if state.IsShielded(m.shieldLockPath) {
				prevSample = RawCounters{}
				breachStart = time.Time{}
				m.handleShieldedTick(ctx, &lastPollAt)
				continue
			}

			if !m.cfg.DDoSShield.Enabled {
				continue
			}
			lastPollAt = time.Time{}

			wanDevs := m.resolveWANDevices(ctx)
			if len(wanDevs) == 0 {
				prevSample = RawCounters{}
				breachStart = time.Time{}
				continue
			}

			cur, err := m.reader.Read(wanDevs[0], m.cfg.WAN.OverlayIface, m.cfg.WAN.LANIface)
			if err != nil {
				m.logger.Debug("failed reading ddos metrics", "err", err)
				prevSample = RawCounters{}
				breachStart = time.Time{}
				continue
			}

			rates := ComputeRates(prevSample, cur)
			prevSample = cur

			reason := m.evaluateBreach(ctx, wanDevs[0], rates)
			if reason == "" {
				breachStart = time.Time{}
				continue
			}
			if breachStart.IsZero() {
				breachStart = m.nowFn()
				m.logger.Warn("DDoS threshold breached, starting sustain timer", "reason", reason)
				continue
			}
			if m.nowFn().Sub(breachStart) >= m.cfg.DDoSShield.SustainDuration.Std() {
				breachStart = time.Time{}
				prevSample = RawCounters{}
				if err := m.EnterShield(ctx, reason, EnterOptions{}); err != nil {
					m.logger.Error("EnterShield failed", "err", err)
				} else {
					lastPollAt = m.nowFn()
				}
			}
		}
	}
}

func (m *ShieldManager) handleShieldedTick(ctx context.Context, lastPollAt *time.Time) {
	m.ensureFirewall(ctx)

	pollInterval := m.cfg.DDoSShield.StatusPollInterval.Std()
	if pollInterval <= 0 {
		pollInterval = 2 * time.Minute
	}
	if m.worker == nil || m.cfg.DDoSShield.WorkerURL == "" {
		return
	}
	if !lastPollAt.IsZero() && m.nowFn().Sub(*lastPollAt) < pollInterval {
		return
	}

	*lastPollAt = m.nowFn()
	action, err := m.worker.PollStatus(ctx)
	if err != nil {
		m.logger.Warn("worker /edge/status poll failed", "err", err)
		return
	}
	if action == "resume" {
		m.logger.Info("worker instructed action=resume, exiting shield mode")
		if exitErr := m.ExitShield(ctx, true); exitErr != nil {
			m.logger.Error("exit shield failed", "err", exitErr)
		}
	}
}

func (m *ShieldManager) evaluateBreach(ctx context.Context, wanL3 string, rates RateSnapshot) string {
	if rates.Conntrack > m.cfg.DDoSShield.ConntrackThreshold {
		return fmt.Sprintf("conntrack=%d > %d", rates.Conntrack, m.cfg.DDoSShield.ConntrackThreshold)
	}
	if !rates.Valid || rates.JunkMbps <= m.cfg.DDoSShield.JunkMbpsThreshold {
		return ""
	}
	if rates.RXPPS > m.cfg.DDoSShield.RXPPSThreshold {
		return fmt.Sprintf("junk=%.1fMbps rx_pps=%.0f > %.0f", rates.JunkMbps, rates.RXPPS, m.cfg.DDoSShield.RXPPSThreshold)
	}
	if m.allPingsFail(ctx, wanL3) {
		return fmt.Sprintf("junk=%.1fMbps + ping_loss", rates.JunkMbps)
	}
	return ""
}

func (m *ShieldManager) allPingsFail(ctx context.Context, wanL3 string) bool {
	if m.pinger == nil {
		return false
	}
	targets := m.cfg.PPPoEGuard.PingTargets
	if len(targets) == 0 {
		targets = []string{"1.1.1.1", "8.8.8.8"}
	}
	for _, target := range targets {
		if err := m.pinger.Ping(ctx, target, wanL3, defaultPingTimeout); err == nil {
			return false
		}
	}
	return true
}

func (m *ShieldManager) ensureFirewall(ctx context.Context) {
	active, _ := m.firewall.IsActive(ctx)
	if active {
		return
	}
	if err := m.firewall.ApplyShield(ctx, m.resolveWANDevices(ctx), m.cfg.DDoSShield.WANIngressPort); err != nil {
		m.logger.Warn("failed ensuring nft shield rule", "err", err)
	}
}

func (m *ShieldManager) resolveWANDevices(ctx context.Context) []string {
	var devs []string
	addIfValid := func(dev string) {
		if dev != "" && dev != m.cfg.WAN.OverlayIface && dev != m.cfg.WAN.LANIface && dev != "lo" {
			devs = append(devs, dev)
		}
	}

	if st, err := m.ubus.Status(ctx, m.cfg.WAN.IfaceV4); err == nil {
		addIfValid(st.EffectiveL3Device())
		addIfValid(st.Device)
	}
	if m.cfg.WAN.IfaceV6 != "" {
		if st6, err := m.ubus.Status(ctx, m.cfg.WAN.IfaceV6); err == nil {
			addIfValid(st6.EffectiveL3Device())
			addIfValid(st6.Device)
		}
	}
	if len(devs) == 0 {
		devs = append(devs, "pppoe-"+m.cfg.WAN.IfaceV4)
	}
	return normalizeIfaces(devs)
}
