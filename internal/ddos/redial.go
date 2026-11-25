package ddos

import (
	"context"
	"time"

	"github.com/diepkhoa/openwrt-cf-edge/internal/state"
)

func (m *ShieldManager) consumeRedialQuota() (bool, int) {
	now := m.nowFn().UTC()
	cutoff := now.Add(-time.Hour)
	limit := m.cfg.DDoSShield.MaxRedialsPerHour
	if limit <= 0 {
		limit = 3
	}
	if m.store == nil {
		return true, 1
	}

	allowed := false
	recentCount := 0
	_ = m.store.Update(func(rt *state.RuntimeState) error {
		kept := rt.RedialHistory[:0]
		for _, ts := range rt.RedialHistory {
			if ts.After(cutoff) {
				kept = append(kept, ts)
			}
		}
		recentCount = len(kept)
		if recentCount < limit {
			kept = append(kept, now)
			recentCount = len(kept)
			allowed = true
		}
		rt.RedialHistory = kept
		return nil
	})
	return allowed, recentCount
}

func (m *ShieldManager) performRedial(ctx context.Context) string {
	if m.redialHook != nil {
		m.redialHook(true)
		defer m.redialHook(false)
	}

	_ = m.ubus.Down(ctx, m.cfg.WAN.IfaceV4)
	if m.cfg.WAN.IfaceV6 != "" {
		_ = m.ubus.Down(ctx, m.cfg.WAN.IfaceV6)
	}

	if !sleepCtx(ctx, m.brasFlushWait) {
		return "aborted during BRAS flush"
	}

	_ = m.ubus.Up(ctx, m.cfg.WAN.IfaceV4)
	if m.cfg.WAN.IfaceV6 != "" {
		_ = m.ubus.Up(ctx, m.cfg.WAN.IfaceV6)
	}

	deadline := m.nowFn().Add(m.reconnectMax)
	for m.nowFn().Before(deadline) {
		if ctx.Err() != nil {
			return "aborted waiting for reconnect"
		}
		if st, err := m.ubus.Status(ctx, m.cfg.WAN.IfaceV4); err == nil && st.Up && st.PrimaryIPv4() != "" {
			return "redialed & WAN online"
		}
		if !sleepCtx(ctx, m.reconnectPoll) {
			return "aborted waiting for reconnect"
		}
	}
	return "redialed (WAN reconnect 120s timeout)"
}

func (m *ShieldManager) shouldSendRateLimitNotice() bool {
	now := m.nowFn()
	if m.lastRateLimitAt.IsZero() || now.Sub(m.lastRateLimitAt) >= 10*time.Minute {
		m.lastRateLimitAt = now
		return true
	}
	return false
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
