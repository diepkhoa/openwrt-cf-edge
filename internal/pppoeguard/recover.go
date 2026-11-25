package pppoeguard

import (
	"context"
	"time"

	"github.com/diepkhoa/openwrt-cf-edge/internal/notify"
	"github.com/diepkhoa/openwrt-cf-edge/internal/state"
	"github.com/diepkhoa/openwrt-cf-edge/internal/ubus"
)

func (g *Guard) recoverLoop(ctx context.Context, events <-chan ubus.Event) {
	g.recordStatus("recovering", "initial_wait")
	if g.initialWait > 0 {
		if recovered := g.waitForHealthyOrTimer(ctx, g.initialWait, events); recovered || ctx.Err() != nil {
			if recovered {
				g.recordStatus("healthy", "auto_recovered")
			}
			return
		}
	}

	pendingCycles := 0
	intervened := false

	for attempt := 1; ; attempt++ {
		if ctx.Err() != nil {
			return
		}
		if g.externalRedial.Load() {
			if !sleepCtx(ctx, 5*time.Second) {
				return
			}
			continue
		}

		report := g.health.Check(ctx)
		if ctx.Err() != nil {
			return
		}
		if report.IsHealthy() {
			g.recordStatus("healthy", "recovered")
			if intervened && g.notifier != nil {
				msg := notify.FormatPPPoEAction(g.cfg.NodeName, "WAN Recovered", "PPPoE is healthy again with IP "+report.IPv4)
				_ = g.notifier.Send(ctx, msg)
			}
			return
		}

		if !report.Pending {
			pendingCycles = 0
			intervened = true
			g.logger.Warn("WAN down with pending=false (likely AUTH_FAILED/block_restart), cycling interface")
			g.cycleInterface(ctx, g.authDownWait, "auth_failed_redial")
		} else {
			pendingCycles++
			if pendingCycles > maxPendingCycles {
				pendingCycles = 0
				intervened = true
				g.logger.Warn("WAN stuck pending > 3 cycles, forcing interface reset")
				g.cycleInterface(ctx, g.pendingDownWait, "stuck_pending_redial")
			} else {
				g.recordStatus("pending", "waiting_pppd")
			}
		}

		waitDur := g.fastInterval
		if attempt > 5 {
			waitDur = g.slowInterval
		}
		if recovered := g.waitForHealthyOrTimer(ctx, waitDur, events); recovered || ctx.Err() != nil {
			if recovered {
				g.recordStatus("healthy", "recovered")
				if intervened && g.notifier != nil {
					rep := g.health.Check(ctx)
					msg := notify.FormatPPPoEAction(g.cfg.NodeName, "WAN Recovered", "PPPoE is healthy again with IP "+rep.IPv4)
					_ = g.notifier.Send(ctx, msg)
				}
			}
			return
		}
	}
}

func (g *Guard) cycleInterface(ctx context.Context, downWait time.Duration, actionLabel string) {
	iface := g.cfg.WAN.IfaceV4
	g.recordRedial(actionLabel)
	if err := g.ubus.Down(ctx, iface); err != nil && ctx.Err() == nil {
		g.logger.Warn("ubus down failed", "iface", iface, "err", err)
	}
	if !sleepCtx(ctx, downWait) {
		return
	}
	if err := g.ubus.Up(ctx, iface); err != nil && ctx.Err() == nil {
		g.logger.Warn("ubus up failed", "iface", iface, "err", err)
	}
	if g.notifier != nil {
		msg := notify.FormatPPPoEAction(g.cfg.NodeName, actionLabel, "Cycled "+iface+" via ubus down/up")
		_ = g.notifier.Send(ctx, msg)
	}
}

func (g *Guard) waitForHealthyOrTimer(ctx context.Context, d time.Duration, events <-chan ubus.Event) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-timer.C:
			return false
		case ev, ok := <-events:
			if !ok {
				return false
			}
			if ev.Interface == g.cfg.WAN.IfaceV4 && ev.Action == "ifup" && !g.externalRedial.Load() {
				if g.health.Check(ctx).IsHealthy() {
					return true
				}
			}
		}
	}
}

func (g *Guard) waitDrainEvents(ctx context.Context, d time.Duration, events <-chan ubus.Event) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-timer.C:
			return true
		case _, ok := <-events:
			if !ok {
				return false
			}
		}
	}
}

func (g *Guard) recordStatus(st, action string) {
	if g.store == nil {
		return
	}
	_ = g.store.Update(func(rt *state.RuntimeState) error {
		if rt.PPPoEStatus == nil {
			rt.PPPoEStatus = &state.PPPoERuntimeInfo{}
		}
		rt.PPPoEStatus.State = st
		rt.PPPoEStatus.LastCheck = time.Now().UTC()
		if action != "" {
			rt.PPPoEStatus.LastAction = action
		}
		return nil
	})
}

func (g *Guard) recordRedial(action string) {
	if g.store == nil {
		return
	}
	_ = g.store.Update(func(rt *state.RuntimeState) error {
		if rt.PPPoEStatus == nil {
			rt.PPPoEStatus = &state.PPPoERuntimeInfo{}
		}
		rt.PPPoEStatus.State = "redialing"
		rt.PPPoEStatus.LastCheck = time.Now().UTC()
		rt.PPPoEStatus.LastAction = action
		rt.PPPoEStatus.RedialCount++
		return nil
	})
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
