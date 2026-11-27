package cloudflare

import (
	"context"

	"github.com/diepkhoa/openwrt-cf-edge/internal/ipwatch"
	"github.com/diepkhoa/openwrt-cf-edge/internal/notify"
	"github.com/diepkhoa/openwrt-cf-edge/internal/state"
)

func (u *Updater) flushDDNSNotification(ctx context.Context, snap ipwatch.Snapshot, updatedLabels []string) {
	st := u.store.Get()
	combined := deduplicateStrings(append(append([]string(nil), st.PendingNotify...), updatedLabels...))
	if len(combined) == 0 {
		return
	}

	ipv4 := snap.IPv4
	if ipv4 == "" {
		ipv4 = st.LastIPv4
	}
	ipv6 := snap.IPv6
	if ipv6 == "" {
		ipv6 = st.LastIPv6
	}

	msg := notify.FormatDDNSUpdate(u.cfg.NodeName, ipv4, ipv6, combined)
	if err := u.notifier.Send(ctx, msg); err != nil {
		u.logger.Warn("failed to send Telegram notification", "err", err)
		if saveErr := u.savePendingNotify(combined); saveErr != nil {
			u.logger.Error("failed to save pending notifications", "err", saveErr)
		}
		return
	}
	if len(st.PendingNotify) > 0 {
		_ = u.savePendingNotify(nil)
	}
}

func (u *Updater) savePendingNotify(labels []string) error {
	return u.store.Update(func(cur *state.RuntimeState) error {
		if len(labels) == 0 {
			cur.PendingNotify = nil
			return nil
		}
		cur.PendingNotify = append([]string(nil), labels...)
		return nil
	})
}

func deduplicateStrings(items []string) []string {
	seen := make(map[string]struct{}, len(items))
	out := make([]string, 0, len(items))
	for _, s := range items {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
