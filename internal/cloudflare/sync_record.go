package cloudflare

import (
	"context"
	"strings"
	"time"

	"github.com/diepkhoa/openwrt-cf-edge/internal/ipwatch"
	"github.com/diepkhoa/openwrt-cf-edge/internal/state"
)

func (u *Updater) syncTask(ctx context.Context, st *state.RuntimeState, task syncTask, force bool) (changed bool, dirty bool, err error) {
	key := state.RecordKey(task.Record.Subdomain, task.Type)
	cached := st.Records[key]
	recordID := cached.RecordID

	if !force && recordID != "" && cached.IP == task.TargetIP && cached.Proxied == task.Record.Proxied {
		return false, false, nil
	}

	if recordID == "" || force {
		listed, listErr := retryValue(ctx, u.apiRetries, u.apiRetryDelay, func(callCtx context.Context) ([]DNSRecord, error) {
			return u.api.ListRecords(callCtx, u.cfg.Cloudflare.ZoneID, task.Type, task.Record.Subdomain)
		})
		if listErr != nil {
			return false, false, listErr
		}

		matched, keepForUpdate, staleIDs := classifyRecords(listed, task.TargetIP)
		for _, delID := range staleIDs {
			if delErr := u.withAPIRetryNoVal(ctx, func(callCtx context.Context) error {
				return u.api.DeleteRecord(callCtx, u.cfg.Cloudflare.ZoneID, delID)
			}); delErr != nil {
				u.logger.Warn("failed to delete duplicate/stale DNS record", "id", delID, "err", delErr)
			}
		}

		if matched != nil {
			recordID = matched.ID
			st.Records[key] = state.RecordState{
				RecordID:  matched.ID,
				Subdomain: task.Record.Subdomain,
				Type:      task.Type,
				IP:        task.TargetIP,
				Proxied:   matched.Proxied,
				UpdatedAt: time.Now().UTC(),
			}
			dirty = true
			if matched.Proxied == task.Record.Proxied {
				return len(staleIDs) > 0, dirty, nil
			}
		} else {
			recordID = keepForUpdate
		}
	}

	desired := DNSRecord{
		Type:    task.Type,
		Name:    task.Record.Subdomain,
		Content: task.TargetIP,
		TTL:     defaultTTL,
		Proxied: task.Record.Proxied,
	}

	if recordID != "" {
		updated, putErr := retryValue(ctx, u.apiRetries, u.apiRetryDelay, func(callCtx context.Context) (DNSRecord, error) {
			return u.api.UpdateRecord(callCtx, u.cfg.Cloudflare.ZoneID, recordID, desired)
		})
		if putErr == nil {
			st.Records[key] = state.RecordState{
				RecordID:  updated.ID,
				Subdomain: task.Record.Subdomain,
				Type:      task.Type,
				IP:        task.TargetIP,
				Proxied:   task.Record.Proxied,
				UpdatedAt: time.Now().UTC(),
			}
			return true, true, nil
		}
		if !IsNotFoundError(putErr) {
			return false, dirty, putErr
		}
		u.logger.Info("cached record_id missing on Cloudflare, recreating via POST", "subdomain", task.Record.Subdomain, "old_id", recordID)
		delete(st.Records, key)
		dirty = true
	}

	created, postErr := retryValue(ctx, u.apiRetries, u.apiRetryDelay, func(callCtx context.Context) (DNSRecord, error) {
		return u.api.CreateRecord(callCtx, u.cfg.Cloudflare.ZoneID, desired)
	})
	if postErr != nil {
		return false, dirty, postErr
	}
	st.Records[key] = state.RecordState{
		RecordID:  created.ID,
		Subdomain: task.Record.Subdomain,
		Type:      task.Type,
		IP:        task.TargetIP,
		Proxied:   task.Record.Proxied,
		UpdatedAt: time.Now().UTC(),
	}
	return true, true, nil
}

func classifyRecords(records []DNSRecord, targetIP string) (matched *DNSRecord, keepForUpdate string, deleteIDs []string) {
	for i := range records {
		if records[i].Content == targetIP && matched == nil {
			matched = &records[i]
			continue
		}
		if matched == nil && keepForUpdate == "" {
			keepForUpdate = records[i].ID
			continue
		}
		deleteIDs = append(deleteIDs, records[i].ID)
	}
	if matched != nil && keepForUpdate != "" {
		deleteIDs = append(deleteIDs, keepForUpdate)
		keepForUpdate = ""
	}
	return matched, keepForUpdate, deleteIDs
}

func (u *Updater) withAPIRetryNoVal(ctx context.Context, fn func(context.Context) error) error {
	_, err := retryValue(ctx, u.apiRetries, u.apiRetryDelay, func(c context.Context) (struct{}, error) {
		return struct{}{}, fn(c)
	})
	return err
}

func retryValue[T any](ctx context.Context, maxRetries int, delay time.Duration, fn func(context.Context) (T, error)) (T, error) {
	var zero T
	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if ctx.Err() != nil {
			return zero, ctx.Err()
		}
		val, err := fn(ctx)
		if err == nil {
			return val, nil
		}
		lastErr = err
		if !IsRetryableError(err) || attempt == maxRetries {
			return zero, err
		}
		if delay > 0 {
			if sleepErr := sleepCtx(ctx, delay); sleepErr != nil {
				return zero, sleepErr
			}
		}
	}
	return zero, lastErr
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (u *Updater) buildTasks(snap ipwatch.Snapshot, filterSubdomains []string) []syncTask {
	var filter map[string]struct{}
	if len(filterSubdomains) > 0 {
		filter = make(map[string]struct{}, len(filterSubdomains))
		for _, sub := range filterSubdomains {
			filter[strings.ToLower(strings.TrimSpace(sub))] = struct{}{}
		}
	}

	var tasks []syncTask
	for _, rec := range u.cfg.Cloudflare.Records {
		if filter != nil {
			if _, ok := filter[strings.ToLower(rec.Subdomain)]; !ok {
				continue
			}
		}
		if rec.IPv4 && snap.IPv4 != "" {
			tasks = append(tasks, syncTask{Record: rec, Type: "A", TargetIP: snap.IPv4})
		}
		if rec.IPv6 && snap.IPv6 != "" {
			tasks = append(tasks, syncTask{Record: rec, Type: "AAAA", TargetIP: snap.IPv6})
		}
	}
	return tasks
}

func (u *Updater) allTasksSynced(st state.RuntimeState, tasks []syncTask) bool {
	for _, task := range tasks {
		entry, ok := st.Records[state.RecordKey(task.Record.Subdomain, task.Type)]
		if !ok || entry.RecordID == "" || entry.IP != task.TargetIP || entry.Proxied != task.Record.Proxied {
			return false
		}
	}
	return true
}

func (u *Updater) persistState(next state.RuntimeState) error {
	return u.store.Update(func(cur *state.RuntimeState) error {
		if next.LastIPv4 != "" {
			cur.LastIPv4 = next.LastIPv4
		}
		if next.LastIPv6 != "" {
			cur.LastIPv6 = next.LastIPv6
		}
		cur.LastUpdated = next.LastUpdated
		for k, v := range next.Records {
			cur.Records[k] = v
		}
		return nil
	})
}
