package main

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/diepkhoa/openwrt-cf-edge/internal/config"
)

func TestNextDailyRun(t *testing.T) {
	loc := time.FixedZone("GMT+7", 7*3600)

	// Before 03:30 on same day -> runs today at 03:30.
	t1 := time.Date(2026, 11, 27, 2, 15, 0, 0, loc)
	got1 := nextDailyRun(t1, 3, 30)
	want1 := time.Date(2026, 11, 27, 3, 30, 0, 0, loc)
	if !got1.Equal(want1) {
		t.Fatalf("got1=%v, want=%v", got1, want1)
	}

	// Exactly at 03:30 -> runs tomorrow at 03:30 (prevents restart loop).
	got2 := nextDailyRun(want1, 3, 30)
	want2 := time.Date(2026, 11, 28, 3, 30, 0, 0, loc)
	if !got2.Equal(want2) {
		t.Fatalf("got2=%v, want=%v", got2, want2)
	}

	// Late on Nov 30 -> rolls cleanly to Dec 1.
	t3 := time.Date(2026, 11, 30, 23, 50, 0, 0, loc)
	got3 := nextDailyRun(t3, 3, 30)
	want3 := time.Date(2026, 12, 1, 3, 30, 0, 0, loc)
	if !got3.Equal(want3) {
		t.Fatalf("got3=%v, want=%v", got3, want3)
	}
}

type fakeAutoNotifier struct {
	msgs []string
}

func (f *fakeAutoNotifier) Send(_ context.Context, msg string) error {
	f.msgs = append(f.msgs, msg)
	return nil
}

func TestAutoUpdaterRunOnceShieldNotifyAndRestart(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "shield.lock")
	if err := os.WriteFile(lockPath, []byte(`{"active":true}`), 0644); err != nil {
		t.Fatal(err)
	}

	var updateCalls, restartCalls int
	notif := &fakeAutoNotifier{}
	cfg := &config.Config{
		NodeName: "knr3053",
		AutoUpdate: config.AutoUpdateConfig{
			Enabled: true,
			Time:    "03:30",
			Restart: true,
		},
	}

	u := newAutoUpdater(cfg, notif, lockPath, newLoggerWithWriter(&strings.Builder{}, slog.LevelInfo, false))
	u.updateFn = func(context.Context) (bool, string, error) {
		updateCalls++
		return true, "v0.1.9", nil
	}
	u.restartFn = func() error {
		restartCalls++
		return nil
	}

	// While shielded, scheduled auto-update must skip.
	u.runOnce(context.Background())
	if updateCalls != 0 || restartCalls != 0 {
		t.Fatalf("expected skip while shielded, got update=%d restart=%d", updateCalls, restartCalls)
	}

	// Remove shield.lock -> must update, send Telegram notification, and trigger restart.
	_ = os.Remove(lockPath)
	u.runOnce(context.Background())
	if updateCalls != 1 || restartCalls != 1 || len(notif.msgs) != 1 {
		t.Fatalf("unexpected calls after shield removed: update=%d restart=%d msgs=%d", updateCalls, restartCalls, len(notif.msgs))
	}
	if !strings.Contains(notif.msgs[0], "v0.1.9") {
		t.Fatalf("expected new version in Telegram notification, got %q", notif.msgs[0])
	}
}
