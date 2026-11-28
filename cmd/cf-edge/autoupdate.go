package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/diepkhoa/openwrt-cf-edge/internal/config"
	"github.com/diepkhoa/openwrt-cf-edge/internal/notify"
	"github.com/diepkhoa/openwrt-cf-edge/internal/platform"
	"github.com/diepkhoa/openwrt-cf-edge/internal/state"
)

type selfUpdateFunc func(ctx context.Context) (updated bool, newTag string, err error)

type autoUpdater struct {
	cfg            *config.Config
	notifier       notify.Notifier
	shieldLockPath string
	logger         *slog.Logger
	nowFn          func() time.Time
	customClock    bool
	updateFn       selfUpdateFunc
	refreshFn      func(context.Context)
	restartFn      func() error
}

func newAutoUpdater(cfg *config.Config, notifier notify.Notifier, shieldLockPath string, logger *slog.Logger) *autoUpdater {
	if logger == nil {
		logger = slog.Default()
	}
	if shieldLockPath == "" {
		shieldLockPath = state.DefaultShieldLockPath
	}
	return &autoUpdater{
		cfg:            cfg,
		notifier:       notifier,
		shieldLockPath: shieldLockPath,
		logger:         logger,
		nowFn:          time.Now,
		updateFn:       defaultAutoSelfUpdate,
		refreshFn:      defaultAutoRefreshExample,
		restartFn:      defaultRestartService,
	}
}

func defaultAutoRefreshExample(ctx context.Context) {
	execPath, err := os.Executable()
	if err != nil {
		return
	}
	if resolved, rErr := filepath.EvalSymlinks(execPath); rErr == nil {
		execPath = resolved
	}
	refreshExampleConfigViaBinary(ctx, execPath, defaultConfigPath)
}

func defaultAutoSelfUpdate(ctx context.Context) (bool, string, error) {
	execPath, err := os.Executable()
	if err != nil {
		return false, "", err
	}
	if resolved, err := filepath.EvalSymlinks(execPath); err == nil {
		execPath = resolved
	}
	runCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	client := &http.Client{Timeout: 60 * time.Second}
	return performSelfUpdate(runCtx, client, defaultGitHubAPIBase, githubRepo, "", runtime.GOARCH, execPath, false)
}

func defaultRestartService() error {
	return startServiceRestartAsync(platform.Detect())
}

func nextDailyRun(now time.Time, hour, minute int) time.Time {
	next := time.Date(now.Year(), now.Month(), now.Day(), hour, minute, 0, 0, now.Location())
	if !next.After(now) {
		next = time.Date(now.Year(), now.Month(), now.Day()+1, hour, minute, 0, 0, now.Location())
	}
	return next
}

// Run waits until the configured daily local time and applies updates if a newer release is available.
func (u *autoUpdater) Run(ctx context.Context) {
	if !u.cfg.AutoUpdate.Enabled {
		return
	}
	hour, minute, err := config.ParseDailyTime(u.cfg.AutoUpdate.Time)
	if err != nil {
		u.logger.Error("invalid auto_update.time, disabling scheduler", "err", err)
		return
	}

	for {
		if !u.customClock {
			syncLocalTimezone()
		}
		now := u.nowFn()
		next := nextDailyRun(now, hour, minute)
		wait := next.Sub(now)
		u.logger.Info("scheduled daily auto-update", "time", u.cfg.AutoUpdate.Time, "next_run", next.Format("2006-01-02 15:04:05 -07:00"))

		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}

		u.runOnce(ctx)
	}
}

func (u *autoUpdater) runOnce(ctx context.Context) {
	if state.IsShielded(u.shieldLockPath) {
		u.logger.Warn("shield lock active, skipping scheduled auto-update")
		return
	}

	updated, newTag, err := u.updateFn(ctx)
	if err != nil {
		if ctx.Err() == nil {
			u.logger.Warn("scheduled auto-update failed", "err", err)
		}
		return
	}
	if !updated {
		u.logger.Info("auto-update check completed: already up to date", "version", newTag)
		return
	}

	u.logger.Info("auto-update applied", "from", version, "to", newTag)
	if u.refreshFn != nil {
		u.refreshFn(ctx)
	}
	if u.notifier != nil {
		msg := notify.FormatAutoUpdate(u.cfg.NodeName, version, newTag, u.cfg.AutoUpdate.Restart)
		if sendErr := u.notifier.Send(ctx, msg); sendErr != nil {
			u.logger.Warn("telegram auto-update notification failed", "err", sendErr)
		}
	}

	if u.cfg.AutoUpdate.Restart {
		u.logger.Info("restarting cf-edge service")
		if restErr := u.restartFn(); restErr != nil {
			u.logger.Error("failed restarting cf-edge service", "err", restErr)
		}
	}
}
