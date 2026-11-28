package main

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/diepkhoa/openwrt-cf-edge/internal/platform"
)

func execServiceRestart(ctx context.Context, env platform.Env) error {
	var cmd *exec.Cmd
	switch env.ServiceMgr {
	case platform.ServiceProcd:
		cmd = exec.CommandContext(ctx, platform.DefaultInitScript, "restart")
	case platform.ServiceSystemd:
		cmd = exec.CommandContext(ctx, "systemctl", "restart", "cf-edge")
	default:
		return fmt.Errorf("no supported init script (%s) or systemd unit (cf-edge.service) found", platform.DefaultInitScript)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func startServiceRestartAsync(env platform.Env) error {
	// Start non-blocking so procd/systemd SIGTERM stops the running daemon without deadlock.
	switch env.ServiceMgr {
	case platform.ServiceProcd:
		return exec.Command(platform.DefaultInitScript, "restart").Start()
	case platform.ServiceSystemd:
		return exec.Command("systemctl", "restart", "cf-edge").Start()
	default:
		return fmt.Errorf("no supported service manager detected")
	}
}
