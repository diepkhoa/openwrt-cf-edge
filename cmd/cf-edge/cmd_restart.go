package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/diepkhoa/openwrt-cf-edge/internal/config"
	"github.com/diepkhoa/openwrt-cf-edge/internal/platform"
)

func runRestart(args []string) error {
	fs := flag.NewFlagSet("restart", flag.ContinueOnError)
	cfgPath := fs.String("c", defaultConfigPath, "path to config.yaml")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	return executeRestart(ctx, os.Stdout, *cfgPath, platform.Detect(), execServiceRestart)
}

func executeRestart(
	ctx context.Context,
	w io.Writer,
	cfgPath string,
	env platform.Env,
	runner func(context.Context, platform.Env) error,
) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("config validation failed (service NOT restarted): %w", err)
	}
	if env.ServiceMgr == platform.ServiceNone {
		return fmt.Errorf("no supported service manager (OpenWrt init script or systemd unit) found; restart manually")
	}
	if err := runner(ctx, env); err != nil {
		return fmt.Errorf("restart service failed: %w", err)
	}
	fmt.Fprintf(w, "Config valid (node=%s); service cf-edge restarted (%s)\n", cfg.NodeName, env.ServiceMgr)
	return nil
}
