package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/diepkhoa/openwrt-cf-edge/internal/cloudflare"
	"github.com/diepkhoa/openwrt-cf-edge/internal/state"
)

func runUpdate(args []string) error {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	cfgPath := fs.String("c", defaultConfigPath, "path to config.yaml")
	force := fs.Bool("force", false, "bypass cooldown and verify records against Cloudflare API")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return err
	}

	if state.IsShielded(state.DefaultShieldLockPath) {
		return fmt.Errorf("DDoS shield lock (%s) is active; run 'cf-edge shield exit' before updating DNS", state.DefaultShieldLockPath)
	}

	logger := newLogger(os.Stdout, slog.LevelInfo, false)
	deps, err := buildDeps(*cfgPath, logger)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	snap, err := deps.discoverer.Discover(ctx)
	if err != nil {
		return fmt.Errorf("discover WAN IP: %w", err)
	}

	if err := deps.updater.Sync(ctx, snap, cloudflare.SyncOptions{Force: *force}); err != nil {
		return err
	}
	fmt.Printf("DDNS update completed (IPv4=%q IPv6=%q force=%v)\n", snap.IPv4, snap.IPv6, *force)
	return nil
}

// reorderFlags moves flag arguments ahead of positional arguments so Go's flag package accepts both orders.
func reorderFlags(args []string) []string {
	var flags, pos []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if len(arg) > 0 && arg[0] == '-' {
			flags = append(flags, arg)
			if arg == "-c" || arg == "--repo" || arg == "--version" {
				if i+1 < len(args) {
					i++
					flags = append(flags, args[i])
				}
			}
			continue
		}
		pos = append(pos, arg)
	}
	return append(flags, pos...)
}
