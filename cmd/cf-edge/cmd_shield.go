package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/diepkhoa/openwrt-cf-edge/internal/ddos"
	"github.com/diepkhoa/openwrt-cf-edge/internal/state"
)

func runShield(args []string) error {
	fs := flag.NewFlagSet("shield", flag.ContinueOnError)
	cfgPath := fs.String("c", defaultConfigPath, "path to config.yaml")
	noRedial := fs.Bool("no-redial", false, "skip WAN redial when entering shield manually")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return err
	}

	rest := fs.Args()
	if len(rest) == 0 {
		return fmt.Errorf("usage: cf-edge shield [-c config.yaml] <enter [--no-redial] | exit | status>")
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	deps, err := buildDeps(*cfgPath, logger)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	switch rest[0] {
	case "enter":
		if err := deps.shieldMgr.EnterShield(ctx, "manual CLI shield enter", ddos.EnterOptions{
			Manual:   true,
			NoRedial: *noRedial,
		}); err != nil {
			return err
		}
		fmt.Printf("Shield mode ENTERED (lock=%s, port=%d, no_redial=%v)\n",
			state.DefaultShieldLockPath, deps.cfg.DDoSShield.WANIngressPort, *noRedial)
		return nil

	case "exit":
		if err := deps.shieldMgr.ExitShield(ctx, true); err != nil {
			return err
		}
		fmt.Println("Shield mode EXITED (lock removed, firewall cleared, DNS force-synced)")
		return nil

	case "status":
		lock, exists, err := state.ReadShieldLock(state.DefaultShieldLockPath)
		if err != nil {
			return err
		}
		nftActive, _ := deps.firewall.IsActive(ctx)
		if !exists {
			fmt.Printf("Shield: inactive (nft_table=%v)\n", nftActive)
			return nil
		}
		fmt.Printf("Shield: ACTIVE\n  node:       %s\n  reason:     %s\n  manual:     %v\n  port:       %d\n  entered_at: %s\n  nft_table:  %v\n",
			lock.NodeName, lock.Reason, lock.Manual, lock.WANIngressPort, lock.EnteredAt.Local().Format(time.RFC3339), nftActive)
		return nil

	default:
		return fmt.Errorf("unknown shield action %q (expected enter|exit|status)", rest[0])
	}
}
