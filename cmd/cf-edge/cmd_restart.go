package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/diepkhoa/openwrt-cf-edge/internal/config"
)

func runRestart(args []string) error {
	fs := flag.NewFlagSet("restart", flag.ContinueOnError)
	cfgPath := fs.String("c", defaultConfigPath, "path to config.yaml")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	return executeRestart(ctx, os.Stdout, *cfgPath, defaultInitScript, execInitRestart)
}

func executeRestart(
	ctx context.Context,
	w io.Writer,
	cfgPath string,
	initScript string,
	runner func(context.Context, string) error,
) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("config validation failed (service NOT restarted): %w", err)
	}
	if _, err := os.Stat(initScript); err != nil {
		return fmt.Errorf("init script %s not found; restart your service manager manually", initScript)
	}
	if err := runner(ctx, initScript); err != nil {
		return fmt.Errorf("restart service failed: %w", err)
	}
	fmt.Fprintf(w, "Config valid (node=%s); service cf-edge restarted\n", cfg.NodeName)
	return nil
}
