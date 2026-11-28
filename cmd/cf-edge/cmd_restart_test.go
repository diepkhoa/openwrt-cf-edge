package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/diepkhoa/openwrt-cf-edge/internal/platform"
)

func TestExecuteRestartValidatesBeforeRestarting(t *testing.T) {
	dir := t.TempDir()
	env := platform.Env{HasUbus: true, ServiceMgr: platform.ServiceProcd}

	var calls int
	runner := func(context.Context, platform.Env) error {
		calls++
		return nil
	}

	// Invalid config must NOT restart service.
	badCfg := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(badCfg, []byte("cloudflare:\n  zone_id: only-zone\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := executeRestart(context.Background(), &out, badCfg, env, runner); err == nil || !strings.Contains(err.Error(), "service NOT restarted") {
		t.Fatalf("expected validation block error, got: %v", err)
	}
	if calls != 0 {
		t.Fatalf("service must not restart when config is invalid, calls=%d", calls)
	}

	// Valid config + procd/systemd must validate and call runner once.
	goodCfg := filepath.Join(dir, "good.yaml")
	if err := os.WriteFile(goodCfg, []byte("node_name: x96air\ncloudflare:\n  enabled: false\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := executeRestart(context.Background(), &out, goodCfg, env, runner); err != nil {
		t.Fatalf("executeRestart failed: %v", err)
	}
	if calls != 1 || !strings.Contains(out.String(), "service cf-edge restarted") {
		t.Fatalf("unexpected restart result: calls=%d out=%q", calls, out.String())
	}

	// Missing service manager must return clear error.
	if err := executeRestart(context.Background(), &out, goodCfg, platform.Env{ServiceMgr: platform.ServiceNone}, runner); err == nil {
		t.Fatal("expected error when no service manager found")
	}

	// Runner error propagates cleanly.
	failRunner := func(context.Context, platform.Env) error { return errors.New("exit 1") }
	if err := executeRestart(context.Background(), &out, goodCfg, env, failRunner); err == nil || !strings.Contains(err.Error(), "restart service failed") {
		t.Fatalf("expected restart failure error, got: %v", err)
	}
}
