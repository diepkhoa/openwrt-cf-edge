package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExecuteRestartValidatesBeforeRestarting(t *testing.T) {
	dir := t.TempDir()
	initPath := filepath.Join(dir, "init-cf-edge")
	if err := os.WriteFile(initPath, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatal(err)
	}

	var calls int
	runner := func(context.Context, string) error {
		calls++
		return nil
	}

	// Invalid config must NOT restart service.
	badCfg := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(badCfg, []byte("cloudflare:\n  zone_id: only-zone\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := executeRestart(context.Background(), &out, badCfg, initPath, runner); err == nil || !strings.Contains(err.Error(), "service NOT restarted") {
		t.Fatalf("expected validation block error, got: %v", err)
	}
	if calls != 0 {
		t.Fatalf("service must not restart when config is invalid, calls=%d", calls)
	}

	// Valid config + existing init script must validate and call runner once.
	goodCfg := filepath.Join(dir, "good.yaml")
	if err := os.WriteFile(goodCfg, []byte("node_name: x96air\ncloudflare:\n  enabled: false\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := executeRestart(context.Background(), &out, goodCfg, initPath, runner); err != nil {
		t.Fatalf("executeRestart failed: %v", err)
	}
	if calls != 1 || !strings.Contains(out.String(), "service cf-edge restarted") {
		t.Fatalf("unexpected restart result: calls=%d out=%q", calls, out.String())
	}

	// Runner error propagates cleanly.
	failRunner := func(context.Context, string) error { return errors.New("exit 1") }
	if err := executeRestart(context.Background(), &out, goodCfg, initPath, failRunner); err == nil || !strings.Contains(err.Error(), "restart service failed") {
		t.Fatalf("expected restart failure error, got: %v", err)
	}
}
