package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPerformSelfUpdateVerifiesSHA256AndReplacesAtomically(t *testing.T) {
	newBin := []byte("#!/bin/sh\necho v1.2.0\n")
	sum := sha256.Sum256(newBin)
	hexSum := hex.EncodeToString(sum[:])

	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/diepkhoa/openwrt-cf-edge/releases/latest":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"tag_name": "v1.2.0",
				"assets": []map[string]string{
					{"name": "cf-edge-linux-arm64", "browser_download_url": srvURL + "/dl/cf-edge-linux-arm64"},
					{"name": "checksums.txt", "browser_download_url": srvURL + "/dl/checksums.txt"},
				},
			})
		case "/dl/cf-edge-linux-arm64":
			_, _ = w.Write(newBin)
		case "/dl/checksums.txt":
			_, _ = w.Write([]byte(hexSum + "  cf-edge-linux-arm64\n"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	srvURL = srv.URL

	target := filepath.Join(t.TempDir(), "cf-edge")
	if err := os.WriteFile(target, []byte("old-binary"), 0755); err != nil {
		t.Fatal(err)
	}

	updated, tag, err := performSelfUpdate(t.Context(), srv.Client(), srv.URL, "diepkhoa/openwrt-cf-edge", "", "arm64", target, false)
	if err != nil {
		t.Fatalf("performSelfUpdate failed: %v", err)
	}
	if !updated || tag != "v1.2.0" {
		t.Fatalf("expected updated=true tag=v1.2.0, got updated=%v tag=%q", updated, tag)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(newBin) {
		t.Fatalf("binary content mismatch: got %q", string(got))
	}
}

func TestPerformSelfUpdateRejectsBadChecksum(t *testing.T) {
	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/diepkhoa/openwrt-cf-edge/releases/latest":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"tag_name": "v1.2.0",
				"assets": []map[string]string{
					{"name": "cf-edge-linux-amd64", "browser_download_url": srvURL + "/dl/bin"},
					{"name": "checksums.txt", "browser_download_url": srvURL + "/dl/sums"},
				},
			})
		case "/dl/bin":
			_, _ = w.Write([]byte("tampered"))
		case "/dl/sums":
			_, _ = w.Write([]byte("0000000000000000000000000000000000000000000000000000000000000000  cf-edge-linux-amd64\n"))
		}
	}))
	defer srv.Close()
	srvURL = srv.URL

	target := filepath.Join(t.TempDir(), "cf-edge")
	if err := os.WriteFile(target, []byte("original"), 0755); err != nil {
		t.Fatal(err)
	}

	_, _, err := performSelfUpdate(t.Context(), srv.Client(), srv.URL, "diepkhoa/openwrt-cf-edge", "", "amd64", target, false)
	if err == nil || !strings.Contains(err.Error(), "SHA256 mismatch") {
		t.Fatalf("expected SHA256 mismatch error, got %v", err)
	}
	got, _ := os.ReadFile(target)
	if string(got) != "original" {
		t.Fatalf("original binary should remain untouched on checksum failure")
	}
}

func TestMaybeRestartServiceBehavior(t *testing.T) {
	dir := t.TempDir()
	initPath := filepath.Join(dir, "init-cf-edge")
	cfgPath := filepath.Join(dir, "config.yaml")

	var calls int
	runner := func(context.Context, string) error {
		calls++
		return nil
	}

	// Missing init/config should skip gracefully without error.
	if err := maybeRestartService(context.Background(), initPath, cfgPath, runner); err != nil {
		t.Fatalf("unexpected error when files missing: %v", err)
	}
	if calls != 0 {
		t.Fatalf("expected 0 restart calls when init/config missing, got %d", calls)
	}

	// When both exist, CLI self-update restarts service automatically.
	if err := os.WriteFile(initPath, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, []byte("node_name: test\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := maybeRestartService(context.Background(), initPath, cfgPath, runner); err != nil {
		t.Fatalf("unexpected error when init and config exist: %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected 1 automatic restart call, got %d", calls)
	}
}
