package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExecuteValidateTextAndJSON(t *testing.T) {
	dir := t.TempDir()
	validPath := filepath.Join(dir, "valid.yaml")
	validYAML := `
node_name: "edge-1"
wan:
  iface_v4: "wan"
cloudflare:
  zone_id: "zone-abc"
  api_token: "tok-xyz"
  records:
    - subdomain: "vpn.example.com"
      ipv4: true
auto_update:
  enabled: true
  time: "03:30"
`
	if err := os.WriteFile(validPath, []byte(validYAML), 0600); err != nil {
		t.Fatal(err)
	}

	var textBuf bytes.Buffer
	if err := executeValidate(&textBuf, validPath, false); err != nil {
		t.Fatalf("executeValidate valid text failed: %v", err)
	}
	if !strings.Contains(textBuf.String(), "Config valid (node=edge-1, records=1") {
		t.Fatalf("unexpected text validate output: %q", textBuf.String())
	}

	var jsonBuf bytes.Buffer
	if err := executeValidate(&jsonBuf, validPath, true); err != nil {
		t.Fatalf("executeValidate valid JSON failed: %v", err)
	}
	var out validateOutput
	if err := json.Unmarshal(jsonBuf.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal validate JSON failed: %v", err)
	}
	if !out.Valid || out.Node != "edge-1" || out.Records != 1 {
		t.Fatalf("unexpected validate JSON: %+v", out)
	}

	// Invalid config must return error and valid=false JSON.
	badPath := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(badPath, []byte("cloudflare:\n  zone_id: z\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var badBuf bytes.Buffer
	if err := executeValidate(&badBuf, badPath, true); err == nil {
		t.Fatal("expected error for invalid config")
	}
	var badOut validateOutput
	if err := json.Unmarshal(badBuf.Bytes(), &badOut); err != nil {
		t.Fatalf("unmarshal bad validate JSON failed: %v", err)
	}
	if badOut.Valid || badOut.Error == "" {
		t.Fatalf("expected valid=false with error message, got %+v", badOut)
	}
}

func TestRenderVersionTextAndJSON(t *testing.T) {
	var textBuf bytes.Buffer
	if err := renderVersion(&textBuf, false); err != nil {
		t.Fatalf("renderVersion text failed: %v", err)
	}
	if !strings.HasPrefix(textBuf.String(), "cf-edge ") {
		t.Fatalf("unexpected version text output: %q", textBuf.String())
	}

	var jsonBuf bytes.Buffer
	if err := renderVersion(&jsonBuf, true); err != nil {
		t.Fatalf("renderVersion JSON failed: %v", err)
	}
	var v versionOutput
	if err := json.Unmarshal(jsonBuf.Bytes(), &v); err != nil {
		t.Fatalf("unmarshal version JSON failed: %v", err)
	}
	if v.Version == "" || v.Repo == "" || v.OS == "" {
		t.Fatalf("expected populated version JSON, got %+v", v)
	}
}
