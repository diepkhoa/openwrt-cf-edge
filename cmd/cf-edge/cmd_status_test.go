package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/diepkhoa/openwrt-cf-edge/internal/config"
	"github.com/diepkhoa/openwrt-cf-edge/internal/state"
	"github.com/diepkhoa/openwrt-cf-edge/internal/ubus"
)

func TestRenderStatusIncludesVersionAndDisabledFeaturesAsFalse(t *testing.T) {
	cfg := &config.Config{
		NodeName: "knr3053",
		WAN:      config.WANConfig{IfaceV4: "wan"},
		Cloudflare: config.CloudflareConfig{
			Records: []config.RecordConfig{{Subdomain: "test.example.com", IPv4: true, IPv6: false}},
		},
		Reconcile:  config.ReconcileConfig{Enabled: false},
		PPPoEGuard: config.PPPoEGuardConfig{Enabled: false},
		DDoSShield: config.DDoSShieldConfig{Enabled: false},
		AutoUpdate: config.AutoUpdateConfig{Enabled: false, Time: "03:30", Restart: true},
		Telegram:   config.TelegramConfig{Enabled: false},
	}

	var buf bytes.Buffer
	renderStatus(&buf, statusReport{
		OS:        "linux/arm64",
		Version:   "v0.1.3",
		Cfg:       cfg,
		StateFile: "/tmp/cf-edge-state.json",
		State:     state.RuntimeState{LastIPv4: "42.118.213.53"},
		LiveIPv4:  "42.118.213.53",
		LiveL3Dev: "phy1-sta0",
		UbusStatus: ubus.InterfaceStatus{
			Up:       true,
			L3Device: "phy1-sta0",
		},
	})

	out := buf.String()
	for _, want := range []string{
		"OS:            linux/arm64",
		"Version:       v0.1.3",
		"IPv6 DDNS:     false",
		"Reconcile:     false",
		"PPPoE Guard:   false",
		"DDoS Shield:   false (shield=inactive, nft=false)",
		"Auto-Update:   false",
		"Telegram:      false",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("status output missing %q:\n%s", want, out)
		}
	}
}

func TestRenderStatusEnabledAutoUpdateAndFeatures(t *testing.T) {
	cfg := &config.Config{
		NodeName: "knr3053",
		WAN:      config.WANConfig{IfaceV4: "wan"},
		Cloudflare: config.CloudflareConfig{
			Records: []config.RecordConfig{{Subdomain: "test.example.com", IPv4: true, IPv6: true}},
		},
		Reconcile:  config.ReconcileConfig{Enabled: true, Interval: config.Duration(10 * time.Minute)},
		PPPoEGuard: config.PPPoEGuardConfig{Enabled: true},
		DDoSShield: config.DDoSShieldConfig{Enabled: true},
		AutoUpdate: config.AutoUpdateConfig{Enabled: true, Time: "04:15", Restart: true},
		Telegram:   config.TelegramConfig{Enabled: true},
	}

	var buf bytes.Buffer
	renderStatus(&buf, statusReport{
		OS:       "linux/arm64",
		Version:  "v0.1.3",
		Cfg:      cfg,
		LiveIPv4: "42.118.213.53",
		LiveIPv6: "2405::1",
		State: state.RuntimeState{
			PPPoEStatus: &state.PPPoERuntimeInfo{State: "healthy", RedialCount: 0, LastAction: "none"},
		},
	})

	out := buf.String()
	for _, want := range []string{
		"Auto-Update:   true (time=04:15, restart=true)",
		"Reconcile:     true (interval=10m0s)",
		"PPPoE Guard:   true (state=healthy redials=0 last_action=none)",
		"Telegram:      true",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("status output missing %q:\n%s", want, out)
		}
	}
}

func TestRenderStatusJSON(t *testing.T) {
	cfg := &config.Config{
		NodeName: "edge-main",
		WAN:      config.WANConfig{IfaceV4: "wan"},
		Cloudflare: config.CloudflareConfig{
			Records: []config.RecordConfig{{Subdomain: "wg.example.com", IPv4: true, IPv6: false}},
		},
		Reconcile:  config.ReconcileConfig{Enabled: true, Interval: config.Duration(10 * time.Minute)},
		DDoSShield: config.DDoSShieldConfig{Enabled: true},
		AutoUpdate: config.AutoUpdateConfig{Enabled: false, Time: "03:30", Restart: true},
	}

	var buf bytes.Buffer
	err := renderStatusJSON(&buf, statusReport{
		OS:        "linux/arm64",
		Version:   "v0.1.5",
		Cfg:       cfg,
		StateFile: "/tmp/cf-edge-state.json",
		LiveIPv4:  "198.51.100.10",
		LiveL3Dev: "pppoe-wan",
		Shielded:  true,
		NftActive: true,
		Lock: state.ShieldLock{
			Active:         true,
			Reason:         "conntrack=6000",
			WANIngressPort: 443,
			EnteredAt:      time.Unix(1700000000, 0).UTC(),
		},
		UbusStatus: ubus.InterfaceStatus{Up: true, L3Device: "pppoe-wan", Uptime: 3600},
		State: state.RuntimeState{
			LastIPv4: "198.51.100.10",
			Records: map[string]state.RecordState{
				"wg.example.com|A": {RecordID: "rid-1", Subdomain: "wg.example.com", Type: "A", IP: "198.51.100.10"},
			},
		},
	})
	if err != nil {
		t.Fatalf("renderStatusJSON failed: %v", err)
	}

	var decoded statusJSON
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("unmarshal status JSON failed: %v", err)
	}
	if decoded.Version != "v0.1.5" || !decoded.Shield.Active || !decoded.Shield.NftActive {
		t.Fatalf("unexpected shield/version JSON: %+v", decoded)
	}
	if !decoded.Features.DDoSShield || decoded.Features.AutoUpdate || decoded.Features.IPv6DDNS {
		t.Fatalf("unexpected features JSON: %+v", decoded.Features)
	}
	if len(decoded.Records) != 1 || decoded.Records[0].RecordID != "rid-1" || !decoded.PPPoE.Up {
		t.Fatalf("unexpected records/pppoe JSON: %+v", decoded)
	}
}
