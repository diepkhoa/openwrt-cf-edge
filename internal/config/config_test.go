package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseValidFullConfig(t *testing.T) {
	raw := `
node_name: "edge-x96"
wan:
  iface_v4: "wan"
  iface_v6: "wan6"
  overlay_iface: "wt0"
  lan_iface: "br-lan"
cloudflare:
  zone_id: "zone-123"
  api_token: "token-abc"
  records:
    - subdomain: "wg-x96.example.com."
      ipv4: true
      ipv6: true
      proxied: false
reconcile:
  enabled: true
  interval: "15m"
  resolvers: ["1.1.1.1", "8.8.8.8:53"]
pppoe_guard:
  enabled: true
  boot_grace: "60s"
  initial_wait: "30s"
  ping_targets: ["1.1.1.1"]
ddos_shield:
  enabled: true
  worker_url: "https://shield.example.com/"
  worker_token: "w-secret"
  wan_ingress_port: 8443
  check_interval: "5s"
  sustain_duration: "25s"
  conntrack_threshold: 6000
  junk_mbps_threshold: 350
  rx_pps_threshold: 85000
  max_redials_per_hour: 4
  status_poll_interval: "3m"
telegram:
  enabled: true
  bot_token: "bot-123"
  chat_id: "chat-456"
`
	cfg, err := Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse returned unexpected error: %v", err)
	}
	if cfg.NodeName != "edge-x96" {
		t.Fatalf("NodeName = %q, want edge-x96", cfg.NodeName)
	}
	if cfg.WAN.LANIface != "br-lan" {
		t.Fatalf("LANIface = %q, want br-lan", cfg.WAN.LANIface)
	}
	if cfg.Cloudflare.Records[0].Subdomain != "wg-x96.example.com" {
		t.Fatalf("Subdomain = %q, want trailing dot stripped", cfg.Cloudflare.Records[0].Subdomain)
	}
	if !cfg.NeedsIPv6() {
		t.Fatal("NeedsIPv6() = false, want true")
	}
	if cfg.Reconcile.Resolvers[0] != "1.1.1.1:53" {
		t.Fatalf("Resolver[0] = %q, want 1.1.1.1:53", cfg.Reconcile.Resolvers[0])
	}
	if cfg.DDoSShield.WorkerURL != "https://shield.example.com" {
		t.Fatalf("WorkerURL = %q, want trailing slash trimmed", cfg.DDoSShield.WorkerURL)
	}
	if cfg.DDoSShield.RXPPSThreshold != 85000 {
		t.Fatalf("RXPPSThreshold = %v, want 85000", cfg.DDoSShield.RXPPSThreshold)
	}
}

func TestParseDefaultsAndOptionalFields(t *testing.T) {
	raw := `
cloudflare:
  zone_id: "zone-123"
  api_token: "token-abc"
  records:
    - subdomain: "node.example.com"
      ipv4: true
      ipv6: false
`
	cfg, err := Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if !cfg.Cloudflare.Enabled {
		t.Fatal("Cloudflare.Enabled should default to true")
	}
	if cfg.NodeName == "" {
		t.Fatal("NodeName should default to hostname or openwrt")
	}
	if cfg.WAN.IfaceV4 != "wan" {
		t.Fatalf("IfaceV4 = %q, want wan", cfg.WAN.IfaceV4)
	}
	if cfg.NeedsIPv6() {
		t.Fatal("NeedsIPv6() = true, want false")
	}
	if !cfg.Reconcile.Enabled || cfg.Reconcile.Interval.Std() != 10*time.Minute {
		t.Fatalf("unexpected reconcile defaults: %+v", cfg.Reconcile)
	}
	if cfg.DDoSShield.WANIngressPort != 443 || cfg.DDoSShield.RXPPSThreshold != 80000 {
		t.Fatalf("unexpected ddos defaults: %+v", cfg.DDoSShield)
	}
	if cfg.AutoUpdate.Enabled || cfg.AutoUpdate.Time != "03:30" || !cfg.AutoUpdate.Restart {
		t.Fatalf("unexpected auto_update defaults: %+v", cfg.AutoUpdate)
	}
	if cfg.EdgeFirewall.Enabled || cfg.EdgeFirewall.RefreshInterval.Std() != 7*24*time.Hour ||
		cfg.EdgeFirewall.CachePath != DefaultGeoIPCachePath || !cfg.EdgeFirewall.IncludeCloudflare ||
		!cfg.EdgeFirewall.RollbackOnCheckFail {
		t.Fatalf("unexpected edge_firewall defaults: %+v", cfg.EdgeFirewall)
	}
}

func TestLoadFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := `
cloudflare:
  zone_id: "z"
  api_token: "t"
  records:
    - subdomain: "a.example.com"
      ipv4: true
reconcile:
  enabled: false
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.Reconcile.Enabled {
		t.Fatal("Reconcile.Enabled = true, want false")
	}
}

func TestParseValidationErrors(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "missing zone_id",
			yaml: "cloudflare:\n  api_token: t\n  records:\n    - subdomain: a.b\n      ipv4: true",
			want: "zone_id",
		},
		{
			name: "duplicate subdomain",
			yaml: "cloudflare:\n  zone_id: z\n  api_token: t\n  records:\n    - subdomain: a.b\n      ipv4: true\n    - subdomain: A.B.\n      ipv6: true",
			want: "duplicate",
		},
		{
			name: "record neither ipv4 nor ipv6",
			yaml: "cloudflare:\n  zone_id: z\n  api_token: t\n  records:\n    - subdomain: a.b",
			want: "ipv4 or ipv6",
		},
		{
			name: "invalid duration",
			yaml: "cloudflare:\n  zone_id: z\n  api_token: t\n  records:\n    - subdomain: a.b\n      ipv4: true\nreconcile:\n  interval: bad",
			want: "invalid duration",
		},
		{
			name: "ddos missing overlay_iface",
			yaml: "cloudflare:\n  zone_id: z\n  api_token: t\n  records:\n    - subdomain: a.b\n      ipv4: true\nddos_shield:\n  enabled: true\n  worker_url: https://w.example.com\n  worker_token: tok",
			want: "overlay_iface",
		},
		{
			name: "ddos invalid worker_url",
			yaml: "wan:\n  overlay_iface: wt0\ncloudflare:\n  zone_id: z\n  api_token: t\n  records:\n    - subdomain: a.b\n      ipv4: true\nddos_shield:\n  enabled: true\n  worker_url: ftp://bad\n  worker_token: tok",
			want: "worker_url",
		},
		{
			name: "telegram missing chat_id",
			yaml: "cloudflare:\n  zone_id: z\n  api_token: t\n  records:\n    - subdomain: a.b\n      ipv4: true\ntelegram:\n  enabled: true\n  bot_token: b",
			want: "chat_id",
		},
		{
			name: "auto_update invalid time",
			yaml: "cloudflare:\n  zone_id: z\n  api_token: t\n  records:\n    - subdomain: a.b\n      ipv4: true\nauto_update:\n  enabled: true\n  time: \"25:99\"",
			want: "auto_update.time",
		},
		{
			name: "edge_firewall forbidden br-lan wan_devices",
			yaml: "wan:\n  lan_iface: br-lan\n  overlay_iface: wt0\ncloudflare:\n  zone_id: z\n  api_token: t\n  records:\n    - subdomain: a.b\n      ipv4: true\nedge_firewall:\n  enabled: true\n  wan_devices: [\"br-lan\"]\n  rules:\n    - name: web\n      chain: input\n      proto: tcp\n      ports: [443]",
			want: "edge_firewall.wan_devices",
		},
		{
			name: "edge_firewall port 22 blocked by default",
			yaml: "cloudflare:\n  zone_id: z\n  api_token: t\n  records:\n    - subdomain: a.b\n      ipv4: true\nedge_firewall:\n  enabled: true\n  rules:\n    - name: ssh\n      chain: input\n      proto: tcp\n      ports: [22]",
			want: "port 22",
		},
		{
			name: "edge_firewall udp with max_conns_per_ip rejected",
			yaml: "cloudflare:\n  zone_id: z\n  api_token: t\n  records:\n    - subdomain: a.b\n      ipv4: true\nedge_firewall:\n  enabled: true\n  rules:\n    - name: rtc\n      chain: forward\n      proto: udp\n      ports: [50044]\n      max_conns_per_ip: 10",
			want: "only apply to tcp",
		},
	}

	// Also verify normalizing single-digit hour and preserving restart=false.
	customAU := `
cloudflare:
  zone_id: z
  api_token: t
  records:
    - subdomain: a.b
      ipv4: true
auto_update:
  enabled: true
  time: "4:5"
  restart: false
`
	parsedAU, err := Parse([]byte(customAU))
	if err != nil {
		t.Fatalf("unexpected auto_update parse error: %v", err)
	}
	if !parsedAU.AutoUpdate.Enabled || parsedAU.AutoUpdate.Time != "04:05" || parsedAU.AutoUpdate.Restart {
		t.Fatalf("unexpected parsed auto_update: %+v", parsedAU.AutoUpdate)
	}

	// When cloudflare.enabled=false, zone/token/records are optional and reconcile cascades to false.
	noDDNS, err := Parse([]byte(`
cloudflare:
  enabled: false
reconcile:
  enabled: true
edge_firewall:
  enabled: true
  rules:
    - name: web
      chain: input
      proto: tcp
      ports: [443]
`))
	if err != nil {
		t.Fatalf("expected valid config with cloudflare.enabled=false, got: %v", err)
	}
	if noDDNS.Cloudflare.Enabled || noDDNS.Reconcile.Enabled || noDDNS.NeedsIPv6() {
		t.Fatalf("expected DDNS, Reconcile, and IPv6 DDNS disabled, got cf=%v rec=%v", noDDNS.Cloudflare.Enabled, noDDNS.Reconcile.Enabled)
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.yaml))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want substring %q", err.Error(), tc.want)
			}
		})
	}
}
