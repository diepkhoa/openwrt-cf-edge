package meshwatch

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/diepkhoa/openwrt-cf-edge/internal/config"
)

func TestParseNetBirdStatusRealRouterSample(t *testing.T) {
	// Live JSON shape captured from NetBird 0.84.0 on OpenWrt router knr3053.
	raw := []byte(`{
		"peers": {
			"total": 2,
			"connected": 2,
			"details": [
				{
					"fqdn": "x96air.netbird.cloud",
					"netbirdIp": "100.123.14.49",
					"status": "Connected",
					"connectionType": "P2P",
					"iceCandidateEndpoint": {"local": "42.118.213.53:60012", "remote": "1.54.4.207:60002"},
					"latency": 6209040
				},
				{
					"fqdn": "compute-node.netbird.cloud",
					"netbirdIp": "100.123.184.112",
					"status": "Connected",
					"connectionType": "P2P",
					"iceCandidateEndpoint": {"local": "192.168.1.252:60012", "remote": "192.168.12.5:51820"},
					"latency": 1471195
				}
			]
		},
		"management": {"url": "https://api.netbird.io:443", "connected": true},
		"signal": {"url": "https://signal.netbird.io:443", "connected": true},
		"netbirdIp": "100.123.130.59/16",
		"fqdn": "knr3053.netbird.cloud"
	}`)

	st, err := ParseNetBirdStatus(raw)
	if err != nil {
		t.Fatalf("ParseNetBirdStatus failed: %v", err)
	}
	if st.SelfIP != "100.123.130.59" || !st.ManagementConnected || !st.SignalConnected {
		t.Fatalf("unexpected top-level NetBirdStatus: %+v", st)
	}
	p, ok := st.Peers["100.123.14.49"]
	if !ok || p.Status != "Connected" || p.RemoteEndpoint != "1.54.4.207:60002" {
		t.Fatalf("unexpected x96air peer entry: %+v", p)
	}
}

type fakeNB struct {
	mu     sync.Mutex
	selfIP string
	mgmtOK bool
}

func (f *fakeNB) Status(context.Context) (NetBirdStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return NetBirdStatus{SelfIP: f.selfIP, ManagementConnected: f.mgmtOK, SignalConnected: f.mgmtOK}, nil
}

type fakePinger struct {
	mu   sync.Mutex
	down map[string]bool
}

func (f *fakePinger) Ping(_ context.Context, target, _ string, _ time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down[target] {
		return errors.New("timeout")
	}
	return nil
}

type fakeNotifier struct {
	mu   sync.Mutex
	msgs []string
}

func (n *fakeNotifier) Send(_ context.Context, msg string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.msgs = append(n.msgs, msg)
	return nil
}

func meshTestConfig() *config.Config {
	return &config.Config{
		NodeName: "test-node",
		WAN:      config.WANConfig{OverlayDevice: "wt0"},
		MeshWatchdog: config.MeshWatchdogConfig{
			Enabled:            true,
			CheckInterval:      config.Duration(30 * time.Second),
			FailThreshold:      2,
			RecoveryThreshold:  2,
			RequireNetBirdMgmt: true,
			MinOtherSiteOnline: 1,
			RankDelayStep:      config.Duration(time.Millisecond),
			Peers: []config.MeshPeerConfig{
				{Name: "proxmox", IP: "100.123.184.112", Site: "site-proxmox", CanNotify: true},
				{Name: "x96air", IP: "100.123.14.49", Site: "site-edge", CanNotify: true},
				{Name: "knr3053", IP: "100.123.130.59", Site: "site-branch", CanNotify: true},
			},
		},
	}
}

func TestMeshWatchdogPriorityGatesAndRecovery(t *testing.T) {
	// Scenario A: Rank #2 (x96air) sees #1 (proxmox) down & #3 (knr3053, other site) up -> alerts and recovers.
	cfg := meshTestConfig()
	cfg.NodeName = "x96air"
	nb := &fakeNB{selfIP: "100.123.14.49", mgmtOK: true}
	pinger := &fakePinger{down: map[string]bool{"100.123.184.112": true}}
	notif := &fakeNotifier{}
	now := time.Unix(1000, 0)

	wd := NewWatchdog(cfg, nb, pinger, notif, nil)
	wd.nowFn = func() time.Time { return now }

	wd.step(context.Background())
	if len(notif.msgs) != 0 {
		t.Fatalf("must not alert before FailThreshold=2, got %v", notif.msgs)
	}
	now = now.Add(30 * time.Second)
	wd.step(context.Background())
	if len(notif.msgs) != 1 || !strings.Contains(notif.msgs[0], "proxmox") || !strings.Contains(notif.msgs[0], "OFFLINE") {
		t.Fatalf("expected proxmox OFFLINE alert from x96air, got %v", notif.msgs)
	}

	// Bring proxmox back -> 2 healthy checks trigger ONLINE recovery with downtime.
	pinger.mu.Lock()
	pinger.down["100.123.184.112"] = false
	pinger.mu.Unlock()
	now = now.Add(90 * time.Second)
	wd.step(context.Background())
	now = now.Add(30 * time.Second)
	wd.step(context.Background())
	if len(notif.msgs) != 2 || !strings.Contains(notif.msgs[1], "ONLINE") || !strings.Contains(notif.msgs[1], "2m0s") {
		t.Fatalf("expected proxmox ONLINE recovery with 2m0s downtime, got %v", notif.msgs)
	}

	// Check SnapshotPeers exports live state cleanly.
	samples := wd.SnapshotPeers()
	if len(samples) != 3 || !samples[0].Up {
		t.Fatalf("unexpected SnapshotPeers: %+v", samples)
	}
}

func TestMeshWatchdogSuppressesWhenHigherRankUpOrIsolated(t *testing.T) {
	// Scenario B: Rank #3 (knr3053) sees proxmox down, but #2 (x96air) is UP -> #3 must stay silent.
	cfg := meshTestConfig()
	cfg.NodeName = "knr3053"
	nb := &fakeNB{selfIP: "100.123.130.59", mgmtOK: true}
	pinger := &fakePinger{down: map[string]bool{"100.123.184.112": true}}
	notif := &fakeNotifier{}
	wd := NewWatchdog(cfg, nb, pinger, notif, nil)

	wd.step(context.Background())
	wd.step(context.Background())
	if len(notif.msgs) != 0 {
		t.Fatalf("expected knr3053 to stay silent while x96air (#2) is online, got %v", notif.msgs)
	}

	// Scenario C: Self loses NetBird management internet (even if LAN peer looks reachable) -> must stay silent.
	cfgIso := meshTestConfig()
	cfgIso.MeshWatchdog.Peers[1].Site = "site-proxmox" // simulate another peer on same site reachable via LAN
	nbIso := &fakeNB{selfIP: "100.123.184.112", mgmtOK: false}
	pingerIso := &fakePinger{down: map[string]bool{"100.123.130.59": true}}
	notifIso := &fakeNotifier{}
	wdIso := NewWatchdog(cfgIso, nbIso, pingerIso, notifIso, nil)

	wdIso.step(context.Background())
	wdIso.step(context.Background())
	if len(notifIso.msgs) != 0 {
		t.Fatalf("expected isolated node with management.connected=false to stay silent, got %v", notifIso.msgs)
	}
}
