package meshwatch

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
)

// NetBirdClient queries local NetBird daemon status.
type NetBirdClient interface {
	Status(ctx context.Context) (NetBirdStatus, error)
}

// ExecNetBirdClient invokes `netbird status --json`.
type ExecNetBirdClient struct{}

// Status runs `netbird status --json` and parses the local node and peer state.
func (ExecNetBirdClient) Status(ctx context.Context) (NetBirdStatus, error) {
	out, err := exec.CommandContext(ctx, "netbird", "status", "--json").CombinedOutput()
	if err != nil {
		return NetBirdStatus{}, fmt.Errorf("netbird status --json: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return ParseNetBirdStatus(out)
}

// NetBirdStatus summarizes the fields needed from `netbird status --json`.
type NetBirdStatus struct {
	SelfIP              string
	FQDN                string
	ManagementConnected bool
	SignalConnected     bool
	Peers               map[string]NetBirdPeerInfo
}

// NetBirdPeerInfo summarizes per-peer state from `peers.details`.
type NetBirdPeerInfo struct {
	NetBirdIP      string
	FQDN           string
	Status         string
	ConnectionType string
	RemoteEndpoint string
	LatencyNs      int64
}

type rawNetBirdJSON struct {
	NetBirdIP  string `json:"netbirdIp"`
	FQDN       string `json:"fqdn"`
	Management struct {
		Connected bool `json:"connected"`
	} `json:"management"`
	Signal struct {
		Connected bool `json:"connected"`
	} `json:"signal"`
	Peers struct {
		Details []struct {
			FQDN                 string `json:"fqdn"`
			NetBirdIP            string `json:"netbirdIp"`
			Status               string `json:"status"`
			ConnectionType       string `json:"connectionType"`
			Latency              int64  `json:"latency"`
			IceCandidateEndpoint struct {
				Remote string `json:"remote"`
			} `json:"iceCandidateEndpoint"`
		} `json:"details"`
	} `json:"peers"`
}

// ParseNetBirdStatus decodes `netbird status --json` output cleanly.
func ParseNetBirdStatus(data []byte) (NetBirdStatus, error) {
	var raw rawNetBirdJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return NetBirdStatus{}, fmt.Errorf("decode netbird status json: %w", err)
	}
	out := NetBirdStatus{
		SelfIP:              stripCIDR(raw.NetBirdIP),
		FQDN:                strings.TrimSpace(raw.FQDN),
		ManagementConnected: raw.Management.Connected,
		SignalConnected:     raw.Signal.Connected,
		Peers:               make(map[string]NetBirdPeerInfo, len(raw.Peers.Details)),
	}
	for _, d := range raw.Peers.Details {
		ip := stripCIDR(d.NetBirdIP)
		if ip == "" {
			continue
		}
		out.Peers[ip] = NetBirdPeerInfo{
			NetBirdIP:      ip,
			FQDN:           strings.TrimSpace(d.FQDN),
			Status:         strings.TrimSpace(d.Status),
			ConnectionType: strings.TrimSpace(d.ConnectionType),
			RemoteEndpoint: strings.TrimSpace(d.IceCandidateEndpoint.Remote),
			LatencyNs:      d.Latency,
		}
	}
	return out, nil
}

func stripCIDR(raw string) string {
	s := strings.TrimSpace(raw)
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Addr().String()
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return a.String()
	}
	return ""
}
