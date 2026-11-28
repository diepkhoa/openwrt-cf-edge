package config

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

func defaultMeshWatchdogConfig() MeshWatchdogConfig {
	return MeshWatchdogConfig{
		Enabled:            false,
		CheckInterval:      Duration(30 * time.Second),
		FailThreshold:      3,
		RecoveryThreshold:  2,
		RequireNetBirdMgmt: true,
		MinOtherSiteOnline: 1,
		RankDelayStep:      Duration(10 * time.Second),
	}
}

func (c *Config) validateMeshWatchdog() error {
	m := &c.MeshWatchdog
	if m.CheckInterval.Std() <= 0 {
		return errors.New("mesh_watchdog.check_interval must be positive")
	}
	if m.FailThreshold < 1 || m.RecoveryThreshold < 1 {
		return errors.New("mesh_watchdog fail_threshold and recovery_threshold must be >= 1")
	}
	if m.MinOtherSiteOnline < 0 {
		return errors.New("mesh_watchdog.min_other_site_online must be non-negative")
	}
	if m.RankDelayStep.Std() < 0 {
		return errors.New("mesh_watchdog.rank_delay_step must be non-negative")
	}
	if !m.Enabled {
		return nil
	}
	if c.WAN.EffectiveOverlayDevice() == "" {
		return errors.New("wan.overlay_device (or overlay_iface) must not be empty when mesh_watchdog is enabled")
	}
	if len(m.Peers) < 2 {
		return errors.New("mesh_watchdog.peers must contain at least 2 peers when mesh_watchdog is enabled")
	}

	seenIPs := make(map[string]struct{}, len(m.Peers))
	for i := range m.Peers {
		p := &m.Peers[i]
		p.Name = strings.TrimSpace(p.Name)
		p.Site = strings.TrimSpace(p.Site)
		if p.Name == "" {
			return fmt.Errorf("mesh_watchdog.peers[%d].name must not be empty", i)
		}
		if p.Site == "" {
			return fmt.Errorf("mesh_watchdog.peers[%d].site (%s) must not be empty", i, p.Name)
		}
		ipStr := normalizeMeshIP(p.IP)
		addr, err := netip.ParseAddr(ipStr)
		if err != nil {
			return fmt.Errorf("mesh_watchdog.peers[%d].ip (%q): %w", i, p.IP, err)
		}
		p.IP = addr.String()
		if _, dup := seenIPs[p.IP]; dup {
			return fmt.Errorf("duplicate mesh_watchdog peer IP %q", p.IP)
		}
		seenIPs[p.IP] = struct{}{}
	}
	return nil
}

func normalizeMeshIP(raw string) string {
	s := strings.TrimSpace(raw)
	if idx := strings.IndexByte(s, '/'); idx > 0 {
		s = s[:idx]
	}
	return s
}
