package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/diepkhoa/openwrt-cf-edge/internal/config"
	"github.com/diepkhoa/openwrt-cf-edge/internal/edgefw"
	"github.com/diepkhoa/openwrt-cf-edge/internal/state"
	"github.com/diepkhoa/openwrt-cf-edge/internal/ubus"
)

type statusReport struct {
	OS           string
	Version      string
	Cfg          *config.Config
	StateFile    string
	State        state.RuntimeState
	LiveIPv4     string
	LiveL3Dev    string
	LiveIPv4Err  error
	LiveIPv6     string
	LiveIPv6Err  error
	Lock         state.ShieldLock
	Shielded     bool
	LockErr      error
	NftActive    bool
	EdgeFWStatus edgefw.RuntimeStatus
	UbusStatus   ubus.InterfaceStatus
	UbusErr      error
}

func runStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	cfgPath := fs.String("c", defaultConfigPath, "path to config.yaml")
	jsonOut := fs.Bool("json", false, "output status as JSON")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return err
	}

	logger := newLogger(os.Stderr, slog.LevelWarn, false)
	deps, err := buildDeps(*cfgPath, logger)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rep := statusReport{
		OS:        runtime.GOOS + "/" + runtime.GOARCH,
		Version:   version,
		Cfg:       deps.cfg,
		StateFile: deps.store.Path(),
		State:     deps.store.Get(),
	}
	rep.LiveIPv4, rep.LiveL3Dev, rep.LiveIPv4Err = deps.discoverer.DiscoverIPv4(ctx)
	if deps.cfg.NeedsIPv6() {
		rep.LiveIPv6, rep.LiveIPv6Err = deps.discoverer.DiscoverIPv6(ctx)
	}
	rep.Lock, rep.Shielded, rep.LockErr = state.ReadShieldLock(state.DefaultShieldLockPath)
	rep.NftActive, _ = deps.firewall.IsActive(ctx)
	rep.EdgeFWStatus = deps.edgeFW.Status(ctx)
	rep.UbusStatus, rep.UbusErr = deps.ubusClient.Status(ctx, deps.cfg.WAN.IfaceV4)

	if *jsonOut {
		return renderStatusJSON(os.Stdout, rep)
	}
	renderStatus(os.Stdout, rep)
	return nil
}

func renderStatus(w io.Writer, rep statusReport) {
	st := rep.State
	cfg := rep.Cfg

	fmt.Fprintf(w, "OS:            %s\n", rep.OS)
	fmt.Fprintf(w, "Version:       %s\n", rep.Version)
	fmt.Fprintf(w, "Node:          %s\n", cfg.NodeName)
	fmt.Fprintf(w, "State File:    %s\n", rep.StateFile)
	if cfg.Cloudflare.Enabled {
		fmt.Fprintf(w, "Cached IPv4:   %s\n", valueOrDash(st.LastIPv4))
		fmt.Fprintf(w, "Cached IPv6:   %s\n", valueOrDash(st.LastIPv6))
		if !st.LastUpdated.IsZero() {
			fmt.Fprintf(w, "Last Sync:     %s\n", st.LastUpdated.Local().Format(time.RFC3339))
		}
	}

	if rep.LiveIPv4Err == nil {
		fmt.Fprintf(w, "Live WAN IPv4: %s (dev=%s)\n", rep.LiveIPv4, valueOrDash(rep.LiveL3Dev))
	} else {
		fmt.Fprintf(w, "Live WAN IPv4: unavailable (%v)\n", rep.LiveIPv4Err)
	}
	if cfg.Cloudflare.Enabled {
		if cfg.NeedsIPv6() {
			if rep.LiveIPv6Err == nil {
				fmt.Fprintf(w, "Live WAN IPv6: %s\n", rep.LiveIPv6)
			} else {
				fmt.Fprintf(w, "Live WAN IPv6: unavailable (%v)\n", rep.LiveIPv6Err)
			}
		} else {
			fmt.Fprintln(w, "Live WAN IPv6: false (disabled)")
		}
		fmt.Fprintf(w, "DDNS:          true (records=%d)\n", len(cfg.Cloudflare.Records))
		fmt.Fprintf(w, "IPv6 DDNS:     %v\n", cfg.NeedsIPv6())
	} else {
		fmt.Fprintln(w, "DDNS:          false")
	}

	if cfg.Cloudflare.Enabled && cfg.Reconcile.Enabled {
		fmt.Fprintf(w, "Reconcile:     true (interval=%s)\n", cfg.Reconcile.Interval.Std())
	} else {
		fmt.Fprintln(w, "Reconcile:     false")
	}

	fmt.Fprintf(w, "PPPoE Guard:   %s\n", formatPPPoEGuardStatus(cfg.PPPoEGuard.Enabled, st.PPPoEStatus))
	fmt.Fprintf(w, "DDoS Shield:   %s\n", formatDDoSShieldStatus(cfg.DDoSShield.Enabled, rep.Shielded, rep.Lock, rep.LockErr, rep.NftActive))
	fmt.Fprintf(w, "Edge Firewall: %s\n", formatEdgeFirewallStatus(cfg.EdgeFirewall.Enabled, rep.EdgeFWStatus))

	if cfg.AutoUpdate.Enabled {
		fmt.Fprintf(w, "Auto-Update:   true (time=%s, restart=%v)\n", cfg.AutoUpdate.Time, cfg.AutoUpdate.Restart)
	} else {
		fmt.Fprintln(w, "Auto-Update:   false")
	}
	fmt.Fprintf(w, "Telegram:      %v\n", cfg.Telegram.Enabled)

	if rep.UbusErr != nil {
		fmt.Fprintf(w, "PPPoE (%s):   unavailable (%v)\n", cfg.WAN.IfaceV4, rep.UbusErr)
	} else {
		var errCodes []string
		for _, e := range rep.UbusStatus.Errors {
			errCodes = append(errCodes, e.Code)
		}
		errSummary := "none"
		if len(errCodes) > 0 {
			errSummary = strings.Join(errCodes, ",")
		}
		fmt.Fprintf(w, "PPPoE (%s):   up=%v pending=%v dev=%s uptime=%ds errors=%s\n",
			cfg.WAN.IfaceV4, rep.UbusStatus.Up, rep.UbusStatus.Pending, valueOrDash(rep.UbusStatus.EffectiveL3Device()), rep.UbusStatus.Uptime, errSummary)
	}

	if cfg.Cloudflare.Enabled && len(st.Records) > 0 {
		fmt.Fprintln(w, "DNS Records:")
		keys := make([]string, 0, len(st.Records))
		for k := range st.Records {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			rec := st.Records[k]
			fmt.Fprintf(w, "  - %-32s %-4s %-39s (id=%s proxied=%v)\n",
				rec.Subdomain, rec.Type, rec.IP, rec.RecordID, rec.Proxied)
		}
	}
}

func formatPPPoEGuardStatus(enabled bool, info *state.PPPoERuntimeInfo) string {
	if !enabled {
		return "false"
	}
	if info != nil {
		return fmt.Sprintf("true (state=%s redials=%d last_action=%s)", info.State, info.RedialCount, valueOrDash(info.LastAction))
	}
	return "true (idle)"
}

func formatDDoSShieldStatus(enabled, shielded bool, lock state.ShieldLock, lockErr error, nftActive bool) string {
	if shielded {
		return fmt.Sprintf("%v (ACTIVE reason=%q manual=%v port=%d since=%s nft=%v)",
			enabled, lock.Reason, lock.Manual, lock.WANIngressPort, lock.EnteredAt.Local().Format(time.RFC3339), nftActive)
	}
	if lockErr != nil {
		return fmt.Sprintf("%v (lock_err=%v, nft=%v)", enabled, lockErr, nftActive)
	}
	return fmt.Sprintf("%v (shield=inactive, nft=%v)", enabled, nftActive)
}

func formatEdgeFirewallStatus(enabled bool, st edgefw.RuntimeStatus) string {
	if !enabled && !st.NftActive {
		return "false"
	}
	return fmt.Sprintf("%v (nft=%v rules=%d geoip_v4=%d geoip_v6=%d)",
		enabled, st.NftActive, st.RuleCount, st.GeoIPv4Count, st.GeoIPv6Count)
}

func valueOrDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}
