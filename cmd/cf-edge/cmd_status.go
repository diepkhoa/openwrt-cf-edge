package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/diepkhoa/openwrt-cf-edge/internal/state"
)

func runStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	cfgPath := fs.String("c", defaultConfigPath, "path to config.yaml")
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

	st := deps.store.Get()
	lock, shielded, lockErr := state.ReadShieldLock(state.DefaultShieldLockPath)
	nftActive, _ := deps.firewall.IsActive(ctx)

	fmt.Printf("Node:          %s\n", deps.cfg.NodeName)
	fmt.Printf("State File:    %s\n", deps.store.Path())
	fmt.Printf("Cached IPv4:   %s\n", valueOrDash(st.LastIPv4))
	fmt.Printf("Cached IPv6:   %s\n", valueOrDash(st.LastIPv6))
	if !st.LastUpdated.IsZero() {
		fmt.Printf("Last Sync:     %s\n", st.LastUpdated.Local().Format(time.RFC3339))
	}

	if v4, l3, err := deps.discoverer.DiscoverIPv4(ctx); err == nil {
		fmt.Printf("Live WAN IPv4: %s (dev=%s)\n", v4, valueOrDash(l3))
	} else {
		fmt.Printf("Live WAN IPv4: unavailable (%v)\n", err)
	}
	if deps.cfg.NeedsIPv6() {
		if v6, err := deps.discoverer.DiscoverIPv6(ctx); err == nil {
			fmt.Printf("Live WAN IPv6: %s\n", v6)
		} else {
			fmt.Printf("Live WAN IPv6: unavailable (%v)\n", err)
		}
	}

	if shielded {
		fmt.Printf("DDoS Shield:   ACTIVE (reason=%q manual=%v port=%d since=%s nft=%v)\n",
			lock.Reason, lock.Manual, lock.WANIngressPort, lock.EnteredAt.Local().Format(time.RFC3339), nftActive)
	} else if lockErr != nil {
		fmt.Printf("DDoS Shield:   UNKNOWN (%v, nft=%v)\n", lockErr, nftActive)
	} else {
		fmt.Printf("DDoS Shield:   inactive (nft=%v)\n", nftActive)
	}

	ubusSt, ubusErr := deps.ubusClient.Status(ctx, deps.cfg.WAN.IfaceV4)
	if ubusErr != nil {
		fmt.Printf("PPPoE (%s):   unavailable (%v)\n", deps.cfg.WAN.IfaceV4, ubusErr)
	} else {
		var errCodes []string
		for _, e := range ubusSt.Errors {
			errCodes = append(errCodes, e.Code)
		}
		errSummary := "none"
		if len(errCodes) > 0 {
			errSummary = strings.Join(errCodes, ",")
		}
		fmt.Printf("PPPoE (%s):   up=%v pending=%v dev=%s uptime=%ds errors=%s\n",
			deps.cfg.WAN.IfaceV4, ubusSt.Up, ubusSt.Pending, valueOrDash(ubusSt.EffectiveL3Device()), ubusSt.Uptime, errSummary)
	}
	if st.PPPoEStatus != nil {
		fmt.Printf("PPPoE Guard:   state=%s redials=%d last_action=%s\n",
			st.PPPoEStatus.State, st.PPPoEStatus.RedialCount, valueOrDash(st.PPPoEStatus.LastAction))
	}

	if len(st.Records) > 0 {
		fmt.Println("DNS Records:")
		keys := make([]string, 0, len(st.Records))
		for k := range st.Records {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			rec := st.Records[k]
			fmt.Printf("  - %-32s %-4s %-39s (id=%s proxied=%v)\n",
				rec.Subdomain, rec.Type, rec.IP, rec.RecordID, rec.Proxied)
		}
	}
	return nil
}

func valueOrDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}
