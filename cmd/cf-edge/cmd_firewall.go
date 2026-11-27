package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/diepkhoa/openwrt-cf-edge/internal/edgefw"
)

func runFirewall(args []string) error {
	fs := flag.NewFlagSet("firewall", flag.ContinueOnError)
	cfgPath := fs.String("c", defaultConfigPath, "path to config.yaml")
	refresh := fs.Bool("refresh", false, "force refresh GeoIP and Cloudflare IP ranges")
	wanDev := fs.String("wan-dev", "", "override WAN L3 device (comma-separated) for render/apply")
	jsonOut := fs.Bool("json", false, "output status as JSON")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return err
	}

	rest := fs.Args()
	if len(rest) == 0 {
		return fmt.Errorf("usage: cf-edge firewall [-c config.yaml] <render [--wan-dev dev] | apply [--refresh] | remove | status [--json]>")
	}

	var devOverride []string
	for _, d := range strings.Split(*wanDev, ",") {
		if trimmed := strings.TrimSpace(d); trimmed != "" {
			devOverride = append(devOverride, trimmed)
		}
	}

	outLog := os.Stdout
	if rest[0] == "render" || *jsonOut {
		outLog = os.Stderr
	}
	logger := newLogger(outLog, slog.LevelInfo, false)
	deps, err := buildDeps(*cfgPath, logger)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	opts := edgefw.ApplyOptions{
		ForceRefresh:    *refresh,
		WANDevOverride:  devOverride,
		NotifyOnFailure: true,
	}

	switch rest[0] {
	case "render":
		script, _, _, err := deps.edgeFW.Render(ctx, opts)
		if err != nil {
			return err
		}
		fmt.Print(script)
		return nil

	case "apply":
		if err := deps.edgeFW.Apply(ctx, opts); err != nil {
			return err
		}
		st := deps.edgeFW.Status(ctx)
		fmt.Printf("Edge firewall APPLIED (table=inet %s, wan=%s, rules=%d, geoip_v4=%d, geoip_v6=%d)\n",
			edgefw.TableName, strings.Join(st.WANDevices, ","), st.RuleCount, st.GeoIPv4Count, st.GeoIPv6Count)
		return nil

	case "remove":
		if err := deps.edgeFW.Remove(ctx); err != nil {
			return err
		}
		fmt.Printf("Edge firewall REMOVED (table=inet %s)\n", edgefw.TableName)
		return nil

	case "status":
		st := deps.edgeFW.Status(ctx)
		if *jsonOut {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(st)
		}
		updated := "-"
		if !st.CacheUpdatedAt.IsZero() {
			updated = st.CacheUpdatedAt.Local().Format(time.RFC3339)
		}
		fmt.Printf("Edge Firewall: %v (nft_active=%v, rules=%d, geoip_v4=%d, geoip_v6=%d, cache_updated=%s)\n",
			st.Enabled, st.NftActive, st.RuleCount, st.GeoIPv4Count, st.GeoIPv6Count, updated)
		return nil

	default:
		return fmt.Errorf("unknown firewall action %q (expected render|apply|remove|status)", rest[0])
	}
}
