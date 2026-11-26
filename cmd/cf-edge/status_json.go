package main

import (
	"encoding/json"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/diepkhoa/openwrt-cf-edge/internal/state"
)

type statusJSON struct {
	OS         string             `json:"os"`
	Version    string             `json:"version"`
	Node       string             `json:"node"`
	StateFile  string             `json:"state_file"`
	CachedIPv4 string             `json:"cached_ipv4,omitempty"`
	CachedIPv6 string             `json:"cached_ipv6,omitempty"`
	LastSync   string             `json:"last_sync,omitempty"`
	LiveIPv4   string             `json:"live_ipv4,omitempty"`
	LiveL3Dev  string             `json:"live_l3_dev,omitempty"`
	LiveV4Err  string             `json:"live_ipv4_error,omitempty"`
	LiveIPv6   string             `json:"live_ipv6,omitempty"`
	LiveV6Err  string             `json:"live_ipv6_error,omitempty"`
	Features   statusFeaturesJSON `json:"features"`
	Shield     statusShieldJSON   `json:"shield"`
	PPPoE      statusPPPoEJSON    `json:"pppoe"`
	Records    []state.RecordState `json:"records"`
}

type statusFeaturesJSON struct {
	IPv6DDNS          bool   `json:"ipv6_ddns"`
	Reconcile         bool   `json:"reconcile"`
	ReconcileInterval string `json:"reconcile_interval"`
	PPPoEGuard        bool   `json:"pppoe_guard"`
	DDoSShield        bool   `json:"ddos_shield"`
	AutoUpdate        bool   `json:"auto_update"`
	AutoUpdateTime    string `json:"auto_update_time"`
	AutoUpdateRestart bool   `json:"auto_update_restart"`
	Telegram          bool   `json:"telegram"`
}

type statusShieldJSON struct {
	Active         bool   `json:"active"`
	Manual         bool   `json:"manual"`
	Reason         string `json:"reason,omitempty"`
	WANIngressPort int    `json:"wan_ingress_port,omitempty"`
	EnteredAt      string `json:"entered_at,omitempty"`
	NftActive      bool   `json:"nft_active"`
	LockError      string `json:"lock_error,omitempty"`
}

type statusPPPoEJSON struct {
	Iface           string `json:"iface"`
	Up              bool   `json:"up"`
	Pending         bool   `json:"pending"`
	Dev             string `json:"dev,omitempty"`
	Uptime          int64  `json:"uptime"`
	Errors          string `json:"errors,omitempty"`
	GuardState      string `json:"guard_state,omitempty"`
	GuardRedials    int    `json:"guard_redials,omitempty"`
	GuardLastAction string `json:"guard_last_action,omitempty"`
	Error           string `json:"error,omitempty"`
}

func renderStatusJSON(w io.Writer, rep statusReport) error {
	st := rep.State
	cfg := rep.Cfg

	out := statusJSON{
		OS:         rep.OS,
		Version:    rep.Version,
		Node:       cfg.NodeName,
		StateFile:  rep.StateFile,
		CachedIPv4: st.LastIPv4,
		CachedIPv6: st.LastIPv6,
		Features: statusFeaturesJSON{
			IPv6DDNS:          cfg.NeedsIPv6(),
			Reconcile:         cfg.Reconcile.Enabled,
			ReconcileInterval: cfg.Reconcile.Interval.Std().String(),
			PPPoEGuard:        cfg.PPPoEGuard.Enabled,
			DDoSShield:        cfg.DDoSShield.Enabled,
			AutoUpdate:        cfg.AutoUpdate.Enabled,
			AutoUpdateTime:    cfg.AutoUpdate.Time,
			AutoUpdateRestart: cfg.AutoUpdate.Restart,
			Telegram:          cfg.Telegram.Enabled,
		},
		Shield: statusShieldJSON{
			Active:         rep.Shielded,
			Manual:         rep.Lock.Manual,
			Reason:         rep.Lock.Reason,
			WANIngressPort: rep.Lock.WANIngressPort,
			NftActive:      rep.NftActive,
		},
		PPPoE: statusPPPoEJSON{
			Iface: cfg.WAN.IfaceV4,
		},
		Records: make([]state.RecordState, 0, len(st.Records)),
	}

	if !st.LastUpdated.IsZero() {
		out.LastSync = st.LastUpdated.UTC().Format(time.RFC3339)
	}
	if rep.LiveIPv4Err == nil {
		out.LiveIPv4 = rep.LiveIPv4
		out.LiveL3Dev = rep.LiveL3Dev
	} else {
		out.LiveV4Err = rep.LiveIPv4Err.Error()
	}
	if cfg.NeedsIPv6() {
		if rep.LiveIPv6Err == nil {
			out.LiveIPv6 = rep.LiveIPv6
		} else {
			out.LiveV6Err = rep.LiveIPv6Err.Error()
		}
	}
	if rep.Shielded && !rep.Lock.EnteredAt.IsZero() {
		out.Shield.EnteredAt = rep.Lock.EnteredAt.UTC().Format(time.RFC3339)
	}
	if rep.LockErr != nil {
		out.Shield.LockError = rep.LockErr.Error()
	}

	if rep.UbusErr != nil {
		out.PPPoE.Error = rep.UbusErr.Error()
	} else {
		out.PPPoE.Up = rep.UbusStatus.Up
		out.PPPoE.Pending = rep.UbusStatus.Pending
		out.PPPoE.Dev = rep.UbusStatus.EffectiveL3Device()
		out.PPPoE.Uptime = rep.UbusStatus.Uptime
		if len(rep.UbusStatus.Errors) > 0 {
			codes := make([]string, 0, len(rep.UbusStatus.Errors))
			for _, e := range rep.UbusStatus.Errors {
				codes = append(codes, e.Code)
			}
			out.PPPoE.Errors = strings.Join(codes, ",")
		}
	}
	if st.PPPoEStatus != nil {
		out.PPPoE.GuardState = st.PPPoEStatus.State
		out.PPPoE.GuardRedials = st.PPPoEStatus.RedialCount
		out.PPPoE.GuardLastAction = st.PPPoEStatus.LastAction
	}

	keys := make([]string, 0, len(st.Records))
	for k := range st.Records {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		out.Records = append(out.Records, st.Records[k])
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
