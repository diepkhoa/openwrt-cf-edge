package metrics

import (
	"encoding/json"
	"fmt"
	"strings"
)

// RuleCounter captures packet and byte totals for a single nftables rule.
type RuleCounter struct {
	Chain   string
	Rule    string
	Verdict string
	Packets int64
	Bytes   int64
}

type nftJSONOutput struct {
	Nftables []struct {
		Rule *nftRule `json:"rule"`
	} `json:"nftables"`
}

type nftRule struct {
	Chain   string           `json:"chain"`
	Comment string           `json:"comment"`
	Expr    []map[string]any `json:"expr"`
}

// ParseNftCounters extracts rule counters from `nft -j list table inet cf_edge_fw` JSON output.
func ParseNftCounters(data []byte) ([]RuleCounter, error) {
	var parsed nftJSONOutput
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil, fmt.Errorf("decode nft json: %w", err)
	}

	var out []RuleCounter
	for _, entry := range parsed.Nftables {
		if entry.Rule == nil {
			continue
		}
		packets, bytes, ok := extractCounter(entry.Rule.Expr)
		if !ok {
			continue
		}
		verdict := extractVerdict(entry.Rule.Expr)
		ruleName := deriveRuleLabel(entry.Rule.Comment, entry.Rule.Expr, verdict)
		out = append(out, RuleCounter{
			Chain:   entry.Rule.Chain,
			Rule:    ruleName,
			Verdict: verdict,
			Packets: packets,
			Bytes:   bytes,
		})
	}
	return out, nil
}

func extractCounter(exprs []map[string]any) (packets, bytes int64, ok bool) {
	for _, e := range exprs {
		raw, exists := e["counter"]
		if !exists {
			continue
		}
		m, isMap := raw.(map[string]any)
		if !isMap {
			continue
		}
		p, okP := asInt64(m["packets"])
		b, okB := asInt64(m["bytes"])
		if okP && okB {
			return p, b, true
		}
	}
	return 0, 0, false
}

func extractVerdict(exprs []map[string]any) string {
	for _, e := range exprs {
		for _, v := range []string{"drop", "accept", "return", "reject", "jump"} {
			if _, ok := e[v]; ok {
				return v
			}
		}
	}
	return "unknown"
}

func deriveRuleLabel(comment string, exprs []map[string]any, verdict string) string {
	if c := strings.TrimSpace(comment); c != "" {
		return c
	}
	rawBytes, _ := json.Marshal(exprs)
	s := string(rawBytes)

	switch {
	case strings.Contains(s, `"invalid"`):
		return "ct_invalid"
	case strings.Contains(s, `@pps_v4_`):
		return "per_ip_pps_v4"
	case strings.Contains(s, `@pps_v6_`):
		return "per_ip_pps_v6"
	case strings.Contains(s, `@conn_v4_`):
		return "conn_limit_v4"
	case strings.Contains(s, `@conn_v6_`):
		return "conn_limit_v6"
	case strings.Contains(s, `@syn_v4_`):
		return "syn_rate_v4"
	case strings.Contains(s, `@syn_v6_`):
		return "syn_rate_v6"
	case strings.Contains(s, `"limit"`):
		return "global_pps"
	case strings.Contains(s, `"flags"`) && strings.Contains(s, `"psh"`):
		if strings.Contains(s, `"rst"`) {
			return "tcp_flags_null"
		}
		return "tcp_flags_xmas"
	case strings.Contains(s, `"flags"`) && strings.Contains(s, `"fin"`) && strings.Contains(s, `"syn"`):
		return "tcp_flags_synfin"
	case strings.Contains(s, `"flags"`) && strings.Contains(s, `"syn"`) && strings.Contains(s, `"rst"`):
		return "tcp_flags_synrst"
	case verdict == "return":
		return "passed_to_fw4"
	default:
		return verdict
	}
}

func asInt64(v any) (int64, bool) {
	switch n := v.(type) {
	case float64:
		return int64(n), true
	case int64:
		return n, true
	case json.Number:
		i, err := n.Int64()
		return i, err == nil
	default:
		return 0, false
	}
}
