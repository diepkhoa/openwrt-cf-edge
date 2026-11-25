package ddos

import (
	"context"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"time"
)

const shieldTableName = "cf_edge_shield"

// NftRunner executes nftables commands with optional stdin.
type NftRunner interface {
	Run(ctx context.Context, stdin string, args ...string) ([]byte, error)
}

// ExecNftRunner invokes the system `nft` binary.
type ExecNftRunner struct{}

// Run executes `nft` with the given stdin and arguments.
func (ExecNftRunner) Run(ctx context.Context, stdin string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "nft", args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("nft %s: %w (%s)", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

// Firewall manages WAN ingress port blocking rules via a dedicated nftables table.
type Firewall interface {
	ApplyShield(ctx context.Context, wanIfaces []string, port int) error
	RemoveShield(ctx context.Context) error
	IsActive(ctx context.Context) (bool, error)
}

// NftFirewall manages `table inet cf_edge_shield` using `iifname` matches.
type NftFirewall struct {
	runner NftRunner
}

// NewNftFirewall constructs an NftFirewall.
func NewNftFirewall(runner NftRunner) *NftFirewall {
	if runner == nil {
		runner = ExecNftRunner{}
	}
	return &NftFirewall{runner: runner}
}

// BuildShieldScript constructs an atomic nftables script using `iifname` (never `iif`)
// to drop inbound TCP and UDP traffic on port across wanIfaces without affecting outbound traffic.
func BuildShieldScript(wanIfaces []string, port int) string {
	clean := normalizeIfaces(wanIfaces)
	if len(clean) == 0 {
		clean = []string{"pppoe-wan"}
	}

	var quoted []string
	for _, dev := range clean {
		quoted = append(quoted, fmt.Sprintf("%q", dev))
	}
	ifaceSet := "{ " + strings.Join(quoted, ", ") + " }"

	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s\n", shieldTableName)
	fmt.Fprintf(&b, "flush table inet %s\n", shieldTableName)
	fmt.Fprintf(&b, "table inet %s {\n", shieldTableName)
	fmt.Fprintf(&b, "  chain input {\n")
	fmt.Fprintf(&b, "    type filter hook input priority -10; policy accept;\n")
	fmt.Fprintf(&b, "    iifname %s tcp dport %d drop\n", ifaceSet, port)
	fmt.Fprintf(&b, "    iifname %s udp dport %d drop\n", ifaceSet, port)
	fmt.Fprintf(&b, "  }\n")
	fmt.Fprintf(&b, "  chain forward {\n")
	fmt.Fprintf(&b, "    type filter hook forward priority -10; policy accept;\n")
	fmt.Fprintf(&b, "    iifname %s tcp dport %d drop\n", ifaceSet, port)
	fmt.Fprintf(&b, "    iifname %s udp dport %d drop\n", ifaceSet, port)
	fmt.Fprintf(&b, "  }\n")
	fmt.Fprintf(&b, "}\n")
	return b.String()
}

// ApplyShield creates or replaces `table inet cf_edge_shield`.
func (f *NftFirewall) ApplyShield(ctx context.Context, wanIfaces []string, port int) error {
	callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	script := BuildShieldScript(wanIfaces, port)
	_, err := f.runner.Run(callCtx, script, "-f", "-")
	return err
}

// RemoveShield deletes `table inet cf_edge_shield` if it exists.
func (f *NftFirewall) RemoveShield(ctx context.Context) error {
	active, err := f.IsActive(ctx)
	if err != nil || !active {
		return nil
	}
	callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err = f.runner.Run(callCtx, "", "delete", "table", "inet", shieldTableName)
	return err
}

// IsActive returns true when `table inet cf_edge_shield` is loaded in nftables.
func (f *NftFirewall) IsActive(ctx context.Context) (bool, error) {
	callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err := f.runner.Run(callCtx, "", "list", "table", "inet", shieldTableName)
	if err != nil {
		return false, nil
	}
	return true, nil
}

func normalizeIfaces(ifaces []string) []string {
	seen := make(map[string]struct{}, len(ifaces))
	var out []string
	for _, dev := range ifaces {
		d := strings.TrimSpace(dev)
		if d == "" {
			continue
		}
		if _, exists := seen[d]; exists {
			continue
		}
		seen[d] = struct{}{}
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}
