package edgefw

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// NftRunner executes nftables CLI commands.
type NftRunner interface {
	Run(ctx context.Context, stdin string, args ...string) ([]byte, error)
}

// ExecNftRunner invokes the system `nft` binary.
type ExecNftRunner struct{}

// Run executes `nft` with optional stdin script and arguments.
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

func snapshotTable(ctx context.Context, runner NftRunner) (bool, string) {
	out, err := runner.Run(ctx, "", "list", "table", "inet", TableName)
	if err != nil {
		return false, ""
	}
	return true, fmt.Sprintf("table inet %s\ndelete table inet %s\n%s\n", TableName, TableName, string(out))
}

func rollbackTable(ctx context.Context, runner NftRunner, hadPrev bool, prevDump string) {
	if hadPrev && strings.TrimSpace(prevDump) != "" {
		_, _ = runner.Run(ctx, prevDump, "-f", "-")
		return
	}
	_, _ = runner.Run(ctx, "", "delete", "table", "inet", TableName)
}

func isTableActive(ctx context.Context, runner NftRunner) bool {
	_, err := runner.Run(ctx, "", "list", "table", "inet", TableName)
	return err == nil
}
