package platform

import (
	"context"
	"log/slog"
	"os"
	"os/exec"
	"strings"

	"github.com/diepkhoa/openwrt-cf-edge/internal/ubus"
)

const DefaultInitScript = "/etc/init.d/cf-edge"

// ServiceManager identifies the init system supervising cf-edge.
type ServiceManager string

const (
	ServiceProcd   ServiceManager = "procd"
	ServiceSystemd ServiceManager = "systemd"
	ServiceNone    ServiceManager = "none"
)

// Env describes host runtime capabilities (OpenWrt ubus vs generic Linux).
type Env struct {
	HasUbus    bool
	ServiceMgr ServiceManager
}

// String returns a human-readable platform summary.
func (e Env) String() string {
	if e.HasUbus {
		return "openwrt (ubus, " + string(e.ServiceMgr) + ")"
	}
	return "linux (no ubus, " + string(e.ServiceMgr) + ")"
}

// Detect inspects the host for OpenWrt ubus and service manager binaries/files.
func Detect() Env {
	return DetectWith(exec.LookPath, os.Stat)
}

// DetectWith allows unit tests to stub PATH lookups and file stats.
func DetectWith(lookPath func(string) (string, error), statFn func(string) (os.FileInfo, error)) Env {
	_, ubusErr := lookPath("ubus")
	hasUbus := ubusErr == nil

	svc := ServiceNone
	if _, err := statFn(DefaultInitScript); err == nil {
		svc = ServiceProcd
	} else if _, err := lookPath("systemctl"); err == nil {
		for _, unit := range []string{
			"/etc/systemd/system/cf-edge.service",
			"/lib/systemd/system/cf-edge.service",
			"/usr/lib/systemd/system/cf-edge.service",
		} {
			if _, uErr := statFn(unit); uErr == nil {
				svc = ServiceSystemd
				break
			}
		}
	}

	return Env{
		HasUbus:    hasUbus,
		ServiceMgr: svc,
	}
}

// ResolveKernelDevice ensures name maps to an actual Linux kernel network device.
// If /sys/class/net/<name> does not exist on OpenWrt, it queries ubus for the underlying
// l3_device (e.g. resolving logical interface "netbird" -> "wt0" or "lan" -> "br-lan.50").
func ResolveKernelDevice(ctx context.Context, ubusClient ubus.Client, name string, logger *slog.Logger) string {
	return resolveKernelDeviceWith(ctx, ubusClient, name, os.Stat, logger)
}

func resolveKernelDeviceWith(
	ctx context.Context,
	ubusClient ubus.Client,
	name string,
	statFn func(string) (os.FileInfo, error),
	logger *slog.Logger,
) string {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return ""
	}
	if _, err := statFn("/sys/class/net/" + trimmed); err == nil {
		return trimmed
	}
	if ubusClient == nil {
		return trimmed
	}
	st, err := ubusClient.Status(ctx, trimmed)
	if err != nil {
		return trimmed
	}
	if dev := st.EffectiveL3Device(); dev != "" && dev != trimmed {
		if logger != nil {
			logger.Info("resolved logical interface to kernel L3 device", "interface", trimmed, "device", dev)
		}
		return dev
	}
	return trimmed
}
