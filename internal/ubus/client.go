package ubus

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

const defaultCallTimeout = 5 * time.Second

// Runner executes `ubus` CLI commands and returns stdout.
type Runner interface {
	Run(ctx context.Context, args ...string) ([]byte, error)
}

// ExecRunner invokes the system `ubus` binary.
type ExecRunner struct{}

// Run executes `ubus` with the provided arguments.
func (ExecRunner) Run(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "ubus", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("ubus %s: %w (%s)", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

// IPv4Address represents an IPv4 entry returned by `ubus call network.interface.<iface> status`.
type IPv4Address struct {
	Address string `json:"address"`
	Mask    int    `json:"mask"`
}

// IPv6Address represents an IPv6 entry returned by ubus interface status.
type IPv6Address struct {
	Address string `json:"address"`
	Mask    int    `json:"mask"`
}

// UbusError represents a netifd error entry such as AUTH_FAILED.
type UbusError struct {
	Subsystem string `json:"subsystem"`
	Code      string `json:"code"`
}

// InterfaceStatus represents the JSON output of `ubus call network.interface.<iface> status`.
type InterfaceStatus struct {
	Up          bool          `json:"up"`
	Pending     bool          `json:"pending"`
	Available   bool          `json:"available"`
	Autostart   bool          `json:"autostart"`
	Proto       string        `json:"proto"`
	Device      string        `json:"device"`
	L3Device    string        `json:"l3_device"`
	Uptime      int64         `json:"uptime"`
	IPv4Address []IPv4Address `json:"ipv4-address"`
	IPv6Address []IPv6Address `json:"ipv6-address"`
	Errors      []UbusError   `json:"errors"`
}

// PrimaryIPv4 returns the first assigned IPv4 address, or empty string if none exists.
func (s InterfaceStatus) PrimaryIPv4() string {
	for _, a := range s.IPv4Address {
		if addr := strings.TrimSpace(a.Address); addr != "" {
			return addr
		}
	}
	return ""
}

// EffectiveL3Device returns L3Device when present, otherwise Device.
func (s InterfaceStatus) EffectiveL3Device() string {
	if dev := strings.TrimSpace(s.L3Device); dev != "" {
		return dev
	}
	return strings.TrimSpace(s.Device)
}

// Client interacts with OpenWrt netifd network interfaces via ubus.
type Client interface {
	Status(ctx context.Context, iface string) (InterfaceStatus, error)
	Down(ctx context.Context, iface string) error
	Up(ctx context.Context, iface string) error
}

// UbusClient implements Client using a Runner.
type UbusClient struct {
	runner Runner
}

// NewClient constructs a UbusClient. If runner is nil, ExecRunner is used.
func NewClient(runner Runner) *UbusClient {
	if runner == nil {
		runner = ExecRunner{}
	}
	return &UbusClient{runner: runner}
}

// Status queries `ubus call network.interface.<iface> status`.
func (c *UbusClient) Status(ctx context.Context, iface string) (InterfaceStatus, error) {
	if strings.TrimSpace(iface) == "" {
		return InterfaceStatus{}, fmt.Errorf("ubus status: empty interface name")
	}
	callCtx, cancel := withDefaultTimeout(ctx, defaultCallTimeout)
	defer cancel()

	out, err := c.runner.Run(callCtx, "call", "network.interface."+iface, "status")
	if err != nil {
		return InterfaceStatus{}, err
	}
	var st InterfaceStatus
	if err := json.Unmarshal(out, &st); err != nil {
		return InterfaceStatus{}, fmt.Errorf("decode ubus status for %s: %w", iface, err)
	}
	return st, nil
}

// Down executes `ubus call network.interface.<iface> down`.
func (c *UbusClient) Down(ctx context.Context, iface string) error {
	if strings.TrimSpace(iface) == "" {
		return nil
	}
	callCtx, cancel := withDefaultTimeout(ctx, defaultCallTimeout)
	defer cancel()
	_, err := c.runner.Run(callCtx, "call", "network.interface."+iface, "down")
	return err
}

// Up executes `ubus call network.interface.<iface> up`.
func (c *UbusClient) Up(ctx context.Context, iface string) error {
	if strings.TrimSpace(iface) == "" {
		return nil
	}
	callCtx, cancel := withDefaultTimeout(ctx, defaultCallTimeout)
	defer cancel()
	_, err := c.runner.Run(callCtx, "call", "network.interface."+iface, "up")
	return err
}

func withDefaultTimeout(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if _, hasDeadline := ctx.Deadline(); hasDeadline {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, d)
}
