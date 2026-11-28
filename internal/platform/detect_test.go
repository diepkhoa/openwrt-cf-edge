package platform

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/diepkhoa/openwrt-cf-edge/internal/ubus"
)

type fakeFileInfo struct{}

func (fakeFileInfo) Name() string       { return "f" }
func (fakeFileInfo) Size() int64        { return 0 }
func (fakeFileInfo) Mode() os.FileMode  { return 0755 }
func (fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (fakeFileInfo) IsDir() bool        { return false }
func (fakeFileInfo) Sys() any           { return nil }

func TestDetectWithOpenWrtAndLinuxLXC(t *testing.T) {
	openwrt := DetectWith(
		func(bin string) (string, error) {
			if bin == "ubus" {
				return "/bin/ubus", nil
			}
			return "", errors.New("not found")
		},
		func(path string) (os.FileInfo, error) {
			if path == DefaultInitScript {
				return fakeFileInfo{}, nil
			}
			return nil, os.ErrNotExist
		},
	)
	if !openwrt.HasUbus || openwrt.ServiceMgr != ServiceProcd {
		t.Fatalf("unexpected OpenWrt detection: %+v", openwrt)
	}

	lxc := DetectWith(
		func(bin string) (string, error) {
			if bin == "systemctl" {
				return "/usr/bin/systemctl", nil
			}
			return "", errors.New("not found")
		},
		func(path string) (os.FileInfo, error) {
			if path == "/etc/systemd/system/cf-edge.service" {
				return fakeFileInfo{}, nil
			}
			return nil, os.ErrNotExist
		},
	)
	if lxc.HasUbus || lxc.ServiceMgr != ServiceSystemd {
		t.Fatalf("unexpected Linux LXC detection: %+v", lxc)
	}
}

type fakeUbus struct {
	devices map[string]string
}

func (f fakeUbus) Status(_ context.Context, iface string) (ubus.InterfaceStatus, error) {
	dev, ok := f.devices[iface]
	if !ok {
		return ubus.InterfaceStatus{}, errors.New("not found")
	}
	return ubus.InterfaceStatus{Up: true, L3Device: dev}, nil
}
func (fakeUbus) Down(context.Context, string) error { return nil }
func (fakeUbus) Up(context.Context, string) error   { return nil }

func TestResolveKernelDeviceFallsBackToUbusL3Device(t *testing.T) {
	statFn := func(path string) (os.FileInfo, error) {
		if path == "/sys/class/net/pppoe-wan" {
			return fakeFileInfo{}, nil
		}
		return nil, os.ErrNotExist
	}
	ub := fakeUbus{devices: map[string]string{
		"netbird": "wt0",
		"lan":     "br-lan.50",
	}}

	if got := resolveKernelDeviceWith(context.Background(), ub, "pppoe-wan", statFn, nil); got != "pppoe-wan" {
		t.Fatalf("existing sysfs device changed unexpectedly: %q", got)
	}
	if got := resolveKernelDeviceWith(context.Background(), ub, "netbird", statFn, nil); got != "wt0" {
		t.Fatalf("expected netbird -> wt0, got %q", got)
	}
	if got := resolveKernelDeviceWith(context.Background(), ub, "lan", statFn, nil); got != "br-lan.50" {
		t.Fatalf("expected lan -> br-lan.50, got %q", got)
	}
}
