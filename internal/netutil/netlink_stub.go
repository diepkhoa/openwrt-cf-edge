//go:build !linux

package netutil

import (
	"context"
	"errors"
	"syscall"
)

// LinuxInspector provides stub Netlink lookups on non-Linux hosts.
type LinuxInspector struct{}

// DefaultRouteIPv4 is only supported on Linux.
func (LinuxInspector) DefaultRouteIPv4(_ context.Context) (string, string, error) {
	return "", "", errors.New("netlink default route lookup is only supported on linux")
}

// GlobalIPv6Addrs is only supported on Linux.
func (LinuxInspector) GlobalIPv6Addrs(_ context.Context, _ string) ([]IPv6AddrInfo, error) {
	return nil, errors.New("netlink IPv6 address lookup is only supported on linux")
}

// BindDeviceControl is a no-op on non-Linux hosts.
func BindDeviceControl(_ string) func(network, address string, c syscall.RawConn) error {
	return nil
}
