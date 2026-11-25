//go:build linux

package netutil

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// LinuxInspector queries Linux Netlink sockets for addresses and routes.
type LinuxInspector struct{}

// DefaultRouteIPv4 returns the interface and primary IPv4 address holding the default route,
// excluding tunnel/overlay devices (wg*, wt*, warp*, tun*).
func (LinuxInspector) DefaultRouteIPv4(_ context.Context) (string, string, error) {
	rib, err := syscall.NetlinkRIB(syscall.RTM_GETROUTE, syscall.AF_INET)
	if err != nil {
		return "", "", fmt.Errorf("netlink RTM_GETROUTE: %w", err)
	}
	msgs, err := syscall.ParseNetlinkMessage(rib)
	if err != nil {
		return "", "", fmt.Errorf("parse route netlink: %w", err)
	}

	type routeCandidate struct {
		oif    int
		metric uint32
	}
	var candidates []routeCandidate

	for _, m := range msgs {
		if m.Header.Type != syscall.RTM_NEWROUTE || len(m.Data) < syscall.SizeofRtMsg {
			continue
		}
		rt := (*syscall.RtMsg)(unsafe.Pointer(&m.Data[0]))
		if rt.Family != syscall.AF_INET || rt.Dst_len != 0 || rt.Type != syscall.RTN_UNICAST {
			continue
		}
		attrs, err := syscall.ParseNetlinkRouteAttr(&m)
		if err != nil {
			continue
		}

		table := uint32(rt.Table)
		oif := 0
		var metric uint32
		for _, a := range attrs {
			switch a.Attr.Type {
			case unix.RTA_TABLE:
				if len(a.Value) >= 4 {
					table = binary.LittleEndian.Uint32(a.Value)
				}
			case syscall.RTA_OIF:
				if len(a.Value) >= 4 {
					oif = int(binary.LittleEndian.Uint32(a.Value))
				}
			case syscall.RTA_PRIORITY:
				if len(a.Value) >= 4 {
					metric = binary.LittleEndian.Uint32(a.Value)
				}
			}
		}
		if table != unix.RT_TABLE_MAIN || oif <= 0 {
			continue
		}
		candidates = append(candidates, routeCandidate{oif: oif, metric: metric})
	}

	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].metric < candidates[j].metric
	})

	for _, cand := range candidates {
		iface, err := net.InterfaceByIndex(cand.oif)
		if err != nil || ShouldExcludeRouteIface(iface.Name) {
			continue
		}
		if ip := firstInterfaceIPv4(iface); ip != "" {
			return iface.Name, ip, nil
		}
	}
	return "", "", errors.New("no valid IPv4 default route interface found")
}

func firstInterfaceIPv4(iface *net.Interface) string {
	addrs, err := iface.Addrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if v4 := ipNet.IP.To4(); v4 != nil {
			return v4.String()
		}
	}
	return ""
}

// GlobalIPv6Addrs returns IPv6 addresses on devName along with deprecated/temporary flags and preferred lifetime.
func (LinuxInspector) GlobalIPv6Addrs(_ context.Context, devName string) ([]IPv6AddrInfo, error) {
	iface, err := net.InterfaceByName(devName)
	if err != nil {
		return nil, fmt.Errorf("lookup interface %s: %w", devName, err)
	}
	rib, err := syscall.NetlinkRIB(syscall.RTM_GETADDR, syscall.AF_INET6)
	if err != nil {
		return nil, fmt.Errorf("netlink RTM_GETADDR: %w", err)
	}
	msgs, err := syscall.ParseNetlinkMessage(rib)
	if err != nil {
		return nil, fmt.Errorf("parse addr netlink: %w", err)
	}

	var out []IPv6AddrInfo
	for _, m := range msgs {
		if m.Header.Type != syscall.RTM_NEWADDR || len(m.Data) < syscall.SizeofIfAddrmsg {
			continue
		}
		ifa := (*syscall.IfAddrmsg)(unsafe.Pointer(&m.Data[0]))
		if int(ifa.Index) != iface.Index || ifa.Family != syscall.AF_INET6 {
			continue
		}
		attrs, err := syscall.ParseNetlinkRouteAttr(&m)
		if err != nil {
			continue
		}

		var ipBytes []byte
		flags := uint32(ifa.Flags)
		preferredLFT := uint32(1)
		hasCacheInfo := false

		for _, a := range attrs {
			switch a.Attr.Type {
			case syscall.IFA_ADDRESS:
				if len(ipBytes) == 0 {
					ipBytes = a.Value
				}
			case syscall.IFA_LOCAL:
				ipBytes = a.Value
			case unix.IFA_FLAGS:
				if len(a.Value) >= 4 {
					flags = binary.LittleEndian.Uint32(a.Value)
				}
			case syscall.IFA_CACHEINFO:
				if len(a.Value) >= 4 {
					preferredLFT = binary.LittleEndian.Uint32(a.Value[:4])
					hasCacheInfo = true
				}
			}
		}

		if len(ipBytes) != 16 {
			continue
		}
		addr, ok := netip.AddrFromSlice(ipBytes)
		if !ok {
			continue
		}
		deprecated := (flags & unix.IFA_F_DEPRECATED) != 0
		if hasCacheInfo && preferredLFT == 0 {
			deprecated = true
		}
		out = append(out, IPv6AddrInfo{
			Addr:         addr,
			Deprecated:   deprecated,
			Temporary:    (flags & unix.IFA_F_TEMPORARY) != 0,
			PreferredLFT: preferredLFT,
		})
	}
	return out, nil
}

// BindDeviceControl returns a net.Dialer Control function binding sockets to iface via SO_BINDTODEVICE.
func BindDeviceControl(iface string) func(network, address string, c syscall.RawConn) error {
	if iface == "" {
		return nil
	}
	return func(_, _ string, c syscall.RawConn) error {
		var sockErr error
		err := c.Control(func(fd uintptr) {
			sockErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface)
		})
		if err != nil {
			return err
		}
		return sockErr
	}
}
