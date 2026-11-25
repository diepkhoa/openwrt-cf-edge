//go:build linux

package netutil

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync/atomic"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

const protocolICMP = 1

// RawPinger sends ICMPv4 Echo requests directly via raw sockets bound to an L3 device.
type RawPinger struct {
	seq atomic.Uint32
}

// Ping sends an ICMPv4 Echo Request to target out of iface and waits for the matching reply.
func (p *RawPinger) Ping(ctx context.Context, target string, iface string, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	targetIP, err := resolveIPv4(ctx, target)
	if err != nil {
		return err
	}

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_ICMP)
	if err != nil {
		return fmt.Errorf("open raw icmp socket: %w", err)
	}
	if iface != "" {
		if err := unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface); err != nil {
			_ = unix.Close(fd)
			return fmt.Errorf("SO_BINDTODEVICE(%s): %w", iface, err)
		}
	}

	f := os.NewFile(uintptr(fd), "icmp-ping")
	pc, err := net.FilePacketConn(f)
	_ = f.Close()
	if err != nil {
		return fmt.Errorf("wrap icmp socket: %w", err)
	}
	defer pc.Close()

	stopWatch := context.AfterFunc(ctx, func() {
		_ = pc.SetDeadline(time.Now())
	})
	defer stopWatch()

	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := pc.SetDeadline(deadline); err != nil {
		return fmt.Errorf("set icmp deadline: %w", err)
	}

	id := os.Getpid() & 0xffff
	seq := int(p.seq.Add(1) & 0xffff)
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   id,
			Seq:  seq,
			Data: []byte("cf-edge"),
		},
	}
	pkt, err := msg.Marshal(nil)
	if err != nil {
		return fmt.Errorf("marshal icmp echo: %w", err)
	}

	if _, err := pc.WriteTo(pkt, &net.IPAddr{IP: targetIP}); err != nil {
		return fmt.Errorf("send icmp echo to %s: %w", targetIP, err)
	}

	buf := make([]byte, 1500)
	for {
		n, peer, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("icmp echo reply from %s: %w", targetIP, err)
		}
		if !peerMatchesIP(peer, targetIP) {
			continue
		}
		reply, err := icmp.ParseMessage(protocolICMP, buf[:n])
		if err != nil {
			continue
		}
		if reply.Type != ipv4.ICMPTypeEchoReply {
			continue
		}
		echo, ok := reply.Body.(*icmp.Echo)
		if !ok {
			continue
		}
		if echo.ID == id && echo.Seq == seq {
			return nil
		}
	}
}

func resolveIPv4(ctx context.Context, target string) (net.IP, error) {
	if ip := net.ParseIP(target).To4(); ip != nil {
		return ip, nil
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", target)
	if err != nil {
		return nil, fmt.Errorf("resolve ping target %s: %w", target, err)
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			return v4, nil
		}
	}
	return nil, fmt.Errorf("no IPv4 address for ping target %s", target)
}

func peerMatchesIP(peer net.Addr, want net.IP) bool {
	ipAddr, ok := peer.(*net.IPAddr)
	if !ok {
		return false
	}
	return ipAddr.IP.Equal(want)
}
