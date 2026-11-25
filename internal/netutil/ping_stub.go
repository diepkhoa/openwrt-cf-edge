//go:build !linux

package netutil

import (
	"context"
	"errors"
	"time"
)

// RawPinger is a stub Pinger on non-Linux hosts.
type RawPinger struct{}

// Ping is only supported on Linux.
func (*RawPinger) Ping(_ context.Context, _ string, _ string, _ time.Duration) error {
	return errors.New("raw icmp ping is only supported on linux")
}
