package pppoeguard

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/diepkhoa/openwrt-cf-edge/internal/config"
	"github.com/diepkhoa/openwrt-cf-edge/internal/state"
	"github.com/diepkhoa/openwrt-cf-edge/internal/ubus"
)

type mockUbus struct {
	mu       sync.Mutex
	statuses []ubus.InterfaceStatus
	idx      int
	downs    atomic.Int32
	ups      atomic.Int32
}

func (m *mockUbus) Status(_ context.Context, _ string) (ubus.InterfaceStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.statuses) == 0 {
		return ubus.InterfaceStatus{}, errors.New("no status")
	}
	i := m.idx
	if i >= len(m.statuses) {
		i = len(m.statuses) - 1
	} else {
		m.idx++
	}
	return m.statuses[i], nil
}

func (m *mockUbus) Down(_ context.Context, _ string) error {
	m.downs.Add(1)
	return nil
}

func (m *mockUbus) Up(_ context.Context, _ string) error {
	m.ups.Add(1)
	return nil
}

type mockPinger struct {
	fail atomic.Bool
}

func (p *mockPinger) Ping(_ context.Context, _ string, _ string, _ time.Duration) error {
	if p.fail.Load() {
		return errors.New("timeout")
	}
	return nil
}

type fakeOpener struct {
	ch chan string
}

func (f *fakeOpener) Open(ctx context.Context) (io.ReadCloser, func() error, error) {
	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		for {
			select {
			case <-ctx.Done():
				return
			case line, ok := <-f.ch:
				if !ok {
					return
				}
				_, _ = pw.Write([]byte(line + "\n"))
			}
		}
	}()
	return pr, nil, nil
}

func newTestConfig() *config.Config {
	return &config.Config{
		NodeName: "vnpt-gw",
		WAN:      config.WANConfig{IfaceV4: "wan"},
		PPPoEGuard: config.PPPoEGuardConfig{
			Enabled:     true,
			BootGrace:   config.Duration(time.Millisecond),
			InitialWait: config.Duration(time.Millisecond),
			PingTargets: []string{"1.1.1.1"},
		},
	}
}

func TestGuardRecoversAuthFailedAndPendingStuck(t *testing.T) {
	ub := &mockUbus{
		statuses: []ubus.InterfaceStatus{
			// Initial boot check: healthy
			{Up: true, L3Device: "pppoe-wan", IPv4Address: []ubus.IPv4Address{{Address: "203.0.113.1"}}},
			// After ifdown: pending=false (AUTH_FAILED lockout) -> immediate down/up
			{Up: false, Pending: false},
			// Next 4 checks: pending=true (>3 cycles triggers forced down/up)
			{Up: false, Pending: true},
			{Up: false, Pending: true},
			{Up: false, Pending: true},
			{Up: false, Pending: true},
			// Finally healthy!
			{Up: true, L3Device: "pppoe-wan", IPv4Address: []ubus.IPv4Address{{Address: "203.0.113.2"}}},
		},
	}
	pinger := &mockPinger{}
	opener := &fakeOpener{ch: make(chan string, 4)}
	listener := ubus.NewListener(opener, nil)
	store := state.NewStore(filepath.Join(t.TempDir(), "state.json"))

	guard := NewGuard(newTestConfig(), ub, listener, pinger, store, nil, nil,
		WithTimings(time.Millisecond, time.Millisecond, time.Millisecond, time.Millisecond, time.Millisecond, 2*time.Millisecond),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go listener.Run(ctx)
	go guard.Run(ctx)

	time.Sleep(20 * time.Millisecond)
	opener.ch <- `{"network.interface":{"action":"ifdown","interface":"wan"}}`

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if ub.downs.Load() >= 2 && ub.ups.Load() >= 2 {
			st := store.Get()
			if st.PPPoEStatus != nil && st.PPPoEStatus.State == "healthy" {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("expected >=2 recovery redials and healthy status, got downs=%d ups=%d status=%+v",
		ub.downs.Load(), ub.ups.Load(), store.Get().PPPoEStatus)
}

func TestGuardIgnoresExternalRedial(t *testing.T) {
	ub := &mockUbus{
		statuses: []ubus.InterfaceStatus{
			{Up: true, L3Device: "pppoe-wan", IPv4Address: []ubus.IPv4Address{{Address: "203.0.113.1"}}},
		},
	}
	opener := &fakeOpener{ch: make(chan string, 4)}
	listener := ubus.NewListener(opener, nil)
	guard := NewGuard(newTestConfig(), ub, listener, &mockPinger{}, nil, nil, nil,
		WithTimings(time.Millisecond, time.Millisecond, time.Millisecond, time.Millisecond, time.Millisecond, time.Millisecond),
	)
	guard.SetExternalRedialing(true)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go listener.Run(ctx)
	go guard.Run(ctx)

	time.Sleep(20 * time.Millisecond)
	opener.ch <- `{"network.interface":{"action":"ifdown","interface":"wan"}}`
	time.Sleep(40 * time.Millisecond)

	if ub.downs.Load() != 0 {
		t.Fatalf("expected 0 redials while externalRedial=true, got %d", ub.downs.Load())
	}
}
