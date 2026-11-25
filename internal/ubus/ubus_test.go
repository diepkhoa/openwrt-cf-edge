package ubus

import (
	"context"
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"time"
)

type mockRunner struct {
	out []byte
	err error
	got [][]string
}

func (m *mockRunner) Run(_ context.Context, args ...string) ([]byte, error) {
	m.got = append(m.got, args)
	return m.out, m.err
}

func TestUbusClientStatusAndActions(t *testing.T) {
	sample := `{
		"up": true,
		"pending": false,
		"proto": "pppoe",
		"device": "eth1.35",
		"l3_device": "pppoe-wan",
		"uptime": 1200,
		"ipv4-address": [{"address": "203.0.113.5", "mask": 32}],
		"errors": [{"subsystem": "interface", "code": "AUTH_FAILED"}]
	}`
	mr := &mockRunner{out: []byte(sample)}
	client := NewClient(mr)

	st, err := client.Status(context.Background(), "wan")
	if err != nil {
		t.Fatalf("Status failed: %v", err)
	}
	if !st.Up || st.Pending || st.PrimaryIPv4() != "203.0.113.5" || st.EffectiveL3Device() != "pppoe-wan" {
		t.Fatalf("unexpected status: %+v", st)
	}
	if len(st.Errors) != 1 || st.Errors[0].Code != "AUTH_FAILED" {
		t.Fatalf("expected AUTH_FAILED error parsed, got %+v", st.Errors)
	}

	if err := client.Down(context.Background(), "wan"); err != nil {
		t.Fatalf("Down failed: %v", err)
	}
	if err := client.Up(context.Background(), "wan"); err != nil {
		t.Fatalf("Up failed: %v", err)
	}
	if len(mr.got) != 3 {
		t.Fatalf("expected 3 ubus calls, got %d", len(mr.got))
	}
}

type fakeStreamOpener struct {
	opens atomic.Int32
}

func (f *fakeStreamOpener) Open(_ context.Context) (io.ReadCloser, func() error, error) {
	n := f.opens.Add(1)
	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		if n == 1 {
			_, _ = pw.Write([]byte(`{"network.interface":{"action":"ifup","interface":"wan"}}` + "\n"))
			return
		}
		_, _ = pw.Write([]byte(`{"network.interface":{"action":"ifupdate","interface":"wan6"}}` + "\n"))
		time.Sleep(50 * time.Millisecond)
	}()
	return pr, func() error { return errors.New("eof") }, nil
}

func TestListenerReconnectAndFanOut(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	opener := &fakeStreamOpener{}
	listener := NewListener(opener, nil)

	ch1, unsub1 := listener.Subscribe(4)
	defer unsub1()
	ch2, unsub2 := listener.Subscribe(4)
	defer unsub2()

	go listener.Run(ctx)

	ev1 := <-ch1
	ev1b := <-ch2
	if ev1.Action != "ifup" || ev1.Interface != "wan" || ev1b.Action != "ifup" {
		t.Fatalf("unexpected first event: %+v / %+v", ev1, ev1b)
	}

	// Second event arrives after listener reconnects following EOF.
	ev2 := <-ch1
	if ev2.Action != "ifupdate" || ev2.Interface != "wan6" {
		t.Fatalf("unexpected reconnected event: %+v", ev2)
	}
}
