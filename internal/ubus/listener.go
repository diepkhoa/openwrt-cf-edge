package ubus

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Event represents an event emitted by `ubus listen network.interface`.
type Event struct {
	Action    string `json:"action"`
	Interface string `json:"interface"`
	Device    string `json:"device,omitempty"`
	L3Device  string `json:"l3_device,omitempty"`
}

// StreamOpener starts a `ubus listen network.interface` stream.
type StreamOpener interface {
	Open(ctx context.Context) (io.ReadCloser, func() error, error)
}

// ExecStreamOpener runs `ubus listen network.interface` via os/exec.
type ExecStreamOpener struct{}

// Open launches `ubus listen network.interface` and returns its stdout stream.
func (ExecStreamOpener) Open(ctx context.Context) (io.ReadCloser, func() error, error) {
	cmd := exec.CommandContext(ctx, "ubus", "listen", "network.interface")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}
	return stdout, cmd.Wait, nil
}

// Listener maintains an auto-restarting `ubus listen network.interface` stream
// and fans out parsed events to multiple subscribers without blocking.
type Listener struct {
	opener StreamOpener
	logger *slog.Logger

	mu   sync.RWMutex
	subs map[int]chan Event
	next int
}

// NewListener constructs a ubus event Listener.
func NewListener(opener StreamOpener, logger *slog.Logger) *Listener {
	if opener == nil {
		opener = ExecStreamOpener{}
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Listener{
		opener: opener,
		logger: logger,
		subs:   make(map[int]chan Event),
	}
}

// Subscribe registers a buffered channel to receive network.interface events.
func (l *Listener) Subscribe(bufSize int) (<-chan Event, func()) {
	if bufSize <= 0 {
		bufSize = 16
	}
	ch := make(chan Event, bufSize)

	l.mu.Lock()
	id := l.next
	l.next++
	l.subs[id] = ch
	l.mu.Unlock()

	cancel := func() {
		l.mu.Lock()
		if existing, ok := l.subs[id]; ok {
			delete(l.subs, id)
			close(existing)
		}
		l.mu.Unlock()
	}
	return ch, cancel
}

// Run continuously listens for ubus events and reconnects with backoff if disconnected.
func (l *Listener) Run(ctx context.Context) {
	backoff := time.Second
	const maxBackoff = 10 * time.Second

	for {
		if ctx.Err() != nil {
			return
		}
		startedAt := time.Now()
		err := l.consumeStream(ctx)
		if ctx.Err() != nil {
			return
		}
		if time.Since(startedAt) > 30*time.Second {
			backoff = time.Second
		}
		l.logger.Warn("ubus listen stream ended, restarting", "err", err, "backoff", backoff)

		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

func (l *Listener) consumeStream(ctx context.Context) error {
	stream, waitFn, err := l.opener.Open(ctx)
	if err != nil {
		return err
	}
	defer stream.Close()

	scanner := bufio.NewScanner(stream)
	scanner.Buffer(make([]byte, 4096), 64*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		ev, ok := parseEventLine(line)
		if ok {
			l.publish(ev)
		}
	}
	scanErr := scanner.Err()
	if waitFn != nil {
		if waitErr := waitFn(); waitErr != nil && scanErr == nil {
			return waitErr
		}
	}
	return scanErr
}

func parseEventLine(line string) (Event, bool) {
	var envelope map[string]Event
	if err := json.Unmarshal([]byte(line), &envelope); err != nil {
		return Event{}, false
	}
	ev, ok := envelope["network.interface"]
	if !ok || strings.TrimSpace(ev.Action) == "" {
		return Event{}, false
	}
	return ev, true
}

func (l *Listener) publish(ev Event) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	for _, ch := range l.subs {
		select {
		case ch <- ev:
		default:
			// Drop oldest event if subscriber channel is full so ubus reader never blocks.
			select {
			case <-ch:
			default:
			}
			select {
			case ch <- ev:
			default:
			}
		}
	}
}
