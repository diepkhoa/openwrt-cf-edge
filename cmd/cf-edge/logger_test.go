package main

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestNewLoggerWithWriterTimestampToggle(t *testing.T) {
	var noTimeBuf bytes.Buffer
	logNoTime := newLoggerWithWriter(&noTimeBuf, slog.LevelInfo, false)
	logNoTime.Info("WAN ubus event received", "action", "ifup", "interface", "wan6")

	gotNoTime := noTimeBuf.String()
	if strings.Contains(gotNoTime, "time=") {
		t.Fatalf("expected top-level time attribute omitted for syslog/non-TTY, got: %q", gotNoTime)
	}
	if !strings.Contains(gotNoTime, "level=INFO") || !strings.Contains(gotNoTime, `msg="WAN ubus event received"`) || !strings.Contains(gotNoTime, "interface=wan6") {
		t.Fatalf("missing expected log fields: %q", gotNoTime)
	}

	var withTimeBuf bytes.Buffer
	logWithTime := newLoggerWithWriter(&withTimeBuf, slog.LevelInfo, true)
	logWithTime.Info("interactive run")
	if !strings.Contains(withTimeBuf.String(), "time=") {
		t.Fatalf("expected time attribute present for interactive TTY, got: %q", withTimeBuf.String())
	}

	var groupBuf bytes.Buffer
	logGroup := newLoggerWithWriter(&groupBuf, slog.LevelInfo, false).WithGroup("meta")
	logGroup.Info("grouped", "time", "keep-me")
	if !strings.Contains(groupBuf.String(), "meta.time=keep-me") {
		t.Fatalf("expected grouped time attribute preserved, got: %q", groupBuf.String())
	}
}
