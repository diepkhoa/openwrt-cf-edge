package main

import (
	"io"
	"log/slog"
	"os"
)

// newLogger creates a text slog.Logger that omits the top-level "time" attribute
// when writing to a non-TTY (such as OpenWrt procd -> logd syslog) or when forceNoTime is true.
func newLogger(w *os.File, level slog.Level, forceNoTime bool) *slog.Logger {
	includeTime := !forceNoTime && isTerminalFile(w)
	return newLoggerWithWriter(w, level, includeTime)
}

func newLoggerWithWriter(w io.Writer, level slog.Level, includeTime bool) *slog.Logger {
	opts := &slog.HandlerOptions{Level: level}
	if !includeTime {
		opts.ReplaceAttr = func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		}
	}
	return slog.New(slog.NewTextHandler(w, opts))
}

func isTerminalFile(f *os.File) bool {
	if f == nil {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}
