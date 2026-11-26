package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParsePOSIXTZ(t *testing.T) {
	cases := []struct {
		raw        string
		wantOK     bool
		wantName   string
		wantOffset int
	}{
		{raw: "<+07>-7\n", wantOK: true, wantName: "+07", wantOffset: 7 * 3600},
		{raw: "ICT-7", wantOK: true, wantName: "ICT", wantOffset: 7 * 3600},
		{raw: "<+0530>-5:30", wantOK: true, wantName: "+0530", wantOffset: 5*3600 + 30*60},
		{raw: "<-03>3", wantOK: true, wantName: "-03", wantOffset: -3 * 3600},
		{raw: "EST5EDT,M3.2.0,M11.1.0", wantOK: true, wantName: "EST", wantOffset: -5 * 3600},
		{raw: "UTC0", wantOK: true, wantName: "UTC", wantOffset: 0},
		{raw: "invalid", wantOK: false},
		{raw: "", wantOK: false},
	}

	for _, tc := range cases {
		loc, ok := parsePOSIXTZ(tc.raw)
		if ok != tc.wantOK {
			t.Fatalf("parsePOSIXTZ(%q) ok=%v, want %v", tc.raw, ok, tc.wantOK)
		}
		if !ok {
			continue
		}
		name, offset := time.Date(2026, 11, 27, 0, 0, 0, 0, loc).Zone()
		if name != tc.wantName || offset != tc.wantOffset {
			t.Fatalf("parsePOSIXTZ(%q) = (%q, %d), want (%q, %d)", tc.raw, name, offset, tc.wantName, tc.wantOffset)
		}
	}
}

func TestDetectOpenWrtLocationFromTZFileAndUCI(t *testing.T) {
	dir := t.TempDir()
	tmpTZ := filepath.Join(dir, "TZ")
	if err := os.WriteFile(tmpTZ, []byte("<+07>-7\n"), 0644); err != nil {
		t.Fatal(err)
	}

	loc := detectOpenWrtLocation(filepath.Join(dir, "missing-localtime"), "", []string{tmpTZ}, "")
	if loc == nil {
		t.Fatal("expected non-nil location from /tmp/TZ")
	}
	nowInLoc := time.Date(2026, 11, 27, 2, 41, 55, 0, loc)
	next := nextDailyRun(nowInLoc, 3, 30)
	_, offset := next.Zone()
	if offset != 7*3600 || next.Hour() != 3 || next.Minute() != 30 {
		t.Fatalf("unexpected local schedule with OpenWrt TZ: next=%v offset=%d", next, offset)
	}

	// Fallback to /etc/config/system when /tmp/TZ does not exist.
	uciPath := filepath.Join(dir, "system")
	uciContent := `
config system
	option hostname 'knr3053'
	option timezone '<+07>-7'
	option zonename 'Asia/Ho Chi Minh'
`
	if err := os.WriteFile(uciPath, []byte(uciContent), 0644); err != nil {
		t.Fatal(err)
	}
	locUCI := detectOpenWrtLocation(filepath.Join(dir, "missing-localtime"), "", []string{filepath.Join(dir, "missing-TZ")}, uciPath)
	if locUCI == nil {
		t.Fatal("expected non-nil location from UCI /etc/config/system")
	}
	_, offUCI := time.Now().In(locUCI).Zone()
	if offUCI != 7*3600 {
		t.Fatalf("UCI offset=%d, want %d", offUCI, 7*3600)
	}
}
