package main

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var tzMu sync.Mutex

// syncLocalTimezone aligns time.Local with OpenWrt's /etc/TZ or /tmp/TZ when Go's
// pure-Go time package falls back to UTC on minimal systems lacking zoneinfo.
func syncLocalTimezone() {
	tzMu.Lock()
	defer tzMu.Unlock()

	loc := detectOpenWrtLocation("/etc/localtime", os.Getenv("TZ"), []string{"/etc/TZ", "/tmp/TZ"}, "/etc/config/system")
	if loc != nil {
		time.Local = loc
	}
}

func detectOpenWrtLocation(localtimePath, envTZ string, tzFiles []string, uciSystemPath string) *time.Location {
	// If TZ env var is explicitly set, try loading it as IANA or POSIX TZ.
	if s := strings.TrimSpace(envTZ); s != "" {
		if loc := resolveTZString(s); loc != nil {
			return loc
		}
	}

	// Respect standard OS zoneinfo when /etc/localtime exists and current local zone is non-UTC.
	if localtimePath != "" {
		if _, err := os.Stat(localtimePath); err == nil {
			_, offset := time.Now().Zone()
			if offset != 0 {
				return nil
			}
		}
	}

	for _, p := range tzFiles {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if loc := resolveTZString(string(data)); loc != nil {
			return loc
		}
	}

	if uciSystemPath != "" {
		if tz := readUCITimezone(uciSystemPath); tz != "" {
			if loc := resolveTZString(tz); loc != nil {
				return loc
			}
		}
	}
	return nil
}

func resolveTZString(raw string) *time.Location {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil
	}
	// If it looks like an IANA location (e.g. "Asia/Ho_Chi_Minh"), try LoadLocation first.
	if strings.Contains(s, "/") {
		if loc, err := time.LoadLocation(s); err == nil {
			return loc
		}
	}
	if loc, ok := parsePOSIXTZ(s); ok {
		return loc
	}
	if loc, err := time.LoadLocation(s); err == nil {
		return loc
	}
	return nil
}

// parsePOSIXTZ parses POSIX TZ strings written by OpenWrt to /tmp/TZ (e.g. "<+07>-7", "ICT-7", "<+0530>-5:30").
func parsePOSIXTZ(raw string) (*time.Location, bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil, false
	}
	// Strip DST transition rules after comma; extract std name + offset.
	if idx := strings.IndexByte(s, ','); idx >= 0 {
		s = s[:idx]
	}

	var name string
	var rest string
	if strings.HasPrefix(s, "<") {
		end := strings.IndexByte(s, '>')
		if end <= 1 {
			return nil, false
		}
		name = s[1:end]
		rest = s[end+1:]
	} else {
		i := 0
		for i < len(s) {
			c := s[i]
			if c == '+' || c == '-' || (c >= '0' && c <= '9') {
				break
			}
			i++
		}
		if i < 3 {
			return nil, false
		}
		name = s[:i]
		rest = s[i:]
	}

	if rest == "" {
		return nil, false
	}

	// Cut trailing DST abbreviation if present (e.g. "-5EDT" -> "-5").
	endOff := 0
	for endOff < len(rest) {
		c := rest[endOff]
		if (c >= '0' && c <= '9') || c == ':' || (endOff == 0 && (c == '+' || c == '-')) {
			endOff++
			continue
		}
		break
	}
	offStr := rest[:endOff]
	if offStr == "" {
		return nil, false
	}

	offsetSec, ok := parsePOSIXOffset(offStr)
	if !ok {
		return nil, false
	}
	return time.FixedZone(name, offsetSec), true
}

func parsePOSIXOffset(s string) (int, bool) {
	// In POSIX TZ, '-' means East of UTC (positive offset) and '+'/unsigned means West of UTC (negative).
	sign := -1
	if strings.HasPrefix(s, "-") {
		sign = 1
		s = s[1:]
	} else if strings.HasPrefix(s, "+") {
		sign = -1
		s = s[1:]
	}
	if s == "" {
		return 0, false
	}

	parts := strings.Split(s, ":")
	if len(parts) > 3 {
		return 0, false
	}
	var vals [3]int
	for i, p := range parts {
		v, err := strconv.Atoi(p)
		if err != nil || v < 0 {
			return 0, false
		}
		vals[i] = v
	}
	if vals[0] > 24 || vals[1] >= 60 || vals[2] >= 60 {
		return 0, false
	}
	total := vals[0]*3600 + vals[1]*60 + vals[2]
	return sign * total, true
}

func readUCITimezone(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "option") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[1] == "timezone" {
			val := strings.Join(fields[2:], " ")
			val = strings.Trim(val, `"'`)
			return strings.TrimSpace(val)
		}
	}
	return ""
}
