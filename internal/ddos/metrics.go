package ddos

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const conntrackCountPath = "/proc/sys/net/netfilter/nf_conntrack_count"

// RawCounters holds raw procfs/sysfs counters sampled at a point in time.
type RawCounters struct {
	Timestamp      time.Time
	Conntrack      int64
	WANRxBytes     uint64
	WANRxPackets   uint64
	OverlayTxBytes uint64
	LANTxBytes     uint64
}

// SampleReader reads kernel network and conntrack counters.
type SampleReader interface {
	Read(wanL3, overlayIface, lanIface string) (RawCounters, error)
}

// ProcSysReader reads counters directly from /proc and /sys on Linux.
type ProcSysReader struct {
	procRoot string
	sysRoot  string
}

// NewProcSysReader constructs a reader rooted at /proc and /sys.
func NewProcSysReader() *ProcSysReader {
	return &ProcSysReader{
		procRoot: "/proc",
		sysRoot:  "/sys",
	}
}

// Read collects conntrack, WAN RX bytes/packets, Overlay TX bytes, and optional LAN TX bytes.
func (r *ProcSysReader) Read(wanL3, overlayIface, lanIface string) (RawCounters, error) {
	var out RawCounters
	out.Timestamp = time.Now()

	ctPath := filepath.Join(r.procRoot, "sys", "net", "netfilter", "nf_conntrack_count")
	if r.procRoot == "/proc" {
		ctPath = conntrackCountPath
	}
	if ct, err := readInt64File(ctPath); err == nil {
		out.Conntrack = ct
	} else if !errors.Is(err, os.ErrNotExist) {
		return out, err
	}

	if wanL3 == "" {
		return out, errors.New("empty wan L3 device")
	}
	rxBytes, err := readUint64File(filepath.Join(r.sysRoot, "class", "net", wanL3, "statistics", "rx_bytes"))
	if err != nil {
		return out, fmt.Errorf("read wan rx_bytes: %w", err)
	}
	rxPkts, err := readUint64File(filepath.Join(r.sysRoot, "class", "net", wanL3, "statistics", "rx_packets"))
	if err != nil {
		return out, fmt.Errorf("read wan rx_packets: %w", err)
	}
	out.WANRxBytes = rxBytes
	out.WANRxPackets = rxPkts

	if overlayIface != "" {
		if txOverlay, err := readUint64File(filepath.Join(r.sysRoot, "class", "net", overlayIface, "statistics", "tx_bytes")); err == nil {
			out.OverlayTxBytes = txOverlay
		}
	}
	if lanIface != "" {
		if txLAN, err := readUint64File(filepath.Join(r.sysRoot, "class", "net", lanIface, "statistics", "tx_bytes")); err == nil {
			out.LANTxBytes = txLAN
		}
	}
	return out, nil
}

// RateSnapshot contains derived traffic rates between two consecutive RawCounters samples.
type RateSnapshot struct {
	Valid         bool
	Conntrack     int64
	RXWANMbps     float64
	TXOverlayMbps float64
	TXLANMbps     float64
	JunkMbps      float64
	RXPPS         float64
}

// ComputeRates computes traffic rates between prev and cur, guarding against counter resets.
func ComputeRates(prev, cur RawCounters) RateSnapshot {
	snap := RateSnapshot{Conntrack: cur.Conntrack}
	dt := cur.Timestamp.Sub(prev.Timestamp).Seconds()
	if dt <= 0 || prev.Timestamp.IsZero() {
		return snap
	}
	if cur.WANRxBytes < prev.WANRxBytes || cur.WANRxPackets < prev.WANRxPackets {
		// Interface counter reset (e.g., PPPoE device recreated).
		return snap
	}

	var dOverlay uint64
	if cur.OverlayTxBytes >= prev.OverlayTxBytes {
		dOverlay = cur.OverlayTxBytes - prev.OverlayTxBytes
	}
	var dLAN uint64
	if cur.LANTxBytes >= prev.LANTxBytes {
		dLAN = cur.LANTxBytes - prev.LANTxBytes
	}

	dWanBytes := cur.WANRxBytes - prev.WANRxBytes
	dWanPkts := cur.WANRxPackets - prev.WANRxPackets

	snap.Valid = true
	snap.RXWANMbps = float64(dWanBytes*8) / dt / 1_000_000.0
	snap.TXOverlayMbps = float64(dOverlay*8) / dt / 1_000_000.0
	snap.TXLANMbps = float64(dLAN*8) / dt / 1_000_000.0
	snap.JunkMbps = snap.RXWANMbps - snap.TXOverlayMbps - snap.TXLANMbps
	if snap.JunkMbps < 0 {
		snap.JunkMbps = 0
	}
	snap.RXPPS = float64(dWanPkts) / dt
	return snap
}

func readUint64File(path string) (uint64, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
}

func readInt64File(path string) (int64, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
}
