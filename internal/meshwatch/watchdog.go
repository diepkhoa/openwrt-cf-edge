package meshwatch

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/diepkhoa/openwrt-cf-edge/internal/config"
	"github.com/diepkhoa/openwrt-cf-edge/internal/metrics"
	"github.com/diepkhoa/openwrt-cf-edge/internal/netutil"
	"github.com/diepkhoa/openwrt-cf-edge/internal/notify"
)

// Watchdog monitors NetBird mesh peers over the overlay device and sends priority-gated alerts.
type Watchdog struct {
	cfg       *config.Config
	nb        NetBirdClient
	pinger    netutil.Pinger
	notifier  notify.Notifier
	logger    *slog.Logger
	resolveIP func(string) (string, error)
	nowFn     func() time.Time

	mu       sync.Mutex
	trackers []peerTracker
	selfIdx  int
}

// NewWatchdog constructs a MeshWatchdog supervisor.
func NewWatchdog(
	cfg *config.Config,
	nb NetBirdClient,
	pinger netutil.Pinger,
	notifier notify.Notifier,
	logger *slog.Logger,
) *Watchdog {
	if nb == nil {
		nb = ExecNetBirdClient{}
	}
	if pinger == nil {
		pinger = &netutil.RawPinger{}
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Watchdog{
		cfg:       cfg,
		nb:        nb,
		pinger:    pinger,
		notifier:  notifier,
		logger:    logger,
		resolveIP: metrics.ResolveInterfaceIP,
		nowFn:     time.Now,
		trackers:  make([]peerTracker, len(cfg.MeshWatchdog.Peers)),
		selfIdx:   -1,
	}
}

// SnapshotPeers implements metrics.PeerMetricsProvider so /metrics exports live mesh health.
func (w *Watchdog) SnapshotPeers() []metrics.PeerSample {
	w.mu.Lock()
	defer w.mu.Unlock()

	out := make([]metrics.PeerSample, 0, len(w.cfg.MeshWatchdog.Peers))
	for i, p := range w.cfg.MeshWatchdog.Peers {
		out = append(out, metrics.PeerSample{
			Name:  p.Name,
			IP:    p.IP,
			Site:  p.Site,
			Up:    w.trackers[i].lastUp,
			RTTMs: w.trackers[i].lastRTTMs,
		})
	}
	return out
}

// Run polls NetBird status and overlay peers periodically until ctx is cancelled.
func (w *Watchdog) Run(ctx context.Context) {
	if !w.cfg.MeshWatchdog.Enabled {
		return
	}

	ticker := time.NewTicker(w.cfg.MeshWatchdog.CheckInterval.Std())
	defer ticker.Stop()

	w.step(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.step(ctx)
		}
	}
}

func (w *Watchdog) step(ctx context.Context) {
	probeCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	nbCtx, nbCancel := context.WithTimeout(probeCtx, 5*time.Second)
	nbStat, nbErr := w.nb.Status(nbCtx)
	nbCancel()

	mgmtOK := nbErr == nil && nbStat.ManagementConnected
	selfIP := nbStat.SelfIP
	if selfIP == "" && w.resolveIP != nil {
		if ip, err := w.resolveIP(w.cfg.WAN.EffectiveOverlayDevice()); err == nil {
			selfIP = ip
		}
	}

	selfIdx := findPeerIndex(w.cfg.MeshWatchdog.Peers, selfIP)
	if selfIdx < 0 {
		w.logger.Debug("mesh_watchdog could not match local NetBird IP in peers list", "self_ip", selfIP, "err", nbErr)
		return
	}

	probeOK, rttMs := w.probePeers(probeCtx, selfIdx)

	w.mu.Lock()
	w.selfIdx = selfIdx
	alerts, delay := evaluateTransitions(w.cfg.MeshWatchdog, w.trackers, selfIdx, mgmtOK, probeOK, rttMs, w.nowFn())
	w.mu.Unlock()

	if len(alerts) == 0 {
		return
	}
	mgmtStillOK := true
	if delay > 0 {
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		mgmtStillOK = w.mgmtHealthy(ctx)
	}
	if !mgmtStillOK {
		return
	}

	for _, al := range alerts {
		if delay > 0 && !w.stillAuthorizedForTarget(ctx, selfIdx, al.TargetIdx) {
			continue
		}
		detail := fmt.Sprintf("missed %d probes (%d other-site peers online)", al.FailCount, al.OtherSites)
		if al.Status == "ONLINE" {
			detail = fmt.Sprintf("reachable again after %s downtime", al.DownFor.Round(time.Second))
		}
		w.logger.Warn("mesh watchdog peer transition", "peer", al.Peer.Name, "ip", al.Peer.IP, "status", al.Status, "detail", detail)
		if w.notifier != nil {
			msg := notify.FormatMeshPeerAlert(w.cfg.NodeName, al.Peer.Name, al.Peer.IP, al.Peer.Site, al.Status, detail)
			if err := w.notifier.Send(ctx, msg); err != nil {
				w.logger.Warn("failed sending mesh peer alert", "peer", al.Peer.Name, "err", err)
			}
		}
	}
}

func (w *Watchdog) mgmtHealthy(ctx context.Context) bool {
	if !w.cfg.MeshWatchdog.RequireNetBirdMgmt {
		return true
	}
	nbCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	st, err := w.nb.Status(nbCtx)
	cancel()
	return err == nil && st.ManagementConnected
}

func (w *Watchdog) stillAuthorizedForTarget(ctx context.Context, selfIdx, targetIdx int) bool {
	for i := 0; i < selfIdx; i++ {
		if i == targetIdx {
			continue
		}
		p := w.cfg.MeshWatchdog.Peers[i]
		if !p.CanNotify {
			continue
		}
		if w.pingOne(ctx, p.IP) >= 0 {
			return false
		}
	}
	return true
}

func (w *Watchdog) probePeers(ctx context.Context, selfIdx int) ([]bool, []float64) {
	n := len(w.cfg.MeshWatchdog.Peers)
	ok := make([]bool, n)
	rtt := make([]float64, n)
	var wg sync.WaitGroup
	for i, p := range w.cfg.MeshWatchdog.Peers {
		if i == selfIdx {
			ok[i] = true
			continue
		}
		wg.Add(1)
		go func(idx int, ip string) {
			defer wg.Done()
			if ms := w.pingOne(ctx, ip); ms >= 0 {
				ok[idx] = true
				rtt[idx] = ms
			}
		}(i, p.IP)
	}
	wg.Wait()
	return ok, rtt
}

func (w *Watchdog) pingOne(ctx context.Context, ip string) float64 {
	start := time.Now()
	if err := w.pinger.Ping(ctx, ip, w.cfg.WAN.EffectiveOverlayDevice(), 2*time.Second); err != nil {
		return -1
	}
	return float64(time.Since(start).Microseconds()) / 1000.0
}

func findPeerIndex(peers []config.MeshPeerConfig, selfIP string) int {
	if selfIP == "" {
		return -1
	}
	for i, p := range peers {
		if p.IP == selfIP {
			return i
		}
	}
	return -1
}
