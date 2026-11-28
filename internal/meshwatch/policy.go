package meshwatch

import (
	"time"

	"github.com/diepkhoa/openwrt-cf-edge/internal/config"
)

type peerTracker struct {
	failCount     int
	recoveryCount int
	alertedDown   bool
	downSince     time.Time
	lastUp        bool
	lastRTTMs     float64
}

type pendingAlert struct {
	TargetIdx  int
	Peer       config.MeshPeerConfig
	Status     string // "OFFLINE" or "ONLINE"
	DownFor    time.Duration
	FailCount  int
	OtherSites int
}

// evaluateTransitions updates peer state counters and computes any alerts this node is authorized to send.
func evaluateTransitions(
	cfg config.MeshWatchdogConfig,
	trackers []peerTracker,
	selfIdx int,
	mgmtOK bool,
	probeOK []bool,
	rttMs []float64,
	now time.Time,
) (alerts []pendingAlert, delay time.Duration) {
	if selfIdx < 0 || selfIdx >= len(cfg.Peers) {
		return nil, 0
	}

	selfSite := cfg.Peers[selfIdx].Site
	otherSiteOnline := 0
	for i, p := range cfg.Peers {
		if i == selfIdx {
			continue
		}
		trackers[i].lastUp = probeOK[i]
		trackers[i].lastRTTMs = rttMs[i]

		if probeOK[i] {
			if p.Site != selfSite {
				otherSiteOnline++
			}
			trackers[i].failCount = 0
			if trackers[i].alertedDown {
				trackers[i].recoveryCount++
			}
		} else {
			trackers[i].recoveryCount = 0
			trackers[i].failCount++
		}
	}
	trackers[selfIdx].lastUp = true

	// Gate 1 & Gate 2: Require local NetBird management connection + at least N other-site peers online.
	if cfg.RequireNetBirdMgmt && !mgmtOK {
		return nil, 0
	}
	if otherSiteOnline < cfg.MinOtherSiteOnline {
		return nil, 0
	}

	// Gate 3: Evaluate per-target transitions and check priority per target.
	// Note: if target i is the highest-priority peer itself recovering (ONLINE), a lower-rank
	// reporter that tracked target i's outage remains authorized unless another peer j < selfIdx (j != i) is online.
	for i, p := range cfg.Peers {
		if i == selfIdx {
			continue
		}
		tr := &trackers[i]
		if !tr.alertedDown && tr.failCount >= cfg.FailThreshold {
			tr.alertedDown = true
			tr.downSince = now
			tr.recoveryCount = 0
			if rank, ok := priorityRankForTarget(cfg, selfIdx, i, probeOK); ok {
				if d := time.Duration(rank) * cfg.RankDelayStep.Std(); d > delay {
					delay = d
				}
				alerts = append(alerts, pendingAlert{
					TargetIdx:  i,
					Peer:       p,
					Status:     "OFFLINE",
					FailCount:  tr.failCount,
					OtherSites: otherSiteOnline,
				})
			}
		} else if tr.alertedDown && tr.recoveryCount >= cfg.RecoveryThreshold {
			tr.alertedDown = false
			downFor := time.Duration(0)
			if !tr.downSince.IsZero() {
				downFor = now.Sub(tr.downSince)
			}
			tr.downSince = time.Time{}
			tr.recoveryCount = 0
			if rank, ok := priorityRankForTarget(cfg, selfIdx, i, probeOK); ok {
				if d := time.Duration(rank) * cfg.RankDelayStep.Std(); d > delay {
					delay = d
				}
				alerts = append(alerts, pendingAlert{
					TargetIdx:  i,
					Peer:       p,
					Status:     "ONLINE",
					DownFor:    downFor,
					OtherSites: otherSiteOnline,
				})
			}
		}
	}
	return alerts, delay
}

func priorityRankForTarget(cfg config.MeshWatchdogConfig, selfIdx, targetIdx int, probeOK []bool) (rank int, authorized bool) {
	if !cfg.Peers[selfIdx].CanNotify {
		return 0, false
	}
	for j := 0; j < selfIdx; j++ {
		if !cfg.Peers[j].CanNotify || j == targetIdx {
			continue
		}
		if probeOK[j] {
			return 0, false
		}
		rank++
	}
	return rank, true
}
