package monitor

import (
	"context"
	"fmt"
	"time"

	"wg-monitor/network"
	"wg-monitor/wireguard"
)

// HealthResult is the unified health snapshot produced every cycle.
type HealthResult struct {
	Timestamp         time.Time
	ServiceRunning    bool
	ServiceState      wireguard.ServiceState
	HandshakeAge      time.Duration
	HasHandshake      bool
	InternetReachable bool
	VPNReachable      bool
	Healthy           bool

	FailedTargets     []string
	SuccessfulTargets []string
	Error             error
}

// HealthChecker runs the layered health probes and produces a HealthResult.
// It must not perform any recovery — detection and recovery are separated.
type HealthChecker struct {
	wg         wireguard.Controller
	checker    network.TargetChecker
	targets    []network.Target
	internet   *network.Target
	minSuccess int
}

// NewHealthChecker builds a checker. internet may be nil (then InternetReachable
// is reported as true and not used to block the healthy verdict).
func NewHealthChecker(wg wireguard.Controller, checker network.TargetChecker, targets []network.Target, internet *network.Target, minSuccess int) *HealthChecker {
	if minSuccess < 1 {
		minSuccess = 1
	}
	return &HealthChecker{wg: wg, checker: checker, targets: targets, internet: internet, minSuccess: minSuccess}
}

// Check runs all probes. Any single failure is captured, never panics.
func (h *HealthChecker) Check(ctx context.Context) HealthResult {
	res := HealthResult{Timestamp: time.Now()}

	state, err := h.wg.ServiceStatus(ctx)
	res.ServiceState = state
	res.ServiceRunning = state == wireguard.StateRunning
	if err != nil {
		res.Error = err
	}

	if ts, err := h.wg.TunnelStatus(ctx); err == nil && ts != nil && ts.Peer != nil {
		if ts.Peer.HasHandshake {
			res.HasHandshake = true
			res.HandshakeAge = time.Since(ts.Peer.LatestHandshake)
		}
	} else if err != nil {
		if res.Error == nil {
			res.Error = err
		}
	}

	// VPN internal targets: at least minSuccess must succeed.
	var success, fail int
	for _, t := range h.targets {
		ok, _, err := h.checker.Check(ctx, t)
		addr := targetAddr(t)
		if ok {
			success++
			res.SuccessfulTargets = append(res.SuccessfulTargets, addr)
		} else {
			fail++
			res.FailedTargets = append(res.FailedTargets, addr)
		}
		_ = err
	}
	res.VPNReachable = success >= h.minSuccess

	// Optional public internet check (informational only).
	if h.internet != nil {
		ok, _, _ := h.checker.Check(ctx, *h.internet)
		res.InternetReachable = ok
	} else {
		res.InternetReachable = true
	}

	// Healthy = WireGuard service up AND at least one VPN target reachable.
	// Handshake age alone never decides health (no traffic => stale handshake).
	res.Healthy = res.ServiceRunning && res.VPNReachable
	return res
}

func targetAddr(t network.Target) string {
	if t.Protocol == "icmp" || t.Port == 0 {
		return fmt.Sprintf("%s (icmp)", t.Host)
	}
	return fmt.Sprintf("%s:%d (%s)", t.Host, t.Port, t.Protocol)
}
