package monitor

import (
	"context"
	"sync"
	"time"

	"wg-monitor/config"
	"wg-monitor/logger"
	"wg-monitor/network"
	"wg-monitor/system"
	"wg-monitor/wireguard"
)

// actionTimeout bounds a single recovery goroutine regardless of the inner
// controller timeouts.
const actionTimeout = 120 * time.Second

// RecoveryManager drives the recovery state machine. It is the only place that
// triggers recovery actions. A single-flight guard guarantees at most one
// recovery action runs at a time, and a cooldown prevents rapid re-triggering.
type RecoveryManager struct {
	mu sync.Mutex

	cfg      config.RecoveryConfig
	wg       wireguard.Controller
	netCtl   network.Controller
	sysCtl   system.Controller
	rebooter *system.RebootTracker
	log      *logger.Logger

	unhealthySince *time.Time
	currentLevel   RecoveryLevel
	wgRestarts     int
	netRestarts    int
	lastActionAt   time.Time
	active         bool
}

// NewRecoveryManager wires the recovery dependencies.
func NewRecoveryManager(cfg config.RecoveryConfig, wg wireguard.Controller, netCtl network.Controller, sysCtl system.Controller, rebooter *system.RebootTracker, log *logger.Logger) *RecoveryManager {
	return &RecoveryManager{
		cfg:      cfg,
		wg:       wg,
		netCtl:   netCtl,
		sysCtl:   sysCtl,
		rebooter: rebooter,
		log:      log,
	}
}

// Process evaluates a health result and, if warranted, schedules a recovery
// action. It is safe to call every cycle; it never blocks on the running
// recovery (single-flight) and keeps recording health in the meantime.
func (rm *RecoveryManager) Process(ctx context.Context, res HealthResult) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	now := time.Now()

	if res.Healthy {
		if rm.unhealthySince != nil {
			rm.log.Infof("recovery success: vpn healthy again (resetting counters)")
		}
		rm.resetLocked()
		return
	}

	if rm.unhealthySince == nil {
		t := now
		rm.unhealthySince = &t
	}
	duration := now.Sub(*rm.unhealthySince)

	target := rm.levelForDuration(duration)
	if target == LevelHealthy {
		rm.log.Warnf("vpn unhealthy duration=%s observing (no action yet)", duration.Round(time.Second))
		return
	}

	// Cooldown: do not start a new action too soon after the previous one.
	if !rm.lastActionAt.IsZero() && now.Sub(rm.lastActionAt) < rm.cfg.RecoveryCooldown.Duration() {
		return
	}
	// Single-flight: a recovery is already running.
	if rm.active {
		return
	}

	rm.dispatchLocked(ctx, target, now)
}

func (rm *RecoveryManager) dispatchLocked(ctx context.Context, target RecoveryLevel, now time.Time) {
	switch target {
	case LevelRestartWireGuard:
		if rm.currentLevel > LevelRestartWireGuard {
			return
		}
		if rm.wgRestarts >= rm.cfg.MaxWGRestart {
			rm.log.Warnf("wg restart exhausted (count=%d); escalating to network", rm.wgRestarts)
			rm.currentLevel = LevelRestartNetwork
			return
		}
		rm.active = true
		rm.wgRestarts++
		rm.currentLevel = LevelRestartWireGuard
		rm.lastActionAt = now
		go rm.runAction(ctx, "restart_wireguard", func(c context.Context) error { return rm.wg.RestartTunnel(c) }, rm.cfg.WGRestartWait.Duration())

	case LevelRestartNetwork:
		if rm.currentLevel > LevelRestartNetwork {
			return
		}
		if rm.netRestarts >= rm.cfg.MaxNetworkRestart {
			rm.log.Warnf("network restart exhausted (count=%d); escalating to computer", rm.netRestarts)
			rm.currentLevel = LevelRestartComputer
			return
		}
		rm.active = true
		rm.netRestarts++
		rm.currentLevel = LevelRestartNetwork
		rm.lastActionAt = now
		go rm.runAction(ctx, "restart_network", func(c context.Context) error { return rm.netCtl.RestartAdapter(c) }, rm.cfg.NetworkRestartWait.Duration())

	case LevelRestartComputer:
		ok, reason := rm.rebooter.CanReboot(now)
		if !ok {
			rm.log.Errorf("AUTO_REBOOT_BLOCKED reason=%s", reason)
			rm.lastActionAt = now // throttle re-logging
			return
		}
		rm.active = true
		go rm.runReboot(ctx)
	}
}

// levelForDuration maps the continuous-unhealthy duration to the desired level.
func (rm *RecoveryManager) levelForDuration(d time.Duration) RecoveryLevel {
	switch {
	case d >= rm.cfg.ComputerRestartAfter.Duration():
		return LevelRestartComputer
	case d >= rm.cfg.NetworkRestartAfter.Duration():
		return LevelRestartNetwork
	case d >= rm.cfg.WGRestartAfter.Duration():
		return LevelRestartWireGuard
	default:
		return LevelHealthy
	}
}

func (rm *RecoveryManager) runAction(parent context.Context, action string, fn func(context.Context) error, wait time.Duration) {
	rm.log.Infof("recovery action=%s", action)
	ctx, cancel := context.WithTimeout(parent, actionTimeout)
	defer cancel()
	if err := fn(ctx); err != nil {
		rm.log.Errorf("recovery action=%s result=failed err=%v", action, err)
	} else {
		rm.log.Infof("recovery action=%s result=success", action)
	}
	if wait > 0 {
		select {
		case <-time.After(wait):
		case <-parent.Done():
		}
	}
	rm.mu.Lock()
	rm.active = false
	rm.mu.Unlock()
}

func (rm *RecoveryManager) runReboot(parent context.Context) {
	rm.log.Errorf("recovery action=restart_computer (escalation limit reached)")
	rm.rebooter.Record(time.Now())
	rm.mu.Lock()
	rm.lastActionAt = time.Now()
	rm.mu.Unlock()
	if err := rm.sysCtl.RestartComputer(parent); err != nil {
		rm.log.Errorf("recovery action=restart_computer result=failed err=%v", err)
	}
	rm.mu.Lock()
	rm.active = false
	rm.mu.Unlock()
}

// resetLocked clears the failure timer and counters after a healthy result.
// It deliberately leaves lastActionAt and active untouched: the cooldown must
// still apply after a recovery, and a running action must finish on its own.
func (rm *RecoveryManager) resetLocked() {
	rm.unhealthySince = nil
	rm.currentLevel = LevelHealthy
	rm.wgRestarts = 0
	rm.netRestarts = 0
}

// CurrentState reports the state-machine position for diagnostics.
func (rm *RecoveryManager) CurrentState() HealthState {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	if rm.unhealthySince == nil {
		return StateHealthy
	}
	switch rm.currentLevel {
	case LevelRestartWireGuard:
		return StateWGRestart
	case LevelRestartNetwork:
		return StateNetworkRestart
	case LevelRestartComputer:
		return StateComputerRestart
	default:
		return StateDegraded
	}
}

// UnhealthyDuration reports how long the VPN has been unhealthy (0 if healthy).
func (rm *RecoveryManager) UnhealthyDuration() time.Duration {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	if rm.unhealthySince == nil {
		return 0
	}
	return time.Since(*rm.unhealthySince)
}
