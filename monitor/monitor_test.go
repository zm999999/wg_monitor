package monitor

import (
	"context"
	"testing"
	"time"

	"wg-monitor/config"
	"wg-monitor/logger"
	"wg-monitor/network"
	"wg-monitor/system"
	"wg-monitor/wireguard"
)

func TestStartupGracePeriod(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Health.StartupGracePeriod = config.Duration(time.Hour)

	wg := newMockWG()
	wg.state = wireguard.StateStopped
	tc := &mockTargetChecker{ok: false}
	checker := NewHealthChecker(wg, tc, []network.Target{{Host: "10.10.0.1", Port: 443, Protocol: "tcp"}}, nil, 1)
	log := logger.NewStderr(logger.LevelError)
	rm := NewRecoveryManager(cfg.Recovery, wg, newMockNet(), newMockSys(),
		system.NewRebootTracker(t.TempDir()+"/r.json", 1, time.Minute, time.Hour),
		logger.NewStderr(logger.LevelError))
	mon := New(cfg, checker, rm, log)
	mon.graceUntil = time.Now().Add(time.Hour)

	// During the grace period, a failing health result must NOT trigger recovery.
	mon.cycle(context.Background())

	if rm.UnhealthyDuration() != 0 {
		t.Fatalf("recovery must be suppressed during grace period (UnhealthyDuration=%s)", rm.UnhealthyDuration())
	}
	if wg.restarts != 0 {
		t.Fatalf("no restart allowed during grace period (got %d)", wg.restarts)
	}
}
