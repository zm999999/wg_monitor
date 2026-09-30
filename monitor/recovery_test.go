package monitor

import (
	"context"
	"testing"
	"time"

	"wg-monitor/config"
	"wg-monitor/logger"
	"wg-monitor/system"
)

func testRecoveryConfig() config.RecoveryConfig {
	return config.RecoveryConfig{
		WGRestartAfter:       config.Duration(30 * time.Second),
		NetworkRestartAfter:  config.Duration(90 * time.Second),
		ComputerRestartAfter: config.Duration(180 * time.Second),
		WGRestartWait:        config.Duration(5 * time.Millisecond),
		NetworkRestartWait:   config.Duration(5 * time.Millisecond),
		MaxWGRestart:         3,
		MaxNetworkRestart:    2,
		MaxRebootPerHour:     1,
		RebootCooldown:       config.Duration(30 * time.Minute),
		RecoveryCooldown:     config.Duration(50 * time.Millisecond),
	}
}

func newTestRM(cfg config.RecoveryConfig, wg *mockWG, netCtl *mockNet, sysCtl *mockSys, rebooter *system.RebootTracker) *RecoveryManager {
	log := logger.NewStderr(logger.LevelError)
	return NewRecoveryManager(cfg, wg, netCtl, sysCtl, rebooter, log)
}

func TestHealthy(t *testing.T) {
	wg := newMockWG()
	netC := newMockNet()
	sys := newMockSys()
	rm := newTestRM(testRecoveryConfig(), wg, netC, sys, system.NewRebootTracker(t.TempDir()+"/r.json", 1, time.Minute, time.Hour))

	rm.Process(context.Background(), HealthResult{Healthy: true, ServiceRunning: true, VPNReachable: true})

	if wg.restarts != 0 || netC.restarts != 0 || sys.reboots != 0 {
		t.Fatalf("healthy must not trigger recovery (wg=%d net=%d sys=%d)", wg.restarts, netC.restarts, sys.reboots)
	}
}

func TestTransientFailure(t *testing.T) {
	wg := newMockWG()
	netC := newMockNet()
	sys := newMockSys()
	rm := newTestRM(testRecoveryConfig(), wg, netC, sys, system.NewRebootTracker(t.TempDir()+"/r.json", 1, time.Minute, time.Hour))

	// A blip followed immediately by recovery must not trigger any action.
	rm.Process(context.Background(), HealthResult{Healthy: false})
	rm.Process(context.Background(), HealthResult{Healthy: true})

	if wg.restarts != 0 {
		t.Fatalf("transient failure should not restart WireGuard (got %d)", wg.restarts)
	}
	if rm.UnhealthyDuration() != 0 {
		t.Fatalf("counters should have reset (duration=%s)", rm.UnhealthyDuration())
	}
}

func TestWireGuardRecovery(t *testing.T) {
	wg := newMockWG()
	netC := newMockNet()
	sys := newMockSys()
	rm := newTestRM(testRecoveryConfig(), wg, netC, sys, system.NewRebootTracker(t.TempDir()+"/r.json", 1, time.Minute, time.Hour))

	past := time.Now().Add(-time.Minute) // 60s > 30s threshold
	rm.unhealthySince = &past
	rm.Process(context.Background(), HealthResult{Healthy: false})

	waitCh(wg.ch)
	if wg.restarts != 1 {
		t.Fatalf("expected 1 WireGuard restart, got %d", wg.restarts)
	}
	if netC.restarts != 0 || sys.reboots != 0 {
		t.Fatalf("no escalation expected yet (net=%d sys=%d)", netC.restarts, sys.reboots)
	}
}

func TestNetworkRecovery(t *testing.T) {
	wg := newMockWG()
	netC := newMockNet()
	sys := newMockSys()
	rm := newTestRM(testRecoveryConfig(), wg, netC, sys, system.NewRebootTracker(t.TempDir()+"/r.json", 1, time.Minute, time.Hour))

	past := time.Now().Add(-2 * time.Minute) // 120s -> network level
	rm.unhealthySince = &past
	rm.Process(context.Background(), HealthResult{Healthy: false})

	waitCh(netC.ch)
	if netC.restarts != 1 {
		t.Fatalf("expected 1 network restart, got %d", netC.restarts)
	}
	if wg.restarts != 0 || sys.reboots != 0 {
		t.Fatalf("wrong escalation (wg=%d sys=%d)", wg.restarts, sys.reboots)
	}
}

func TestRebootAllowed(t *testing.T) {
	wg := newMockWG()
	netC := newMockNet()
	sys := newMockSys()
	rm := newTestRM(testRecoveryConfig(), wg, netC, sys, system.NewRebootTracker(t.TempDir()+"/r.json", 1, time.Minute, time.Hour))

	past := time.Now().Add(-3 * time.Hour) // beyond computer threshold
	rm.unhealthySince = &past
	rm.Process(context.Background(), HealthResult{Healthy: false})

	waitCh(sys.ch)
	if sys.reboots != 1 {
		t.Fatalf("expected computer restart, got %d", sys.reboots)
	}
}

func TestRebootLimit(t *testing.T) {
	wg := newMockWG()
	netC := newMockNet()
	sys := newMockSys()
	rebooter := system.NewRebootTracker(t.TempDir()+"/r.json", 1, time.Minute, time.Hour)
	rebooter.Record(time.Now()) // already rebooted this hour
	rm := newTestRM(testRecoveryConfig(), wg, netC, sys, rebooter)

	past := time.Now().Add(-3 * time.Hour)
	rm.unhealthySince = &past
	rm.Process(context.Background(), HealthResult{Healthy: false})

	// Reboot must be blocked; no shutdown issued.
	if sys.reboots != 0 {
		t.Fatalf("reboot must be blocked by limit, got %d", sys.reboots)
	}
}

func TestRecoveryCooldown(t *testing.T) {
	wg := newMockWG()
	netC := newMockNet()
	sys := newMockSys()
	rm := newTestRM(testRecoveryConfig(), wg, netC, sys, system.NewRebootTracker(t.TempDir()+"/r.json", 1, time.Minute, time.Hour))

	past := time.Now().Add(-time.Minute)
	rm.unhealthySince = &past
	rm.Process(context.Background(), HealthResult{Healthy: false})
	waitCh(wg.ch) // first restart happened

	// Immediate second call must be suppressed by the cooldown (or active guard).
	rm.Process(context.Background(), HealthResult{Healthy: false})
	if wg.restarts != 1 {
		t.Fatalf("cooldown should prevent a second restart, got %d", wg.restarts)
	}
}

func TestResetAfterRecovery(t *testing.T) {
	wg := newMockWG()
	netC := newMockNet()
	sys := newMockSys()
	rm := newTestRM(testRecoveryConfig(), wg, netC, sys, system.NewRebootTracker(t.TempDir()+"/r.json", 1, time.Minute, time.Hour))

	past := time.Now().Add(-time.Minute)
	rm.unhealthySince = &past
	rm.Process(context.Background(), HealthResult{Healthy: false})
	waitCh(wg.ch)

	if rm.wgRestarts == 0 {
		t.Fatal("expected a wg restart count > 0")
	}
	// Recover.
	rm.Process(context.Background(), HealthResult{Healthy: true})
	if rm.wgRestarts != 0 || rm.UnhealthyDuration() != 0 || rm.CurrentState() != StateHealthy {
		t.Fatalf("counters not cleared after recovery (wg=%d dur=%s state=%s)", rm.wgRestarts, rm.UnhealthyDuration(), rm.CurrentState())
	}
}
