package monitor

import (
	"context"
	"fmt"
	"strings"
	"time"

	"wg-monitor/config"
	"wg-monitor/logger"
)

// Monitor owns the health-check loop. It runs detection (HealthChecker) and
// recovery (RecoveryManager) but contains no OS-specific logic itself.
type Monitor struct {
	cfg        *config.Config
	checker    *HealthChecker
	recovery   *RecoveryManager
	log        *logger.Logger
	graceUntil time.Time
}

// New builds a Monitor. gracePeriod suppresses recovery for that long after
// start so Windows can finish initializing network/WireGuard on boot.
func New(cfg *config.Config, checker *HealthChecker, recovery *RecoveryManager, log *logger.Logger) *Monitor {
	return &Monitor{
		cfg:        cfg,
		checker:    checker,
		recovery:   recovery,
		log:        log,
		graceUntil: time.Now().Add(cfg.Health.StartupGracePeriod.Duration()),
	}
}

// Run loops until ctx is cancelled. Each tick performs a health check and, once
// the startup grace period has elapsed, feeds the result to the recovery
// manager. On cancellation it returns promptly (in-progress recovery finishes
// under its own context).
func (m *Monitor) Run(ctx context.Context) error {
	m.log.Infof("monitor started; startup grace period until %s",
		m.graceUntil.Format("15:04:05"))
	ticker := time.NewTicker(m.cfg.Health.Interval.Duration())
	defer ticker.Stop()

	m.cycle(ctx)
	for {
		select {
		case <-ctx.Done():
			m.log.Infof("monitor stopping (ctx cancelled)")
			return nil
		case <-ticker.C:
			m.cycle(ctx)
		}
	}
}

func (m *Monitor) cycle(ctx context.Context) {
	res := m.checker.Check(ctx)
	m.logResult(res)

	if time.Now().Before(m.graceUntil) {
		m.log.Debugf("startup grace period active; recovery suppressed (state=%s)", m.recovery.CurrentState())
		return
	}
	m.recovery.Process(ctx, res)
}

func (m *Monitor) logResult(res HealthResult) {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("health check service=%s", res.ServiceState))
	if res.HasHandshake {
		sb.WriteString(fmt.Sprintf(" handshake_age=%s", res.HandshakeAge.Round(time.Second)))
	} else {
		sb.WriteString(" handshake_age=none")
	}
	if res.InternetReachable {
		sb.WriteString(" internet=ok")
	} else {
		sb.WriteString(" internet=fail")
	}
	if res.VPNReachable {
		sb.WriteString(" vpn=healthy")
	} else {
		sb.WriteString(" vpn=unhealthy")
	}
	if res.Error != nil {
		sb.WriteString(fmt.Sprintf(" err=%v", res.Error))
	}
	m.log.Infof(sb.String())

	for _, t := range res.FailedTargets {
		m.log.Warnf("vpn target failed target=%s", t)
	}
	for _, t := range res.SuccessfulTargets {
		m.log.Debugf("vpn target ok target=%s", t)
	}
}

// Check runs a single health probe (used by the `check` subcommand).
func (m *Monitor) Check(ctx context.Context) HealthResult {
	return m.checker.Check(ctx)
}

// Summary renders a one-shot health summary for the `check` subcommand.
func (m *Monitor) Summary(res HealthResult) string {
	var b strings.Builder
	service := res.ServiceState.String()
	if !res.ServiceRunning {
		service = "DOWN(" + service + ")"
	}
	handshake := "none"
	if res.HasHandshake {
		handshake = res.HandshakeAge.Round(time.Second).String()
	}
	internet := "OK"
	if !res.InternetReachable {
		internet = "FAIL"
	}
	vpn := "OK"
	if !res.VPNReachable {
		vpn = "FAIL"
	}
	overall := "HEALTHY"
	if !res.Healthy {
		overall = "UNHEALTHY"
	}
	fmt.Fprintf(&b, "WireGuard Service : %s\n", service)
	fmt.Fprintf(&b, "Handshake Age     : %s\n", handshake)
	fmt.Fprintf(&b, "Internet          : %s\n", internet)
	fmt.Fprintf(&b, "VPN Target        : %s\n", vpn)
	fmt.Fprintf(&b, "Overall           : %s\n", overall)
	if len(res.FailedTargets) > 0 {
		fmt.Fprintf(&b, "Failed Targets    : %s\n", strings.Join(res.FailedTargets, ", "))
	}
	return b.String()
}
