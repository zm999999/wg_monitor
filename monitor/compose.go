package monitor

import (
	"path/filepath"
	"time"

	"wg-monitor/config"
	"wg-monitor/logger"
	"wg-monitor/network"
	"wg-monitor/system"
	"wg-monitor/wireguard"
)

// Compose wires the real (Windows) controllers and returns a ready Monitor plus
// its RecoveryManager. Keeping composition here means run/check/service modes
// share identical wiring.
func Compose(cfg *config.Config, log *logger.Logger) (*Monitor, *RecoveryManager) {
	wgCtl := wireguard.NewController(
		cfg.WireGuard.ServiceName,
		cfg.WireGuard.InterfaceName,
		cfg.WireGuard.WGExecutable,
		wireguard.DefaultTimeouts(),
	)

	checker := network.NewConnectivityChecker(5*time.Second, 5*time.Second)

	targets := make([]network.Target, 0, len(cfg.Targets))
	for _, t := range cfg.Targets {
		targets = append(targets, network.Target{Host: t.Host, Port: t.Port, Protocol: t.Protocol})
	}
	var internet *network.Target
	if cfg.Internet != nil {
		internet = &network.Target{Host: cfg.Internet.Host, Port: cfg.Internet.Port, Protocol: cfg.Internet.Protocol}
	}

	health := NewHealthChecker(wgCtl, checker, targets, internet, cfg.Health.MinSuccessTargets)

	netCtl := network.NewController(cfg.Network.AdapterName, cfg.Recovery.NetworkRestartWait.Duration())
	sysCtl := system.NewController(10)
	rebootPath := filepath.Join(cfg.Windows.StateDir, "reboots.json")
	rebooter := system.NewRebootTracker(
		rebootPath,
		cfg.Recovery.MaxRebootPerHour,
		cfg.Recovery.RebootCooldown.Duration(),
		time.Hour,
	)

	recovery := NewRecoveryManager(cfg.Recovery, wgCtl, netCtl, sysCtl, rebooter, log)
	mon := New(cfg, health, recovery, log)
	return mon, recovery
}
