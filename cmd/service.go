// Package cmd implements the Windows Service control surface (install /
// uninstall / start / stop / status) and the svc.Handler that runs the monitor
// when launched by the Service Control Manager.
package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"wg-monitor/config"
	"wg-monitor/logger"
	"wg-monitor/monitor"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// ServiceName is the registered Windows service name. It MUST match the name
// passed to svc.Run when the SCM launches the binary.
const ServiceName = "WGMonitor"

const (
	displayName = "WG Monitor"
	description = "WireGuard VPN auto-monitor & self-healing Windows service"
	stopTimeout = 30 * time.Second
)

// ServiceHandler implements svc.Handler.
type ServiceHandler struct {
	mon  *monitor.Monitor
	log  *logger.Logger
	done chan struct{}
}

// NewServiceHandler builds a handler wrapping the monitor.
func NewServiceHandler(mon *monitor.Monitor, log *logger.Logger) *ServiceHandler {
	return &ServiceHandler{mon: mon, log: log, done: make(chan struct{})}
}

// Execute is invoked by the SCM. It runs the monitor until a Stop/Shutdown
// control arrives, then cancels the monitor context and waits for it to finish.
func (h *ServiceHandler) Execute(_ []string, r <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	running := svc.Status{State: svc.Running, Accepts: cmdsAccepted}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	h.log.Infof("service executing (START_PENDING)")
	status <- svc.Status{State: svc.StartPending, Accepts: cmdsAccepted}

	go func() {
		if err := h.mon.Run(ctx); err != nil {
			h.log.Errorf("monitor run error: %v", err)
		}
		close(h.done)
	}()

	status <- running

	for req := range r {
		switch req.Cmd {
		case svc.Interrogate:
			status <- running
		case svc.Stop, svc.Shutdown:
			h.log.Infof("service stop requested")
			status <- svc.Status{State: svc.StopPending, Accepts: cmdsAccepted}
			cancel()
			select {
			case <-h.done:
			case <-time.After(stopTimeout):
				h.log.Warnf("service stop timed out after %s", stopTimeout)
			}
			status <- svc.Status{State: svc.Stopped, Accepts: cmdsAccepted}
			return false, 0
		}
	}
	return false, 0
}

func exePath() (string, error) {
	p, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Abs(p)
}

// InstallService registers the service for automatic start and installs the
// event source. configPath, if non-empty, is embedded into the service command
// line (BinaryPathName) so the service launched by the SCM uses that exact
// config rather than the runtime fallback resolution. Requires administrator.
func InstallService(configPath string) error {
	ex, err := exePath()
	if err != nil {
		return err
	}
	// Embed the -config argument into the service command line. The SCM passes
	// BinaryPathName as argv to the service, and findConfig() reads -config
	// from os.Args — so this is how an operator-specified config reaches the
	// service. The exe path is always quoted to survive spaces.
	binPath := `"` + ex + `"`
	if configPath != "" {
		binPath += ` -config "` + configPath + `"`
	}
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect service manager: %w", err)
	}
	defer m.Disconnect()

	if s, err := m.OpenService(ServiceName); err == nil {
		s.Close()
		return fmt.Errorf("service %s already exists", ServiceName)
	}
	s, err := m.CreateService(ServiceName, ex, mgr.Config{
		DisplayName:    displayName,
		Description:    description,
		BinaryPathName: binPath,
		StartType:      mgr.StartAutomatic,
		ServiceType:    windows.SERVICE_WIN32_OWN_PROCESS,
		Dependencies:   []string{"WireGuard"},
	})
	if err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	defer s.Close()

	logger.InstallEventSource(ServiceName)
	if configPath != "" {
		fmt.Printf("service %s installed (start=auto) config=%s\n", ServiceName, configPath)
		return nil
	}
	// No -config supplied: report the location the service will actually load
	// (same precedence as findConfig: WGMONITOR_CONFIG env, then config.yaml
	// next to the exe). This is informational only — install never fails on a
	// missing config; that error only happens at service start.
	if hint := resolveConfigHint(); hint != "" {
		fmt.Printf("service %s installed (start=auto) config=%s\n", ServiceName, hint)
	} else {
		fmt.Printf("service %s installed (start=auto); config resolved at start from WGMONITOR_CONFIG or config.yaml next to the exe\n", ServiceName)
	}
	return nil
}

// resolveConfigHint returns the config path the service would load when no
// -config was given, using the same precedence as findConfig (env, then exe-dir
// config.yaml). Returns "" when neither exists at install time — the service
// will resolve it again at start, so install must not fail here.
func resolveConfigHint() string {
	if p := os.Getenv("WGMONITOR_CONFIG"); p != "" {
		return p
	}
	if ex, err := exePath(); err == nil {
		cand := filepath.Join(filepath.Dir(ex), "config.yaml")
		if _, err := os.Stat(cand); err == nil {
			return cand
		}
	}
	return ""
}

// UninstallService deletes the service and removes the event source.
func UninstallService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect service manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(ServiceName)
	if err != nil {
		return fmt.Errorf("service %s not found: %w", ServiceName, err)
	}
	defer s.Close()

	if err := s.Delete(); err != nil {
		return fmt.Errorf("delete service: %w", err)
	}
	logger.RemoveEventSource(ServiceName)
	fmt.Printf("service %s uninstalled\n", ServiceName)
	return nil
}

// StartService sends the start control to the registered service.
func StartService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect service manager: %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(ServiceName)
	if err != nil {
		return fmt.Errorf("service %s not found: %w", ServiceName, err)
	}
	defer s.Close()
	if err := s.Start(); err != nil {
		return fmt.Errorf("start service: %w", err)
	}
	fmt.Printf("service %s start sent\n", ServiceName)
	return nil
}

// StopService sends the stop control to the registered service.
func StopService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect service manager: %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(ServiceName)
	if err != nil {
		return fmt.Errorf("service %s not found: %w", ServiceName, err)
	}
	defer s.Close()
	if _, err := s.Control(svc.Stop); err != nil {
		return fmt.Errorf("stop service: %w", err)
	}
	fmt.Printf("service %s stop sent\n", ServiceName)
	return nil
}

// QueryStatus returns the current service state name.
func QueryStatus() (string, error) {
	m, err := mgr.Connect()
	if err != nil {
		return "", fmt.Errorf("connect service manager: %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(ServiceName)
	if err != nil {
		return "", fmt.Errorf("service %s not found: %w", ServiceName, err)
	}
	defer s.Close()
	st, err := s.Query()
	if err != nil {
		return "", fmt.Errorf("query service: %w", err)
	}
	return stateName(st.State), nil
}

func stateName(state svc.State) string {
	switch state {
	case svc.Stopped:
		return "STOPPED"
	case svc.StartPending:
		return "START_PENDING"
	case svc.StopPending:
		return "STOP_PENDING"
	case svc.Running:
		return "RUNNING"
	case svc.ContinuePending:
		return "CONTINUE_PENDING"
	case svc.PausePending:
		return "PAUSE_PENDING"
	case svc.Paused:
		return "PAUSED"
	default:
		return "UNKNOWN"
	}
}

// LoadConfig resolves and loads the configuration for service-mode execution.
func LoadConfig(path string) (*config.Config, error) {
	return config.Load(path)
}
