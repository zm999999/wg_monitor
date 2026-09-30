package wireguard

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// ServiceState is a normalized Windows service state.
type ServiceState int

const (
	StateUnknown ServiceState = iota
	StateRunning
	StateStopped
	StateStartPending
	StateStopPending
)

// String renders the state.
func (s ServiceState) String() string {
	switch s {
	case StateRunning:
		return "RUNNING"
	case StateStopped:
		return "STOPPED"
	case StateStartPending:
		return "START_PENDING"
	case StateStopPending:
		return "STOP_PENDING"
	default:
		return "UNKNOWN"
	}
}

// ErrServiceNotFound is returned when the WireGuard service does not exist.
var ErrServiceNotFound = errors.New("wireguard service not found")

// Timeouts bounds every external operation performed by the controller.
type Timeouts struct {
	WGExec   time.Duration
	SvcStop  time.Duration
	SvcStart time.Duration
}

// DefaultTimeouts returns保守 default timeouts.
func DefaultTimeouts() Timeouts {
	return Timeouts{
		WGExec:   10 * time.Second,
		SvcStop:  15 * time.Second,
		SvcStart: 30 * time.Second,
	}
}

// Controller abstracts WireGuard operations so the monitor and its tests never
// touch the real OS.
type Controller interface {
	// ServiceStatus returns the current Windows service state.
	ServiceStatus(ctx context.Context) (ServiceState, error)
	// RestartTunnel stops then starts the WireGuard tunnel service.
	RestartTunnel(ctx context.Context) error
	// TunnelStatus returns the parsed `wg show` output for the interface.
	TunnelStatus(ctx context.Context) (*TunnelStatus, error)
}

type windowsController struct {
	serviceName   string
	interfaceName string
	wgExe         string
	timeouts      Timeouts
}

// NewController builds the production WireGuard controller.
func NewController(serviceName, interfaceName, wgExe string, t Timeouts) Controller {
	if wgExe == "" {
		wgExe = "wg.exe"
	}
	return &windowsController{
		serviceName:   serviceName,
		interfaceName: interfaceName,
		wgExe:         wgExe,
		timeouts:      t,
	}
}

func (c *windowsController) ServiceStatus(ctx context.Context) (ServiceState, error) {
	m, err := mgr.Connect()
	if err != nil {
		return StateUnknown, fmt.Errorf("connect service manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(c.serviceName)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return StateUnknown, ErrServiceNotFound
		}
		return StateUnknown, fmt.Errorf("open service %s: %w", c.serviceName, err)
	}
	defer s.Close()

	st, err := s.Query()
	if err != nil {
		return StateUnknown, fmt.Errorf("query service: %w", err)
	}
	switch st.State {
	case svc.Running:
		return StateRunning, nil
	case svc.Stopped:
		return StateStopped, nil
	case svc.StartPending:
		return StateStartPending, nil
	case svc.StopPending:
		return StateStopPending, nil
	default:
		return StateUnknown, nil
	}
}

// needsStop reports whether the tunnel must be stopped before it can be
// restarted. A service that is already stopped (the anomaly this monitor
// recovers from) must NOT receive a Stop control: the SCM returns
// ERROR_SERVICE_NOT_ACTIVE ("The service has not been started"), which would
// abort the whole restart before the Start step runs. So an already-stopped
// service should simply be started.
func needsStop(st ServiceState) bool {
	return st == StateRunning
}

func (c *windowsController) RestartTunnel(ctx context.Context) error {
	// Only stop a currently-running service. If it is already stopped or in an
	// indeterminate state, go straight to starting it.
	if st, stErr := c.ServiceStatus(ctx); stErr == nil && needsStop(st) {
		if err := c.control(ctx, "stop", c.timeouts.SvcStop); err != nil {
			return fmt.Errorf("stop service: %w", err)
		}
		if err := c.waitForState(ctx, StateStopped, c.timeouts.SvcStop); err != nil {
			return fmt.Errorf("wait stopped: %w", err)
		}
	}
	// Start (or re-start) the tunnel.
	if err := c.control(ctx, "start", c.timeouts.SvcStart); err != nil {
		// Starting a service that is already running is not a failure for us.
		if cur, _ := c.ServiceStatus(ctx); cur != StateRunning {
			return fmt.Errorf("start service: %w", err)
		}
	}
	if err := c.waitForState(ctx, StateRunning, c.timeouts.SvcStart); err != nil {
		return fmt.Errorf("wait running: %w", err)
	}
	return nil
}

// control runs a service start/stop, bounded by ctx.
func (c *windowsController) control(parent context.Context, action string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		m, err := mgr.Connect()
		if err != nil {
			done <- err
			return
		}
		defer m.Disconnect()
		s, err := m.OpenService(c.serviceName)
		if err != nil {
			done <- err
			return
		}
		defer s.Close()
		if action == "start" {
			done <- s.Start()
		} else {
			_, cerr := s.Control(svc.Stop)
			done <- cerr
		}
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		return err
	}
}

// waitForState polls the service until it reaches target or ctx elapses.
func (c *windowsController) waitForState(parent context.Context, target ServiceState, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		st, err := c.ServiceStatus(ctx)
		if err == nil && st == target {
			return nil
		}
		select {
		case <-ctx.Done():
			if err != nil {
				return fmt.Errorf("waiting for %s: %w", target, err)
			}
			return fmt.Errorf("timeout waiting for %s (last state=%s)", target, st)
		case <-ticker.C:
		}
	}
}

func (c *windowsController) TunnelStatus(ctx context.Context) (*TunnelStatus, error) {
	tctx, cancel := context.WithTimeout(ctx, c.timeouts.WGExec)
	defer cancel()
	cmd := exec.CommandContext(tctx, c.wgExe, "show", c.interfaceName)
	out, err := cmd.Output()
	if err != nil {
		if tctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("wg.exe timeout after %s: %w", c.timeouts.WGExec, err)
		}
		return nil, fmt.Errorf("wg.exe show %s: %w", c.interfaceName, err)
	}
	return ParseWGOutput(string(out))
}
