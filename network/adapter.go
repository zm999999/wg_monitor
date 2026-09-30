package network

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Controller abstracts network adapter control for testability.
type Controller interface {
	// RestartAdapter disables then re-enables the configured adapter.
	RestartAdapter(ctx context.Context) error
}

type windowsAdapter struct {
	name    string
	timeout time.Duration
	wait    time.Duration
	psPath  string
}

// NewController builds the production adapter controller.
// restartWait is the pause between disable and enable (network_restart_wait).
func NewController(adapterName string, restartWait time.Duration) Controller {
	return &windowsAdapter{
		name:    adapterName,
		timeout: 60 * time.Second,
		wait:    restartWait,
		psPath:  "powershell.exe",
	}
}

func (a *windowsAdapter) RestartAdapter(parent context.Context) error {
	if err := a.runPS(parent, fmt.Sprintf("Disable-NetAdapter -Name '%s' -Confirm:$false -ErrorAction Stop", a.name)); err != nil {
		return fmt.Errorf("disable adapter: %w", err)
	}
	select {
	case <-time.After(a.wait):
	case <-parent.Done():
		return parent.Err()
	}
	if err := a.runPS(parent, fmt.Sprintf("Enable-NetAdapter -Name '%s' -Confirm:$false -ErrorAction Stop", a.name)); err != nil {
		return fmt.Errorf("enable adapter: %w", err)
	}
	return nil
}

func (a *windowsAdapter) runPS(parent context.Context, script string) error {
	ctx, cancel := context.WithTimeout(parent, a.timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, a.psPath, "-NoProfile", "-NonInteractive", "-Command", script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w (output: %s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}
