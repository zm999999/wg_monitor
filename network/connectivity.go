// Package network handles VPN reachability probing and network adapter control.
package network

import (
	"context"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Target is a single reachability probe definition.
type Target struct {
	Host     string
	Port     int
	Protocol string // "tcp" (default) or "icmp"
}

// TargetChecker probes a Target and reports reachability.
type TargetChecker interface {
	Check(ctx context.Context, t Target) (ok bool, elapsed time.Duration, err error)
}

// ConnectivityChecker is the production TargetChecker.
type ConnectivityChecker struct {
	TCPTimeout  time.Duration
	ICMPTimeout time.Duration
	PingCmd     string
}

// NewConnectivityChecker builds a checker with the given per-probe timeouts.
func NewConnectivityChecker(tcp, icmp time.Duration) *ConnectivityChecker {
	return &ConnectivityChecker{
		TCPTimeout:  tcp,
		ICMPTimeout: icmp,
		PingCmd:     "ping",
	}
}

// Check probes the target. A probe failure is reported as ok=false with a nil
// error: for health purposes an unreachable target is not an exceptional error.
func (c *ConnectivityChecker) Check(ctx context.Context, t Target) (bool, time.Duration, error) {
	start := time.Now()
	switch strings.ToLower(strings.TrimSpace(t.Protocol)) {
	case "icmp":
		ok, err := c.ping(ctx, t.Host, c.ICMPTimeout)
		return ok, time.Since(start), err
	default:
		ok, err := c.tcp(ctx, t.Host, t.Port, c.TCPTimeout)
		return ok, time.Since(start), err
	}
}

func (c *ConnectivityChecker) tcp(parent context.Context, host string, port int, timeout time.Duration) (bool, error) {
	dctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := (&net.Dialer{}).DialContext(dctx, "tcp", addr)
	if err != nil {
		return false, nil
	}
	_ = conn.Close()
	return true, nil
}

func (c *ConnectivityChecker) ping(parent context.Context, host string, timeout time.Duration) (bool, error) {
	ms := int(timeout.Milliseconds())
	if ms <= 0 {
		ms = 2000
	}
	dctx, cancel := context.WithTimeout(parent, timeout+2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(dctx, c.PingCmd, "-n", "1", "-w", strconv.Itoa(ms), host)
	out, err := cmd.Output()
	if err != nil {
		// ping returns non-zero when the host is unreachable; treat as failure.
		return false, nil
	}
	if strings.Contains(string(out), "Reply from") {
		return true, nil
	}
	return false, nil
}
