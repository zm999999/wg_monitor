package monitor

import (
	"context"
	"time"

	"wg-monitor/network"
	"wg-monitor/wireguard"
)

// --- Mocks implementing the OS-facing interfaces (no real Windows calls) ---

type mockWG struct {
	state      wireguard.ServiceState
	stateErr   error
	tunnel     *wireguard.TunnelStatus
	tunnelErr  error
	restartErr error
	restarts   int
	ch         chan struct{}
}

func newMockWG() *mockWG { return &mockWG{ch: make(chan struct{}, 16)} }

func (m *mockWG) ServiceStatus(context.Context) (wireguard.ServiceState, error) {
	return m.state, m.stateErr
}
func (m *mockWG) RestartTunnel(context.Context) error {
	m.restarts++
	if m.ch != nil {
		m.ch <- struct{}{}
	}
	return m.restartErr
}
func (m *mockWG) TunnelStatus(context.Context) (*wireguard.TunnelStatus, error) {
	return m.tunnel, m.tunnelErr
}

type mockNet struct {
	err      error
	restarts int
	ch       chan struct{}
}

func newMockNet() *mockNet { return &mockNet{ch: make(chan struct{}, 16)} }

func (m *mockNet) RestartAdapter(context.Context) error {
	m.restarts++
	if m.ch != nil {
		m.ch <- struct{}{}
	}
	return m.err
}

type mockSys struct {
	err     error
	reboots int
	ch      chan struct{}
}

func newMockSys() *mockSys { return &mockSys{ch: make(chan struct{}, 16)} }

func (m *mockSys) RestartComputer(context.Context) error {
	m.reboots++
	if m.ch != nil {
		m.ch <- struct{}{}
	}
	return m.err
}

type mockTargetChecker struct {
	ok bool
}

func (m *mockTargetChecker) Check(context.Context, network.Target) (bool, time.Duration, error) {
	return m.ok, 0, nil
}

func waitCh(ch chan struct{}) { <-ch }

// newUnhealthyChecker builds a *HealthChecker that always reports unhealthy.
func newUnhealthyChecker() *HealthChecker {
	wg := newMockWG()
	wg.state = wireguard.StateStopped
	tc := &mockTargetChecker{ok: false}
	return NewHealthChecker(wg, tc, []network.Target{{Host: "10.10.0.1", Port: 443, Protocol: "tcp"}}, nil, 1)
}
