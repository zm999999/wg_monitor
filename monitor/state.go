package monitor

// RecoveryLevel is the escalating level of automatic recovery.
type RecoveryLevel int

const (
	LevelHealthy RecoveryLevel = iota
	LevelRestartWireGuard
	LevelRestartNetwork
	LevelRestartComputer
)

func (l RecoveryLevel) String() string {
	switch l {
	case LevelRestartWireGuard:
		return "RESTART_WIREGUARD"
	case LevelRestartNetwork:
		return "RESTART_NETWORK"
	case LevelRestartComputer:
		return "RESTART_COMPUTER"
	default:
		return "HEALTHY"
	}
}

// HealthState is the reported monitoring state machine position.
type HealthState int

const (
	StateHealthy HealthState = iota
	StateDegraded
	StateWGRestart
	StateNetworkRestart
	StateComputerRestart
)

func (s HealthState) String() string {
	switch s {
	case StateDegraded:
		return "DEGRADED"
	case StateWGRestart:
		return "WG_RESTART"
	case StateNetworkRestart:
		return "NETWORK_RESTART"
	case StateComputerRestart:
		return "COMPUTER_RESTART"
	default:
		return "HEALTHY"
	}
}
