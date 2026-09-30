// Package config loads, validates and applies defaults to the wg-monitor
// YAML configuration. No value used by the monitor may be hard-coded; every
// tunable parameter lives in the configuration file.
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration is a time.Duration that supports YAML values like "180s", "30m".
type Duration time.Duration

// Duration returns the underlying time.Duration.
func (d Duration) Duration() time.Duration { return time.Duration(d) }

// String implements fmt.Stringer.
func (d Duration) String() string { return time.Duration(d).String() }

// UnmarshalYAML parses a duration string (or a bare integer interpreted as
// seconds) from YAML.
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	if s == "" {
		*d = 0
		return nil
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(parsed)
	return nil
}

// MarshalYAML renders the duration in its canonical string form.
func (d Duration) MarshalYAML() (interface{}, error) {
	return time.Duration(d).String(), nil
}

// Config is the root configuration.
type Config struct {
	WireGuard WireGuardConfig `yaml:"wireguard"`
	Health    HealthConfig    `yaml:"health"`
	Targets   []TargetConfig  `yaml:"targets"`
	Internet  *TargetConfig   `yaml:"internet,omitempty"`
	Network   NetworkConfig   `yaml:"network"`
	Recovery  RecoveryConfig  `yaml:"recovery"`
	Logging   LoggingConfig   `yaml:"logging"`
	Windows   WindowsConfig   `yaml:"windows"`
}

type WireGuardConfig struct {
	ServiceName      string   `yaml:"service_name"`
	InterfaceName    string   `yaml:"interface_name"`
	HandshakeTimeout Duration `yaml:"handshake_timeout"`
	// WGExecutable is the path to wg.exe. Defaults to "wg.exe" (PATH lookup).
	WGExecutable string `yaml:"wg_executable"`
}

type HealthConfig struct {
	Interval           Duration `yaml:"interval"`
	StartupGracePeriod Duration `yaml:"startup_grace_period"`
	MinSuccessTargets  int      `yaml:"min_success_targets"`
}

// TargetConfig describes a single VPN reachability probe.
type TargetConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Protocol string `yaml:"protocol"` // "tcp" (default) or "icmp"
}

type NetworkConfig struct {
	AdapterName string `yaml:"adapter_name"`
}

type RecoveryConfig struct {
	WGRestartAfter       Duration `yaml:"wg_restart_after"`
	NetworkRestartAfter  Duration `yaml:"network_restart_after"`
	ComputerRestartAfter Duration `yaml:"computer_restart_after"`

	WGRestartWait      Duration `yaml:"wg_restart_wait"`
	NetworkRestartWait Duration `yaml:"network_restart_wait"`

	MaxWGRestart      int `yaml:"max_wg_restart"`
	MaxNetworkRestart int `yaml:"max_network_restart"`

	MaxRebootPerHour int      `yaml:"max_reboot_per_hour"`
	RebootCooldown   Duration `yaml:"reboot_cooldown"`
	RecoveryCooldown Duration `yaml:"recovery_cooldown"`
}

type LoggingConfig struct {
	Level      string `yaml:"level"` // DEBUG | INFO | WARN | ERROR
	File       string `yaml:"file"`
	MaxSizeMB  int    `yaml:"max_size_mb"`
	MaxBackups int    `yaml:"max_backups"`
}

type WindowsConfig struct {
	// ServiceName is the Windows service name we register (e.g. "WGMonitor").
	ServiceName string `yaml:"service_name"`
	// EventSource is the Windows Event Log source name.
	EventSource string `yaml:"event_source"`
	// StateDir stores cross-run state such as reboot records.
	StateDir string `yaml:"state_dir"`
}

// DefaultConfig returns a configuration populated with safe defaults. Values
// present in the loaded file override these.
func DefaultConfig() *Config {
	return &Config{
		WireGuard: WireGuardConfig{
			HandshakeTimeout: Duration(180 * time.Second),
			WGExecutable:     "wg.exe",
		},
		Health: HealthConfig{
			Interval:           Duration(10 * time.Second),
			StartupGracePeriod: Duration(120 * time.Second),
			MinSuccessTargets:  1,
		},
		Network: NetworkConfig{AdapterName: "Ethernet"},
		Recovery: RecoveryConfig{
			WGRestartAfter:       Duration(30 * time.Second),
			NetworkRestartAfter:  Duration(90 * time.Second),
			ComputerRestartAfter: Duration(180 * time.Second),
			WGRestartWait:        Duration(10 * time.Second),
			NetworkRestartWait:   Duration(15 * time.Second),
			MaxWGRestart:         3,
			MaxNetworkRestart:    2,
			MaxRebootPerHour:     1,
			RebootCooldown:       Duration(30 * time.Minute),
			RecoveryCooldown:     Duration(60 * time.Second),
		},
		Logging: LoggingConfig{
			Level:      "INFO",
			MaxSizeMB:  50,
			MaxBackups: 5,
		},
		Windows: WindowsConfig{
			ServiceName: "WGMonitor",
			EventSource: "WGMonitor",
		},
	}
}

// Load reads the YAML file at path, merges it over the defaults, and validates.
func Load(path string) (*Config, error) {
	cfg := DefaultConfig()
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read config %s: %w", path, err)
		}
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parse config %s: %w", path, err)
		}
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Validate enforces invariants that the monitor depends on.
func (c *Config) Validate() error {
	if c.WireGuard.ServiceName == "" {
		return fmt.Errorf("wireguard.service_name must not be empty")
	}
	if c.WireGuard.InterfaceName == "" {
		return fmt.Errorf("wireguard.interface_name must not be empty")
	}
	if c.Health.Interval.Duration() <= 0 {
		return fmt.Errorf("health.interval must be > 0")
	}
	if c.Health.MinSuccessTargets < 1 {
		return fmt.Errorf("health.min_success_targets must be >= 1")
	}
	if len(c.Targets) == 0 {
		return fmt.Errorf("at least one target must be configured")
	}
	for i, t := range c.Targets {
		if t.Host == "" {
			return fmt.Errorf("targets[%d].host must not be empty", i)
		}
		switch proto := normalizeProto(t.Protocol); proto {
		case "tcp":
			if t.Port <= 0 || t.Port > 65535 {
				return fmt.Errorf("targets[%d].port must be in 1..65535 for tcp", i)
			}
		case "icmp":
			// host only
		default:
			return fmt.Errorf("targets[%d].protocol %q unsupported (use tcp|icmp)", i, t.Protocol)
		}
	}
	if c.Network.AdapterName == "" {
		return fmt.Errorf("network.adapter_name must not be empty")
	}
	if c.Recovery.MaxWGRestart < 0 || c.Recovery.MaxNetworkRestart < 0 {
		return fmt.Errorf("recovery max restart counts must be >= 0")
	}
	if c.Recovery.WGRestartAfter.Duration() > c.Recovery.NetworkRestartAfter.Duration() ||
		c.Recovery.NetworkRestartAfter.Duration() > c.Recovery.ComputerRestartAfter.Duration() {
		return fmt.Errorf("recovery thresholds must satisfy wg_restart_after <= network_restart_after <= computer_restart_after")
	}
	if c.Logging.File == "" {
		return fmt.Errorf("logging.file must not be empty")
	}
	if c.Windows.StateDir == "" {
		return fmt.Errorf("windows.state_dir must not be empty")
	}
	if c.Logging.MaxSizeMB <= 0 {
		c.Logging.MaxSizeMB = 50
	}
	if c.Logging.MaxBackups < 0 {
		c.Logging.MaxBackups = 0
	}
	return nil
}

func normalizeProto(p string) string {
	if p == "" {
		return "tcp"
	}
	return p
}
