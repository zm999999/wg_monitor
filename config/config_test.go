package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// baseConfig returns a fully-populated, valid configuration. Tests mutate a
// copy of it to exercise specific validation rules. Required fields (service
// name, interface, targets, logging file, state dir) must be supplied by the
// user — they no longer have hard-coded fallbacks.
func baseConfig() *Config {
	return &Config{
		WireGuard: WireGuardConfig{
			ServiceName:      "WireGuardTunnel$x",
			InterfaceName:    "x",
			HandshakeTimeout: Duration(180 * time.Second),
			WGExecutable:     "wg.exe",
		},
		Health: HealthConfig{
			Interval:           Duration(10 * time.Second),
			StartupGracePeriod: Duration(120 * time.Second),
			MinSuccessTargets:  1,
		},
		Targets: []TargetConfig{{Host: "10.0.0.1", Port: 443, Protocol: "tcp"}},
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
		Logging: LoggingConfig{Level: "INFO", File: `C:\tmp\l.log`, MaxSizeMB: 50, MaxBackups: 5},
		Windows: WindowsConfig{ServiceName: "WGMonitor", EventSource: "WGMonitor", StateDir: `C:\tmp\state`},
	}
}

// TestLoadRequiresConfig verifies that a bare Load("") (no file, required
// fields missing) now errors instead of silently running on hard-coded
// defaults.
func TestLoadRequiresConfig(t *testing.T) {
	if _, err := Load(""); err == nil {
		t.Fatal("expected error when no config file and required fields are missing")
	}
}

// TestLoadAppliesDefaults verifies that optional tunables still receive safe
// defaults when the YAML omits them, while required fields are taken from the
// file.
func TestLoadAppliesDefaults(t *testing.T) {
	src := `
wireguard:
  service_name: "WireGuardTunnel$x"
  interface_name: "x"
targets:
  - host: "10.0.0.1"
    port: 443
    protocol: "tcp"
network:
  adapter_name: "Ethernet"
logging:
  file: "C:\\tmp\\l.log"
windows:
  state_dir: "C:\\tmp\\state"
`
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(p, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}
	if cfg.Health.Interval.Duration() != 10*time.Second {
		t.Fatalf("interval default = %s, want 10s", cfg.Health.Interval)
	}
	if cfg.WireGuard.HandshakeTimeout.Duration() != 180*time.Second {
		t.Fatalf("handshake_timeout default = %s, want 180s", cfg.WireGuard.HandshakeTimeout)
	}
	if cfg.Recovery.MaxWGRestart != 3 {
		t.Fatalf("max_wg_restart default = %d, want 3", cfg.Recovery.MaxWGRestart)
	}
}

func TestDurationParse(t *testing.T) {
	var d Duration
	if err := yaml.Unmarshal([]byte("\"180s\""), &d); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if d.Duration() != 180*time.Second {
		t.Fatalf("got %s, want 180s", d)
	}

	var d2 Duration
	if err := yaml.Unmarshal([]byte("\"30m\""), &d2); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if d2.Duration() != 30*time.Minute {
		t.Fatalf("got %s, want 30m", d2)
	}
}

func TestValidateNoTargets(t *testing.T) {
	cfg := baseConfig()
	cfg.Targets = nil
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error when no targets configured")
	}
}

func TestValidateThresholdOrder(t *testing.T) {
	cfg := baseConfig()
	cfg.Recovery.NetworkRestartAfter = Duration(time.Second)
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for inverted recovery thresholds")
	}
}

func TestValidateBadProtocol(t *testing.T) {
	cfg := baseConfig()
	cfg.Targets[0].Protocol = "udp"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for unsupported protocol")
	}
}

func TestValidateEmptyServiceName(t *testing.T) {
	cfg := baseConfig()
	cfg.WireGuard.ServiceName = ""
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for empty service name")
	}
}

func TestValidateEmptyStateDir(t *testing.T) {
	cfg := baseConfig()
	cfg.Windows.StateDir = ""
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for empty windows.state_dir")
	}
}
