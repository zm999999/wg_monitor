package wireguard

import (
	"testing"
	"time"
)

func TestParseWGOutput(t *testing.T) {
	in := `interface: my-tunnel
  public key: abc123
  listening port: 51820

peer: xyz789
  endpoint: 1.2.3.4:51820
  allowed ips: 10.10.0.0/24
  latest handshake: 12 seconds ago
  transfer: 1.23 MiB received, 4.56 MiB sent
  persistent keepalive: every 25 seconds`

	ts, err := ParseWGOutput(in)
	if err != nil {
		t.Fatalf("ParseWGOutput error: %v", err)
	}
	if ts.Interface != "my-tunnel" {
		t.Fatalf("interface = %q", ts.Interface)
	}
	if ts.ListenPort != 51820 {
		t.Fatalf("listen port = %d", ts.ListenPort)
	}
	if ts.Peer == nil {
		t.Fatal("expected a peer")
	}
	if ts.Peer.Endpoint != "1.2.3.4:51820" {
		t.Fatalf("endpoint = %q", ts.Peer.Endpoint)
	}
	if !ts.Peer.HasHandshake {
		t.Fatal("expected handshake present")
	}
	if ts.Peer.AllowedIPs != "10.10.0.0/24" {
		t.Fatalf("allowed ips = %q", ts.Peer.AllowedIPs)
	}
}

func TestParseHandshakeNone(t *testing.T) {
	in := `interface: x
peer: y
  latest handshake: (none)`
	ts, err := ParseWGOutput(in)
	if err != nil {
		t.Fatalf("ParseWGOutput error: %v", err)
	}
	if ts.Peer == nil {
		t.Fatal("expected a peer")
	}
	if ts.Peer.HasHandshake {
		t.Fatal("handshake should be absent")
	}
}

func TestParseHandshakeMinutes(t *testing.T) {
	age, has, err := parseHandshakeAge("5 minutes, 30 seconds ago")
	if err != nil {
		t.Fatalf("parseHandshakeAge error: %v", err)
	}
	if !has {
		t.Fatal("expected handshake present")
	}
	if age != 330*time.Second {
		t.Fatalf("age = %s, want 330s", age)
	}
}

func TestParseHandshakeHours(t *testing.T) {
	age, has, err := parseHandshakeAge("2 hours, 1 minute ago")
	if err != nil {
		t.Fatalf("parseHandshakeAge error: %v", err)
	}
	if !has || age != 2*time.Hour+time.Minute {
		t.Fatalf("age = %s, want 2h1m", age)
	}
}

func TestParseHandshakeInvalid(t *testing.T) {
	if _, _, err := parseHandshakeAge("soon"); err == nil {
		t.Fatal("expected error for malformed handshake")
	}
}

// TestRestartStopDecision guards the fix for the "service already stopped"
// recovery failure: RestartTunnel must NOT send a Stop control to an already
// stopped service (SCM returns ERROR_SERVICE_NOT_ACTIVE), it should start it.
func TestRestartStopDecision(t *testing.T) {
	cases := []struct {
		state ServiceState
		want  bool
	}{
		{StateRunning, true},
		{StateStopped, false},
		{StateStartPending, false},
		{StateStopPending, false},
		{StateUnknown, false},
	}
	for _, tc := range cases {
		if got := needsStop(tc.state); got != tc.want {
			t.Errorf("needsStop(%v) = %v, want %v", tc.state, got, tc.want)
		}
	}
}
