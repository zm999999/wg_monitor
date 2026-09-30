// Package wireguard contains the WireGuard monitoring and control logic.
// The Windows implementation calls the Service Control Manager and wg.exe, but
// the output parsing is implemented as pure functions so it can be unit tested
// without touching the OS.
package wireguard

import (
	"fmt"
	"strings"
	"time"
)

// TunnelStatus holds the parsed state of a WireGuard interface and its first peer.
type TunnelStatus struct {
	Interface  string
	PublicKey  string
	ListenPort int
	Peer       *PeerStatus
}

// PeerStatus holds the parsed state of a single WireGuard peer.
type PeerStatus struct {
	PublicKey           string
	Endpoint            string
	LatestHandshake     time.Time
	HasHandshake        bool
	TransferRx          int64
	TransferTx          int64
	AllowedIPs          string
	PersistentKeepalive string
}

// ParseWGOutput parses the output of `wg show <interface>`.
//
// Example:
//
//	interface: my-tunnel
//	  public key: xxxx
//	  listening port: 51820
//
//	peer: yyyy
//	  endpoint: 1.2.3.4:51820
//	  allowed ips: 10.10.0.0/24
//	  latest handshake: 12 seconds ago
//	  transfer: 1.23 MiB received, 4.56 MiB sent
//	  persistent keepalive: every 25 seconds
func ParseWGOutput(out string) (*TunnelStatus, error) {
	ts := &TunnelStatus{}
	lines := strings.Split(out, "\n")
	inPeer := false
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		key, val, ok := splitKV(line)
		if !ok {
			continue
		}
		switch {
		case key == "interface":
			ts.Interface = val
			inPeer = false
		case key == "public key" && !inPeer:
			ts.PublicKey = val
		case key == "listening port" && !inPeer:
			fmt.Sscanf(val, "%d", &ts.ListenPort)
		case key == "peer":
			ts.Peer = &PeerStatus{PublicKey: val}
			inPeer = true
		case inPeer && key == "endpoint":
			ts.Peer.Endpoint = val
		case inPeer && key == "allowed ips":
			ts.Peer.AllowedIPs = val
		case inPeer && key == "latest handshake":
			age, has, err := parseHandshakeAge(val)
			if err != nil {
				return nil, fmt.Errorf("parse handshake %q: %w", val, err)
			}
			ts.Peer.HasHandshake = has
			if has {
				ts.Peer.LatestHandshake = time.Now().Add(-age)
			}
		case inPeer && key == "transfer":
			rx, tx, err := parseTransfer(val)
			if err != nil {
				return nil, err
			}
			ts.Peer.TransferRx = rx
			ts.Peer.TransferTx = tx
		case inPeer && key == "persistent keepalive":
			ts.Peer.PersistentKeepalive = val
		}
	}
	if ts.Interface == "" {
		return nil, fmt.Errorf("no interface section found in wg output")
	}
	return ts, nil
}

// splitKV splits a "key: value" line. Returns ok=false when not a kv line.
func splitKV(line string) (string, string, bool) {
	idx := strings.Index(line, ":")
	if idx < 0 {
		return "", "", false
	}
	return strings.TrimSpace(line[:idx]), strings.TrimSpace(line[idx+1:]), true
}

// parseHandshakeAge parses "latest handshake" values such as:
//
//	"(none)"
//	"12 seconds ago"
//	"5 minutes, 30 seconds ago"
//	"1 hour, 2 minutes ago"
//
// It returns the age (relative to now) and whether a handshake ever occurred.
func parseHandshakeAge(s string) (time.Duration, bool, error) {
	if strings.TrimSpace(s) == "" || strings.EqualFold(s, "(none)") {
		return 0, false, nil
	}
	if !strings.HasSuffix(s, "ago") {
		return 0, false, fmt.Errorf("unexpected handshake format %q", s)
	}
	body := strings.TrimSuffix(strings.TrimSpace(s), "ago")
	body = strings.TrimSpace(body)
	var total time.Duration
	parts := strings.Split(body, ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		var n int
		var unit string
		if _, err := fmt.Sscanf(p, "%d %s", &n, &unit); err != nil {
			return 0, false, fmt.Errorf("parse handshake part %q: %w", p, err)
		}
		switch strings.TrimSpace(unit) {
		case "second", "seconds":
			total += time.Duration(n) * time.Second
		case "minute", "minutes":
			total += time.Duration(n) * time.Minute
		case "hour", "hours":
			total += time.Duration(n) * time.Hour
		case "day", "days":
			total += time.Duration(n) * 24 * time.Hour
		default:
			return 0, false, fmt.Errorf("unknown handshake unit %q", unit)
		}
	}
	return total, true, nil
}

// parseTransfer parses "1.23 MiB received, 4.56 MiB sent".
func parseTransfer(s string) (int64, int64, error) {
	var rx, tx float64
	if _, err := fmt.Sscanf(s, "%f %s received, %f %s sent", &rx, new(string), &tx, new(string)); err != nil {
		return 0, 0, fmt.Errorf("parse transfer %q: %w", s, err)
	}
	return int64(rx * 1024 * 1024), int64(tx * 1024 * 1024), nil
}
