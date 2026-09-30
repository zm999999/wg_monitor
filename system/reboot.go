// Package system provides controlled computer restart and persistent reboot
// bookkeeping used to prevent reboot loops.
package system

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// Controller abstracts a computer restart so tests can use a mock.
type Controller interface {
	RestartComputer(ctx context.Context) error
}

type windowsSystem struct {
	delaySeconds int
}

// NewController builds the production restart controller.
// delaySeconds is passed to `shutdown /t` (grace before forced restart).
func NewController(delaySeconds int) Controller {
	if delaySeconds < 0 {
		delaySeconds = 10
	}
	return &windowsSystem{delaySeconds: delaySeconds}
}

func (s *windowsSystem) RestartComputer(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "shutdown", "/r", "/t", strconv.Itoa(s.delaySeconds), "/f")
	return cmd.Run()
}

// RebootRecord is the on-disk persistence format.
type RebootRecord struct {
	Reboots []string `json:"reboots"`
}

// RebootTracker records automatic reboots and decides whether another is
// permitted. It is the core of the infinite-reboot protection: records are
// persisted to disk so they survive a reboot and block an immediate re-trigger
// after Windows comes back up.
type RebootTracker struct {
	mu       sync.Mutex
	path     string
	window   time.Duration
	cooldown time.Duration
	max      int
	times    []time.Time
}

// NewRebootTracker loads any existing records from path.
func NewRebootTracker(path string, max int, cooldown, window time.Duration) *RebootTracker {
	if window <= 0 {
		window = time.Hour
	}
	if max < 1 {
		max = 1
	}
	t := &RebootTracker{path: path, window: window, cooldown: cooldown, max: max}
	t.load()
	return t
}

// CanReboot reports whether an automatic reboot is currently allowed and why.
func (t *RebootTracker) CanReboot(now time.Time) (bool, string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.pruneLocked(now)
	if len(t.times) >= t.max {
		return false, fmt.Sprintf("max_reboot_per_hour=%d reached in the last %s", t.max, t.window)
	}
	if len(t.times) > 0 {
		last := t.times[len(t.times)-1]
		if since := now.Sub(last); since < t.cooldown {
			return false, fmt.Sprintf("reboot_cooldown=%s not elapsed (last reboot %s ago)", t.cooldown, since.Round(time.Second))
		}
	}
	return true, ""
}

// Record stores a reboot timestamp durably.
func (t *RebootTracker) Record(now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.times = append(t.times, now)
	t.pruneLocked(now)
	t.saveLocked()
}

func (t *RebootTracker) pruneLocked(now time.Time) {
	cutoff := now.Add(-t.window)
	kept := t.times[:0]
	for _, tm := range t.times {
		if tm.After(cutoff) {
			kept = append(kept, tm)
		}
	}
	t.times = kept
}

func (t *RebootTracker) load() {
	data, err := os.ReadFile(t.path)
	if err != nil {
		return // no record yet
	}
	var rec RebootRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return
	}
	for _, s := range rec.Reboots {
		if tm, err := time.Parse(time.RFC3339, s); err == nil {
			t.times = append(t.times, tm)
		}
	}
}

func (t *RebootTracker) saveLocked() {
	dir := filepath.Dir(t.path)
	_ = os.MkdirAll(dir, 0o755)
	rec := RebootRecord{}
	for _, tm := range t.times {
		rec.Reboots = append(rec.Reboots, tm.Format(time.RFC3339))
	}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(t.path, data, 0o644)
}
