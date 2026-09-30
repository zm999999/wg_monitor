package logger

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoggerLevelFilter(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "l.log")
	log, err := New(Options{Level: LevelInfo, File: p, MaxSizeMB: 50, MaxBackups: 0})
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	defer log.Close()

	log.Debugf("debug-should-not-appear")
	log.Infof("info-should-appear")

	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	if strings.Contains(string(data), "debug-should-not-appear") {
		t.Fatal("DEBUG was logged despite INFO level")
	}
	if !strings.Contains(string(data), "info-should-appear") {
		t.Fatal("INFO was not logged")
	}
}

func TestRollingWriterRotates(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "r.log")

	rw, err := NewRollingWriter(p, 1, 2) // 1 MB limit, keep 2 backups
	if err != nil {
		t.Fatalf("NewRollingWriter error: %v", err)
	}
	defer rw.Close()

	chunk := strings.Repeat("x", 600*1024) // 600 KB
	if _, err := rw.Write([]byte(chunk + "\n")); err != nil {
		t.Fatalf("write1: %v", err)
	}
	if _, err := rw.Write([]byte(chunk + "\n")); err != nil { // ~1.2 MB total -> rotates
		t.Fatalf("write2: %v", err)
	}

	if _, err := os.Stat(p + ".1"); err != nil {
		t.Fatalf("expected rotated backup %s.1: %v", p, err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatalf("stat current: %v", err)
	}
	// After rotation the current file should be far smaller than the 1.2 MB written.
	if fi.Size() > 1*1024*1024 {
		t.Fatalf("current file not rotated, size=%d", fi.Size())
	}
}
