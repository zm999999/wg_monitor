// Package logger provides a leveled, rolling file logger plus an optional
// Windows Event Log sink. Both are behind small interfaces so the rest of the
// program never depends on concrete logging implementations.
package logger

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Level is a severity level.
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	default:
		return "INFO"
	}
}

// ParseLevel converts a string to a Level, defaulting to INFO on unknown input.
func ParseLevel(s string) Level {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "DEBUG":
		return LevelDebug
	case "INFO":
		return LevelInfo
	case "WARN", "WARNING":
		return LevelWarn
	case "ERROR":
		return LevelError
	default:
		return LevelInfo
	}
}

// EventLogger is the minimal interface for an external event sink (Event Log).
type EventLogger interface {
	Info(string)
	Warning(string)
	Error(string)
	Close() error
}

// RollingWriter is an io.Writer that rotates the underlying file once it
// exceeds maxSize bytes, keeping up to maxBackups compressed-free copies.
type RollingWriter struct {
	mu         sync.Mutex
	path       string
	maxSize    int64
	maxBackups int
	file       *os.File
	size       int64
}

// NewRollingWriter opens (or creates) path for appending and reports its size.
func NewRollingWriter(path string, maxSizeMB, maxBackups int) (*RollingWriter, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create log dir %s: %w", dir, err)
	}
	rw := &RollingWriter{
		path:       path,
		maxSize:    int64(maxSizeMB) * 1024 * 1024,
		maxBackups: maxBackups,
	}
	if err := rw.reopenLocked(); err != nil {
		return nil, err
	}
	return rw, nil
}

func (rw *RollingWriter) reopenLocked() error {
	f, err := os.OpenFile(rw.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	fi, statErr := f.Stat()
	if statErr != nil {
		f.Close()
		return statErr
	}
	rw.file = f
	rw.size = fi.Size()
	return nil
}

// Write appends p and rotates when the size limit is reached.
func (rw *RollingWriter) Write(p []byte) (int, error) {
	rw.mu.Lock()
	defer rw.mu.Unlock()
	if rw.file == nil {
		if err := rw.reopenLocked(); err != nil {
			return 0, err
		}
	}
	n, err := rw.file.Write(p)
	if err != nil {
		return n, err
	}
	rw.size += int64(n)
	if rw.maxSize > 0 && rw.size >= rw.maxSize {
		if rerr := rw.rotateLocked(); rerr != nil {
			return n, rerr
		}
	}
	return n, nil
}

func (rw *RollingWriter) rotateLocked() error {
	_ = rw.file.Close()
	rw.file = nil
	// Shift existing backups: .maxBackups -> dropped, .1 -> .2, ...
	for i := rw.maxBackups; i >= 1; i-- {
		src := rw.backupName(i)
		if i == rw.maxBackups {
			_ = os.Remove(src)
			continue
		}
		dst := rw.backupName(i + 1)
		_ = os.Rename(rw.backupName(i), dst)
	}
	if rw.maxBackups > 0 {
		_ = os.Rename(rw.path, rw.backupName(1))
	} else {
		_ = os.Remove(rw.path)
	}
	return rw.reopenLocked()
}

func (rw *RollingWriter) backupName(i int) string {
	return fmt.Sprintf("%s.%d", rw.path, i)
}

// Close flushes and closes the current file.
func (rw *RollingWriter) Close() error {
	rw.mu.Lock()
	defer rw.mu.Unlock()
	if rw.file != nil {
		err := rw.file.Close()
		rw.file = nil
		return err
	}
	return nil
}

// Logger is the program-wide leveled logger.
type Logger struct {
	mu     sync.Mutex
	rw     *RollingWriter
	el     EventLogger
	level  Level
	stderr bool
}

// Options configures a Logger.
type Options struct {
	Level      Level
	File       string
	MaxSizeMB  int
	MaxBackups int
	// EventLog, if non-nil, receives WARN/INFO/ERROR events.
	EventLog EventLogger
	// Also write to stderr (useful in foreground `run` mode).
	Stderr bool
}

// New creates a Logger writing to a rolling file. File creation failures are
// surfaced as an error; the caller may decide to proceed with stderr only.
func New(o Options) (*Logger, error) {
	rw, err := NewRollingWriter(o.File, o.MaxSizeMB, o.MaxBackups)
	if err != nil {
		return nil, err
	}
	return &Logger{
		rw:     rw,
		el:     o.EventLog,
		level:  o.Level,
		stderr: o.Stderr,
	}, nil
}

// NewStderr creates a logger that only writes to stderr. Used when the log file
// itself is unavailable so the program still emits diagnostics.
func NewStderr(level Level) *Logger {
	return &Logger{level: level, stderr: true}
}

func (lg *Logger) emit(level Level, msg string) {
	if level < lg.level {
		return
	}
	ts := time.Now().Format("2006-01-02 15:04:05")
	line := fmt.Sprintf("%s %-5s %s\n", ts, level.String(), msg)

	lg.mu.Lock()
	if lg.rw != nil {
		_, _ = lg.rw.Write([]byte(line))
	}
	if lg.stderr {
		_, _ = io.WriteString(os.Stderr, line)
	}
	el := lg.el
	lg.mu.Unlock()

	if el != nil {
		switch level {
		case LevelInfo:
			el.Info(msg)
		case LevelWarn:
			el.Warning(msg)
		case LevelError:
			el.Error(msg)
		}
	}
}

// Debugf logs at DEBUG level.
func (lg *Logger) Debugf(format string, args ...interface{}) {
	lg.emit(LevelDebug, fmt.Sprintf(format, args...))
}

// Infof logs at INFO level.
func (lg *Logger) Infof(format string, args ...interface{}) {
	lg.emit(LevelInfo, fmt.Sprintf(format, args...))
}

// Warnf logs at WARN level.
func (lg *Logger) Warnf(format string, args ...interface{}) {
	lg.emit(LevelWarn, fmt.Sprintf(format, args...))
}

// Errorf logs at ERROR level.
func (lg *Logger) Errorf(format string, args ...interface{}) {
	lg.emit(LevelError, fmt.Sprintf(format, args...))
}

// Close flushes the file and the event sink.
func (lg *Logger) Close() {
	lg.mu.Lock()
	el := lg.el
	rw := lg.rw
	lg.mu.Unlock()
	if rw != nil {
		_ = rw.Close()
	}
	if el != nil {
		_ = el.Close()
	}
}
