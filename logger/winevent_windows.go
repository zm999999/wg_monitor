//go:build windows

package logger

import (
	"golang.org/x/sys/windows/svc/eventlog"
)

// windowsEventLogger forwards events to the Windows Event Log.
type windowsEventLogger struct {
	w *eventlog.Log
}

func (e *windowsEventLogger) Info(m string)    { _ = e.w.Info(1, m) }
func (e *windowsEventLogger) Warning(m string) { _ = e.w.Warning(2, m) }
func (e *windowsEventLogger) Error(m string)   { _ = e.w.Error(3, m) }
func (e *windowsEventLogger) Close() error     { return e.w.Close() }

// OpenWindowsEventLog opens the named event source. Returns nil when the source
// is not installed, so callers transparently fall back to file-only logging.
func OpenWindowsEventLog(source string) EventLogger {
	w, err := eventlog.Open(source)
	if err != nil {
		return nil
	}
	return &windowsEventLogger{w: w}
}

// InstallEventSource registers the event source (requires administrator).
// InstallAsEventCreate uses this executable as the message file; events are
// logged as raw strings.
func InstallEventSource(source string) {
	_ = eventlog.InstallAsEventCreate(source, eventlog.Error|eventlog.Warning|eventlog.Info)
}

// RemoveEventSource unregisters the event source.
func RemoveEventSource(source string) {
	_ = eventlog.Remove(source)
}
