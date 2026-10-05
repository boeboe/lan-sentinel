// Package service holds the glue between the daemon and systemd: readiness
// and watchdog notification (sd_notify) and the journald log handler
// (systemd.go).
package service

import "log/slog"

// Custom slog levels beyond the standard four. Events use Notice; journald
// maps it to priority 5.
const (
	LevelTrace  = slog.Level(-8)
	LevelNotice = slog.Level(2)
)

// Notifier reports daemon lifecycle to the service manager.
type Notifier interface {
	Ready() error
	Reloading() error
	Stopping() error
	Watchdog() error
	// WatchdogInterval is the interval at which Watchdog must be called, or
	// false if the service manager does not use a watchdog.
	WatchdogInterval() (interval int64, ok bool)
	Status(msg string) error
}
