// Package logging builds the slog handler for the configured format:
// journald under systemd, text or JSON on a terminal or in a container.
// Observations are never logged; only lifecycle messages and state
// transitions are.
package logging

import (
	"fmt"
	"io"
	"log/slog"
	"strings"

	"lan-sentinel/internal/service"
)

// Levels, including the two custom ones.
const (
	LevelTrace  = service.LevelTrace
	LevelNotice = service.LevelNotice
)

// ParseLevel parses trace, debug, info, warn or error.
func ParseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(s) {
	case "trace":
		return LevelTrace, nil
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	}
	return 0, fmt.Errorf("unknown log level %q", s)
}

// Options configures New.
type Options struct {
	// Format is journald, json or text.
	Format string
	Level  slog.Leveler
	Writer io.Writer
}

// New returns a handler for o.Format.
func New(o Options) (slog.Handler, error) {
	ho := &slog.HandlerOptions{Level: o.Level, ReplaceAttr: levelNames}
	switch o.Format {
	case "text":
		return slog.NewTextHandler(o.Writer, ho), nil
	case "json":
		return slog.NewJSONHandler(o.Writer, ho), nil
	case "journald":
		return service.NewJournalHandler(o.Level)
	}
	return nil, fmt.Errorf("unknown log format %q", o.Format)
}

// levelNames prints the custom levels as TRACE and NOTICE instead of
// DEBUG-4 and INFO+2.
func levelNames(groups []string, a slog.Attr) slog.Attr {
	if len(groups) > 0 || a.Key != slog.LevelKey {
		return a
	}
	if l, ok := a.Value.Any().(slog.Level); ok {
		switch l {
		case LevelTrace:
			a.Value = slog.StringValue("TRACE")
		case LevelNotice:
			a.Value = slog.StringValue("NOTICE")
		}
	}
	return a
}
