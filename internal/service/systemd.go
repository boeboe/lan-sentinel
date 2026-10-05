package service

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-systemd/v22/daemon"
	"github.com/coreos/go-systemd/v22/journal"
	"golang.org/x/sys/unix"
)

// NewNotifier returns the systemd sd_notify notifier. Without
// $NOTIFY_SOCKET (not started by systemd) every call is a no-op.
func NewNotifier() Notifier { return systemdNotifier{} }

type systemdNotifier struct{}

func notify(state string) error {
	if _, err := daemon.SdNotify(false, state); err != nil {
		return fmt.Errorf("sd_notify %s: %w", strings.SplitN(state, "\n", 2)[0], err)
	}
	return nil
}

func (systemdNotifier) Ready() error { return notify(daemon.SdNotifyReady) }

// Reloading includes MONOTONIC_USEC as required by Type=notify-reload and
// accepted by Type=notify.
func (systemdNotifier) Reloading() error {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return notify(daemon.SdNotifyReloading)
	}
	usec := ts.Nano() / int64(time.Microsecond)
	return notify(daemon.SdNotifyReloading + "\nMONOTONIC_USEC=" + strconv.FormatInt(usec, 10))
}

func (systemdNotifier) Stopping() error { return notify(daemon.SdNotifyStopping) }

func (systemdNotifier) Watchdog() error { return notify(daemon.SdNotifyWatchdog) }

func (systemdNotifier) Status(msg string) error { return notify("STATUS=" + msg) }

func (systemdNotifier) WatchdogInterval() (int64, bool) {
	d, err := daemon.SdWatchdogEnabled(false)
	if err != nil || d == 0 {
		return 0, false
	}
	return int64(d), true
}

// JournalAvailable reports whether the journald socket is reachable.
func JournalAvailable() bool { return journal.Enabled() }

// NewJournalHandler returns a slog handler that writes structured entries to
// journald: attributes become upper-case fields (event=ip_changed becomes
// EVENT=ip_changed), the message becomes MESSAGE and the level maps to
// PRIORITY.
func NewJournalHandler(level slog.Leveler) (slog.Handler, error) {
	if !journal.Enabled() {
		return nil, fmt.Errorf("journald socket not available")
	}
	return &journalHandler{level: level, send: journal.Send}, nil
}

type journalHandler struct {
	level  slog.Leveler
	attrs  []slog.Attr
	groups []string
	send   func(msg string, p journal.Priority, vars map[string]string) error
}

func (h *journalHandler) Enabled(_ context.Context, l slog.Level) bool {
	return l >= h.level.Level()
}

func (h *journalHandler) Handle(_ context.Context, r slog.Record) error {
	vars := map[string]string{"SYSLOG_IDENTIFIER": "lan-sentinel"}
	for _, a := range h.attrs {
		addJournalAttr(vars, "", a)
	}
	prefix := journalGroupPrefix(h.groups)
	r.Attrs(func(a slog.Attr) bool {
		addJournalAttr(vars, prefix, a)
		return true
	})
	return h.send(r.Message, journalPriority(r.Level), vars)
}

func (h *journalHandler) WithAttrs(as []slog.Attr) slog.Handler {
	c := *h
	prefix := journalGroupPrefix(h.groups)
	for _, a := range as {
		c.attrs = append(append([]slog.Attr(nil), c.attrs...), slog.Attr{Key: prefix + a.Key, Value: a.Value})
	}
	return &c
}

func (h *journalHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	c := *h
	c.groups = append(append([]string(nil), h.groups...), name)
	return &c
}

func journalGroupPrefix(groups []string) string {
	if len(groups) == 0 {
		return ""
	}
	return strings.Join(groups, "_") + "_"
}

func addJournalAttr(vars map[string]string, prefix string, a slog.Attr) {
	a.Value = a.Value.Resolve()
	if a.Equal(slog.Attr{}) {
		return
	}
	if a.Value.Kind() == slog.KindGroup {
		p := prefix
		if a.Key != "" {
			p += a.Key + "_"
		}
		for _, ga := range a.Value.Group() {
			addJournalAttr(vars, p, ga)
		}
		return
	}
	if k := journalField(prefix + a.Key); k != "" {
		vars[k] = a.Value.String()
	}
}

// journalField converts a key to a valid journal field name: upper-case
// letters, digits and underscores, not starting with an underscore.
func journalField(k string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(k) {
		switch {
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return strings.TrimLeft(b.String(), "_")
}

func journalPriority(l slog.Level) journal.Priority {
	switch {
	case l < slog.LevelInfo:
		return journal.PriDebug
	case l < LevelNotice:
		return journal.PriInfo
	case l < slog.LevelWarn:
		return journal.PriNotice
	case l < slog.LevelError:
		return journal.PriWarning
	default:
		return journal.PriErr
	}
}
