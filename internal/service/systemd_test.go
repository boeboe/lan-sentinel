package service

import (
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-systemd/v22/journal"
)

// listen creates a fake systemd notify socket and points NOTIFY_SOCKET at it.
func listen(t *testing.T) *net.UnixConn {
	t.Helper()
	path := filepath.Join(t.TempDir(), "notify.sock")
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	t.Setenv("NOTIFY_SOCKET", path)
	return conn
}

func recv(t *testing.T, conn *net.UnixConn) string {
	t.Helper()
	buf := make([]byte, 512)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	return string(buf[:n])
}

func TestNotifier(t *testing.T) {
	conn := listen(t)
	n := NewNotifier()
	tests := []struct {
		name string
		call func() error
		want string
	}{
		{"ready", n.Ready, "READY=1"},
		{"reloading", n.Reloading, "RELOADING=1\nMONOTONIC_USEC="},
		{"stopping", n.Stopping, "STOPPING=1"},
		{"watchdog", n.Watchdog, "WATCHDOG=1"},
		{"status", func() error { return n.Status("running") }, "STATUS=running"},
	}
	for _, tt := range tests {
		if err := tt.call(); err != nil {
			t.Fatalf("%s: %v", tt.name, err)
		}
		if got := recv(t, conn); !strings.HasPrefix(got, tt.want) {
			t.Errorf("%s sent %q, want prefix %q", tt.name, got, tt.want)
		}
	}
}

func TestNotifierErrors(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", filepath.Join(t.TempDir(), "missing.sock"))
	if err := NewNotifier().Ready(); err == nil || !strings.Contains(err.Error(), "sd_notify READY=1") {
		t.Errorf("Ready to a missing socket: %v", err)
	}
}

func TestWatchdogInterval(t *testing.T) {
	n := NewNotifier()
	t.Setenv("WATCHDOG_USEC", "")
	if _, ok := n.WatchdogInterval(); ok {
		t.Error("watchdog reported without WATCHDOG_USEC")
	}
	t.Setenv("WATCHDOG_USEC", "60000000")
	t.Setenv("WATCHDOG_PID", strconv.Itoa(os.Getpid()))
	iv, ok := n.WatchdogInterval()
	if !ok || time.Duration(iv) != time.Minute {
		t.Errorf("WatchdogInterval = %v, %v; want 1m", time.Duration(iv), ok)
	}
}

func TestJournalWithoutSocket(t *testing.T) {
	if JournalAvailable() {
		t.Skip("a journald socket exists here")
	}
	if _, err := NewJournalHandler(slog.LevelInfo); err == nil {
		t.Error("journal handler created without a journald socket")
	}
}

func TestJournalPriority(t *testing.T) {
	for level, want := range map[slog.Level]journal.Priority{
		LevelTrace: journal.PriDebug, slog.LevelDebug: journal.PriDebug, slog.LevelInfo: journal.PriInfo,
		LevelNotice: journal.PriNotice, slog.LevelWarn: journal.PriWarning, slog.LevelError: journal.PriErr,
	} {
		if got := journalPriority(level); got != want {
			t.Errorf("journalPriority(%v) = %d, want %d", level, got, want)
		}
	}
}
