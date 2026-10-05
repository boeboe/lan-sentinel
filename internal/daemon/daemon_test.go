package daemon

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"lan-sentinel/internal/clock"
	"lan-sentinel/internal/config"
	"lan-sentinel/internal/platform"
	"lan-sentinel/internal/platform/fake"
)

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type fakeNotifier struct {
	mu       sync.Mutex
	calls    []string
	watchdog time.Duration
}

func (f *fakeNotifier) record(c string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, c)
	return nil
}

func (f *fakeNotifier) Ready() error            { return f.record("READY") }
func (f *fakeNotifier) Reloading() error        { return f.record("RELOADING") }
func (f *fakeNotifier) Stopping() error         { return f.record("STOPPING") }
func (f *fakeNotifier) Watchdog() error         { return f.record("WATCHDOG") }
func (f *fakeNotifier) Status(msg string) error { return f.record("STATUS=" + msg) }
func (f *fakeNotifier) WatchdogInterval() (int64, bool) {
	return int64(f.watchdog), f.watchdog > 0
}

func (f *fakeNotifier) count(c string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, x := range f.calls {
		if x == c {
			n++
		}
	}
	return n
}

type harness struct {
	t        *testing.T
	dir      string
	cfgPath  string
	d        *Daemon
	log      *syncBuffer
	notifier *fakeNotifier
	signals  chan os.Signal
	sim      *clock.Sim
	errc     chan error
}

func testConfig(dir, level, extra string) string {
	return `version: 1
interfaces:
  - name: eth1
    active: { enabled: true, networks: [192.168.110.0/24] }
storage: { path: ` + filepath.Join(dir, "data", "hosts.db") + ` }
api: { socket: ./api.sock }
logging: { level: ` + level + `, format: text }
` + extra
}

func start(t *testing.T, cfg string, watchdog time.Duration) *harness {
	t.Helper()
	dir := t.TempDir()
	h := &harness{
		t: t, dir: dir, cfgPath: filepath.Join(dir, "config.yaml"), log: &syncBuffer{},
		notifier: &fakeNotifier{watchdog: watchdog}, signals: make(chan os.Signal, 1),
		sim: clock.NewSim(time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)), errc: make(chan error, 1),
	}
	h.writeConfig(strings.ReplaceAll(cfg, "$DIR", dir))
	backends, _, _, _, _ := fake.Backends()
	d, err := New(Options{
		Load:     config.LoadOptions{Path: h.cfgPath},
		Stderr:   h.log,
		Clock:    h.sim,
		Backends: &backends,
		Notifier: h.notifier,
		Signals:  h.signals,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h.d = d
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { h.errc <- d.Run(ctx) }()
	select {
	case <-d.Ready():
	case err := <-h.errc:
		t.Fatalf("Run exited during startup: %v\n%s", err, h.log)
	case <-time.After(10 * time.Second):
		t.Fatalf("daemon not ready\n%s", h.log)
	}
	return h
}

func (h *harness) writeConfig(s string) {
	h.t.Helper()
	if err := os.WriteFile(h.cfgPath, []byte(s), 0o600); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) waitLog(substr string) {
	h.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(h.log.String(), substr) {
		if time.Now().After(deadline) {
			h.t.Fatalf("log never contained %q:\n%s", substr, h.log)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (h *harness) stop() {
	h.t.Helper()
	h.signals <- syscall.SIGTERM
	select {
	case err := <-h.errc:
		if err != nil {
			h.t.Fatalf("Run: %v\n%s", err, h.log)
		}
	case <-time.After(10 * time.Second):
		h.t.Fatalf("daemon did not stop\n%s", h.log)
	}
}

func TestStartupAndShutdown(t *testing.T) {
	dir := "$DIR"
	h := start(t, testConfig(dir, "info", "active: { tcp: { enabled: true, targets: [{port: 502, timeout: 750ms}] } }\n"), 0)

	if h.notifier.count("READY") != 1 || h.notifier.count("STATUS=running") != 1 {
		t.Errorf("notifications = %v", h.notifier.calls)
	}
	want := map[string]platform.State{
		"capture": platform.StateRunning, "interface": platform.StateRunning, "neighbor": platform.StateRunning,
		// Probe engines land in phase 4: enabled ones are reported failed.
		"arp": platform.StateFailed, "tcp": platform.StateFailed, "icmp": platform.StateDisabled,
	}
	got := h.d.Collectors()
	if len(got) != len(want) {
		t.Fatalf("collectors = %+v", got)
	}
	for _, c := range got {
		if c.Interface != "eth1" || c.State != want[c.Collector] {
			t.Errorf("collector %s on %s = %s, want %s", c.Collector, c.Interface, c.State, want[c.Collector])
		}
	}

	h.stop()
	if h.notifier.count("STOPPING") != 1 {
		t.Errorf("STOPPING not sent: %v", h.notifier.calls)
	}
	db := filepath.Join(h.dir, "data", "hosts.db")
	if _, err := os.Stat(db); err != nil {
		t.Fatalf("database not created: %v", err)
	}
	if fi, err := os.Stat(db + "-wal"); err == nil && fi.Size() > 0 {
		t.Errorf("WAL left behind after clean shutdown (%d bytes)", fi.Size())
	}
	for _, msg := range []string{"lan-sentinel starting", "database ready", "lan-sentinel stopped"} {
		if !strings.Contains(h.log.String(), msg) {
			t.Errorf("log missing %q", msg)
		}
	}
}

func TestReload(t *testing.T) {
	h := start(t, testConfig("$DIR", "info", ""), 0)
	defer h.stop()

	// Reloadable changes apply; storage needs a restart and is kept.
	next := strings.Replace(testConfig(h.dir, "debug", "presence: { active: 2m, recent: 30m, stale: 24h }\n"),
		filepath.Join(h.dir, "data", "hosts.db"), filepath.Join(h.dir, "other.db"), 1)
	h.writeConfig(next)
	h.signals <- syscall.SIGHUP
	h.waitLog("configuration reloaded")

	cfg := h.d.Config()
	if cfg.Logging.Level != "debug" || cfg.Presence.Active.D() != 2*time.Minute {
		t.Errorf("reloadable values not applied: level=%s presence.active=%s", cfg.Logging.Level, cfg.Presence.Active)
	}
	if cfg.Storage.Path != filepath.Join(h.dir, "data", "hosts.db") {
		t.Errorf("restart-only storage.path changed to %s", cfg.Storage.Path)
	}
	if !strings.Contains(h.log.String(), "need a restart") || !strings.Contains(h.log.String(), "storage") {
		t.Errorf("no restart warning naming storage:\n%s", h.log)
	}

	// An invalid file is rejected as a whole.
	h.writeConfig(testConfig(h.dir, "loud", ""))
	h.signals <- syscall.SIGHUP
	h.waitLog("configuration reload rejected")
	if h.d.Config().Logging.Level != "debug" {
		t.Errorf("rejected reload changed the level to %s", h.d.Config().Logging.Level)
	}
	if h.notifier.count("RELOADING") != 2 || h.notifier.count("READY") != 3 {
		t.Errorf("reload notifications = %v", h.notifier.calls)
	}
}

func TestWatchdogPingsWhileStoreResponds(t *testing.T) {
	h := start(t, testConfig("$DIR", "info", ""), 20*time.Second)
	defer h.stop()
	for i := 1; i <= 3; i++ {
		// Wait for the watchdog ticker and the store ticker to be armed.
		h.sim.Advance(10 * time.Second)
		deadline := time.Now().Add(5 * time.Second)
		for h.notifier.count("WATCHDOG") < i {
			if time.Now().After(deadline) {
				t.Fatalf("watchdog ping %d not sent: %v", i, h.notifier.calls)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
}

func TestInvalidConfigFailsStartup(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(p, []byte("version: 1\ninterfaces: []\nbogus: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := New(Options{Load: config.LoadOptions{Path: p}, Stderr: &syncBuffer{}})
	var ve *config.ValidationError
	if !errors.As(err, &ve) || len(ve.Errors) != 2 {
		t.Fatalf("New err = %v, want a validation error with 2 problems", err)
	}
}
