// Package crash kills the daemon with SIGKILL while it writes and checks
// that the database survives (docs/IMPLEMENTATION_PLAN.md, testing
// strategy: kill -9 during write; FR-ST-4, NFR-PERF-2). The test runs the
// daemon in a child process (this test binary run again), reads the
// database read-only from outside while it writes, kills it at varying
// moments and then checks the file.
package crash

import (
	"bufio"
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"lan-sentinel/internal/config"
	"lan-sentinel/internal/daemon"
	"lan-sentinel/internal/observation"
	"lan-sentinel/internal/platform/fake"
	"lan-sentinel/internal/store"
)

// childEnv makes this test binary run the daemon instead of the tests.
const childEnv = "LS_CRASH_CHILD_CONFIG"

// TestDaemonChild is the child process: it runs the daemon on the config in
// childEnv until it is killed. It does nothing in a normal test run.
func TestDaemonChild(t *testing.T) {
	cfg := os.Getenv(childEnv)
	if cfg == "" {
		t.Skip("the crash test's child process")
	}
	backends, _, _, _, _ := fake.Backends()
	err := daemon.Run(context.Background(), daemon.Options{Load: config.LoadOptions{Path: cfg}, Stderr: os.Stderr,
		Backends: &backends, Signals: make(chan os.Signal)})
	if err != nil {
		t.Fatal(err)
	}
}

// replayFile writes n observations of 500 hosts, 10 ms apart, so every
// 5-second batch commits about 500 of them in one transaction: new hosts,
// address bindings and raw observations.
func replayFile(t *testing.T, dir string, n int) string {
	t.Helper()
	path := filepath.Join(dir, "stream.jsonl")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w := bufio.NewWriter(f)
	start := time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)
	for i := range n {
		h := i % 500
		o := observation.Observation{Time: start.Add(time.Duration(i) * 10 * time.Millisecond), Source: observation.PassiveARP,
			MAC: net.HardwareAddr{0x00, 0x1b, 0x1b, 0, byte(h >> 8), byte(h)}, IP: netip.AddrFrom4([4]byte{10, 30, byte(h >> 8), byte(h)}),
			Meta: map[string]string{"arp": "request"}}
		b, err := o.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
		w.Write(append(b, '\n'))
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

// committed counts the rows another process sees committed.
func committed(db string) (hosts, observations int64, err error) {
	conn, err := sql.Open("sqlite", "file:"+db+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		return 0, 0, err
	}
	defer conn.Close()
	if err := conn.QueryRow(`SELECT (SELECT count(*) FROM hosts), (SELECT count(*) FROM observations)`).Scan(&hosts, &observations); err != nil {
		return 0, 0, err
	}
	return hosts, observations, nil
}

func TestKillDuringWrites(t *testing.T) {
	if testing.Short() {
		t.Skip("starts and kills the daemon several times")
	}
	dir := t.TempDir()
	stream := replayFile(t, dir, 200_000)
	db := filepath.Join(dir, "hosts.db")
	cfg := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfg, []byte(fmt.Sprintf(`version: 1
interfaces:
  - name: eth1
    prefixes: [10.30.0.0/16]
    replay: { file: %s }
replay: { exit_when_done: true }
storage: { path: %s }
api: { socket: %s }
logging: { format: text, level: warn }
`, stream, db, filepath.Join(dir, "api.sock"))), 0o600); err != nil {
		t.Fatal(err)
	}

	// Kill points: right after the daemon's first new commit, and later at
	// varying offsets, so some kills land inside a batch's transaction.
	var before int64 // observations in the file before the round
	for round, after := range []time.Duration{0, 37 * time.Millisecond, 120 * time.Millisecond, 250 * time.Millisecond, 600 * time.Millisecond} {
		child := exec.Command(os.Args[0], "-test.run=^TestDaemonChild$", "-test.v=false")
		child.Env = append(os.Environ(), childEnv+"="+cfg)
		child.Stderr = os.Stderr
		if err := child.Start(); err != nil {
			t.Fatal(err)
		}
		// Wait until this daemon has committed something of its own.
		var hosts, obs int64
		deadline := time.Now().Add(60 * time.Second)
		for {
			h, o, err := committed(db)
			if err == nil && o > before {
				hosts, obs = h, o
				break
			}
			if time.Now().After(deadline) {
				_ = child.Process.Kill()
				t.Fatalf("round %d: the daemon committed nothing (%v)", round, err)
			}
			time.Sleep(5 * time.Millisecond)
		}
		time.Sleep(after)
		if h, o, err := committed(db); err == nil {
			hosts, obs = h, o // the latest the outside saw committed before the kill
		}
		if err := child.Process.Signal(syscall.SIGKILL); err != nil {
			t.Fatal(err)
		}
		_ = child.Wait()

		// The file opens without being quarantined, passes the integrity
		// check, and holds everything that was committed.
		st, err := store.Open(context.Background(), store.Options{Path: db})
		if err != nil {
			t.Fatalf("round %d: open after the kill: %v", round, err)
		}
		if r := st.Recovery(); r != nil {
			t.Fatalf("round %d: the database was quarantined after a kill: %+v", round, r)
		}
		var check string
		var h, o int64
		err = st.View(context.Background(), func(ctx context.Context, tx *sql.Tx) error {
			if err := tx.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&check); err != nil {
				return err
			}
			return tx.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM hosts), (SELECT count(*) FROM observations)`).Scan(&h, &o)
		})
		if cerr := st.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		if check != "ok" || h < hosts || o < obs {
			t.Fatalf("round %d after %s: integrity %q; %d hosts and %d observations, %d and %d were committed before the kill",
				round, after, check, h, o, hosts, obs)
		}
		t.Logf("round %d: killed %s after its first commit, with %d hosts and %d observations committed; afterwards %d and %d, integrity ok",
			round, after, hosts, obs, h, o)
		before = o
	}

	// A daemon starts on the file as usual: no DATABASE_RECREATED.
	st, err := store.Open(context.Background(), store.Options{Path: db})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var recreated int64
	if err := st.View(context.Background(), func(ctx context.Context, tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT count(*) FROM events WHERE type = 'DATABASE_RECREATED'`).Scan(&recreated)
	}); err != nil || recreated != 0 {
		t.Errorf("DATABASE_RECREATED events: %d, %v", recreated, err)
	}
}
