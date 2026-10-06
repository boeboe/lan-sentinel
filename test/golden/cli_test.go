package golden

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"lan-sentinel/internal/cli"
	"lan-sentinel/internal/config"
	"lan-sentinel/internal/daemon"
	"lan-sentinel/internal/platform/fake"
	"lan-sentinel/internal/store"
)

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// runCLI runs the lan-sentinel CLI in-process and returns its exit code
// and output.
func runCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := cli.Execute(context.Background(), cli.Env{Args: args, Stdout: &out, Stderr: &errOut, Location: time.UTC,
		Now: func() time.Time { return time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC) }})
	return code, out.String(), errOut.String()
}

// TestCLIReconstruction is the phase 3 exit criterion: the golden
// scenario's queries answered through the CLI, online against the running
// daemon, offline beside it, and offline after it stopped.
func TestCLIReconstruction(t *testing.T) {
	exp := readExpected(t, "reconstruction/expected.json")
	dir := t.TempDir()
	stream, err := filepath.Abs("reconstruction/observations.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "config.yaml")
	cfg := "version: 1\ninterfaces:\n  - name: " + exp.Interface + "\n    prefixes: [" + strings.Join(exp.Prefixes, ", ") + "]\n" +
		"    replay: { file: " + stream + " }\nreplay: { exit_when_done: false }\n" +
		"storage: { path: " + filepath.Join(dir, "hosts.db") + " }\napi: { socket: " + filepath.Join(dir, "api.sock") + " }\n" +
		"logging: { format: text }\n"
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	backends, _, _, _, _ := fake.Backends()
	log := &lockedBuffer{}
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() {
		errc <- daemon.Run(ctx, daemon.Options{Load: config.LoadOptions{Path: cfgPath}, Stderr: log, Backends: &backends,
			Signals: make(chan os.Signal)})
	}()
	deadline := time.Now().Add(30 * time.Second)
	for !strings.Contains(log.String(), "replay data committed") {
		if time.Now().After(deadline) {
			t.Fatalf("replay did not finish:\n%s", log)
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Run("online", func(t *testing.T) { checkCLIAnswers(t, exp, "--config", cfgPath) })
	t.Run("offline beside the daemon", func(t *testing.T) { checkCLIAnswers(t, exp, "--config", cfgPath, "--offline") })

	code, out, stderr := runCLI(t, "--config", cfgPath, "daemon", "status")
	if code != 0 || !strings.Contains(out, "State:      OK") || !strings.Contains(out, "replay") {
		t.Errorf("daemon status: exit %d\n%s%s", code, out, stderr)
	}

	cancel()
	if err := <-errc; err != nil {
		t.Fatalf("daemon: %v\n%s", err, log)
	}
	t.Run("offline after shutdown", func(t *testing.T) {
		code, _, stderr := runCLI(t, "--config", cfgPath, "--offline", "db", "info")
		if code != 0 || !strings.Contains(stderr, "no WAL") {
			t.Errorf("immutable open: exit %d, stderr %q", code, stderr)
		}
		checkCLIAnswers(t, exp, "--config", cfgPath, "--offline")
	})
	if code, _, stderr := runCLI(t, "--config", cfgPath, "daemon", "status"); code != 3 || !strings.Contains(stderr, "unreachable") {
		t.Errorf("status of a stopped daemon: exit %d, %q", code, stderr)
	}
}

// checkCLIAnswers runs every golden query and IP history through the CLI
// with the given global flags.
func checkCLIAnswers(t *testing.T, exp Expected, global ...string) {
	t.Helper()
	byMAC := map[string]string{}
	for label, mac := range exp.Hosts {
		byMAC[mac] = label
	}
	for _, q := range exp.Queries {
		args := append(append([]string{}, global...), "-o", "json", "hosts", "find", q.Find, "--interface", exp.Interface,
			"--at", q.At.Format(time.RFC3339))
		code, out, stderr := runCLI(t, args...)
		name := "find " + q.Find + " --at " + q.At.Format(time.RFC3339)
		wantCode := 0
		if len(q.Holders) == 0 {
			wantCode = 1
		}
		if code != wantCode {
			t.Errorf("%s: exit %d, want %d: %s", name, code, wantCode, stderr)
			continue
		}
		var res store.FindResult
		if err := json.Unmarshal([]byte(out), &res); err != nil {
			t.Fatalf("%s: %v\n%s", name, err, out)
		}
		var got []Holder
		for _, h := range res.Hosts {
			got = append(got, Holder{Host: byMAC[h.MAC], FirstSeen: h.Binding.FirstSeen, EndedAt: h.Binding.EndedAt, Unconfirmed: h.Unconfirmed})
			if h.Conflict != q.Conflict {
				t.Errorf("%s: conflict %v, want %v", name, h.Conflict, q.Conflict)
			}
		}
		sort.Slice(got, func(i, j int) bool { return got[i].Host < got[j].Host })
		if len(got) != len(q.Holders) {
			t.Errorf("%s: holders %+v, want %+v", name, got, q.Holders)
			continue
		}
		for i, w := range q.Holders {
			g := got[i]
			if g.Host != w.Host || !g.FirstSeen.Equal(w.FirstSeen) || !sameTime(g.EndedAt, w.EndedAt) || g.Unconfirmed != w.Unconfirmed {
				t.Errorf("%s: holder %+v, want %+v", name, g, w)
			}
		}
		if q.Previous != nil && (len(res.Previous) != 1 || byMAC[res.Previous[0].MAC] != q.Previous.Host || !res.Previous[0].Binding.EndedAt.Equal(q.Previous.At)) {
			t.Errorf("%s: previous %+v, want %+v", name, res.Previous, q.Previous)
		}
		if q.Next != nil && (len(res.Next) != 1 || byMAC[res.Next[0].MAC] != q.Next.Host || !res.Next[0].Binding.FirstSeen.Equal(q.Next.At)) {
			t.Errorf("%s: next %+v, want %+v", name, res.Next, q.Next)
		}
	}
	for _, h := range exp.History {
		args := append(append([]string{}, global...), "-o", "json", "hosts", "history", h.IP, "--interface", exp.Interface)
		code, out, stderr := runCLI(t, args...)
		if code != 0 {
			t.Errorf("history %s: exit %d: %s", h.IP, code, stderr)
			continue
		}
		var evs []store.Event
		if err := json.Unmarshal([]byte(out), &evs); err != nil {
			t.Fatalf("history %s: %v", h.IP, err)
		}
		var got, want []string
		for _, e := range evs {
			got = append(got, e.TS.UTC().Format(time.RFC3339)+" "+e.Type+" "+byMAC[e.MAC])
		}
		for _, i := range h.Events {
			e := exp.Events[i]
			want = append(want, e.TS.Format(time.RFC3339)+" "+e.Type+" "+e.Host)
		}
		if strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Errorf("history %s:\ngot  %v\nwant %v", h.IP, got, want)
		}
	}
	// The table form of a point-in-time answer.
	at := exp.Queries[0].At.Format(time.RFC3339)
	args := append(append([]string{}, global...), "hosts", "find", exp.Queries[0].Find, "--interface", exp.Interface, "--at", at)
	code, out, _ := runCLI(t, args...)
	if code != 0 || !strings.Contains(out, "Binding:") || !strings.Contains(out, "unconfirmed since") || !strings.Contains(out, "Replaced by:") {
		t.Errorf("table answer: exit %d\n%s", code, out)
	}
}
