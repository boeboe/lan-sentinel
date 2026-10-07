package cli

import (
	"bytes"
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lan-sentinel/internal/api"
	"lan-sentinel/internal/store"
	"lan-sentinel/internal/store/storetest"
)

// describeFixture serves the seeded database with a fake operator Control,
// and host A's MAC also on eth0, so a MAC query can match two hosts.
type describeFixture struct {
	socket string
	ctl    *control
	a      string // host A's MAC
	ids    map[string]string
}

func serveDescribe(t *testing.T) *describeFixture {
	t.Helper()
	st, _, exp := storetest.Seed(t, golden)
	a := exp.Hosts["A"]
	if err := st.Submit(context.Background(), func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO hosts (host_id, context_id, mac, presence, first_seen, last_seen)
			SELECT '0199a0e0-0000-7000-8000-0000000000e0', id, ?, 'ACTIVE', 0, 0 FROM network_contexts WHERE interface = 'eth0'`, a)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.Flush(context.Background()); err != nil || st.OpErrors() != 0 {
		t.Fatalf("seed: %v", err)
	}
	r, err := st.Reader(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	f := &describeFixture{socket: filepath.Join(t.TempDir(), "api.sock"), ctl: &control{}, a: a, ids: map[string]string{}}
	srv := api.New(api.Options{Reader: r, Control: f.ctl})
	ctx, cancel := context.WithCancel(context.Background())
	if err := srv.Start(ctx, f.socket, ""); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); _ = srv.Wait() })
	hosts, err := r.Hosts(context.Background(), store.HostFilter{})
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range hosts {
		f.ids[h.Interface+" "+h.MAC] = h.HostID
	}
	return f
}

func (f *describeFixture) run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := Execute(context.Background(), Env{Args: append([]string{"--socket", f.socket}, args...), Stdout: &out, Stderr: &errb,
		Location: time.UTC, Environ: []string{"LAN_SENTINEL_CONFIG=" + filepath.Join(t.TempDir(), "none.yaml")}})
	return code, out.String(), errb.String()
}

func TestHostsSetAndUnset(t *testing.T) {
	f := serveDescribe(t)
	a1 := f.ids["eth1 "+f.a]
	tests := []struct {
		name    string
		args    []string
		code    int
		out     string
		errText string
		set     map[string]string // what the daemon was asked, by host ID
	}{
		{"set by MAC and interface", []string{"hosts", "set", f.a, "--interface", "eth1", "--description", "Solar panel rooftop"}, 0,
			"Description of 00:1b:1b:aa:bb:01 on eth1: Solar panel rooftop", "", map[string]string{a1: "Solar panel rooftop"}},
		{"set by host ID", []string{"hosts", "set", "--id", "0199a0e0-0000-7000-8000-0000000000e0", "--description", "Mobile phone Bart"}, 0,
			"Mobile phone Bart", "", map[string]string{"0199a0e0-0000-7000-8000-0000000000e0": "Mobile phone Bart"}},
		{"set by current IP", []string{"hosts", "set", "192.168.110.52", "--description", "PLC line 3"}, 0, "PLC line 3", "", map[string]string{a1: "PLC line 3"}},
		{"json", []string{"-o", "json", "hosts", "set", "--id", a1, "--description", "x"}, 0, `"description": "x"`, "", map[string]string{a1: "x"}},
		{"unset", []string{"hosts", "unset", "--id", a1, "--description"}, 0, "Description of 00:1b:1b:aa:bb:01 on eth1 removed.", "", map[string]string{a1: ""}},
		{"a MAC on two interfaces", []string{"hosts", "set", f.a, "--description", "x"}, ExitUsage, "",
			"matches 2 hosts; name one with --interface or its host ID:\n  ", nil},
		{"no such host", []string{"hosts", "set", "--mac", "02:00:00:00:00:99", "--description", "x"}, ExitDegraded, "", "no current host matches", nil},
		{"nothing to set", []string{"hosts", "set", "--id", a1}, ExitUsage, "", "give --description", nil},
		{"empty description", []string{"hosts", "set", "--id", a1, "--description", " "}, ExitUsage, "", "hosts unset --description", nil},
		{"too long", []string{"hosts", "set", "--id", a1, "--description", strings.Repeat("x", store.MaxDescription+1)}, ExitUsage, "", "at most 200", nil},
		{"nothing to unset", []string{"hosts", "unset", "--id", a1}, ExitUsage, "", "give --description", nil},
		{"offline", []string{"--offline", "hosts", "set", "--id", a1, "--description", "x"}, ExitUsage, "", "needs the running daemon", nil},
		{"csv", []string{"-o", "csv", "hosts", "set", "--id", a1, "--description", "x"}, ExitUsage, "", "csv", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f.ctl.described = nil
			code, out, stderr := f.run(t, tt.args...)
			if code != tt.code || !strings.Contains(out, tt.out) || !strings.Contains(stderr, tt.errText) {
				t.Fatalf("exit %d (want %d)\nstdout: %s\nstderr: %s", code, tt.code, out, stderr)
			}
			if len(tt.set) != len(f.ctl.described) {
				t.Errorf("daemon asked %v, want %v", f.ctl.described, tt.set)
			}
			for id, text := range tt.set {
				if got, ok := f.ctl.described[id]; !ok || got != text {
					t.Errorf("daemon asked %v, want %v", f.ctl.described, tt.set)
				}
			}
		})
	}
	// A daemon error is reported.
	f.ctl.err = api.ErrNoScanner
	if code, _, stderr := f.run(t, "hosts", "set", "--id", a1, "--description", "x"); code != ExitError || stderr == "" {
		t.Errorf("daemon error: exit %d %s", code, stderr)
	}
}
