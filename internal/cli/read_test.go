package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"lan-sentinel/internal/api"
	"lan-sentinel/internal/config"
	"lan-sentinel/internal/platform"
	"lan-sentinel/internal/probe/scheduler"
	"lan-sentinel/internal/store"
	"lan-sentinel/internal/store/storetest"
)

const golden = "../../test/golden/reconstruction/"

// clientEnv fixes time and zone so outputs are stable.
var clientNow = storetest.T0.Add(5 * time.Hour)

type eventHub struct {
	mu  sync.Mutex
	chs []chan store.Event
}

func (h *eventHub) Subscribe(n int) (<-chan store.Event, func()) {
	ch := make(chan store.Event, n)
	h.mu.Lock()
	h.chs = append(h.chs, ch)
	h.mu.Unlock()
	return ch, func() {}
}

func (h *eventHub) waitAndPublish(t *testing.T, e store.Event) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		h.mu.Lock()
		n := len(h.chs)
		h.mu.Unlock()
		if n > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Error("no stream subscriber")
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, ch := range h.chs {
		ch <- e
	}
}

type readFixture struct {
	socket, db string
	exp        storetest.Expected
	state      string
	hub        *eventHub
	cancel     context.CancelFunc
}

// serve seeds a database and serves it like the daemon would.
func serve(t *testing.T) *readFixture {
	t.Helper()
	st, db, exp := storetest.Seed(t, golden)
	storetest.AddDHCPServers(t, st)
	r, err := st.Reader(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	f := &readFixture{socket: filepath.Join(t.TempDir(), "api.sock"), db: db, exp: exp, state: api.StateOK, hub: &eventHub{}}
	cfg := config.Defaults()
	cfg.Interfaces = []config.InterfaceConfig{{Name: "eth0"}, {Name: "eth1"}}
	srv := api.New(api.Options{
		Reader: r, Events: f.hub, Config: func() any { return cfg },
		Interfaces: func(ctx context.Context) ([]store.InterfaceInfo, error) {
			ifs, err := r.Interfaces(ctx)
			return api.WithConfig(ifs, cfg), err
		},
		Status: func(context.Context) api.Status {
			return api.Status{Version: "1.2.3", Platform: "linux/arm64", PID: 412, Started: clientNow.Add(-76 * time.Hour), Now: clientNow,
				State: f.state, Database: api.DatabaseStatus{Path: db, OK: f.state != api.StateUnhealthy, Error: "boom", Size: 41e6},
				Active: store.ActiveState{Disabled: true, Reason: "PLC fault"},
				Interfaces: []api.InterfaceStatus{{InterfaceInfo: store.InterfaceInfo{Name: "eth1", State: "up", Prefixes: []string{"192.168.110.0/24"}},
					Collectors: []api.CollectorStatus{
						{CollectorStatus: platform.CollectorStatus{Collector: "arp", State: platform.StateRunning, Backend: "afpacket"},
							LastPass: &scheduler.PassSummary{At: clientNow.Add(-2 * time.Minute), Seconds: 26.3, Probed: 253, Replied: 14, Complete: true}},
						{CollectorStatus: platform.CollectorStatus{Collector: "capture", State: platform.StateFailed, Error: "socket(AF_PACKET): operation not permitted"}},
						{CollectorStatus: platform.CollectorStatus{Collector: "icmp", State: platform.StateRunning, Backend: "ping socket"},
							LastPass: &scheduler.PassSummary{At: clientNow.Add(-90 * time.Minute), Seconds: 4000, Probed: 9, Replied: 7, Blocked: 2}},
						{CollectorStatus: platform.CollectorStatus{Collector: "tcp", State: platform.StateDisabled, Backend: "socket"}},
					}}},
				Hosts:    map[string]map[string]int{"eth1": {"ACTIVE": 1, "STALE": 2}},
				Problems: []string{"eth1 capture: socket(AF_PACKET): operation not permitted"},
			}
		},
	})
	ctx, cancel := context.WithCancel(context.Background())
	f.cancel = cancel
	if err := srv.Start(ctx, f.socket, ""); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); _ = srv.Wait() })
	return f
}

func (f *readFixture) run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := Execute(context.Background(), Env{Args: append([]string{"--socket", f.socket, "--db", f.db}, args...), Stdout: &out,
		Stderr: &errb, Now: func() time.Time { return clientNow }, Location: time.UTC,
		Environ: []string{config.EnvConfigPath + "=" + filepath.Join(filepath.Dir(f.db), "none.yaml")}})
	return code, out.String(), errb.String()
}

func TestReadCommands(t *testing.T) {
	f := serve(t)
	a, b := f.exp.Hosts["A"], f.exp.Hosts["B"]
	tests := []struct {
		name     string
		args     []string
		wantCode int
		want     []string
	}{
		{"hosts list", []string{"hosts", "list"}, 0, []string{"MAC", a, "192.168.110.52", "Siemens AG", "STALE", "plc-b.local", "58m ago"}},
		{"hosts list active", []string{"hosts", "list", "--active", "--interface", "eth1"}, 0, []string{b}},
		{"hosts list csv", []string{"hosts", "list", "-o", "csv", "--port", "502"}, 0, []string{"MAC,IP,HOSTNAME", b + ",192.168.110.50,plc-b.local"}},
		{"hosts list jsonl", []string{"hosts", "list", "-o", "jsonl", "--vendor", "siemens", "--seen-within", "2h"}, 0, []string{`"mac":"` + a + `"`}},
		{"find current", []string{"hosts", "find", "192.168.110.50"}, 0, []string{"Host ID:", b, "Names:", "plc-b.local", "mdns", "Services:", "tcp/502", "OPEN"}},
		{"find conflict at", []string{"hosts", "find", "192.168.110.51", "--at", "2026-10-01 13:10"}, 0, []string{"13:00:00 → open   sources: passive_arp   CONFLICT", "Conflict:", "DUPLICATE_IP_DETECTED"}},
		{"find nobody", []string{"hosts", "find", "--ip", "192.168.110.50", "--at", "2026-10-01T11:30:00Z"}, 1, []string{"No holder of 192.168.110.50", "Previous:", a, "Next:", b}},
		{"find unknown name", []string{"hosts", "find", "--hostname", "ghost"}, 1, []string{"No holder of ghost now"}},
		{"find moved", []string{"hosts", "find", "192.168.110.50", "--at", "2026-10-01T10:30:00Z"}, 0, []string{"Moved to:    192.168.110.51", "Replaced by: 192.168.110.50 → " + b}},
		{"find by mac json", []string{"-o", "json", "hosts", "find", "--mac", a}, 0, []string{`"kind": "mac"`}},
		{"history ip", []string{"hosts", "history", "192.168.110.50", "--until", "2026-10-01T14:00:00Z"}, 0, []string{"HOST_DISCOVERED", "IP_CHANGED", "192.168.110.50 -> 192.168.110.51", "SERVICE_OPENED"}},
		{"history csv", []string{"-o", "csv", "hosts", "history", "--mac", a, "--since", "2026-10-01"}, 0, []string{"TIME,TYPE", "2026-10-01T10:00:00Z,HOST_DISCOVERED"}},
		{"evidence", []string{"hosts", "evidence", a, "--since", "30d"}, 0, []string{"Addresses:", "passive_dhcp", "Observations (raw and roll-ups):", "Events:", "evidence {"}},
		{"evidence jsonl", []string{"-o", "jsonl", "hosts", "evidence", "plant-sw-01"}, 0, []string{`"name":"plant-sw-01"`}},
		{"evidence nothing", []string{"hosts", "evidence", "--hostname", "ghost"}, 1, nil},
		{"observations", []string{"observations", "list", "--unbound"}, 0, []string{"tcp_connect", "192.168.110.99", `{"port":502,"proto":"tcp","state":"REFUSED"}`}},
		{"observations jsonl", []string{"-o", "jsonl", "observations", "list", "--source", "passive_dhcp", "--limit", "1"}, 0, []string{`"source":"passive_dhcp"`}},
		{"rollups", []string{"observations", "list", "--rollups"}, 0, []string{"HOUR", "COUNT"}},
		{"events by type", []string{"events", "list", "--type", "duplicate-ip,DUPLICATE_IP_RESOLVED", "--interface", "eth1"}, 0, []string{"DUPLICATE_IP_DETECTED", "DUPLICATE_IP_RESOLVED", a}},
		{"events json", []string{"-o", "json", "events", "list", "--ip", "192.168.110.52"}, 0, []string{`"type": "IP_CHANGED"`}},
		{"services", []string{"services", "list", "--port", "502"}, 0, []string{"502/tcp", "OPEN", "192.168.110.50"}},
		{"services csv", []string{"-o", "csv", "services", "list", "--state", "open"}, 0, []string{"IP,MAC,IFACE,PORT,STATE,LAST CHECK"}},
		{"interfaces", []string{"interfaces", "list"}, 0, []string{"eth1", "192.168.110.0/24", "on", "unknown"}},
		{"dhcp servers", []string{"dhcp", "servers"}, 0, []string{
			"SERVER ID      RELAY  MAC                IP              IFACE  STATUS      ROUTER         DNS            MASK           LAST SEEN",
			"192.168.110.1  -      00:00:5e:00:01:01  192.168.110.1   eth1   allowed     192.168.110.1  192.168.110.1  255.255.255.0  1h ago",
			"unknown        -      02:00:00:00:00:66  192.168.110.66  eth1   unexpected  -              -              -              3h ago"}},
		{"dhcp servers csv", []string{"-o", "csv", "dhcp", "servers", "--status", "unexpected"}, 0, []string{
			"SERVER ID,RELAY,MAC,IP,IFACE,STATUS,ROUTER,DNS,MASK,LAST SEEN\nunknown,,02:00:00:00:00:66,192.168.110.66,eth1,unexpected,,,,2026-10-01T12:00:00Z"}},
		{"dhcp servers json", []string{"-o", "json", "dhcp", "servers", "--interface", "eth1"}, 0, []string{`"server_id": "192.168.110.1"`, `"status": "unexpected"`}},
		{"dhcp servers bad status", []string{"dhcp", "servers", "--status", "rogue"}, ExitUsage, nil},
		{"db info", []string{"db", "info"}, 0, []string{fmt.Sprintf("Schema:    %d", store.LatestSchemaVersion()), "Journal:   wal", "hosts", "4"}},
		{"db info json", []string{"-o", "json", "db", "info"}, 0, []string{fmt.Sprintf(`"schema_version": %d`, store.LatestSchemaVersion())}},
		{"db check", []string{"db", "check"}, 0, []string{"ok"}},
		{"db check json", []string{"-o", "json", "db", "check"}, 0, []string{`"ok": true`}},
		{"show json", []string{"-o", "json", "hosts", "show", "00000000-0000-0000-0000-000000000000"}, 2, nil},
		{"status degraded is not set", []string{"daemon", "status"}, 0, []string{"Version:    1.2.3 (linux/arm64)   PID 412   up 3d 4h", "DISABLED (PLC fault)", "41 MB", "1 active, 2 stale", "operation not permitted",
			"         arp        running     afpacket    last pass 2m ago: 253 swept, 14 replied (26 s)\n",
			"         icmp       running     ping socket last pass 1h ago: 9 probed, 7 replied, 2 blocked (67 min, cut short)\n",
			"         tcp        disabled    socket\n"}},
		{"status json", []string{"-o", "json", "daemon", "status"}, 0, []string{`"pid": 412`}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, out, stderr := f.run(t, tt.args...)
			if code != tt.wantCode {
				t.Fatalf("exit %d, want %d\nstdout: %s\nstderr: %s", code, tt.wantCode, out, stderr)
			}
			for _, w := range tt.want {
				if !strings.Contains(out, w) {
					t.Errorf("output lacks %q:\n%s", w, out)
				}
			}
		})
	}

	// hosts show with a real ID, table form.
	hosts := f.hostIDs(t)
	code, out, _ := f.run(t, "hosts", "show", hosts[a])
	if code != 0 || !strings.Contains(out, "192.168.110.50   2026-10-01 10:00:00 → 2026-10-01 11:00:00") || !strings.Contains(out, "Identification:") {
		t.Errorf("hosts show: %d\n%s", code, out)
	}
}

func (f *readFixture) hostIDs(t *testing.T) map[string]string {
	t.Helper()
	_, out, _ := f.run(t, "-o", "json", "hosts", "list")
	var hosts []store.HostSummary
	if err := json.Unmarshal([]byte(out), &hosts); err != nil {
		t.Fatal(err)
	}
	ids := map[string]string{}
	for _, h := range hosts {
		ids[h.MAC] = h.HostID
	}
	return ids
}

func TestStatusExitCodes(t *testing.T) {
	f := serve(t)
	f.state = api.StateDegraded
	if code, out, _ := f.run(t, "daemon", "status"); code != ExitDegraded || !strings.Contains(out, "State:      DEGRADED") {
		t.Errorf("degraded: %d\n%s", code, out)
	}
	f.state = api.StateUnhealthy
	if code, out, _ := f.run(t, "daemon", "status", "--quiet"); code != ExitError || out != "" {
		t.Errorf("unhealthy quiet: %d %q", code, out)
	}
	f.cancel()
	time.Sleep(50 * time.Millisecond)
	if code, _, stderr := f.run(t, "daemon", "status"); code != ExitUnreachable || !strings.Contains(stderr, "--offline reads the database directly") {
		t.Errorf("unreachable: %d %s", code, stderr)
	}
	if code, _, _ := f.run(t, "hosts", "list"); code != ExitUnreachable {
		t.Errorf("hosts list with the daemon gone: %d", code)
	}
}

func TestOfflineAndUsage(t *testing.T) {
	f := serve(t)
	a := f.exp.Hosts["A"]
	tests := []struct {
		name     string
		args     []string
		wantCode int
		wantOut  string
		wantErr  string
	}{
		{"offline find", []string{"--offline", "hosts", "find", a}, 0, "192.168.110.52", ""},
		{"offline interfaces", []string{"--offline", "interfaces", "list"}, 0, "eth1", ""},
		{"offline dhcp servers", []string{"--offline", "dhcp", "servers", "--status", "allowed"}, 0, "192.168.110.1", ""},
		{"offline db check", []string{"--offline", "db", "check"}, 0, "ok", ""},
		{"offline status refused", []string{"--offline", "daemon", "status"}, ExitUsage, "", "needs the running daemon"},
		{"offline watch refused", []string{"--offline", "watch"}, ExitUsage, "", "needs the running daemon"},
		{"offline missing db", []string{"--offline", "--db", "/nonexistent/hosts.db", "hosts", "list"}, ExitError, "", "no such file"},
		{"two queries", []string{"hosts", "find", "x", "--ip", "10.0.0.1"}, ExitUsage, "", "give one query"},
		{"no query", []string{"hosts", "history"}, ExitUsage, "", "give one query"},
		{"kind mismatch", []string{"hosts", "find", "--ip", "plc"}, ExitUsage, "", "invalid query"},
		{"bad at", []string{"hosts", "find", "x", "--at", "yesterday"}, ExitUsage, "", "--at: invalid time"},
		{"bad since", []string{"events", "list", "--since", "soon"}, ExitUsage, "", "--since"},
		{"bad until", []string{"observations", "list", "--until", "later"}, ExitUsage, "", "--until"},
		{"bad seen-within", []string{"hosts", "list", "--seen-within", "x"}, ExitUsage, "", "--seen-within"},
		{"bad type", []string{"events", "list", "--type", "nonsense"}, ExitUsage, "", "unknown event type"},
		{"bad watch type", []string{"watch", "--type", "nonsense"}, ExitUsage, "", "unknown event type"},
		{"record csv", []string{"-o", "csv", "hosts", "find", "x"}, ExitUsage, "", "not supported"},
		{"status csv", []string{"-o", "csv", "daemon", "status"}, ExitUsage, "", "not supported"},
		{"db csv", []string{"-o", "csv", "db", "info"}, ExitUsage, "", "not supported"},
		{"check csv", []string{"-o", "csv", "db", "check"}, ExitUsage, "", "not supported"},
		{"evidence csv", []string{"-o", "csv", "hosts", "evidence", "x"}, ExitUsage, "", "not supported"},
		{"watch csv", []string{"-o", "csv", "watch"}, ExitUsage, "", "not supported"},
		{"show csv", []string{"-o", "csv", "hosts", "show", "x"}, ExitUsage, "", "not supported"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, out, stderr := f.run(t, tt.args...)
			if code != tt.wantCode || !strings.Contains(out, tt.wantOut) || !strings.Contains(stderr, tt.wantErr) {
				t.Errorf("exit %d (want %d)\nstdout: %s\nstderr: %s", code, tt.wantCode, out, stderr)
			}
		})
	}
}

func TestWatch(t *testing.T) {
	f := serve(t)
	ctx, cancel := context.WithCancel(context.Background())
	var out bytes.Buffer
	done := make(chan int, 1)
	w := &syncWriter{w: &out}
	go func() {
		done <- Execute(ctx, Env{Args: []string{"--socket", f.socket, "watch", "--interface", "eth1", "--type", "ip-changed"},
			Stdout: w, Stderr: w, Location: time.UTC})
	}()
	f.hub.waitAndPublish(t, store.Event{TS: storetest.T0, Type: "IP_CHANGED", Interface: "eth1", MAC: "00:1b:1b:aa:bb:01",
		Old: "192.168.110.50", New: "192.168.110.51", Evidence: json.RawMessage(`{}`)})
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(w.String(), "192.168.110.50 -> 192.168.110.51") {
		if time.Now().After(deadline) {
			t.Fatalf("watch printed %q", w.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !strings.HasPrefix(w.String(), "10:00:00  IP_CHANGED") {
		t.Errorf("watch line = %q", w.String())
	}
	cancel()
	if code := <-done; code != ExitOK {
		t.Errorf("watch exit after cancel = %d", code)
	}
}

type syncWriter struct {
	mu sync.Mutex
	w  *bytes.Buffer
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

func (s *syncWriter) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.String()
}

func TestTimeArgs(t *testing.T) {
	loc := time.FixedZone("CEST", 2*3600)
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	for in, want := range map[string]string{
		"2026-10-04":                "2026-10-03T22:00:00Z",
		"2026-10-04 10:15":          "2026-10-04T08:15:00Z",
		"2026-10-04 10:15:30":       "2026-10-04T08:15:30Z",
		"2026-10-04T10:15:00Z":      "2026-10-04T10:15:00Z",
		"2026-10-04T10:15:00+02:00": "2026-10-04T08:15:00Z",
	} {
		got, err := parseTimestamp(in, loc)
		if err != nil || got.UTC().Format(time.RFC3339) != want {
			t.Errorf("parseTimestamp(%q) = %v, %v; want %s", in, got.UTC(), err, want)
		}
	}
	for in, want := range map[string]time.Duration{"24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour, "90m": 90 * time.Minute} {
		got, err := parseAgo(in, now, loc)
		if err != nil || now.Sub(got) != want {
			t.Errorf("parseAgo(%q) = %v, %v", in, got, err)
		}
	}
	for _, bad := range []string{"-1h", "xd", "-2d", "yesterday"} {
		if _, err := parseAgo(bad, now, loc); err == nil {
			t.Errorf("parseAgo(%q) accepted", bad)
		}
	}
	a := &app{env: Env{Now: func() time.Time { return now }, Location: time.UTC}}
	for d, want := range map[time.Duration]string{
		12 * time.Second: "12s ago", 14 * time.Minute: "14m ago", 3 * time.Hour: "3h ago", 12 * 24 * time.Hour: "12d ago", -time.Hour: "in the future",
	} {
		if got := a.ago(now.Add(-d)); got != want {
			t.Errorf("ago(%v) = %q, want %q", d, got, want)
		}
	}
	if a.ago(time.Time{}) != "never" {
		t.Error("zero time")
	}
	for d, want := range map[time.Duration]string{
		76 * time.Hour: "3d 4h", 125 * time.Minute: "2h 5m", 61 * time.Second: "1m 1s", 45 * time.Second: "45s",
	} {
		if got := uptime(d); got != want {
			t.Errorf("uptime(%v) = %q, want %q", d, got, want)
		}
	}
	for n, want := range map[int64]string{41e6: "41 MB", 2_500_000_000: "2.5 GB", 12_000: "12 KB", 512: "512 B"} {
		if got := humanBytes(n); got != want {
			t.Errorf("humanBytes(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestCSVCells(t *testing.T) {
	for in, want := range map[string]string{
		"=HYPERLINK(\"x\")": "'=HYPERLINK(\"x\")", "+1": "'+1", "-cmd": "'-cmd", "@SUM(A1)": "'@SUM(A1)", "\tx": "'\tx",
		"-": "", "plc-1": "plc-1", "": "",
	} {
		if got := csvCell(in); got != want {
			t.Errorf("csvCell(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEventsLimitAndPermission(t *testing.T) {
	f := serve(t)
	code, out, _ := f.run(t, "-o", "jsonl", "events", "list", "--limit", "2")
	if code != 0 || strings.Count(out, "\n") != 2 {
		t.Errorf("events --limit 2: exit %d\n%s", code, out)
	}
	if code, out, _ := f.run(t, "-o", "csv", "hosts", "list", "--interface", "eth0"); code != 0 || !strings.Contains(out, "00:1e:c9:00:00:01,,plant-sw-01") {
		t.Errorf("csv placeholders: %d\n%s", code, out)
	}
	if code, _, stderr := f.run(t, "events", "list", "--mac", "nonsense"); code != ExitUsage || !strings.Contains(stderr, "invalid query") {
		t.Errorf("bad MAC filter: %d %s", code, stderr)
	}
	if os.Getuid() == 0 {
		return
	}
	if err := os.Chmod(f.socket, 0); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := f.run(t, "hosts", "list"); code != ExitError || !strings.Contains(stderr, "run with sudo") {
		t.Errorf("inaccessible socket: exit %d %s", code, stderr)
	}
}
