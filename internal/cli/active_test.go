package cli

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lan-sentinel/internal/api"
	"lan-sentinel/internal/config"
	"lan-sentinel/internal/probe"
	"lan-sentinel/internal/probe/scheduler"
	"lan-sentinel/internal/store"
	"lan-sentinel/internal/store/storetest"
)

const scanConfig = `version: 1
interfaces:
  - name: eth1
    active: { enabled: true, networks: [192.168.110.0/24], exclude: [192.168.110.1] }
active:
  tcp: { enabled: true, targets: [{ port: 502, name: modbus, timeout: 750ms }] }
profiles:
  modbus: { arp: true, tcp: [502] }
logging: { format: text }
`

// control answers operator requests from a real plan over scanConfig.
type control struct {
	cfg       *config.Config
	active    store.ActiveState
	err       error
	scan      *scheduler.ScanResult
	scanErr   error
	reload    api.ReloadResult
	described map[string]string
}

// DescribeHost records the call; described maps host IDs to descriptions.
func (c *control) DescribeHost(_ context.Context, _, hostID, description string) (store.HostSummary, error) {
	if c.err != nil {
		return store.HostSummary{}, c.err
	}
	if c.described == nil {
		c.described = map[string]string{}
	}
	c.described[hostID] = description
	return store.HostSummary{HostID: hostID, MAC: "00:1b:1b:aa:bb:01", Interface: "eth1", Description: description}, nil
}

func (c *control) ReloadConfig(context.Context, string) (api.ReloadResult, error) {
	return c.reload, c.err
}

func (c *control) DisableActive(_ context.Context, actor, reason string) (store.ActiveState, error) {
	return store.ActiveState{Disabled: true, Reason: reason, By: actor}, c.err
}

func (c *control) EnableActive(context.Context, string, string) (store.ActiveState, error) {
	return store.ActiveState{}, c.err
}

func (c *control) PlanScan(_ context.Context, req probe.Request) (probe.Plan, error) {
	known := map[string][]netip.Addr{"eth1": {netip.MustParseAddr("192.168.110.50"), netip.MustParseAddr("192.168.110.51")}}
	return probe.Compute(probe.PlanInput{Config: c.cfg, Active: c.active, Known: known}, req), c.err
}

func (c *control) Scan(ctx context.Context, req probe.Request, _ string) (scheduler.ScanResult, error) {
	if c.scan != nil {
		return *c.scan, c.scanErr
	}
	p, _ := c.PlanScan(ctx, req)
	return scheduler.ScanResult{Plan: p, Interfaces: []scheduler.InterfaceResult{{
		Interface: "eth1", Seconds: 27.4, Responders: 3,
		Counts: map[string]map[string]int{"arp": {"reply": 3, "no_reply": 250}, "tcp/502": {"OPEN": 2, "REFUSED": 3}},
	}}}, c.scanErr
}

type controlFixture struct {
	socket, cfgPath string
	ctl             *control
}

func serveControl(t *testing.T) *controlFixture {
	t.Helper()
	f := &controlFixture{socket: filepath.Join(t.TempDir(), "api.sock"), cfgPath: writeFile(t, scanConfig)}
	l, err := config.Load(config.LoadOptions{Path: f.cfgPath})
	if err != nil {
		t.Fatal(err)
	}
	f.ctl = &control{cfg: l.Config}
	srv := api.New(api.Options{Control: f.ctl})
	ctx, cancel := context.WithCancel(context.Background())
	if err := srv.Start(ctx, f.socket, ""); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); _ = srv.Wait() })
	return f
}

func (f *controlFixture) run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := Execute(context.Background(), Env{Args: append([]string{"--socket", f.socket, "--config", f.cfgPath}, args...),
		Stdout: &out, Stderr: &errb, Location: time.UTC})
	return code, out.String(), errb.String()
}

func TestActiveCommands(t *testing.T) {
	f := serveControl(t)
	tests := []struct {
		name    string
		args    []string
		err     error
		code    int
		out     string
		errText string
	}{
		{"disable", []string{"active", "disable", "--reason", "PLC fault"}, nil, 0, "Active discovery disabled (persists across restarts)", ""},
		{"disable json", []string{"-o", "json", "active", "disable", "--reason", "PLC fault"}, nil, 0, `"reason": "PLC fault"`, ""},
		{"disable needs a reason", []string{"active", "disable"}, nil, ExitUsage, "", `"reason" not set`},
		{"enable", []string{"active", "enable"}, nil, 0, "Active discovery enabled.", ""},
		{"enable json", []string{"-o", "json", "active", "enable", "--reason", "fixed"}, nil, 0, `"disabled": false`, ""},
		{"enable while forced", []string{"active", "enable"}, api.ErrForced, ExitError, "", "LAN_SENTINEL_ACTIVE_DISABLED=1"},
		{"disable fails", []string{"active", "disable", "--reason", "x"}, errors.New("bus closed"), ExitError, "", "bus closed"},
		{"offline disable", []string{"--offline", "active", "disable", "--reason", "x"}, nil, ExitUsage, "", "needs the running daemon"},
		{"offline enable", []string{"--offline", "active", "enable"}, nil, ExitUsage, "", "needs the running daemon"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f.ctl.err = tt.err
			code, out, stderr := f.run(t, tt.args...)
			if code != tt.code || !strings.Contains(out, tt.out) || !strings.Contains(stderr, tt.errText) {
				t.Errorf("exit %d (want %d)\nstdout: %s\nstderr: %s", code, tt.code, out, stderr)
			}
		})
	}
}

func TestConfigReload(t *testing.T) {
	f := serveControl(t)
	changed := api.ReloadResult{
		Path:       "/etc/lan-sentinel/config.yaml",
		Applied:    []config.Change{{Key: "interfaces[0].active.enabled", Old: "false", New: "true"}, {Key: "logging.level", Old: "info", New: "debug"}},
		NotApplied: []config.Change{{Key: "interfaces[1].name", New: "eth2"}},
	}
	unchanged := api.ReloadResult{Path: "/etc/lan-sentinel/config.yaml", Applied: []config.Change{}, NotApplied: []config.Change{}}
	rejected := fmt.Errorf("%w: %w", api.ErrConfigRejected, errors.New("invalid configuration /etc/lan-sentinel/config.yaml:\n  active.arp.interval: must be positive"))
	tests := []struct {
		name    string
		args    []string
		res     api.ReloadResult
		err     error
		code    int
		out     []string
		errText string
	}{
		{"applied and not applied", []string{"config", "reload"}, changed, nil, 0, []string{
			"Configuration /etc/lan-sentinel/config.yaml reloaded.\n\nApplied:\n",
			"  interfaces[0].active.enabled  false  true\n",
			"  logging.level                 info   debug\n",
			"Not applied, needs a restart (sudo systemctl restart lan-sentinel):\n  KEY                 RUNNING  FILE\n  interfaces[1].name           eth2\n",
		}, ""},
		{"no changes", []string{"config", "reload"}, unchanged, nil, 0, []string{"reloaded.\nNo changes.\n"}, ""},
		{"json", []string{"-o", "json", "config", "reload"}, unchanged, nil, 0, []string{`"applied": []`, `"not_applied": []`}, ""},
		{"quiet", []string{"--quiet", "config", "reload"}, changed, nil, 0, nil, ""},
		{"rejected", []string{"config", "reload"}, api.ReloadResult{}, rejected, ExitError, nil, "configuration rejected; the running configuration is unchanged: invalid configuration /etc/lan-sentinel/config.yaml:\n  active.arp.interval: must be positive"},
		{"offline", []string{"--offline", "config", "reload"}, api.ReloadResult{}, nil, ExitUsage, nil, "needs the running daemon"},
		{"csv", []string{"-o", "csv", "config", "reload"}, api.ReloadResult{}, nil, ExitUsage, nil, "csv"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f.ctl.reload, f.ctl.err = tt.res, tt.err
			code, out, stderr := f.run(t, tt.args...)
			if code != tt.code || !strings.Contains(stderr, tt.errText) {
				t.Errorf("exit %d (want %d)\nstdout: %s\nstderr: %s", code, tt.code, out, stderr)
			}
			for _, want := range tt.out {
				if !strings.Contains(out, want) {
					t.Errorf("stdout lacks %q:\n%s", want, out)
				}
			}
			if tt.out == nil && out != "" {
				t.Errorf("stdout = %q, want nothing", out)
			}
		})
	}
	// No daemon on the socket.
	var out, errb bytes.Buffer
	code := Execute(context.Background(), Env{Args: []string{"--socket", filepath.Join(t.TempDir(), "none.sock"), "config", "reload"},
		Stdout: &out, Stderr: &errb, Location: time.UTC})
	if code != ExitUnreachable {
		t.Errorf("no daemon: exit %d, %s", code, errb.String())
	}
}

func TestScanPlan(t *testing.T) {
	f := serveControl(t)
	code, out, stderr := f.run(t, "scan", "plan", "--interface", "eth1", "--profile", "modbus")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	for _, want := range []string{
		"Interface:  eth1    Profile: modbus    Networks: 192.168.110.0/24\n",
		"Targets:    253 to sweep (excluded: 192.168.110.1), 2 known hosts\n",
		"Probes:     arp; tcp/502\n",
		"Rates:      arp 10 pps, tcp 5 connects/s (≤4 per interface, ≤1 per host); global cap 20 pps\n",
		"Estimate:   253 ARP requests, 2 TCP connects (at most 3 packets each), at most ~259 packets\n",
		"Duration:   estimated typical ~27 s, estimated no-response ~28 s\n",
		"Assumes:    probes leave paced at the rates above",
		"            no-response: nothing answers, so every phase waits out its reply timeout once (ARP 1s, tcp/502 750ms)\n",
		"Verdict:    ALLOWED\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("plan lacks %q:\n%s", want, out)
		}
	}

	code, out, _ = f.run(t, "-o", "json", "scan", "plan", "--icmp", "--udp", "ntp", "--tcp", "80")
	var p probe.Plan
	if code != 0 || json.Unmarshal([]byte(out), &p) != nil || !p.Allowed || p.Estimate.ICMPEchoes != 2 || p.Estimate.UDPProbes != 2 {
		t.Errorf("json plan: exit %d %s", code, out)
	}

	f.ctl.active = store.ActiveState{Disabled: true, Reason: "PLC fault"}
	code, out, _ = f.run(t, "scan", "plan", "--network", "10.0.0.0/24")
	if code != ExitError || !strings.Contains(out, "Verdict:    REFUSED\n") || !strings.Contains(out, "  - active discovery is disabled by the kill switch (PLC fault)") ||
		!strings.Contains(out, "10.0.0.0/24 is outside the configured networks of eth1") {
		t.Errorf("refused plan: exit %d\n%s", code, out)
	}
	f.ctl.active = store.ActiveState{}

	for _, tt := range []struct {
		args []string
		code int
		err  string
	}{
		{[]string{"scan", "plan", "--network", "bogus"}, ExitUsage, "--network"},
		{[]string{"-o", "csv", "scan", "plan"}, ExitUsage, "not supported"},
		{[]string{"scan", "run", "--network", "bogus"}, ExitUsage, "--network"},
		{[]string{"-o", "csv", "scan", "run"}, ExitUsage, "not supported"},
		{[]string{"--offline", "scan", "run"}, ExitUsage, "needs the running daemon"},
	} {
		if code, _, stderr := f.run(t, tt.args...); code != tt.code || !strings.Contains(stderr, tt.err) {
			t.Errorf("%v: exit %d, %s", tt.args, code, stderr)
		}
	}
	f.ctl.err = api.ErrNoScanner
	if code, _, stderr := f.run(t, "scan", "plan"); code != ExitError || !strings.Contains(stderr, "replay mode") {
		t.Errorf("plan in replay: exit %d, %s", code, stderr)
	}
	if code, _, stderr := f.run(t, "scan", "run"); code != ExitError || !strings.Contains(stderr, "replay mode") {
		t.Errorf("run in replay: exit %d, %s", code, stderr)
	}
}

func TestScanRun(t *testing.T) {
	f := serveControl(t)
	code, out, stderr := f.run(t, "scan", "run", "--profile", "modbus")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	for _, want := range []string{
		"Verdict:    ALLOWED\n",
		"Scanning (estimated typical duration ~27 s) ...\n",
		"eth1: done in 27 s; 3 hosts answered ARP\n",
		"  arp      250 no_reply, 3 reply\n",
		"  tcp/502  2 OPEN, 3 REFUSED\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	code, out, _ = f.run(t, "-o", "json", "scan", "run")
	var res scheduler.ScanResult
	if code != 0 || json.Unmarshal([]byte(out), &res) != nil || res.Interfaces[0].Responders != 3 {
		t.Errorf("json run: exit %d %s", code, out)
	}

	// Refused by the plan: nothing runs.
	f.ctl.active = store.ActiveState{Disabled: true}
	if code, out, _ := f.run(t, "scan", "run"); code != ExitError || !strings.Contains(out, "REFUSED") || strings.Contains(out, "Scanning") {
		t.Errorf("refused run: exit %d\n%s", code, out)
	}
	if code, out, _ := f.run(t, "-o", "json", "scan", "run"); code != ExitError || !strings.Contains(out, `"allowed": false`) {
		t.Errorf("refused json run: exit %d\n%s", code, out)
	}
	f.ctl.active = store.ActiveState{}

	// Refused by the daemon after an allowed plan (the switch was set in
	// between).
	refused := scheduler.ScanResult{Plan: probe.Plan{Reasons: []string{"active discovery is disabled by the kill switch"}}}
	f.ctl.scan, f.ctl.scanErr = &refused, scheduler.ErrScanRefused
	if code, out, _ := f.run(t, "scan", "run"); code != ExitError || strings.Count(out, "Verdict:") != 2 {
		t.Errorf("late refusal: exit %d\n%s", code, out)
	}
	if code, out, _ := f.run(t, "-o", "json", "scan", "run"); code != ExitError || !strings.Contains(out, "kill switch") {
		t.Errorf("late refusal json: exit %d\n%s", code, out)
	}

	aborted := scheduler.ScanResult{Interfaces: []scheduler.InterfaceResult{{Interface: "eth1", Seconds: 3, Aborted: "active discovery is disabled by the kill switch",
		Counts: map[string]map[string]int{"icmp": {"reply": 1}, "udp/ntp": {"no_reply": 1}, "zzz": {"x": 1}}}}}
	f.ctl.scan, f.ctl.scanErr = &aborted, probe.ErrDisabled
	if code, out, _ := f.run(t, "scan", "run"); code != ExitError || !strings.Contains(out, "eth1: aborted after 3 s: active discovery is disabled") {
		t.Errorf("aborted run: exit %d\n%s", code, out)
	}
	f.ctl.scan, f.ctl.scanErr = &scheduler.ScanResult{}, scheduler.ErrScanRunning
	if code, _, stderr := f.run(t, "scan", "run"); code != ExitError || !strings.Contains(stderr, "already running") {
		t.Errorf("busy: exit %d %s", code, stderr)
	}
}

func TestOfflineScanPlan(t *testing.T) {
	st, db, _ := storetest.Seed(t, golden)
	cfgPath := writeFile(t, scanConfig)
	runOffline := func(environ []string, args ...string) (int, string, string) {
		var out, errb bytes.Buffer
		code := Execute(context.Background(), Env{Args: append([]string{"--offline", "--config", cfgPath, "--db", db}, args...),
			Stdout: &out, Stderr: &errb, Environ: environ, Location: time.UTC})
		return code, out.String(), errb.String()
	}
	code, out, stderr := runOffline(nil, "scan", "plan", "--profile", "modbus")
	if code != 0 || !strings.Contains(out, "253 to sweep") || !strings.Contains(out, "known hosts") || !strings.Contains(out, "ALLOWED") {
		t.Fatalf("offline plan: exit %d\n%s\n%s", code, out, stderr)
	}
	code, out, _ = runOffline([]string{config.EnvActiveDisabled + "=1"}, "scan", "plan")
	if code != ExitError || !strings.Contains(out, "kill switch (LAN_SENTINEL_ACTIVE_DISABLED=1)") {
		t.Errorf("offline plan with the environment switch: exit %d\n%s", code, out)
	}
	ctx := context.Background()
	if err := st.Submit(ctx, func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO runtime_state (key, value, updated_at) VALUES ('active_disabled', '{"disabled":true,"reason":"PLC fault"}', 0)`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	code, out, _ = runOffline(nil, "scan", "plan")
	if code != ExitError || !strings.Contains(out, "kill switch (PLC fault)") {
		t.Errorf("offline plan with the persisted switch: exit %d\n%s", code, out)
	}
	if code, _, stderr := runOffline(nil, "--db", "/nonexistent.db", "scan", "plan"); code != ExitError || !strings.Contains(stderr, "no such file") {
		t.Errorf("missing db: exit %d %s", code, stderr)
	}
}

func TestPlanFormatting(t *testing.T) {
	if approx(51.2) != "~52 s" || approx(240) != "~4 min" || approx(7.2*3600) != "~7.2 h" {
		t.Errorf("approx = %q %q %q", approx(51.2), approx(240), approx(7.2*3600))
	}
	if sweepTime(30) != "~30 s" || sweepTime(600) != "~10 min" || sweepTime(6600*1.1) != "~2.0 h" {
		t.Errorf("sweepTime = %q %q %q", sweepTime(30), sweepTime(600), sweepTime(6600*1.1))
	}
	if estimateText(probe.Estimate{}) != "nothing to send" {
		t.Error("empty estimate")
	}
	if trimFloat(2.5) != "2.5" || trimFloat(20) != "20" {
		t.Error("trimFloat")
	}
	// Several interfaces each get their estimate.
	var buf bytes.Buffer
	a := &app{env: Env{Stdout: &buf}}
	_ = a.printPlan(probe.Plan{Probes: probe.Probes{ARP: true}, Rates: probe.Rates{Protocols: map[probe.Protocol]float64{probe.ARP: 10}},
		Interfaces: []probe.InterfacePlan{
			{Interface: "eth1", Networks: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/30")}, SweepTargets: 2, Estimate: probe.Estimate{ARPRequests: 2, Packets: 2, TypicalSeconds: 1.1, NoResponseSeconds: 1.1}},
			{Interface: "eth2", Reasons: []string{"interface is not configured"}},
		}})
	if strings.Count(buf.String(), "Estimate:") != 2 || strings.Contains(buf.String(), "eth2    Networks") {
		t.Errorf("plan:\n%s", buf.String())
	}

	buf.Reset()
	a.env.Location = time.UTC
	a.statusText(&buf, api.Status{LastScan: &store.Scan{Started: storetest.T0, Interface: "eth1", Kind: "arp,tcp/502", Trigger: "operator"}})
	if !strings.Contains(buf.String(), "Last scan:  2026-10-01 10:00:00  eth1  arp,tcp/502 (operator)  running\n") {
		t.Errorf("status:\n%s", buf.String())
	}
}

func TestWideSweepNeedsAcknowledgement(t *testing.T) {
	_, db, _ := storetest.Seed(t, golden)
	cfgPath := writeFile(t, `version: 1
interfaces:
  - name: eth1
    active: { enabled: true, networks: [10.0.0.0/14] }
active: { allow_wide_scan: true, max_sweep_targets: 262144 }
logging: { format: text }
`)
	run := func(args ...string) (int, string, string) {
		var out, errb bytes.Buffer
		code := Execute(context.Background(), Env{Args: append([]string{"--offline", "--config", cfgPath, "--db", db}, args...),
			Stdout: &out, Stderr: &errb, Location: time.UTC})
		return code, out.String(), errb.String()
	}
	code, out, _ := run("scan", "plan")
	if code != ExitError || !strings.Contains(out, "Targets:    262142 to sweep") || !strings.Contains(out, "repeat with --allow-wide") ||
		!strings.Contains(out, "estimated typical ~7.4 h") {
		t.Errorf("wide plan without --allow-wide: exit %d\n%s", code, out)
	}
	if code, out, _ := run("scan", "plan", "--allow-wide"); code != 0 || !strings.Contains(out, "ALLOWED") {
		t.Errorf("wide plan with --allow-wide: exit %d\n%s", code, out)
	}
	code, out, stderr := run("config", "validate")
	if code != 0 || !strings.Contains(out, "sweep 262142 addresses (~7.4 h)") || !strings.Contains(out, "Expert override: active.max_sweep_targets 262144") {
		t.Errorf("config validate: exit %d\n%s%s", code, out, stderr)
	}
}
