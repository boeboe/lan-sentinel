package daemon

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"lan-sentinel/internal/api"
	"lan-sentinel/internal/config"
	"lan-sentinel/internal/metrics"
	"lan-sentinel/internal/platform"
	"lan-sentinel/internal/platform/fake"
	"lan-sentinel/internal/probe"
	"lan-sentinel/internal/probe/scheduler"
	"lan-sentinel/test/frames"
)

var plcMAC = frames.MAC("00:1b:1b:aa:bb:01")

// arpNetwork answers ARP requests for the addresses in hosts.
func arpNetwork(hosts map[string]net.HardwareAddr) func(string, []byte) [][]byte {
	return func(_ string, frame []byte) [][]byte {
		p := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
		a, _ := p.Layer(layers.LayerTypeARP).(*layers.ARP)
		if a == nil || a.Operation != layers.ARPRequest {
			return nil
		}
		target := netip.AddrFrom4([4]byte(a.DstProtAddress)).String()
		mac := hosts[target]
		if mac == nil {
			return nil
		}
		return [][]byte{frames.ARP(layers.ARPReply, mac, target, a.SourceHwAddress, netip.AddrFrom4([4]byte(a.SourceProtAddress)).String())}
	}
}

// drive moves the simulated clock along until stop is closed, so paced
// probes and reply timeouts make progress.
func (h *harness) drive() (stop func()) {
	done, finished := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(finished)
		for {
			select {
			case <-done:
				return
			default:
				h.sim.Advance(20 * time.Millisecond)
				time.Sleep(200 * time.Microsecond)
			}
		}
	}()
	return func() { close(done); <-finished }
}

const activeConfig = `active: { startup_delay: 24h }
`

func activeLinks(_ *fake.Neighbors, i *fake.Interfaces) {
	i.SetLinks([]platform.Link{{Name: "eth1", Index: 2, Up: true, MAC: net.HardwareAddr{2, 0, 0, 0, 0, 9},
		Prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.110.0/24")},
		Addrs:    []netip.Prefix{netip.MustParsePrefix("192.168.110.2/24")}}})
}

func TestOperatorScanThroughTheDaemon(t *testing.T) {
	cfg := strings.Replace(testConfig("$DIR", "info", activeConfig), "networks: [192.168.110.0/24]", "networks: [192.168.110.0/29]", 1)
	h := startWith(t, cfg, 0, activeLinks)
	h.tx.FrameReply = arpNetwork(map[string]net.HardwareAddr{"192.168.110.3": plcMAC})
	h.waitState("eth1", platform.CollectorInterface, platform.StateRunning)
	h.waitState("eth1", platform.CollectorARP, platform.StateRunning)
	client := api.NewClient(filepath.Join(h.dir, "api.sock"), 5*time.Second)
	ctx := context.Background()

	plan, err := client.PlanScan(ctx, probe.Request{})
	if err != nil || !plan.Allowed || plan.Interfaces[0].SweepTargets != 5 {
		t.Fatalf("plan = %+v, %v (6 hosts minus the own .2)", plan, err)
	}
	stop := h.drive()
	res, err := client.Scan(ctx, probe.Request{Interfaces: []string{"eth1"}})
	stop()
	if err != nil || len(res.Interfaces) != 1 || res.Interfaces[0].Responders != 1 || res.Interfaces[0].Counts["arp"]["reply"] != 1 {
		t.Fatalf("scan = %+v, %v", res, err)
	}
	if n := len(h.tx.SentFrames()); n != 5 {
		t.Errorf("%d ARP requests, want 5", n)
	}
	h.waitLog("HOST_DISCOVERED eth1 00:1b:1b:aa:bb:01 192.168.110.3")
	h.waitLog("SCAN_COMPLETED")

	st, err := client.Status(ctx)
	if err != nil || st.LastScan == nil || st.LastScan.Kind != "arp" || st.LastScan.Finished == nil || st.LastScan.Interface != "eth1" {
		t.Errorf("status last scan = %+v, %v", st.LastScan, err)
	}
	m := metricsText(h.d.gather(ctx))
	for _, want := range []string{
		`lan_sentinel_probe_total{interface="eth1",protocol="arp",port="",result="reply"} 1`,
		`lan_sentinel_probe_total{interface="eth1",protocol="arp",port="",result="no_reply"} 4`,
		`lan_sentinel_probe_throttled_total{protocol="arp",reason="protocol"}`,
		`lan_sentinel_scan_duration_seconds{interface="eth1",protocol="arp"}`,
	} {
		if !strings.Contains(m, want) {
			t.Errorf("metrics lack %q:\n%s", want, m)
		}
	}
	if strings.Contains(m, "192.168.110") || strings.Contains(m, "00:1b:1b") {
		t.Error("metrics leak an address")
	}
	h.stop()
	db := filepath.Join(h.dir, "data", "hosts.db")
	if got := queryDB(t, db, `SELECT kind || ' ' || trigger || ' ' || targets || ' ' || (finished_at IS NOT NULL) FROM scans`); len(got) != 1 || got[0] != "arp operator 5 1" {
		t.Errorf("scans = %v", got)
	}
	if got := queryDB(t, db, `SELECT source FROM observations WHERE ip = '192.168.110.3'`); len(got) != 1 || got[0] != "arp_scan" {
		t.Errorf("observations = %v", got)
	}
}

func metricsText(fams []metrics.Family) string {
	var sb strings.Builder
	_ = metrics.Write(&sb, fams)
	return sb.String()
}

func TestKillSwitchPersistsAcrossRestarts(t *testing.T) {
	h := startWith(t, testConfig("$DIR", "info", activeConfig), 0, activeLinks)
	h.waitState("eth1", platform.CollectorARP, platform.StateRunning)
	client := api.NewClient(filepath.Join(h.dir, "api.sock"), 5*time.Second)
	ctx := context.Background()

	st, err := client.DisableActive(ctx, "PLC fault on line 3")
	if err != nil || !st.Disabled || st.Reason != "PLC fault on line 3" || st.By == "" || st.Forced {
		t.Fatalf("disable = %+v, %v", st, err)
	}
	h.waitState("eth1", platform.CollectorARP, platform.StateDisabled)
	if _, err := client.Scan(ctx, probe.Request{}); !errors.Is(err, scheduler.ErrScanRefused) {
		t.Errorf("scan with the switch set: %v", err)
	}
	status, _ := client.Status(ctx)
	if !status.Active.Disabled || status.Active.Reason != "PLC fault on line 3" {
		t.Errorf("status active = %+v", status.Active)
	}
	if m := metricsText(h.d.gather(ctx)); !strings.Contains(m, "lan_sentinel_active_disabled 1") {
		t.Error("active_disabled metric not 1")
	}
	h.waitLog("ACTIVE_DISABLED")
	h.stop()

	// A new daemon on the same database starts with the switch set.
	db := filepath.Join(h.dir, "data", "hosts.db")
	if got := queryDB(t, db, `SELECT json_extract(value, '$.reason') FROM runtime_state WHERE key = 'active_disabled'`); len(got) != 1 || got[0] != "PLC fault on line 3" {
		t.Fatalf("runtime_state = %v", got)
	}
	backends, _, _, ifaces, _ := fake.Backends()
	activeLinks(nil, ifaces)
	d, err := New(Options{Load: config.LoadOptions{Path: h.cfgPath}, Stderr: &syncBuffer{}, Clock: h.sim, Backends: &backends,
		Notifier: &fakeNotifier{}, Signals: make(chan os.Signal)})
	if err != nil {
		t.Fatal(err)
	}
	rctx, cancel := context.WithCancel(ctx)
	errc := make(chan error, 1)
	go func() { errc <- d.Run(rctx) }()
	<-d.Ready()
	if !d.sw.Disabled() || d.sw.State().Reason != "PLC fault on line 3" {
		t.Errorf("switch after restart = %+v", d.sw.State())
	}
	client = api.NewClient(filepath.Join(h.dir, "api.sock"), 5*time.Second)
	if st, err := client.EnableActive(ctx, "fixed"); err != nil || st.Disabled {
		t.Errorf("enable = %+v, %v", st, err)
	}
	if st, err := client.EnableActive(ctx, "again"); err != nil || st.Disabled {
		t.Errorf("enable when enabled = %+v, %v", st, err)
	}
	cancel()
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	if got := queryDB(t, db, `SELECT count(*) FROM runtime_state WHERE key = 'active_disabled'`); got[0] != "0" {
		t.Errorf("runtime_state after enable = %v", got)
	}
	if got := queryDB(t, db, `SELECT type FROM events WHERE type LIKE 'ACTIVE_%' ORDER BY id`); strings.Join(got, ",") != "ACTIVE_DISABLED,ACTIVE_ENABLED" {
		t.Errorf("events = %v (one enable: the second was a no-op)", got)
	}
}

func TestEnvironmentSwitchCannotBeCleared(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(testConfig(dir, "info", "")), 0o600); err != nil {
		t.Fatal(err)
	}
	backends, _, _, _, _ := fake.Backends()
	d, err := New(Options{Load: config.LoadOptions{Path: cfgPath, Environ: []string{config.EnvActiveDisabled + "=1"}},
		Stderr: &syncBuffer{}, Backends: &backends, Notifier: &fakeNotifier{}, Signals: make(chan os.Signal)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- d.Run(ctx) }()
	<-d.Ready()
	client := api.NewClient(filepath.Join(dir, "api.sock"), 5*time.Second)
	if _, err := client.EnableActive(context.Background(), ""); err == nil || !strings.Contains(err.Error(), config.EnvActiveDisabled) {
		t.Errorf("enable while forced: %v", err)
	}
	st, err := client.DisableActive(context.Background(), "belt and braces")
	if err != nil || !st.Forced {
		t.Errorf("disable while forced = %+v, %v", st, err)
	}
	cancel()
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	got := queryDB(t, filepath.Join(dir, "data", "hosts.db"),
		`SELECT json_extract(evidence_json, '$.actor') || ' ' || new_value FROM events WHERE type = 'ACTIVE_DISABLED' ORDER BY id`)
	if len(got) != 2 || !strings.HasPrefix(got[0], "env active discovery disabled by env: LAN_SENTINEL_ACTIVE_DISABLED=1") {
		t.Errorf("events = %v", got)
	}
}

func TestNoScannerInReplay(t *testing.T) {
	d := &Daemon{}
	if _, err := d.PlanScan(context.Background(), probe.Request{}); !errors.Is(err, api.ErrNoScanner) {
		t.Errorf("PlanScan = %v", err)
	}
	if _, err := d.Scan(context.Background(), probe.Request{}, "bart"); !errors.Is(err, api.ErrNoScanner) {
		t.Errorf("Scan = %v", err)
	}
	if links := d.probeLinks(); len(links) != 0 {
		t.Errorf("links without an interface manager = %v", links)
	}
}

func TestReloadAppliesBudgets(t *testing.T) {
	h := startWith(t, testConfig("$DIR", "info", activeConfig), 0, activeLinks)
	defer h.stop()
	h.writeConfig(testConfig(h.dir, "info", "active: { startup_delay: 24h, max_packets_per_second: 30 }\n"))
	h.signals <- syscall.SIGHUP
	h.waitLog("configuration reloaded")
	if got := h.d.Config().Active.MaxPacketsPerSecond; got != 30 {
		t.Errorf("max_packets_per_second = %v", got)
	}
	plan, err := h.d.PlanScan(context.Background(), probe.Request{})
	if err != nil || plan.Rates.GlobalPPS != 30 {
		t.Errorf("plan rates = %+v, %v", plan.Rates, err)
	}
}

// A reload through the API applies each interface's active settings,
// lists restart-only changes as not applied, and rejects a file that does
// not validate as a whole.
func TestReloadConfigThroughTheAPI(t *testing.T) {
	const eth1 = "  - name: eth1\n    active: { enabled: true, networks: [192.168.110.0/24] }\n"
	off := strings.Replace(testConfig("$DIR", "info", activeConfig), "enabled: true", "enabled: false", 1)
	h := startWith(t, off, 0, activeLinks)
	defer h.stop()
	h.waitState("eth1", platform.CollectorARP, platform.StateDisabled)
	client := api.NewClient(filepath.Join(h.dir, "api.sock"), 5*time.Second)
	ctx := context.Background()

	// Switching active discovery on takes effect without a restart.
	h.writeConfig(testConfig(h.dir, "info", activeConfig))
	res, err := client.ReloadConfig(ctx)
	if err != nil || res.Path != h.cfgPath || len(res.NotApplied) != 0 ||
		len(res.Applied) != 1 || res.Applied[0] != (config.Change{Key: "interfaces[0].active.enabled", Old: "false", New: "true"}) {
		t.Fatalf("enable = %+v, %v", res, err)
	}
	h.waitState("eth1", platform.CollectorARP, platform.StateRunning)
	h.waitLog("applied=[interfaces[0].active.enabled]")

	// A new interface needs a restart; the active change beside it applies.
	h.writeConfig(strings.Replace(testConfig(h.dir, "debug", activeConfig), eth1,
		strings.Replace(eth1, "enabled: true", "enabled: false", 1)+"  - name: eth2\n", 1))
	res, err = client.ReloadConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	applied := map[string]bool{}
	for _, c := range res.Applied {
		applied[c.Key] = true
	}
	if len(res.Applied) != 2 || !applied["interfaces[0].active.enabled"] || !applied["logging.level"] {
		t.Errorf("applied = %+v", res.Applied)
	}
	if !slices.Contains(res.NotApplied, config.Change{Key: "interfaces[1].name", New: "eth2"}) {
		t.Errorf("not applied = %+v", res.NotApplied)
	}
	if cfg := h.d.Config(); len(cfg.Interfaces) != 1 || cfg.Interfaces[0].Active.Enabled || cfg.Logging.Level != "debug" {
		t.Errorf("running config = %+v", cfg)
	}
	h.waitState("eth1", platform.CollectorARP, platform.StateDisabled)

	// An invalid file changes nothing.
	h.writeConfig(testConfig(h.dir, "loud", activeConfig))
	if _, err := client.ReloadConfig(ctx); !errors.Is(err, api.ErrConfigRejected) || !strings.Contains(err.Error(), "logging.level") {
		t.Errorf("invalid file: %v", err)
	}
	if h.d.Config().Logging.Level != "debug" {
		t.Errorf("rejected reload changed the level to %s", h.d.Config().Logging.Level)
	}
}

// The running values a reload keeps must validate with the new file: an
// interface that is still monitored keeps its wide network, which the new
// file no longer allows, so the reload is rejected.
func TestReloadRevalidatesKeptValues(t *testing.T) {
	wide := strings.Replace(testConfig("$DIR", "info", "active: { startup_delay: 24h, allow_wide_scan: true }\n"),
		"storage:", "  - name: eth2\n    active: { enabled: true, networks: [10.0.0.0/20] }\nstorage:", 1)
	h := startWith(t, wide, 0, activeLinks)
	defer h.stop()
	h.writeConfig(testConfig(h.dir, "info", activeConfig))
	_, err := h.d.ReloadConfig(context.Background(), "bart")
	if !errors.Is(err, api.ErrConfigRejected) || !strings.Contains(err.Error(), "interfaces[1].active.networks[0]") {
		t.Fatalf("reload = %v", err)
	}
	if cfg := h.d.Config(); !cfg.Active.AllowWideScan || len(cfg.Interfaces) != 2 {
		t.Errorf("running config changed: %+v", cfg.Active)
	}
	h.waitLog("actor=bart")
}

// After shutdown the correlator is gone: kill-switch requests fail at once
// instead of waiting, and a failed enable leaves probing stopped.
func TestKillSwitchAfterShutdown(t *testing.T) {
	h := startWith(t, testConfig("$DIR", "info", activeConfig), 0, activeLinks)
	ctx := context.Background()
	if _, err := h.d.DisableActive(ctx, "bart", "maintenance"); err != nil {
		t.Fatal(err)
	}
	h.stop()
	done := make(chan error, 1)
	go func() {
		_, err := h.d.EnableActive(ctx, "bart", "done")
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Error("enable after shutdown succeeded")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("enable after shutdown blocked")
	}
	if !h.d.sw.Disabled() {
		t.Error("a failed enable resumed probing")
	}
	if _, err := h.d.DisableActive(ctx, "bart", "again"); err == nil {
		t.Error("disable after shutdown reported success")
	}
}

// Events record the kernel clock's state: a box that boots before NTP sync
// marks its events, and daemon status says so.
func TestEventsRecordClockState(t *testing.T) {
	h := startWith(t, testConfig("$DIR", "info", activeConfig), 0, activeLinks)
	clock := h.d.backends.Clock.(*fake.Clock)
	client := api.NewClient(filepath.Join(h.dir, "api.sock"), 5*time.Second)
	h.waitLog("SUBNET_CHANGED")
	st, err := client.Status(context.Background())
	if err != nil || st.Clock != platform.ClockSynced {
		t.Errorf("status clock = %q, %v", st.Clock, err)
	}
	clock.Set(platform.ClockUnsynced)
	if _, err := client.DisableActive(context.Background(), "clock test"); err != nil {
		t.Fatal(err)
	}
	if st, _ := client.Status(context.Background()); st.Clock != platform.ClockUnsynced {
		t.Errorf("status clock = %q", st.Clock)
	}
	h.stop()
	got := queryDB(t, filepath.Join(h.dir, "data", "hosts.db"), `SELECT type || ' ' || clock_sync FROM events ORDER BY id`)
	if len(got) < 2 || got[0] != "SUBNET_CHANGED synced" || got[len(got)-1] != "ACTIVE_DISABLED unsynced" {
		t.Errorf("events = %v", got)
	}
}

func TestUnsyncedClockAtStartIsLogged(t *testing.T) {
	h := startWithClock(t, testConfig("$DIR", "info", activeConfig), 0, activeLinks, platform.ClockUnsynced)
	defer h.stop()
	h.waitLog("system clock is not known to be synchronised")
	st, err := api.NewClient(filepath.Join(h.dir, "api.sock"), 5*time.Second).Status(context.Background())
	if err != nil || st.Clock != platform.ClockUnsynced {
		t.Errorf("status clock = %q, %v", st.Clock, err)
	}
}
