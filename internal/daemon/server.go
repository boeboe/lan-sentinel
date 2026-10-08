package daemon

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"sort"
	"time"

	"lan-sentinel/internal/api"
	"lan-sentinel/internal/buildinfo"
	"lan-sentinel/internal/events"
	"lan-sentinel/internal/metrics"
	"lan-sentinel/internal/observation"
	"lan-sentinel/internal/platform"
	"lan-sentinel/internal/probe"
	"lan-sentinel/internal/probe/scheduler"
	"lan-sentinel/internal/store"
)

// presences are the presence states, for status and metrics.
var presences = []string{"ACTIVE", "RECENT", "STALE", "MISSING"}

// dhcpStatuses are the DHCP server allowlist verdicts (lan_sentinel_dhcp_servers).
var dhcpStatuses = []string{"allowed", "unexpected", "unchecked"}

// startAPI opens the reader and starts the API server on the configured
// socket (and loopback listener, with /metrics when enabled).
func (d *Daemon) startAPI(ctx context.Context) error {
	cfg := d.cfg.Load()
	var m http.Handler
	if cfg.Metrics.Enabled {
		m = metrics.Handler(func(req *http.Request) []metrics.Family { return d.gather(req.Context()) })
	}
	d.api = api.New(api.Options{
		Reader: d.reader, Status: d.status, Interfaces: d.interfaces, Config: func() any { return d.cfg.Load() },
		Events: d.events, Metrics: m, Control: d, Logger: d.log,
	})
	return d.api.Start(ctx, cfg.API.Socket, cfg.API.Listen)
}

// stopAPI waits for the API to shut down (its context is cancelled first)
// and closes the reader, so the store's last connection can remove the
// WAL.
func (d *Daemon) stopAPI() {
	if d.api != nil {
		if err := d.api.Wait(); err != nil {
			d.log.Warn("api stopped with an error", "err", err)
		}
	}
	if d.reader != nil {
		_ = d.reader.Close()
	}
}

// interfaces lists interfaces from the database, completed with the
// configuration and the interface manager's live state.
func (d *Daemon) interfaces(ctx context.Context) ([]store.InterfaceInfo, error) {
	ifs, err := d.reader.Interfaces(ctx)
	if err != nil {
		return nil, err
	}
	ifs = api.WithConfig(ifs, d.cfg.Load())
	if d.ifaces == nil {
		return ifs, nil
	}
	links := d.ifaces.Links()
	for i := range ifs {
		l, ok := links[ifs[i].Name]
		if !ok {
			continue
		}
		switch {
		case !l.Present:
			ifs[i].State = "absent"
		case l.Up:
			ifs[i].State = "up"
		default:
			ifs[i].State = "down"
		}
		if l.MAC != nil {
			ifs[i].MAC = l.MAC.String()
		}
	}
	return ifs, nil
}

// status builds /v1/status: unhealthy when the database does not answer,
// degraded when a configured collector is not running.
func (d *Daemon) status(ctx context.Context) api.Status {
	bi := buildinfo.Get()
	cfg := d.cfg.Load()
	s := api.Status{
		Version: bi.Version, Commit: bi.Commit, Platform: bi.Platform, PID: os.Getpid(), Started: d.started.UTC(), Now: time.Now().UTC(),
		Replay: cfg.ReplayMode(), State: api.StateOK, Database: api.DatabaseStatus{Path: d.store.Path(), OK: true},
		Hosts: map[string]map[string]int{},
	}
	pctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := d.store.Ping(pctx); err != nil {
		s.Database.OK, s.Database.Error = false, "database writer not responding: "+err.Error()
	}
	if info, err := d.reader.DBSummary(ctx); err != nil {
		s.Database.OK, s.Database.Error = false, err.Error()
	} else {
		s.Database.Size, s.Database.UsedSize, s.Database.WALSize, s.Database.SchemaVersion = info.Size, info.UsedSize, info.WALSize, info.SchemaVersion
	}
	s.Active = d.sw.State()
	s.Clock = platform.ClockUnknown
	if d.backends.Clock != nil && !cfg.ReplayMode() {
		s.Clock = d.backends.Clock.State()
	}
	if last, err := d.reader.LastScan(ctx); err == nil {
		s.LastScan = last
	}
	if counts, err := d.reader.HostCounts(ctx); err == nil {
		s.Hosts = counts
	}
	ifs, err := d.interfaces(ctx)
	if err != nil {
		s.Database.OK, s.Database.Error = false, err.Error()
	}
	collectors := d.registry.List()
	var passes map[string]map[string]scheduler.PassSummary
	if d.sched != nil {
		passes = d.sched.LastPasses()
	}
	for _, i := range ifs {
		is := api.InterfaceStatus{InterfaceInfo: i, Collectors: []api.CollectorStatus{}}
		for _, c := range collectors {
			if c.Interface == i.Name {
				cs := api.CollectorStatus{CollectorStatus: c}
				if p, ok := passes[i.Name][c.Collector]; ok {
					cs.LastPass = &p
				}
				is.Collectors = append(is.Collectors, cs)
				if c.State == platform.StateFailed || c.State == platform.StateUnsupported {
					s.Problems = append(s.Problems, c.Interface+" "+c.Collector+": "+c.Error)
				}
			}
		}
		s.Interfaces = append(s.Interfaces, is)
	}
	switch {
	case !s.Database.OK:
		s.State = api.StateUnhealthy
		s.Problems = append(s.Problems, s.Database.Error)
	case d.registry.Degraded():
		s.State = api.StateDegraded
	}
	return s
}

// gather collects the metrics (docs/ARCHITECTURE.md §3, Metrics). Labels are
// the allow-list in metrics.AllowedLabels only (never a MAC, IP or host id).
func (d *Daemon) gather(ctx context.Context) []metrics.Family {
	cfg := d.cfg.Load()
	var fams []metrics.Family
	add := func(name, help, typ string, samples ...metrics.Sample) {
		fams = append(fams, metrics.Family{Name: metrics.Prefix + name, Help: help, Type: typ, Samples: samples})
	}

	// Left out when the count fails: zeros would look like every host left.
	if counts, err := d.reader.HostCounts(ctx); err == nil {
		var hosts []metrics.Sample
		for _, ic := range cfg.Interfaces {
			for _, p := range presences {
				hosts = append(hosts, metrics.Sample{Labels: metrics.L("interface", ic.Name, "presence", p), Value: float64(counts[ic.Name][p])})
			}
		}
		add("hosts", "Hosts per interface and presence state.", metrics.Gauge, hosts...)
	}
	if counts, err := d.reader.DHCPServerCounts(ctx, d.clock.Now().Add(-cfg.Presence.Stale.D())); err == nil {
		var servers []metrics.Sample
		for _, ic := range cfg.Interfaces {
			for _, st := range dhcpStatuses {
				servers = append(servers, metrics.Sample{Labels: metrics.L("interface", ic.Name, "status", st), Value: float64(counts[ic.Name][st])})
			}
		}
		add("dhcp_servers", "DHCP servers (identity, relay and sender) heard from within presence.stale, per interface and allowlist verdict.",
			metrics.Gauge, servers...)
	}

	var evs []metrics.Sample
	emitted := d.events.Counts()
	for _, spec := range events.All() {
		evs = append(evs, metrics.Sample{Labels: metrics.L("type", string(spec.Type)), Value: float64(emitted[spec.Type])})
	}
	add("events_total", "Events emitted since the daemon started.", metrics.Counter, evs...)

	processed, unbound := d.correlator.SourceCounts()
	var obs, unb []metrics.Sample
	for _, src := range observation.Sources {
		obs = append(obs, metrics.Sample{Labels: metrics.L("source", string(src)), Value: float64(processed[src])})
		unb = append(unb, metrics.Sample{Labels: metrics.L("source", string(src)), Value: float64(unbound[src])})
	}
	add("observations_total", "Observations processed by the correlator.", metrics.Counter, obs...)
	add("observations_unbound_total", "Observations without a MAC that matched no host.", metrics.Counter, unb...)
	add("bus_dropped_total", "Observations dropped because the bus was full.", metrics.Counter, metrics.Sample{Value: float64(d.bus.Dropped())})

	if d.capture != nil {
		var drops []metrics.Sample
		for _, st := range d.capture.Stats() {
			drops = append(drops, metrics.Sample{Labels: metrics.L("interface", st.Interface), Value: float64(st.Dropped)})
		}
		add("capture_drops_total", "Frames the kernel dropped because the capture ring was full.", metrics.Counter, drops...)
	}

	if info, err := d.reader.DBSummary(ctx); err == nil {
		add("db_size_bytes", "Database data size (pages in use), compared with storage.retention.max_db_size.", metrics.Gauge,
			metrics.Sample{Value: float64(info.UsedSize)})
	}
	disabled := 0.0
	if d.sw.Disabled() {
		disabled = 1
	}
	add("active_disabled", "1 when the active-discovery kill switch is set.", metrics.Gauge, metrics.Sample{Value: disabled})
	if d.sched != nil {
		d.probeMetrics(add)
	}

	var up []metrics.Sample
	for _, c := range d.registry.List() {
		if c.State == platform.StateDisabled {
			continue
		}
		v := 0.0
		if c.State == platform.StateRunning {
			v = 1
		}
		up = append(up, metrics.Sample{Labels: metrics.L("interface", c.Interface, "collector", c.Collector), Value: v})
	}
	add("collector_up", "1 when a configured collector is running.", metrics.Gauge, up...)
	return fams
}

// probeMetrics adds the active-discovery metrics.
func (d *Daemon) probeMetrics(add func(name, help, typ string, samples ...metrics.Sample)) {
	counts := d.sched.Counts()
	keys := make([]scheduler.Count, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		return fmt.Sprint(a.Interface, a.Protocol, a.Port, a.Result) < fmt.Sprint(b.Interface, b.Protocol, b.Port, b.Result)
	})
	var probes []metrics.Sample
	for _, k := range keys {
		probes = append(probes, metrics.Sample{
			Labels: metrics.L("interface", k.Interface, "protocol", string(k.Protocol), "port", k.Port, "result", k.Result),
			Value:  float64(counts[k]),
		})
	}
	add("probe_total", "Probes sent, per interface, protocol, port and result.", metrics.Counter, probes...)

	throttled := d.budget.Throttled()
	tkeys := make([]probe.Throttle, 0, len(throttled))
	for k := range throttled {
		tkeys = append(tkeys, k)
	}
	sort.Slice(tkeys, func(i, j int) bool {
		return tkeys[i].Protocol < tkeys[j].Protocol || tkeys[i].Protocol == tkeys[j].Protocol && tkeys[i].Reason < tkeys[j].Reason
	})
	var ts []metrics.Sample
	for _, k := range tkeys {
		ts = append(ts, metrics.Sample{Labels: metrics.L("protocol", string(k.Protocol), "reason", k.Reason), Value: float64(throttled[k])})
	}
	add("probe_throttled_total", "Probes that waited for a safety limit, per protocol and limit.", metrics.Counter, ts...)

	durations := d.sched.Durations()
	dkeys := make([][2]string, 0, len(durations))
	for k := range durations {
		dkeys = append(dkeys, k)
	}
	sort.Slice(dkeys, func(i, j int) bool {
		return dkeys[i][0] < dkeys[j][0] || dkeys[i][0] == dkeys[j][0] && dkeys[i][1] < dkeys[j][1]
	})
	var ds []metrics.Sample
	for _, k := range dkeys {
		ds = append(ds, metrics.Sample{Labels: metrics.L("interface", k[0], "protocol", k[1]), Value: durations[k]})
	}
	add("scan_duration_seconds", "Duration of the last probe pass or operator scan, per interface and protocol.", metrics.Gauge, ds...)

	eng := d.identify
	if eng == nil {
		return
	}
	var attempts []metrics.Sample
	for k, n := range eng.Attempts() {
		attempts = append(attempts, metrics.Sample{Labels: metrics.L("probe", k[0], "result", k[1]), Value: float64(n)})
	}
	add("identify_attempts_total", "Identification exchanges that left the box, per probe and result.", metrics.Counter, attempts...)
	var durs []metrics.Sample
	for name, v := range eng.Durations() {
		durs = append(durs, metrics.Sample{Labels: metrics.L("probe", name), Value: v})
	}
	add("identify_duration_seconds", "Duration of the last completed identification exchange.", metrics.Gauge, durs...)
	var suppressed []metrics.Sample
	for k, n := range d.sched.IdentifySuppressed() {
		suppressed = append(suppressed, metrics.Sample{Labels: metrics.L("probe", k[0], "reason", k[1]), Value: float64(n)})
	}
	add("identify_suppressed_total", "Eligible-looking hosts not sent to, per probe and reason.", metrics.Counter, suppressed...)
	var claims []metrics.Sample
	for k, n := range eng.Claims() {
		claims = append(claims, metrics.Sample{Labels: metrics.L("probe", k[0], "field", k[1]), Value: float64(n)})
	}
	add("identify_claims_total", "Identity claims adopted from a successful identification exchange.", metrics.Counter, claims...)
}
