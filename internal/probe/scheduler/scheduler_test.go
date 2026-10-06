package scheduler

import (
	"context"
	"errors"
	"math/rand/v2"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"lan-sentinel/internal/clock"
	"lan-sentinel/internal/config"
	"lan-sentinel/internal/observation"
	"lan-sentinel/internal/platform"
	"lan-sentinel/internal/probe"
	"lan-sentinel/internal/store"
)

var t0 = time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)

func ip(s string) netip.Addr { return netip.MustParseAddr(s) }

// engine is a fake probe engine: it records passes and answers from
// result; with hold set, a pass waits until its context ends.
type engine struct {
	proto  probe.Protocol
	result func(probe.Pass) ([]probe.Result, error)
	hold   bool

	mu     sync.Mutex
	passes []probe.Pass
	ran    chan struct{}
}

func newEngine(p probe.Protocol) *engine { return &engine{proto: p, ran: make(chan struct{}, 100)} }

func (e *engine) Protocol() probe.Protocol { return e.proto }

func (e *engine) Run(ctx context.Context, p probe.Pass) ([]probe.Result, error) {
	if p.Sweep != nil { // list a sweep, for the tests to look at
		for a := range p.Sweep {
			if !p.InSweep(a) {
				return nil, errors.New("sweep yields an address it does not contain")
			}
			p.Targets = append(p.Targets, a)
		}
	}
	e.mu.Lock()
	e.passes = append(e.passes, p)
	result, hold := e.result, e.hold
	e.mu.Unlock()
	e.ran <- struct{}{}
	if hold {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if result != nil {
		return result(p)
	}
	out := make([]probe.Result, 0, len(p.Targets))
	for _, t := range p.Targets {
		out = append(out, probe.Result{Target: t, State: probe.Reply})
	}
	return out, nil
}

func (e *engine) all() []probe.Pass {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.passes)
}

func (e *engine) wait(t *testing.T) probe.Pass {
	t.Helper()
	select {
	case <-e.ran:
	case <-time.After(5 * time.Second):
		t.Fatalf("no %s pass", e.proto)
	}
	p := e.all()
	return p[len(p)-1]
}

func (e *engine) quiet(t *testing.T) {
	t.Helper()
	select {
	case <-e.ran:
		t.Fatalf("unexpected %s pass", e.proto)
	case <-time.After(20 * time.Millisecond):
	}
}

type known map[string][]netip.Addr

func (k known) Known(_ context.Context, iface string) ([]Known, error) {
	if iface == "broken" {
		return nil, errors.New("database busy")
	}
	out := make([]Known, 0, len(k[iface]))
	for _, a := range k[iface] {
		out = append(out, Known{IP: a})
	}
	return out, nil
}

// evidence is a known-host source whose hosts were last confirmed at seen.
type evidence struct {
	mu   sync.Mutex
	ips  []netip.Addr
	seen time.Time
}

func (e *evidence) Known(context.Context, string) ([]Known, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]Known, 0, len(e.ips))
	for _, a := range e.ips {
		out = append(out, Known{IP: a, LastSeen: e.seen})
	}
	return out, nil
}

type rig struct {
	t       *testing.T
	sim     *clock.Sim
	mu      sync.Mutex
	cfg     *config.Config
	links   map[string]probe.Link
	sw      *probe.Switch
	reg     *platform.Registry
	eng     map[probe.Protocol]*engine
	ops     []observation.Operator
	opErr   error
	failOn  observation.OperatorKind // fail only this kind (empty: every one)
	s       *Scheduler
	cancel  context.CancelFunc
	done    chan struct{}
	emitted []observation.Observation
}

func baseConfig() *config.Config {
	cfg := config.Defaults()
	var excl config.AddrOrPrefix
	_ = excl.UnmarshalText([]byte("192.168.110.1"))
	cfg.Interfaces = []config.InterfaceConfig{{Name: "eth1", Active: config.InterfaceActive{
		Enabled: true, Networks: []netip.Prefix{netip.MustParsePrefix("192.168.110.0/28")}, Exclude: []config.AddrOrPrefix{excl},
	}}}
	cfg.Active.ARP = config.ProbeConfig{Enabled: true, Interval: config.Duration(5 * time.Minute)}
	cfg.Profiles = map[string]config.ProfileConfig{"modbus": {ARP: true, TCP: []int{502}}}
	return cfg
}

func newRig(t *testing.T, cfg *config.Config) *rig {
	t.Helper()
	r := &rig{
		t: t, sim: clock.NewSim(t0), cfg: cfg, sw: probe.NewSwitch(store.ActiveState{}),
		links: map[string]probe.Link{"eth1": {Name: "eth1", MAC: net.HardwareAddr{2, 0, 0, 0, 0, 1},
			Addrs: []netip.Prefix{netip.MustParsePrefix("192.168.110.10/24")}}},
		eng: map[probe.Protocol]*engine{},
	}
	r.reg = platform.NewRegistry(r.sim.Now)
	engines := map[probe.Protocol]probe.Engine{}
	for _, p := range Protocols {
		r.eng[p] = newEngine(p)
		engines[p] = r.eng[p]
	}
	conf := func() *config.Config {
		r.mu.Lock()
		defer r.mu.Unlock()
		return r.cfg
	}
	r.s = New(Options{
		Config: conf,
		Links: func() map[string]probe.Link {
			r.mu.Lock()
			defer r.mu.Unlock()
			return r.links
		},
		Known:   known{"eth1": {ip("192.168.110.5"), ip("192.168.110.6")}},
		Engines: engines,
		Budget:  probe.NewBudget(r.sim, probe.Limits{MaxConcurrent: 10}, probe.ConfigPolicy{Switch: r.sw, Config: conf}),
		Switch:  r.sw,
		Emit: func(o observation.Observation) {
			r.mu.Lock()
			r.emitted = append(r.emitted, o)
			r.mu.Unlock()
		},
		Operator: func(_ context.Context, op observation.Operator) error {
			r.mu.Lock()
			defer r.mu.Unlock()
			fail := r.opErr != nil && (r.failOn == "" || r.failOn == op.Kind)
			if op.Kind == observation.OpScanStarted && !fail {
				op.Scan.Handle.ID = int64(len(r.ops) + 1)
			}
			r.ops = append(r.ops, op)
			if fail {
				return r.opErr
			}
			return nil
		},
		Registry: r.reg, Backend: "fake", Clock: r.sim, Rand: rand.New(rand.NewPCG(1, 2)),
	})
	return r
}

func (r *rig) start() {
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel, r.done = cancel, make(chan struct{})
	go func() {
		defer close(r.done)
		_ = r.s.Run(ctx)
	}()
	r.t.Cleanup(r.stop)
}

func (r *rig) stop() {
	if r.cancel != nil {
		r.cancel()
		<-r.done
		r.cancel = nil
	}
}

func (r *rig) setConfig(f func(*config.Config)) {
	r.mu.Lock()
	next := *r.cfg
	next.Active = r.cfg.Active
	f(&next)
	r.cfg = &next
	r.mu.Unlock()
	r.s.Reload()
}

// waiters waits until n timers are armed.
func (r *rig) waiters(n int) {
	r.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for r.sim.Waiters() != n {
		if time.Now().After(deadline) {
			r.t.Fatalf("%d timers armed, want %d", r.sim.Waiters(), n)
		}
		time.Sleep(time.Millisecond)
	}
}

// waitCount waits until a probe counter reaches n: a pass records its
// results after the engine returns.
func (r *rig) waitCount(c Count, n uint64) {
	r.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for r.s.Counts()[c] != n {
		if time.Now().After(deadline) {
			r.t.Fatalf("count %+v = %d, want %d (all %v)", c, r.s.Counts()[c], n, r.s.Counts())
		}
		time.Sleep(time.Millisecond)
	}
}

func (r *rig) state(p probe.Protocol) platform.CollectorStatus {
	for _, c := range r.reg.List() {
		if c.Interface == "eth1" && c.Collector == collectors[p] {
			return c
		}
	}
	return platform.CollectorStatus{}
}

func (r *rig) waitState(p probe.Protocol, st platform.State) {
	r.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for r.state(p).State != st {
		if time.Now().After(deadline) {
			r.t.Fatalf("%s state %+v, want %s", p, r.state(p), st)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestStartupDelayJitterAndInterval(t *testing.T) {
	r := newRig(t, baseConfig())
	r.start()
	r.waiters(1)
	for _, p := range []probe.Protocol{probe.ICMP, probe.TCP, probe.UDP} {
		r.waitState(p, platform.StateDisabled)
	}
	r.waitState(probe.ARP, platform.StateRunning)

	r.sim.Advance(29 * time.Second)
	r.eng[probe.ARP].quiet(t)
	// Startup delay 30 s plus up to 10% of the 5 min interval.
	r.sim.Advance(31 * time.Second)
	first := r.eng[probe.ARP].wait(t)
	firstAt := r.sim.Now()
	if len(first.Targets) != 12 || slices.Contains(first.Targets, ip("192.168.110.1")) || slices.Contains(first.Targets, ip("192.168.110.10")) {
		t.Errorf("sweep targets = %v", first.Targets)
	}
	if slices.IsSortedFunc(first.Targets, func(a, b netip.Addr) int { return a.Compare(b) }) {
		t.Error("targets not shuffled")
	}
	if first.Link.Name != "eth1" || first.Budget == nil || first.Emit == nil || first.Clock != r.sim {
		t.Errorf("pass = %+v", first)
	}

	r.waiters(1)
	r.sim.Advance(4*time.Minute + 29*time.Second) // below 5 min - 10%
	r.eng[probe.ARP].quiet(t)
	r.sim.Advance(61 * time.Second) // beyond 5 min + 10%
	r.eng[probe.ARP].wait(t)
	_ = firstAt

	r.waitCount(Count{Interface: "eth1", Protocol: probe.ARP, Result: "reply"}, 24)
	if _, ok := r.s.Durations()[[2]string{"eth1", "arp"}]; !ok {
		t.Errorf("durations = %v", r.s.Durations())
	}
}

func TestKillSwitchCancelsAndResumes(t *testing.T) {
	r := newRig(t, baseConfig())
	r.eng[probe.ARP].hold = true
	r.start()
	r.waiters(1)
	r.sim.Advance(time.Minute)
	r.eng[probe.ARP].wait(t)

	r.sw.Set(store.ActiveState{Disabled: true, Reason: "PLC fault"})
	r.waitState(probe.ARP, platform.StateDisabled)
	if st := r.state(probe.ARP); !strings.Contains(st.Error, "kill switch") {
		t.Errorf("state = %+v", st)
	}
	r.sim.Advance(time.Hour)
	r.eng[probe.ARP].quiet(t)

	r.eng[probe.ARP].mu.Lock()
	r.eng[probe.ARP].hold = false
	r.eng[probe.ARP].mu.Unlock()
	r.sw.Set(store.ActiveState{})
	// The pass that was cut short was due again long ago.
	r.eng[probe.ARP].wait(t)
	r.waitState(probe.ARP, platform.StateRunning)
}

func TestBackoffOnKnownHosts(t *testing.T) {
	cfg := baseConfig()
	cfg.Active.ARP.Enabled = false
	cfg.Active.ICMP = config.ProbeConfig{Enabled: true, Interval: config.Duration(10 * time.Minute)}
	cfg.Active.StartupDelay = 0
	cfg.Active.Jitter = 0
	r := newRig(t, cfg)
	r.eng[probe.ICMP].result = func(p probe.Pass) ([]probe.Result, error) {
		var out []probe.Result
		for _, tg := range p.Targets {
			st := probe.Reply
			if tg == ip("192.168.110.5") {
				st = probe.NoReply
			}
			out = append(out, probe.Result{Target: tg, State: st})
		}
		return out, nil
	}
	r.start()
	for i := range 3 {
		r.waiters(1)
		if i > 0 {
			r.sim.Advance(10 * time.Minute)
		} else {
			r.sim.Advance(time.Millisecond)
		}
		if p := r.eng[probe.ICMP].wait(t); len(p.Targets) != 2 {
			t.Fatalf("pass %d targets = %v", i, p.Targets)
		}
	}
	r.waiters(1)
	r.sim.Advance(10 * time.Minute)
	if p := r.eng[probe.ICMP].wait(t); !slices.Equal(p.Targets, []netip.Addr{ip("192.168.110.6")}) {
		t.Errorf("after three timeouts the silent host is still probed: %v", p.Targets)
	}
	for range 3 {
		r.waiters(1)
		r.sim.Advance(10 * time.Minute)
		r.eng[probe.ICMP].wait(t)
	}
	passes := r.eng[probe.ICMP].all()
	if last := passes[len(passes)-1]; len(last.Targets) != 2 {
		t.Errorf("four intervals later the silent host is not probed again: %v", last.Targets)
	}
}

func TestBackoffEasedByFreshEvidence(t *testing.T) {
	cfg := baseConfig()
	cfg.Active.ARP.Enabled = false
	cfg.Active.ICMP = config.ProbeConfig{Enabled: true, Interval: config.Duration(10 * time.Minute)}
	cfg.Active.StartupDelay = 0
	cfg.Active.Jitter = 0
	r := newRig(t, cfg)
	src := &evidence{ips: []netip.Addr{ip("192.168.110.5")}}
	r.s.o.Known = src
	r.eng[probe.ICMP].result = func(p probe.Pass) ([]probe.Result, error) {
		var out []probe.Result
		for _, tg := range p.Targets {
			out = append(out, probe.Result{Target: tg, State: probe.NoReply})
		}
		return out, nil
	}
	r.start()
	r.waiters(1)
	r.sim.Advance(time.Millisecond)
	r.eng[probe.ICMP].wait(t)
	for range 2 {
		r.waiters(1)
		r.sim.Advance(10 * time.Minute)
		r.eng[probe.ICMP].wait(t)
	}
	// Three misses: the next pass leaves the host out (the engine is not
	// even run).
	r.waiters(1)
	r.sim.Advance(10 * time.Minute)
	r.eng[probe.ICMP].quiet(t)
	// Passive traffic from the host arrives: the next pass probes it again.
	src.mu.Lock()
	src.seen = r.sim.Now()
	src.mu.Unlock()
	r.waiters(1)
	r.sim.Advance(10 * time.Minute)
	if p := r.eng[probe.ICMP].wait(t); !slices.Equal(p.Targets, []netip.Addr{ip("192.168.110.5")}) {
		t.Errorf("targets after fresh evidence = %v", p.Targets)
	}
}

func TestTCPAndUDPRunPerPortAndProbe(t *testing.T) {
	cfg := baseConfig()
	cfg.Active.ARP.Enabled = false
	cfg.Active.StartupDelay = 0
	cfg.Active.TCP = config.TCPProbeConfig{Enabled: true, Interval: config.Duration(5 * time.Minute),
		Targets: []config.TCPTarget{{Port: 502}, {Port: 80}}}
	cfg.Active.UDP = config.UDPProbeConfig{Enabled: true, Interval: config.Duration(15 * time.Minute), Probes: []string{"ntp", "enip"}}
	r := newRig(t, cfg)
	r.eng[probe.TCP].result = func(p probe.Pass) ([]probe.Result, error) {
		return []probe.Result{{Target: p.Targets[0], Port: p.TCP[0].Port, State: "TIMEOUT"}}, nil
	}
	r.start()
	r.waiters(2)
	r.sim.Advance(2 * time.Minute) // beyond the 10% spread of both intervals
	r.eng[probe.TCP].wait(t)
	r.eng[probe.TCP].wait(t)
	tcp := r.eng[probe.TCP].all()
	if len(tcp[0].TCP) != 1 || len(tcp[1].TCP) != 1 || tcp[0].TCP[0].Port != 502 || tcp[1].TCP[0].Port != 80 {
		t.Errorf("tcp passes %+v, %+v", tcp[0].TCP, tcp[1].TCP)
	}
	r.eng[probe.UDP].wait(t)
	r.eng[probe.UDP].wait(t)
	udp := r.eng[probe.UDP].all()
	if !slices.Equal(udp[0].UDP, []string{"ntp"}) || !slices.Equal(udp[1].UDP, []string{"enip"}) {
		t.Errorf("udp passes %v, %v", udp[0].UDP, udp[1].UDP)
	}
	r.waitCount(Count{Interface: "eth1", Protocol: probe.TCP, Port: "502", Result: "timeout"}, 1)
}

func TestReloadChangesIntervalAndEnabled(t *testing.T) {
	cfg := baseConfig()
	cfg.Active.StartupDelay = 0
	cfg.Active.Jitter = 0
	r := newRig(t, cfg)
	r.start()
	r.waiters(1)
	r.sim.Advance(time.Millisecond)
	r.eng[probe.ARP].wait(t)
	r.waiters(1)

	r.setConfig(func(c *config.Config) { c.Active.ARP.Interval = config.Duration(time.Minute) })
	if took := r.advanceUntil(probe.ARP, 10*time.Second); took > 90*time.Second {
		t.Errorf("next pass %v after a reload to a 1 min interval", took)
	}

	r.setConfig(func(c *config.Config) { c.Active.ARP.Enabled = false })
	r.waitState(probe.ARP, platform.StateDisabled)
	r.sim.Advance(time.Hour)
	r.eng[probe.ARP].quiet(t)

	r.setConfig(func(c *config.Config) { c.Active.ARP.Enabled = true })
	r.waitState(probe.ARP, platform.StateRunning)
	if took := r.advanceUntil(probe.ARP, time.Second); took > 5*time.Second {
		t.Errorf("first pass %v after re-enabling: the startup delay applies only at start", took)
	}
}

// An interface's active discovery follows reloads: off at start, a reload
// that enables it starts its passes, one that disables it stops them.
func TestReloadTogglesInterfaceActive(t *testing.T) {
	cfg := baseConfig()
	cfg.Active.StartupDelay = 0
	cfg.Active.Jitter = 0
	cfg.Interfaces[0].Active.Enabled = false
	r := newRig(t, cfg)
	r.start()
	r.waitState(probe.ARP, platform.StateDisabled)
	r.sim.Advance(time.Hour)
	r.eng[probe.ARP].quiet(t)

	setActive := func(on bool) {
		r.setConfig(func(c *config.Config) {
			c.Interfaces = slices.Clone(c.Interfaces)
			c.Interfaces[0].Active.Enabled = on
		})
	}
	setActive(true)
	r.waitState(probe.ARP, platform.StateRunning)
	if took := r.advanceUntil(probe.ARP, time.Second); took > 5*time.Second {
		t.Errorf("first pass %v after a reload enabled the interface", took)
	}
	setActive(false)
	r.waitState(probe.ARP, platform.StateDisabled)
	r.sim.Advance(time.Hour)
	r.eng[probe.ARP].quiet(t)
}

// advanceUntil moves the clock in steps until p runs and returns how far it
// moved; it tolerates the loop re-arming its timer between steps.
func (r *rig) advanceUntil(p probe.Protocol, step time.Duration) time.Duration {
	r.t.Helper()
	start := r.sim.Now()
	for range 1000 {
		select {
		case <-r.eng[p].ran:
			return r.sim.Now().Sub(start)
		case <-time.After(5 * time.Millisecond):
		}
		r.sim.Advance(step)
	}
	r.t.Fatalf("no %s pass after %v", p, r.sim.Now().Sub(start))
	return 0
}

func TestPassFailuresAndMissingLinks(t *testing.T) {
	cfg := baseConfig()
	cfg.Active.StartupDelay = 0
	cfg.Active.Jitter = 0
	r := newRig(t, cfg)
	r.eng[probe.ARP].result = func(probe.Pass) ([]probe.Result, error) { return nil, errors.New("ENETDOWN") }
	r.start()
	r.waiters(1)
	r.sim.Advance(time.Millisecond)
	r.eng[probe.ARP].wait(t)
	r.waitState(probe.ARP, platform.StateFailed)
	if !strings.Contains(r.state(probe.ARP).Error, "ENETDOWN") {
		t.Errorf("state = %+v", r.state(probe.ARP))
	}

	// The interface goes away: passes are skipped, the state stays.
	r.mu.Lock()
	r.links = map[string]probe.Link{}
	r.mu.Unlock()
	r.waiters(1)
	r.sim.Advance(5 * time.Minute)
	r.eng[probe.ARP].quiet(t)

	r.mu.Lock()
	r.links = map[string]probe.Link{"eth1": {Name: "eth1", MAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}}}
	r.mu.Unlock()
	r.eng[probe.ARP].mu.Lock()
	r.eng[probe.ARP].result = nil
	r.eng[probe.ARP].mu.Unlock()
	r.waiters(1)
	r.sim.Advance(5 * time.Minute)
	r.eng[probe.ARP].wait(t)
	r.waitState(probe.ARP, platform.StateRunning)
}

func TestKnownHostsErrorFailsThePass(t *testing.T) {
	cfg := baseConfig()
	cfg.Interfaces[0].Name = "broken"
	cfg.Active.ARP.Enabled = false
	cfg.Active.ICMP = config.ProbeConfig{Enabled: true, Interval: config.Duration(time.Minute)}
	cfg.Active.StartupDelay = 0
	r := newRig(t, cfg)
	r.links["broken"] = r.links["eth1"]
	r.start()
	r.waiters(1)
	r.sim.Advance(time.Minute)
	deadline := time.Now().Add(5 * time.Second)
	for {
		st := r.reg.List()
		found := false
		for _, c := range st {
			if c.Interface == "broken" && c.Collector == "icmp" && c.State == platform.StateFailed {
				found = true
			}
		}
		if found {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("collectors = %+v", st)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestInactiveInterfaceAndMissingEngine(t *testing.T) {
	cfg := baseConfig()
	cfg.Interfaces = append(cfg.Interfaces, config.InterfaceConfig{Name: "eth0"})
	r := newRig(t, cfg)
	delete(r.s.o.Engines, probe.UDP)
	r.start()
	r.waiters(1)
	for _, c := range r.reg.List() {
		if c.Interface == "eth0" && c.State != platform.StateDisabled {
			t.Errorf("eth0 %s = %s", c.Collector, c.State)
		}
	}
	if r.state(probe.UDP).State != platform.StateDisabled {
		t.Errorf("udp without engine = %+v", r.state(probe.UDP))
	}
}

func TestOperatorScan(t *testing.T) {
	cfg := baseConfig()
	cfg.Active.ARP.Enabled = false // no periodic passes
	r := newRig(t, cfg)
	// The sweep finds a host that is not known yet.
	r.eng[probe.ARP].result = func(p probe.Pass) ([]probe.Result, error) {
		var out []probe.Result
		for _, tg := range p.Targets {
			st := probe.NoReply
			if tg == ip("192.168.110.7") || tg == ip("192.168.110.5") {
				st = probe.Reply
			}
			out = append(out, probe.Result{Target: tg, State: st})
		}
		return out, nil
	}
	r.eng[probe.TCP].result = func(p probe.Pass) ([]probe.Result, error) {
		var out []probe.Result
		for _, tg := range p.Targets {
			out = append(out, probe.Result{Target: tg, Port: p.TCP[0].Port, State: "OPEN"})
		}
		return out, nil
	}
	res, err := r.s.Scan(context.Background(), probe.Request{Profile: "modbus", UDP: []string{"enip"}}, "bart")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Plan.Allowed || len(res.Interfaces) != 1 {
		t.Fatalf("result = %+v", res)
	}
	ir := res.Interfaces[0]
	if ir.Responders != 2 || ir.Aborted != "" || ir.Counts["arp"][probe.Reply] != 2 || ir.Counts["tcp/502"]["OPEN"] != 3 || ir.Counts["udp/enip"][probe.Reply] != 3 {
		t.Errorf("interface result = %+v", ir)
	}
	tcp := r.eng[probe.TCP].all()
	if len(tcp) != 1 || len(tcp[0].Targets) != 3 || !slices.Contains(tcp[0].Targets, ip("192.168.110.7")) {
		t.Errorf("tcp targets = %+v (known hosts plus the ARP responder)", tcp)
	}
	if len(r.eng[probe.ICMP].all()) != 0 {
		t.Error("icmp ran without being asked")
	}
	if len(r.ops) != 2 || r.ops[0].Kind != observation.OpScanStarted || r.ops[1].Kind != observation.OpScanCompleted ||
		r.ops[0].Scan == r.ops[1].Scan || r.ops[0].Scan.Handle != r.ops[1].Scan.Handle || r.ops[1].Scan.Handle.ID != 1 || r.ops[0].Actor != "bart" {
		t.Fatalf("operator messages = %+v (separate copies, one handle)", r.ops)
	}
	sc := r.ops[1].Scan
	if sc.Interface != "eth1" || sc.Kind != "arp,tcp/502,udp/enip" || sc.Targets != 12 ||
		!strings.Contains(r.ops[0].Scan.Summary, "") || !strings.Contains(sc.Summary, "done in") || sc.Results["responders"] != 2 {
		t.Errorf("scan = %+v", sc)
	}
}

func TestOperatorScanRefusedBusyAndAborted(t *testing.T) {
	cfg := baseConfig()
	cfg.Active.ARP.Enabled = false
	r := newRig(t, cfg)

	res, err := r.s.Scan(context.Background(), probe.Request{Interfaces: []string{"eth9"}}, "bart")
	if !errors.Is(err, ErrScanRefused) || res.Plan.Allowed || len(r.ops) != 0 {
		t.Errorf("refused scan: %+v, %v, ops %v", res, err, r.ops)
	}

	r.eng[probe.ARP].hold = true
	done := make(chan error, 1)
	var aborted ScanResult
	go func() {
		var err error
		aborted, err = r.s.Scan(context.Background(), probe.Request{}, "bart")
		done <- err
	}()
	r.eng[probe.ARP].wait(t)
	if _, err := r.s.Scan(context.Background(), probe.Request{}, "eve"); !errors.Is(err, ErrScanRunning) {
		t.Errorf("second scan: %v", err)
	}
	r.sw.Set(store.ActiveState{Disabled: true})
	if err := <-done; !errors.Is(err, probe.ErrDisabled) {
		t.Fatalf("aborted scan: %v", err)
	}
	if len(aborted.Interfaces) != 1 || !strings.Contains(aborted.Interfaces[0].Aborted, "kill switch") {
		t.Errorf("aborted result = %+v", aborted)
	}
	if last := r.ops[len(r.ops)-1]; last.Kind != observation.OpScanCompleted || !strings.Contains(last.Scan.Summary, "aborted") ||
		last.Scan.Results["aborted"] == nil {
		t.Errorf("completion = %+v", last.Scan)
	}

	// With the switch set the plan refuses before anything starts.
	if _, err := r.s.Scan(context.Background(), probe.Request{}, "bart"); !errors.Is(err, ErrScanRefused) {
		t.Errorf("scan with the switch set: %v", err)
	}
}

func TestOperatorScanErrors(t *testing.T) {
	cfg := baseConfig()
	cfg.Active.ARP.Enabled = false
	r := newRig(t, cfg)

	r.links = map[string]probe.Link{}
	res, err := r.s.Scan(context.Background(), probe.Request{}, "bart")
	if err == nil || !strings.Contains(err.Error(), "down or absent") || res.Interfaces[0].Aborted == "" {
		t.Errorf("scan on a missing link: %+v, %v", res, err)
	}

	// The start cannot be recorded: the scan does not run, says so, and a
	// completion is still sent in case the start was queued.
	r = newRig(t, cfg)
	r.opErr = errors.New("bus closed")
	res, err = r.s.Scan(context.Background(), probe.Request{}, "bart")
	if err == nil || !strings.HasPrefix(res.Interfaces[0].Aborted, "not started: bus closed") {
		t.Errorf("unrecorded start: %+v, %v", res, err)
	}
	if len(r.ops) != 2 || r.ops[1].Kind != observation.OpScanCompleted || len(r.eng[probe.ARP].all()) != 0 {
		t.Errorf("ops = %+v, sweeps %d", r.ops, len(r.eng[probe.ARP].all()))
	}

	// The scan ran but its completion cannot be recorded: an error, not an
	// abort.
	r = newRig(t, cfg)
	r.opErr, r.failOn = errors.New("bus closed"), observation.OpScanCompleted
	res, err = r.s.Scan(context.Background(), probe.Request{}, "bart")
	if err == nil || !strings.Contains(err.Error(), "not recorded") || res.Interfaces[0].Aborted != "" {
		t.Errorf("unrecorded completion: %+v, %v", res, err)
	}

	r = newRig(t, cfg)
	r.eng[probe.ARP].result = func(probe.Pass) ([]probe.Result, error) { return nil, errors.New("ENETDOWN") }
	res, err = r.s.Scan(context.Background(), probe.Request{}, "bart")
	if err == nil || res.Interfaces[0].Aborted != "ENETDOWN" {
		t.Errorf("failing sweep: %+v, %v", res, err)
	}

	r = newRig(t, cfg)
	delete(r.s.o.Engines, probe.ICMP)
	if _, err := r.s.Scan(context.Background(), probe.Request{ICMP: true}, "bart"); err == nil {
		t.Error("missing engine not reported")
	}

	cfg2 := baseConfig()
	cfg2.Interfaces[0].Name = "broken"
	r = newRig(t, cfg2)
	if _, err := r.s.Scan(context.Background(), probe.Request{}, "bart"); err == nil {
		t.Error("known-host error not reported")
	}
}

func TestOperatorScanStopsAtFailingProbe(t *testing.T) {
	cfg := baseConfig()
	cfg.Active.ARP.Enabled = false
	for _, tt := range []struct {
		name string
		p    probe.Protocol
		req  probe.Request
	}{
		{"icmp", probe.ICMP, probe.Request{ICMP: true, TCP: []int{502}}},
		{"tcp", probe.TCP, probe.Request{TCP: []int{502}, UDP: []string{"ntp"}}},
		{"udp", probe.UDP, probe.Request{UDP: []string{"ntp"}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := newRig(t, cfg)
			r.eng[tt.p].result = func(probe.Pass) ([]probe.Result, error) { return nil, errors.New("boom") }
			res, err := r.s.Scan(context.Background(), tt.req, "bart")
			if err == nil || res.Interfaces[0].Aborted != "boom" {
				t.Errorf("%+v, %v", res, err)
			}
		})
	}
	// No known hosts and no responders: nothing after the sweep.
	r := newRig(t, cfg)
	r.s.o.Known = known{}
	r.eng[probe.ARP].result = func(probe.Pass) ([]probe.Result, error) { return nil, nil }
	if _, err := r.s.Scan(context.Background(), probe.Request{ARP: true, ICMP: true}, "bart"); err != nil {
		t.Fatal(err)
	}
	if len(r.eng[probe.ICMP].all()) != 0 {
		t.Error("icmp ran without targets")
	}
}

func TestKind(t *testing.T) {
	if got := Kind(probe.Probes{ARP: true, ICMP: true, TCP: []int{502, 80}, UDP: []string{"ntp"}}); got != "arp,icmp,tcp/502,tcp/80,udp/ntp" {
		t.Errorf("Kind = %q", got)
	}
}

func TestDefaults(t *testing.T) {
	s := New(Options{Config: config.Defaults, Budget: probe.NewBudget(nil, probe.Limits{}, nil), Switch: probe.NewSwitch(store.ActiveState{})})
	if s.o.Clock == nil || s.o.Logger == nil || s.rnd == nil {
		t.Error("defaults not set")
	}
	s.Reload()
	if err := s.Run(context.Background()); err != nil { // no interfaces: returns at once
		t.Fatal(err)
	}
	if noAnswer("OPEN") || !noAnswer("TIMEOUT") || !noAnswer("UNREACHABLE") || !noAnswer(probe.NoReply) || noAnswer(probe.Reply) {
		t.Error("noAnswer")
	}
	if ok, _ := probeConfig(config.Defaults(), "ndp"); ok {
		t.Error("ndp has a periodic config")
	}
}

func TestPortLabelIsBounded(t *testing.T) {
	cfg := baseConfig()
	cfg.Active.TCP.Targets = []config.TCPTarget{{Port: 502}}
	for _, tt := range []struct {
		p    probe.Protocol
		port int
		want string
	}{
		{probe.ARP, 0, ""}, {probe.UDP, 123, "123"}, {probe.TCP, 502, "502"}, {probe.TCP, 8080, "other"},
	} {
		if got := portLabel(cfg, tt.p, tt.port); got != tt.want {
			t.Errorf("portLabel(%s, %d) = %q, want %q", tt.p, tt.port, got, tt.want)
		}
	}
	// The modbus profile names 502 too; 503 from a profile is kept.
	cfg.Profiles["extra"] = config.ProfileConfig{TCP: []int{503}}
	if portLabel(cfg, probe.TCP, 503) != "503" {
		t.Error("profile port not labelled")
	}
}
