// Package scheduler runs the probe engines (docs/ARCHITECTURE.md §5): one
// periodic loop per configured interface and protocol, probing while the
// interface has active discovery enabled,
// with a startup delay, interval jitter, randomised target order and
// timeout back-off, and operator scans gated by the same planner as
// `scan plan`. Every probe goes through the shared budget, which checks
// the kill switch and the policy before each send; the kill switch also
// cancels running passes at once.
package scheduler

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"lan-sentinel/internal/clock"
	"lan-sentinel/internal/config"
	"lan-sentinel/internal/observation"
	"lan-sentinel/internal/platform"
	"lan-sentinel/internal/probe"
	"lan-sentinel/internal/probe/idprobe"
	"lan-sentinel/internal/store"
)

// Known is a known host address: an open IPv4 binding, and when its
// holder was last confirmed there (the back-off eases on fresh evidence).
type Known struct {
	IP       netip.Addr
	LastSeen time.Time
}

// KnownSource lists the known IPv4 addresses (open bindings) of an
// interface: the targets of ICMP, TCP and UDP probes.
type KnownSource interface {
	Known(ctx context.Context, iface string) ([]Known, error)
}

// IdentifySource lists identification candidates of an interface (ADR 0011).
type IdentifySource interface {
	IdentifyTargets(ctx context.Context, iface, probe string, since time.Time) ([]store.IdentifyCandidate, error)
}

func addrs(known []Known) []netip.Addr {
	out := make([]netip.Addr, len(known))
	for i, k := range known {
		out[i] = k.IP
	}
	return out
}

// Options configures a Scheduler.
type Options struct {
	Config func() *config.Config
	// Links returns the interfaces that are present and up, with their
	// MAC and addresses.
	Links    func() map[string]probe.Link
	Known    KnownSource
	Identify IdentifySource
	Engines  map[probe.Protocol]probe.Engine
	Budget   *probe.Budget
	Switch   *probe.Switch
	Emit     func(observation.Observation)
	Operator func(context.Context, observation.Operator) error
	Registry *platform.Registry
	// Backend names the facility behind a transport (Transmitter.Backend).
	Backend func(transport string) string
	Clock   clock.Clock
	Logger  *slog.Logger
	Rand    *rand.Rand
	// ReplyTimeout overrides probe.DefaultReplyTimeout (tests).
	ReplyTimeout time.Duration
}

// Protocols in the order a scan runs them.
var Protocols = []probe.Protocol{probe.ARP, probe.ICMP, probe.TCP, probe.UDP, probe.Identify}

var collectors = map[probe.Protocol]string{
	probe.ARP: platform.CollectorARP, probe.ICMP: platform.CollectorICMP,
	probe.TCP: platform.CollectorTCP, probe.UDP: platform.CollectorUDP,
	probe.Identify: platform.CollectorIdentify,
}

// transports says how each protocol's probes leave the box.
var transports = map[probe.Protocol]string{
	probe.ARP: platform.TransportFrames, probe.ICMP: platform.TransportICMP,
	probe.TCP: platform.TransportTCP, probe.UDP: platform.TransportUDP,
	probe.Identify: platform.TransportTCP,
}

// PassSummary is the outcome of the last periodic pass of a probe on an
// interface, for `daemon status`; passes are never logged.
type PassSummary struct {
	At      time.Time `json:"at"` // when it ended
	Seconds float64   `json:"seconds"`
	// Probed counts the probes sent (an ARP sweep's addresses, TCP connects);
	// Replied those answered: a reply, or TCP OPEN or REFUSED; Blocked the
	// ones the policy refused, which were not sent.
	Probed  int `json:"probed"`
	Replied int `json:"replied"`
	Blocked int `json:"blocked,omitempty"`
	// Complete is false for a pass cut short: the kill switch, a reload, a
	// failure.
	Complete bool `json:"complete"`
}

// Scheduler runs periodic probe passes and operator scans.
type Scheduler struct {
	o       Options
	backoff *probe.Backoff
	scanMu  sync.Mutex

	mu         sync.Mutex
	rnd        *rand.Rand
	reload     chan struct{}
	counts     map[Count]uint64
	durations  map[[2]string]float64
	passes     map[[2]string]PassSummary // interface, collector
	suppressed map[[2]string]uint64      // identification probe, reason
	sent       map[[2]string]bool        // host ID, identification probe: exchanges this process sent
}

// Count is a lan_sentinel_probe_total series.
type Count struct {
	Interface string
	Protocol  probe.Protocol
	Port      string // TCP or UDP port, "other" for an unconfigured TCP port; empty for ARP and ICMP
	Result    string
}

// New returns a scheduler.
func New(o Options) *Scheduler {
	if o.Clock == nil {
		o.Clock = clock.Real()
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	if o.Rand == nil {
		o.Rand = rand.New(rand.NewPCG(rand.Uint64(), rand.Uint64())) //nolint:gosec // jitter and probe order, not secrets
	}
	return &Scheduler{
		o: o, backoff: probe.NewBackoff(), rnd: o.Rand, reload: make(chan struct{}),
		counts: map[Count]uint64{}, durations: map[[2]string]float64{}, passes: map[[2]string]PassSummary{},
		suppressed: map[[2]string]uint64{}, sent: map[[2]string]bool{},
	}
}

// Reload applies a reloaded configuration: budgets now; intervals,
// enabled probes and each interface's active settings at each loop's next
// step. The policy checks every probe against the new configuration at
// once.
func (s *Scheduler) Reload() {
	s.o.Budget.SetLimits(probe.LimitsFrom(s.o.Config().Active))
	s.mu.Lock()
	defer s.mu.Unlock()
	close(s.reload)
	s.reload = make(chan struct{})
}

func (s *Scheduler) reloaded() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reload
}

func (s *Scheduler) float() float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rnd.Float64()
}

// sweepOrder walks a sweep in a fresh random order.
func (s *Scheduler) sweepOrder(sw probe.Sweep, pass *probe.Pass) {
	s.mu.Lock()
	r := rand.New(rand.NewPCG(s.rnd.Uint64(), s.rnd.Uint64())) //nolint:gosec // probe order, not a secret
	s.mu.Unlock()
	pass.Sweep, pass.InSweep = sw.Order(r), sw.Contains
}

func (s *Scheduler) shuffle(targets []netip.Addr) []netip.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	return probe.Shuffle(s.rnd, targets)
}

// Counts returns lan_sentinel_probe_total.
func (s *Scheduler) Counts() map[Count]uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[Count]uint64, len(s.counts))
	for k, v := range s.counts {
		out[k] = v
	}
	return out
}

// Durations returns the duration of the last pass or scan per interface
// and protocol (lan_sentinel_scan_duration_seconds).
func (s *Scheduler) Durations() map[[2]string]float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[[2]string]float64, len(s.durations))
	for k, v := range s.durations {
		out[k] = v
	}
	return out
}

// IdentifySuppressed counts the hosts a scheduled identification look
// did not send to, per probe and reason (stale, duplicate, proxy_arp):
// lan_sentinel_identify_suppressed_total. The scheduler owns eligibility
// (ADR 0011), so it counts them.
func (s *Scheduler) IdentifySuppressed() map[[2]string]uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[[2]string]uint64, len(s.suppressed))
	for k, v := range s.suppressed {
		out[k] = v
	}
	return out
}

func (s *Scheduler) suppress(name, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.suppressed[[2]string{name, reason}]++
}

// markSent remembers the hosts an identification exchange went to. The
// once-per-MAC latch is the committed identify_attempts row, and the store
// is up to one batch behind; without this a look that starts before the
// writer has committed the previous look's attempts would send again. A
// blocked job sent nothing and is not an attempt (ADR 0011). On restart
// the committed rows take over.
func (s *Scheduler) markSent(jobs []probe.IdentifyJob, results []probe.Result) {
	hosts := make(map[[2]string]string, len(jobs)) // address, probe → host ID
	for _, j := range jobs {
		hosts[[2]string{j.IP.String(), j.Probe}] = j.HostID
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range results {
		if r.State == probe.Blocked {
			continue
		}
		if id, ok := hosts[[2]string{r.Target.String(), r.Probe}]; ok {
			s.sent[[2]string{id, r.Probe}] = true
		}
	}
}

func (s *Scheduler) wasSent(hostID, name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sent[[2]string{hostID, name}]
}

func (s *Scheduler) record(iface string, p probe.Protocol, results []probe.Result, took time.Duration) {
	cfg := s.o.Config()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range results {
		s.counts[Count{Interface: iface, Protocol: p, Port: portLabel(cfg, p, r.Port), Result: strings.ToLower(r.State)}] += uint64(r.N()) //nolint:gosec // a count
	}
	s.durations[[2]string{iface, string(p)}] = took.Seconds()
}

// summarise records a periodic pass for LastPasses.
func (s *Scheduler) summarise(iface string, p probe.Protocol, results []probe.Result, took time.Duration, complete bool) {
	sum := PassSummary{At: s.o.Clock.Now().UTC(), Seconds: took.Seconds(), Complete: complete}
	for _, r := range results {
		switch r.State {
		case probe.Blocked:
			sum.Blocked += r.N()
			continue
		case probe.Reply, string(observation.ServiceOpen), string(observation.ServiceRefused):
			sum.Replied += r.N()
		}
		sum.Probed += r.N()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.passes[[2]string{iface, collectors[p]}] = sum
}

// LastPasses returns the last periodic pass per interface and probe
// collector (arp, icmp, tcp, udp).
func (s *Scheduler) LastPasses() map[string]map[string]PassSummary {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]map[string]PassSummary{}
	for k, v := range s.passes {
		if out[k[0]] == nil {
			out[k[0]] = map[string]PassSummary{}
		}
		out[k[0]][k[1]] = v
	}
	return out
}

// portLabel keeps the port label's values few (AGENTS.md rule 9): the UDP
// probes' ports and the TCP ports of the configuration (active.tcp.targets
// and profiles); a TCP port given only to `scan run` is "other".
func portLabel(cfg *config.Config, p probe.Protocol, port int) string {
	switch {
	case port <= 0:
		return ""
	case p == probe.UDP:
		return strconv.Itoa(port)
	}
	for _, t := range cfg.Active.TCP.Targets {
		if t.Port == port {
			return strconv.Itoa(port)
		}
	}
	for _, prof := range cfg.Profiles {
		if slices.Contains(prof.TCP, port) {
			return strconv.Itoa(port)
		}
	}
	return "other"
}

// Run starts a loop per configured interface and protocol and blocks
// until ctx is cancelled. The set of interfaces is restart-only; whether
// one has active discovery follows reloads.
func (s *Scheduler) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	for _, ic := range s.o.Config().Interfaces {
		for _, p := range Protocols {
			if s.o.Engines[p] == nil {
				s.report(ic.Name, p, platform.StateDisabled, nil)
				continue
			}
			if !ic.Active.Enabled {
				s.report(ic.Name, p, platform.StateDisabled, nil) // until a reload enables it
			}
			wg.Add(1)
			go func(iface string, p probe.Protocol) {
				defer wg.Done()
				s.loop(ctx, iface, p)
			}(ic.Name, p)
		}
	}
	wg.Wait()
	return nil
}

func (s *Scheduler) report(iface string, p probe.Protocol, state platform.State, err error) {
	if s.o.Registry == nil {
		return
	}
	backend := ""
	if s.o.Backend != nil {
		backend = s.o.Backend(transports[p])
	}
	s.o.Registry.Set(iface, collectors[p], backend, state, err)
}

// probeConfig returns whether p runs periodically and how often.
func probeConfig(cfg *config.Config, iface string, p probe.Protocol) (bool, time.Duration) {
	a := cfg.Active
	switch p {
	case probe.ARP:
		return a.ARP.Enabled, a.ARP.Interval.D()
	case probe.ICMP:
		return a.ICMP.Enabled, a.ICMP.Interval.D()
	case probe.TCP:
		return a.TCP.Enabled && len(a.TCP.Targets) > 0, a.TCP.Interval.D()
	case probe.UDP:
		return a.UDP.Enabled && len(a.UDP.Probes) > 0, a.UDP.Interval.D()
	case probe.Identify:
		ic, ok := probe.InterfaceConfig(cfg, iface)
		return ok && len(ic.Active.Identify) > 0, a.Identify.Interval.D()
	}
	return false, 0
}

// jittered spreads an interval by ±jitter.
func (s *Scheduler) jittered(d time.Duration, jitter float64) time.Duration {
	return time.Duration(float64(d) * (1 + jitter*(2*s.float()-1)))
}

var errKillSwitch = errors.New("active discovery is disabled by the kill switch")

// loop runs the periodic passes of one protocol on one interface. The
// first pass waits for the startup delay plus a random share (up to the
// jitter) of the interval, so a fleet updated at once does not probe at
// once; later passes follow the interval ±jitter.
func (s *Scheduler) loop(ctx context.Context, iface string, p probe.Protocol) {
	var next time.Time
	first, failed := true, false
	for ctx.Err() == nil {
		// The channels first: a reload or switch change after this point
		// closes them, so the loop never waits on a stale configuration.
		reload, changed := s.reloaded(), s.o.Switch.Changed()
		cfg := s.o.Config()
		enabled, interval := probeConfig(cfg, iface, p)
		if ic, ok := probe.InterfaceConfig(cfg, iface); !ok || !ic.Active.Enabled {
			enabled = false
		}
		switch {
		case !enabled:
			s.report(iface, p, platform.StateDisabled, nil)
			next = time.Time{}
			if !s.wait(ctx, nil, reload, nil) {
				return
			}
			continue
		case s.o.Switch.Disabled():
			s.report(iface, p, platform.StateDisabled, errKillSwitch)
			if !s.wait(ctx, nil, reload, changed) {
				return
			}
			continue
		}
		now := s.o.Clock.Now()
		if next.IsZero() {
			spread := time.Duration(s.float() * cfg.Active.Jitter * float64(interval))
			next = now.Add(spread)
			if first {
				next = next.Add(cfg.Active.StartupDelay.D())
			}
			first = false
		} else if limit := now.Add(interval); next.After(limit) {
			next = limit // a shorter interval after a reload
		}
		if !failed {
			s.report(iface, p, platform.StateRunning, nil)
		}
		if d := next.Sub(now); d > 0 {
			t := s.o.Clock.NewTimer(d)
			fired := s.wait(ctx, t.C(), reload, changed)
			t.Stop()
			if !fired || s.o.Clock.Now().Before(next) {
				continue // cancelled, reloaded or the switch changed: look again
			}
		}
		start := s.o.Clock.Now()
		results, ran, err := s.pass(ctx, cfg, iface, p, interval)
		took := s.o.Clock.Now().Sub(start)
		s.record(iface, p, results, took)
		if ran {
			s.summarise(iface, p, results, took, err == nil && ctx.Err() == nil)
		}
		switch {
		case errors.Is(err, probe.ErrDisabled), ctx.Err() != nil:
		case err != nil:
			if !failed {
				s.o.Logger.Warn("probe pass failed", "interface", iface, "protocol", p, "err", err)
			}
			failed = true
			s.report(iface, p, platform.StateFailed, err)
		default:
			failed = false
			s.report(iface, p, platform.StateRunning, nil)
		}
		next = s.o.Clock.Now().Add(s.jittered(interval, cfg.Active.Jitter))
	}
}

// wait blocks until one of the channels fires or ctx ends; it reports
// whether ctx is still alive.
func (s *Scheduler) wait(ctx context.Context, timer <-chan time.Time, reload, changed <-chan struct{}) bool {
	select {
	case <-ctx.Done():
		return false
	case <-timer:
	case <-reload:
	case <-changed:
	}
	return true
}

// passContext is cancelled when the kill switch is set.
func (s *Scheduler) passContext(ctx context.Context) (context.Context, context.CancelFunc) {
	pctx, cancel := context.WithCancel(ctx)
	go func() {
		for {
			ch := s.o.Switch.Changed()
			if s.o.Switch.Disabled() {
				cancel()
				return
			}
			select {
			case <-ch:
			case <-pctx.Done():
				return
			}
		}
	}()
	return pctx, cancel
}

func (s *Scheduler) newPass(ctx context.Context, iface string) (probe.Pass, bool) {
	link, ok := s.o.Links()[iface]
	if !ok {
		return probe.Pass{}, false // absent or down: nothing to send on
	}
	link.Name = iface
	return probe.Pass{Link: link, Budget: s.o.Budget, Emit: s.o.Emit, Clock: s.o.Clock, ReplyTimeout: s.o.ReplyTimeout}, ctx.Err() == nil
}

// pass runs one periodic pass: ARP sweeps the configured networks; ICMP,
// TCP and UDP probe the known hosts that are due (back-off). ran is false
// when there was nothing to send on (the interface is absent or down).
func (s *Scheduler) pass(ctx context.Context, cfg *config.Config, iface string, p probe.Protocol, interval time.Duration) (results []probe.Result, ran bool, err error) {
	ic, ok := probe.InterfaceConfig(cfg, iface)
	if !ok {
		return nil, false, nil
	}
	pass, ok := s.newPass(ctx, iface)
	if !ok {
		return nil, false, nil
	}
	pctx, cancel := s.passContext(ctx)
	defer cancel()
	results, err = s.periodic(pctx, cfg, ic, pass, p, interval)
	return results, true, s.stopped(err)
}

// stopped reports a pass cut short by the kill switch as ErrDisabled, not
// as the cancellation it saw.
func (s *Scheduler) stopped(err error) error {
	if err != nil && s.o.Switch.Disabled() {
		return probe.ErrDisabled
	}
	return err
}

func (s *Scheduler) periodic(pctx context.Context, cfg *config.Config, ic config.InterfaceConfig, pass probe.Pass, p probe.Protocol, interval time.Duration) ([]probe.Result, error) {
	iface := ic.Name
	eng := s.o.Engines[p]
	if p == probe.ARP {
		s.sweepOrder(probe.NewSweep(ic.Active.Networks, ic.Active.Exclude, pass.Link.Own()), &pass)
		return eng.Run(pctx, pass)
	}
	if p == probe.Identify {
		return s.identifyPass(pctx, cfg, ic, pass, false)
	}
	found, err := s.o.Known.Known(pctx, iface)
	if err != nil {
		return nil, fmt.Errorf("known hosts of %s: %w", iface, err)
	}
	lastSeen := make(map[netip.Addr]time.Time, len(found))
	for _, k := range found {
		if k.LastSeen.After(lastSeen[k.IP.Unmap()]) {
			lastSeen[k.IP.Unmap()] = k.LastSeen
		}
	}
	known := probe.KnownTargets(addrs(found), ic.Active.Networks, ic.Active.Exclude, pass.Link.Own())
	var all []probe.Result
	run := func(sub string, set func(*probe.Pass)) error {
		now := s.o.Clock.Now()
		var due []netip.Addr
		for _, ip := range known {
			if s.backoff.Due(iface, p, ip, sub, interval, now, lastSeen[ip]) {
				due = append(due, ip)
			}
		}
		if len(due) == 0 {
			return nil
		}
		ps := pass
		ps.Targets = s.shuffle(due)
		set(&ps)
		results, err := eng.Run(pctx, ps)
		now = s.o.Clock.Now()
		for _, r := range results {
			if r.State != probe.Blocked {
				s.backoff.Record(iface, p, r.Target, sub, noAnswer(r.State), now)
			}
		}
		all = append(all, results...)
		return err
	}
	switch p {
	case probe.ICMP:
		err = run("", func(*probe.Pass) {})
	case probe.TCP:
		for _, tg := range cfg.Active.TCP.Targets {
			if err = run(strconv.Itoa(tg.Port), func(ps *probe.Pass) { ps.TCP = []config.TCPTarget{tg} }); err != nil {
				break
			}
		}
	case probe.UDP:
		for _, name := range cfg.Active.UDP.Probes {
			if err = run(name, func(ps *probe.Pass) { ps.UDP = []string{name} }); err != nil {
				break
			}
		}
	}
	return all, err
}

// identifyPass looks for hosts never attempted (or, when force, any
// eligible host). Suppression is not an attempt.
func (s *Scheduler) identifyPass(ctx context.Context, cfg *config.Config, ic config.InterfaceConfig, pass probe.Pass, force bool) ([]probe.Result, error) {
	if s.o.Identify == nil {
		return nil, nil
	}
	eng := s.o.Engines[probe.Identify]
	if eng == nil {
		return nil, fmt.Errorf("no identify engine")
	}
	since := s.o.Clock.Now().Add(-cfg.Active.Identify.HostMaxAge.D())
	pass.ReplyTimeout = cfg.Active.Identify.Timeout.D()
	var jobs []probe.IdentifyJob
	for _, e := range ic.Active.Identify {
		cands, err := s.o.Identify.IdentifyTargets(ctx, ic.Name, e.Name, since)
		if err != nil {
			return nil, fmt.Errorf("identify targets of %s: %w", ic.Name, err)
		}
		for _, c := range cands {
			if !force && (c.Attempted || s.wasSent(c.HostID, e.Name)) {
				continue
			}
			if c.Suppress != "" && c.Suppress != store.IdentifyAttempted {
				s.suppress(e.Name, c.Suppress)
				continue
			}
			if force && c.Suppress == store.IdentifyAttempted {
				c.Suppress = ""
			}
			if c.Suppress != "" {
				continue
			}
			jobs = append(jobs, probe.IdentifyJob{
				HostID: c.HostID, IP: c.IP, Probe: e.Name,
				UnitID:    uint8(cfg.Active.Identify.UnitIDOf(e)), //nolint:gosec // validated 1–255
				Community: cfg.Active.Identify.CommunityOf(e),
				SNI:       config.ResolveSNI(cfg.Active.Identify.SNIModeOf(e), c.PreferredName, ""),
				Trigger:   observation.TriggerScheduled,
			})
		}
	}
	if len(jobs) == 0 {
		return nil, nil
	}
	pass.Identify = jobs
	results, err := eng.Run(ctx, pass)
	s.markSent(jobs, results)
	return results, err
}

// IdentifyRun sends one forced identification exchange (ADR 0011).
func (s *Scheduler) IdentifyRun(ctx context.Context, iface string, job probe.IdentifyJob) ([]probe.Result, error) {
	pass, ok := s.newPass(ctx, iface)
	if !ok {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("%s is down or absent", iface)
	}
	cfg := s.o.Config()
	pass.ReplyTimeout = cfg.Active.Identify.Timeout.D()
	pass.Identify = []probe.IdentifyJob{job}
	eng := s.o.Engines[probe.Identify]
	if eng == nil {
		return nil, fmt.Errorf("no identify engine")
	}
	pctx, cancel := s.passContext(ctx)
	defer cancel()
	results, err := eng.Run(pctx, pass)
	s.markSent(pass.Identify, results)
	return results, s.stopped(err)
}

// noAnswer is a result that counts towards back-off: nothing came back.
func noAnswer(state string) bool {
	switch observation.ServiceState(state) {
	case observation.ServiceTimeout, observation.ServiceUnreachable:
		return true
	}
	return state == probe.NoReply
}

// Plan computes the plan of an operator scan from the effective
// configuration, the kill switch, the live links and the known hosts.
func (s *Scheduler) Plan(ctx context.Context, req probe.Request) (probe.Plan, error) {
	cfg := s.o.Config()
	in := probe.PlanInput{
		Config: cfg, Active: s.o.Switch.State(), Links: s.o.Links(), Known: map[string][]netip.Addr{},
		IdentifyJobs: map[string]int{}, IdentifyPackets: map[string]int{},
	}
	for _, ic := range cfg.Interfaces {
		known, err := s.o.Known.Known(ctx, ic.Name)
		if err != nil {
			return probe.Plan{}, fmt.Errorf("known hosts of %s: %w", ic.Name, err)
		}
		in.Known[ic.Name] = addrs(known)
		if s.o.Identify == nil || len(ic.Active.Identify) == 0 {
			continue
		}
		since := s.o.Clock.Now().Add(-cfg.Active.Identify.HostMaxAge.D())
		for _, e := range ic.Active.Identify {
			cands, err := s.o.Identify.IdentifyTargets(ctx, ic.Name, e.Name, since)
			if err != nil {
				return probe.Plan{}, fmt.Errorf("identify targets of %s: %w", ic.Name, err)
			}
			for _, c := range cands {
				if c.Suppress != "" || s.wasSent(c.HostID, e.Name) {
					continue
				}
				in.IdentifyJobs[ic.Name]++
				in.IdentifyPackets[ic.Name] += idprobe.BudgetCostOf(e.Name)
			}
		}
	}
	return probe.Compute(in, req), nil
}

// Errors of Scan.
var (
	ErrScanRunning = errors.New("an operator scan is already running")
	ErrScanRefused = errors.New("scan refused")
)

// ScanResult is the outcome of an operator scan.
type ScanResult struct {
	Plan       probe.Plan        `json:"plan"`
	Interfaces []InterfaceResult `json:"interfaces,omitempty"`
}

// InterfaceResult is the outcome on one interface. Counts are per probe
// ("arp", "icmp", "tcp/502", "udp/ntp") and result.
type InterfaceResult struct {
	Interface  string                    `json:"interface"`
	Started    time.Time                 `json:"started"`
	Finished   time.Time                 `json:"finished"`
	Seconds    float64                   `json:"seconds"`
	Responders int                       `json:"responders"` // hosts that answered the ARP sweep
	Counts     map[string]map[string]int `json:"counts"`
	Aborted    string                    `json:"aborted,omitempty"`
}

// Scan runs an operator scan if its plan allows it: per interface the ARP
// sweep first, then ICMP, TCP port by port and UDP probe by probe on the
// known hosts and the ARP responders. Each interface's scan is recorded
// through the correlator (scans row, SCAN_STARTED, SCAN_COMPLETED).
func (s *Scheduler) Scan(ctx context.Context, req probe.Request, actor string) (ScanResult, error) {
	if !s.scanMu.TryLock() {
		return ScanResult{}, ErrScanRunning
	}
	defer s.scanMu.Unlock()
	plan, err := s.Plan(ctx, req)
	if err != nil {
		return ScanResult{}, err
	}
	res := ScanResult{Plan: plan}
	if !plan.Allowed {
		return res, ErrScanRefused
	}
	kind := Kind(plan.Probes)
	for _, ip := range plan.Interfaces {
		r, err := s.scanInterface(ctx, ip, plan, kind, actor)
		res.Interfaces = append(res.Interfaces, r)
		if err != nil {
			return res, err
		}
	}
	return res, nil
}

// Kind names the probes of a scan, e.g. "arp,tcp/502,udp/ntp".
func Kind(pr probe.Probes) string {
	var parts []string
	if pr.ARP {
		parts = append(parts, "arp")
	}
	if pr.ICMP {
		parts = append(parts, "icmp")
	}
	for _, p := range pr.TCP {
		parts = append(parts, "tcp/"+strconv.Itoa(p))
	}
	for _, u := range pr.UDP {
		parts = append(parts, "udp/"+u)
	}
	return strings.Join(parts, ",")
}

func (s *Scheduler) scanInterface(ctx context.Context, ip probe.InterfacePlan, plan probe.Plan, kind, actor string) (InterfaceResult, error) {
	start := s.o.Clock.Now()
	r := InterfaceResult{Interface: ip.Interface, Started: start.UTC(), Counts: map[string]map[string]int{}}
	// The start and the completion each get their own copy of the scan;
	// the correlator links them through the handle.
	sc := observation.Scan{
		Handle: &observation.ScanHandle{}, Interface: ip.Interface, Kind: kind,
		Targets: max(ip.SweepTargets, ip.KnownTargets), Summary: startSummary(ip, plan, kind),
	}
	started := sc
	if err := s.o.Operator(ctx, observation.Operator{Time: start, Kind: observation.OpScanStarted, Actor: actor, Scan: &started}); err != nil {
		// The start may already be queued: complete it too (the correlator
		// ignores a completion whose start it never recorded).
		r.Finished, r.Aborted = r.Started, "not started: "+err.Error()
		_ = s.complete(ctx, actor, sc, r, start) // best effort: the start error is what is reported
		return r, err
	}
	runErr := s.runScan(ctx, ip, plan.Probes, &r)
	end := s.o.Clock.Now()
	r.Finished, r.Seconds = end.UTC(), end.Sub(start).Seconds()
	switch {
	case errors.Is(runErr, probe.ErrDisabled):
		r.Aborted = errKillSwitch.Error()
	case runErr != nil:
		r.Aborted = runErr.Error()
	}
	if err := s.complete(ctx, actor, sc, r, end); err != nil && runErr == nil {
		runErr = fmt.Errorf("operator scan of %s not recorded: %w", ip.Interface, err)
	}
	return r, runErr
}

// recordTimeout bounds recording a scan's completion, which goes on when
// the request is cancelled (a client that gave up still gets its scan
// closed) but must not outlive the correlator.
const recordTimeout = 10 * time.Second

func (s *Scheduler) complete(ctx context.Context, actor string, sc observation.Scan, r InterfaceResult, at time.Time) error {
	sc.Summary, sc.Results = doneSummary(r), resultsJSON(r)
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), recordTimeout)
	defer cancel()
	return s.o.Operator(cctx, observation.Operator{Time: at, Kind: observation.OpScanCompleted, Actor: actor, Scan: &sc})
}

func (s *Scheduler) runScan(ctx context.Context, ip probe.InterfacePlan, pr probe.Probes, r *InterfaceResult) error {
	pass, ok := s.newPass(ctx, ip.Interface)
	if !ok {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("%s is down or absent", ip.Interface)
	}
	pctx, cancel := s.passContext(ctx)
	defer cancel()
	if s.o.Switch.Disabled() {
		return probe.ErrDisabled
	}
	run := func(p probe.Protocol, key string, targets []netip.Addr, set func(*probe.Pass)) ([]probe.Result, error) {
		eng := s.o.Engines[p]
		if eng == nil {
			return nil, fmt.Errorf("no %s engine", p)
		}
		ps := pass
		ps.Targets = targets
		set(&ps)
		start := s.o.Clock.Now()
		results, err := eng.Run(pctx, ps)
		s.record(ip.Interface, p, results, s.o.Clock.Now().Sub(start))
		for _, res := range results {
			if r.Counts[key] == nil {
				r.Counts[key] = map[string]int{}
			}
			r.Counts[key][res.State] += res.N()
		}
		return results, s.stopped(err)
	}
	known := ip.Known
	if pr.ARP {
		results, err := run(probe.ARP, "arp", nil, func(ps *probe.Pass) { s.sweepOrder(ip.Sweep, ps) })
		if err != nil {
			return err
		}
		for _, res := range results {
			if res.State == probe.Reply {
				r.Responders++
				known = append(known, res.Target)
			}
		}
		known = probe.KnownTargets(known, ip.Networks, ip.Excl, ip.Own)
	}
	if len(known) == 0 {
		return nil
	}
	// One random order for every phase: a host is never probed by the
	// next protocol before the previous one has moved on.
	known = s.shuffle(known)
	if pr.ICMP {
		if _, err := run(probe.ICMP, "icmp", known, func(*probe.Pass) {}); err != nil {
			return err
		}
	}
	for _, tg := range ip.TCP {
		if _, err := run(probe.TCP, "tcp/"+strconv.Itoa(tg.Port), known, func(ps *probe.Pass) { ps.TCP = []config.TCPTarget{tg} }); err != nil {
			return err
		}
	}
	for _, name := range pr.UDP {
		if _, err := run(probe.UDP, "udp/"+name, known, func(ps *probe.Pass) { ps.UDP = []string{name} }); err != nil {
			return err
		}
	}
	return nil
}

func startSummary(ip probe.InterfacePlan, plan probe.Plan, kind string) string {
	s := "operator scan " + kind
	if plan.Profile != "" {
		s += " (profile " + plan.Profile + ")"
	}
	return fmt.Sprintf("%s: %d addresses to sweep, %d known hosts", s, ip.SweepTargets, ip.KnownTargets)
}

func doneSummary(r InterfaceResult) string {
	keys := make([]string, 0, len(r.Counts))
	for k := range r.Counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		states := make([]string, 0, len(r.Counts[k]))
		for st, n := range r.Counts[k] {
			states = append(states, fmt.Sprintf("%d %s", n, strings.ToLower(st)))
		}
		sort.Strings(states)
		parts = append(parts, k+" "+strings.Join(states, ", "))
	}
	s := fmt.Sprintf("operator scan done in %.0fs", r.Seconds)
	if r.Aborted != "" {
		s = fmt.Sprintf("operator scan aborted after %.0fs: %s", r.Seconds, r.Aborted)
	}
	if len(parts) > 0 {
		s += "; " + strings.Join(parts, "; ")
	}
	return s
}

func resultsJSON(r InterfaceResult) map[string]any {
	m := map[string]any{"counts": r.Counts, "responders": r.Responders, "seconds": r.Seconds}
	if r.Aborted != "" {
		m["aborted"] = r.Aborted
	}
	return m
}
