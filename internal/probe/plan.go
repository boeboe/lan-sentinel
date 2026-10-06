package probe

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"lan-sentinel/internal/config"
	"lan-sentinel/internal/store"
)

// DefaultTCPTimeout is the connect timeout of a port that is not among
// active.tcp.targets (an operator scan of another port).
const DefaultTCPTimeout = time.Second

// Request is an operator scan (`scan plan`, `scan run`, docs/CLI.md).
// Probes named here are added to the profile's; with none at all the scan
// is an ARP sweep.
type Request struct {
	Interfaces []string       `json:"interfaces,omitempty"` // empty: every interface with active discovery
	Networks   []netip.Prefix `json:"networks,omitempty"`   // empty: the interfaces' configured networks
	Profile    string         `json:"profile,omitempty"`
	ARP        bool           `json:"arp,omitempty"`
	ICMP       bool           `json:"icmp,omitempty"`
	TCP        []int          `json:"tcp,omitempty"`
	UDP        []string       `json:"udp,omitempty"`
	// AllowWide acknowledges a sweep of more than
	// config.DefaultMaxSweepTargets addresses, after seeing its plan.
	AllowWide bool `json:"allow_wide,omitempty"`
}

// Probes are the probes of a scan. ARP sweeps the networks; ICMP, TCP and
// UDP probe the known hosts in them (and, in a run, the ARP responders).
type Probes struct {
	ARP  bool     `json:"arp"`
	ICMP bool     `json:"icmp"`
	TCP  []int    `json:"tcp,omitempty"`
	UDP  []string `json:"udp,omitempty"`
}

// Plan is the dry run of a scan: what it would probe, at what rates, for
// how long, and whether it is allowed. `scan run` refuses exactly when the
// plan does.
type Plan struct {
	Allowed    bool            `json:"allowed"`
	Reasons    []string        `json:"reasons,omitempty"`
	Profile    string          `json:"profile,omitempty"`
	Probes     Probes          `json:"probes"`
	Interfaces []InterfacePlan `json:"interfaces"`
	Rates      Rates           `json:"rates"`
	Estimate   Estimate        `json:"estimate"`
	// Assumptions are what the estimate rests on.
	Assumptions []string `json:"assumptions"`
}

// InterfacePlan is the part of a scan on one interface.
type InterfacePlan struct {
	Interface    string         `json:"interface"`
	Networks     []netip.Prefix `json:"networks"`
	SweepTargets int            `json:"sweep_targets"` // ARP: addresses in the networks after excludes
	KnownTargets int            `json:"known_targets"` // ICMP/TCP/UDP: known hosts in the networks
	Excluded     []string       `json:"excluded,omitempty"`
	Reasons      []string       `json:"reasons,omitempty"`
	Estimate     Estimate       `json:"estimate"`

	Sweep Sweep                 `json:"-"`
	Known []netip.Addr          `json:"-"`
	TCP   []config.TCPTarget    `json:"-"`
	Link  Link                  `json:"-"`
	Own   []netip.Addr          `json:"-"`
	Excl  []config.AddrOrPrefix `json:"-"`
}

// Rates are the limits a scan runs under.
type Rates struct {
	GlobalPPS       float64              `json:"global_pps"`
	Protocols       map[Protocol]float64 `json:"protocols"`
	MaxConcurrent   int                  `json:"max_concurrent"`
	TCPPerInterface int                  `json:"tcp_per_interface"`
	TCPPerHost      int                  `json:"tcp_per_host"`
	TargetSpacingMS int64                `json:"target_spacing_ms"`
}

// Estimate is the expected work of a scan: probes per protocol, packets
// sent (a TCP connect counts 3) and two durations: the estimated typical
// duration, where known hosts answer at once and only the ARP sweep waits
// out its reply timeout (most swept addresses are empty), and the
// estimated no-response duration, where nothing answers and every phase
// waits out its reply timeout. Plan.Assumptions spell out the rest.
type Estimate struct {
	ARPRequests       int     `json:"arp_requests"`
	ICMPEchoes        int     `json:"icmp_echoes"`
	TCPConnects       int     `json:"tcp_connects"`
	UDPProbes         int     `json:"udp_probes"`
	Packets           int     `json:"packets"`
	TypicalSeconds    float64 `json:"typical_seconds"`
	NoResponseSeconds float64 `json:"no_response_seconds"`
}

func (e *Estimate) add(o Estimate) {
	e.ARPRequests += o.ARPRequests
	e.ICMPEchoes += o.ICMPEchoes
	e.TCPConnects += o.TCPConnects
	e.UDPProbes += o.UDPProbes
	e.Packets += o.Packets
	e.TypicalSeconds += o.TypicalSeconds
	e.NoResponseSeconds += o.NoResponseSeconds
}

// PlanInput is what a plan is computed from: online, the daemon's
// effective configuration, kill switch, live links and known hosts;
// offline, the configuration file, the persisted switch and the database.
type PlanInput struct {
	Config *config.Config
	Active store.ActiveState
	Links  map[string]Link         // live interface addresses (own IPs are never probed)
	Known  map[string][]netip.Addr // known IPv4 addresses per interface
}

// Compute plans req. Every refusal reason is listed, not only the first.
func Compute(in PlanInput, req Request) Plan {
	cfg := in.Config
	a := cfg.Active
	limits := LimitsFrom(a)
	p := Plan{Profile: req.Profile, Rates: Rates{
		GlobalPPS: limits.GlobalPPS, Protocols: limits.Rates, MaxConcurrent: limits.MaxConcurrent,
		TCPPerInterface: limits.TCPPerInterface, TCPPerHost: limits.TCPPerHost,
		TargetSpacingMS: limits.TargetSpacing.Milliseconds(),
	}}
	refuse := func(format string, args ...any) { p.Reasons = append(p.Reasons, fmt.Sprintf(format, args...)) }

	if in.Active.Disabled {
		refuse("active discovery is disabled by the kill switch%s", why(in.Active.Reason))
	}
	p.Probes = probesOf(cfg, req, refuse)

	names := req.Interfaces
	if len(names) == 0 {
		for _, ic := range cfg.Interfaces {
			if ic.Active.Enabled {
				names = append(names, ic.Name)
			}
		}
		if len(names) == 0 {
			refuse("no interface has active discovery enabled")
		}
	}
	for _, n := range req.Networks {
		if !n.Addr().Is4() {
			refuse("%s: v1 scans IPv4 networks only", n)
		} else if n.Bits() < a.MaxAutoScanPrefixV4 && !a.AllowWideScan {
			refuse("%s is wider than max_auto_scan_prefix_v4 /%d", n, a.MaxAutoScanPrefixV4)
		}
	}
	used := map[netip.Prefix]bool{}
	for _, name := range names {
		ip := planInterface(cfg, in, name, req, p.Probes, used)
		p.Interfaces = append(p.Interfaces, ip)
		p.Estimate.add(ip.Estimate)
	}
	for _, n := range req.Networks {
		if !used[n.Masked()] && n.Addr().Is4() {
			refuse("%s is outside the configured networks of %s", n, joinNames(names))
		}
	}
	for _, ip := range p.Interfaces {
		for _, r := range ip.Reasons {
			refuse("%s: %s", ip.Interface, r)
		}
	}
	p.Assumptions = assumptions(p)
	p.Allowed = len(p.Reasons) == 0
	return p
}

// assumptions explain the estimate of p.
func assumptions(p Plan) []string {
	pr := p.Probes
	known := pr.ICMP || len(pr.TCP) > 0 || len(pr.UDP) > 0
	spacing := time.Duration(p.Rates.TargetSpacingMS) * time.Millisecond
	out := []string{fmt.Sprintf("probes leave paced at the rates above, at most %g packets/s in all (a TCP connect counts 3), "+
		"and at least %v apart per target; sending, connecting and answering take no time", p.Rates.GlobalPPS, spacing)}
	switch {
	case pr.ARP && known:
		out = append(out, "typical: known hosts answer at once; most swept addresses are empty, so the ARP sweep waits its 1s reply timeout once, after its last request")
	case pr.ARP:
		out = append(out, "typical: most swept addresses are empty, so the sweep waits its 1s reply timeout once, after its last request")
	default:
		out = append(out, "typical: known hosts answer at once")
	}
	var waits []string
	if pr.ARP {
		waits = append(waits, "ARP "+DefaultReplyTimeout.String())
	}
	if pr.ICMP {
		waits = append(waits, "ICMP "+DefaultReplyTimeout.String())
	}
	if len(p.Interfaces) > 0 {
		for _, t := range p.Interfaces[0].TCP {
			waits = append(waits, fmt.Sprintf("tcp/%d %v", t.Port, t.Timeout.D()))
		}
	}
	for _, u := range pr.UDP {
		waits = append(waits, "udp/"+u+" "+DefaultReplyTimeout.String())
	}
	out = append(out, "no-response: nothing answers, so every phase waits out its reply timeout once ("+strings.Join(waits, ", ")+")")
	if pr.ARP && known {
		out = append(out, "ICMP, TCP and UDP counts use the hosts known now; hosts that first answer the sweep are probed too, which adds to a run")
	}
	return out
}

func why(reason string) string {
	if reason == "" {
		return ""
	}
	return " (" + reason + ")"
}

func joinNames(names []string) string {
	if len(names) == 1 {
		return names[0]
	}
	return fmt.Sprint(names)
}

// probesOf merges the profile with the request's own probes.
func probesOf(cfg *config.Config, req Request, refuse func(string, ...any)) Probes {
	pr := Probes{ARP: req.ARP, ICMP: req.ICMP, TCP: slices.Clone(req.TCP), UDP: slices.Clone(req.UDP)}
	if req.Profile != "" {
		prof, ok := cfg.Profiles[req.Profile]
		if !ok {
			refuse("unknown profile %q", req.Profile)
		}
		pr.ARP, pr.ICMP = pr.ARP || prof.ARP, pr.ICMP || prof.ICMP
		pr.TCP, pr.UDP = append(pr.TCP, prof.TCP...), append(pr.UDP, prof.UDP...)
	}
	if !pr.ARP && !pr.ICMP && len(pr.TCP) == 0 && len(pr.UDP) == 0 {
		pr.ARP = true
	}
	slices.Sort(pr.TCP)
	pr.TCP = slices.Compact(pr.TCP)
	for _, port := range pr.TCP {
		if port < 1 || port > 65535 {
			refuse("TCP port %d is out of range", port)
		}
	}
	slices.Sort(pr.UDP)
	pr.UDP = slices.Compact(pr.UDP)
	for _, u := range pr.UDP {
		if !slices.Contains(config.UDPProbeNames, u) {
			refuse("unknown UDP probe %q (known: %v)", u, config.UDPProbeNames)
		}
	}
	return pr
}

func planInterface(cfg *config.Config, in PlanInput, name string, req Request, pr Probes, used map[netip.Prefix]bool) InterfacePlan {
	ip := InterfacePlan{Interface: name, Link: in.Links[name]}
	ip.Link.Name = name
	ic, ok := InterfaceConfig(cfg, name)
	switch {
	case !ok:
		ip.Reasons = append(ip.Reasons, "interface is not configured")
		return ip
	case !ic.Active.Enabled:
		ip.Reasons = append(ip.Reasons, "active discovery is disabled on the interface")
		return ip
	}
	ip.Networks = ic.Active.Networks
	if len(req.Networks) > 0 {
		ip.Networks = nil
		for _, n := range req.Networks {
			if n.Addr().Is4() && within(ic.Active.Networks, n) {
				ip.Networks = append(ip.Networks, n.Masked())
				used[n.Masked()] = true
			}
		}
		if len(ip.Networks) == 0 {
			ip.Reasons = append(ip.Reasons, "none of the requested networks is configured on the interface")
			return ip
		}
	}
	ip.Own, ip.Excl = ip.Link.Own(), ic.Active.Exclude
	if pr.ARP {
		ip.Sweep = NewSweep(ip.Networks, ip.Excl, ip.Own)
		ip.SweepTargets, ip.Excluded = ip.Sweep.Len(), ip.Sweep.Excluded()
		switch limit := cfg.Active.MaxSweepTargets; {
		case ip.SweepTargets > limit:
			ip.Reasons = append(ip.Reasons, fmt.Sprintf("the sweep covers %d addresses, more than active.max_sweep_targets (%d)", ip.SweepTargets, limit))
		case ip.SweepTargets > config.DefaultMaxSweepTargets && !req.AllowWide:
			ip.Reasons = append(ip.Reasons, fmt.Sprintf("the sweep covers %d addresses, more than %d: review this plan, then repeat with --allow-wide",
				ip.SweepTargets, config.DefaultMaxSweepTargets))
		}
	}
	if pr.ICMP || len(pr.TCP) > 0 || len(pr.UDP) > 0 {
		ip.Known = KnownTargets(in.Known[name], ip.Networks, ip.Excl, ip.Own)
		ip.KnownTargets = len(ip.Known)
	}
	ip.TCP = tcpTargets(cfg, pr.TCP)
	if ip.SweepTargets == 0 && ip.KnownTargets == 0 {
		ip.Reasons = append(ip.Reasons, "no targets left")
	}
	ip.Estimate = estimate(LimitsFrom(cfg.Active), ip, pr)
	return ip
}

// within reports whether n lies inside one of the networks.
func within(networks []netip.Prefix, n netip.Prefix) bool {
	for _, c := range networks {
		if c.Bits() <= n.Bits() && c.Contains(n.Addr()) {
			return true
		}
	}
	return false
}

// tcpTargets uses the configured name and timeout of a port, if any.
func tcpTargets(cfg *config.Config, ports []int) []config.TCPTarget {
	out := make([]config.TCPTarget, 0, len(ports))
	for _, port := range ports {
		t := config.TCPTarget{Port: port, Timeout: config.Duration(DefaultTCPTimeout)}
		for _, c := range cfg.Active.TCP.Targets {
			if c.Port == port {
				t = c
			}
		}
		out = append(out, t)
	}
	return out
}

// simSweep is how much of a long sweep the estimate simulates; the rest
// goes at the steady pace the simulation reached.
const simSweep = 20000

// estimate counts the probes of one interface and simulates their pacing
// in the order a run sends them: the ARP sweep, then ICMP, TCP port by
// port and UDP probe by probe, the known hosts in the same order in every
// phase.
func estimate(limits Limits, ip InterfacePlan, pr Probes) Estimate {
	var e Estimate
	var sweep, rest []SimProbe
	var typical, worst time.Duration
	phase := func(p Protocol, targets []netip.Addr, wait time.Duration) {
		for _, t := range targets {
			rest = append(rest, SimProbe{Protocol: p, Interface: ip.Interface, Target: t})
		}
		if len(targets) > 0 {
			worst += wait
		}
	}
	if pr.ARP && ip.SweepTargets > 0 {
		e.ARPRequests = ip.SweepTargets
		for _, t := range ip.Sweep.First(simSweep) {
			sweep = append(sweep, SimProbe{Protocol: ARP, Interface: ip.Interface, Target: t})
		}
		typical, worst = DefaultReplyTimeout, DefaultReplyTimeout
	}
	if pr.ICMP {
		e.ICMPEchoes = len(ip.Known)
		phase(ICMP, ip.Known, DefaultReplyTimeout)
	}
	for _, t := range ip.TCP {
		e.TCPConnects += len(ip.Known)
		phase(TCP, ip.Known, t.Timeout.D())
	}
	for range pr.UDP {
		e.UDPProbes += len(ip.Known)
		phase(UDP, ip.Known, DefaultReplyTimeout)
	}
	e.Packets = e.ARPRequests + e.ICMPEchoes + e.UDPProbes + TCPTokens*e.TCPConnects
	var pace time.Duration
	switch {
	case e.ARPRequests > len(sweep):
		// A long sweep: simulate its start, extrapolate its steady pace,
		// then the known-host phases on their own.
		half := len(sweep) / 2
		t := Simulate(limits, time.Unix(0, 0), sweep)
		step := float64(t-Simulate(limits, time.Unix(0, 0), sweep[:half])) / float64(len(sweep)-half)
		pace = t + time.Duration(step*float64(e.ARPRequests-len(sweep)))
		if len(rest) > 0 {
			pace += interval(1, limits.Rates[ARP]) + Simulate(limits, time.Unix(0, 0), rest)
		}
	case len(sweep)+len(rest) > 0:
		pace = Simulate(limits, time.Unix(0, 0), append(sweep, rest...))
	}
	if e.Packets > 0 {
		e.TypicalSeconds, e.NoResponseSeconds = (pace + typical).Seconds(), (pace + worst).Seconds()
	}
	return e
}
