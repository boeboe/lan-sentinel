package probe

import (
	"context"
	"iter"
	"math/rand/v2"
	"net"
	"net/netip"
	"slices"
	"sort"
	"sync"
	"time"

	"lan-sentinel/internal/clock"
	"lan-sentinel/internal/config"
	"lan-sentinel/internal/netrange"
	"lan-sentinel/internal/observation"
)

// Link is what an engine needs to know about its interface: the MAC and
// IPv4 addresses probes are sent from.
type Link struct {
	Name  string
	MAC   net.HardwareAddr
	Addrs []netip.Prefix
}

// SourceFor returns the interface address in the same subnet as target, the
// sender address of an ARP request. Without one it returns 0.0.0.0: an ARP
// probe (RFC 5227), which hosts answer without caching the sender.
func (l Link) SourceFor(target netip.Addr) netip.Addr {
	for _, a := range l.Addrs {
		if a.Addr().Is4() && a.Contains(target) {
			return a.Addr()
		}
	}
	return netip.IPv4Unspecified()
}

// Own returns the interface's IPv4 addresses (never probed).
func (l Link) Own() []netip.Addr {
	var out []netip.Addr
	for _, a := range l.Addrs {
		if a.Addr().Is4() {
			out = append(out, a.Addr())
		}
	}
	return out
}

// Pass is one run of an engine over its targets.
type Pass struct {
	Link    Link
	Targets []netip.Addr // in probe order
	// Sweep, for an ARP sweep, yields the targets in probe order instead of
	// Targets, without listing them; InSweep tells its targets apart.
	Sweep   iter.Seq[netip.Addr]
	InSweep func(netip.Addr) bool
	TCP     []config.TCPTarget
	UDP     []string
	// Identify is the identification jobs of this pass (ADR 0011).
	Identify []IdentifyJob
	Budget   *Budget
	Emit     func(observation.Observation)
	Clock    clock.Clock // nil: the wall clock
	// ReplyTimeout bounds the wait for an ARP, ICMP or UDP reply.
	ReplyTimeout time.Duration
}

// IdentifyJob is one identification exchange: one probe to one host.
type IdentifyJob struct {
	HostID    string
	IP        netip.Addr
	Probe     string
	UnitID    uint8
	Community string
	Force     bool
	Trigger   string // scheduled or operator
	Actor     string // SO_PEERCRED caller of identify run; empty when scheduled
}

// Now returns the pass clock's time in UTC, the time stamped on
// observations.
func (p Pass) Now() time.Time {
	if p.Clock == nil {
		return time.Now().UTC()
	}
	return p.Clock.Now().UTC()
}

// Timeout returns ReplyTimeout or DefaultReplyTimeout.
func (p Pass) Timeout() time.Duration {
	if p.ReplyTimeout > 0 {
		return p.ReplyTimeout
	}
	return DefaultReplyTimeout
}

// After returns a channel that fires after d on the pass clock, and a
// function that stops it.
func (p Pass) After(d time.Duration) (<-chan time.Time, func()) {
	c := p.Clock
	if c == nil {
		c = clock.Real()
	}
	t := c.NewTimer(d)
	return t.C(), func() { t.Stop() }
}

// Result is the outcome of one probe, or of Count probes with the same
// outcome (an ARP sweep reports its unanswered addresses as one result).
type Result struct {
	Target netip.Addr `json:"target,omitzero"`
	Count  int        `json:"count,omitempty"` // 0: one probe
	Port   int        `json:"port,omitempty"`
	Probe  string     `json:"probe,omitempty"` // UDP probe name
	// State: reply or no_reply (ARP, ICMP, UDP); OPEN, REFUSED, TIMEOUT,
	// UNREACHABLE or UNKNOWN (TCP); blocked when the policy refused the
	// probe (excluded, outside the networks) and nothing was sent.
	State string `json:"state"`
}

// N is how many probes the result stands for.
func (r Result) N() int { return max(r.Count, 1) }

// Result states besides the TCP service states.
const (
	Reply   = "reply"
	NoReply = "no_reply"
	Blocked = "blocked"
)

// Engine probes targets of one protocol. It acquires the budget before
// every send and only emits observations; it never touches state. Run
// returns the results so far and an error when the pass stopped early: the
// kill switch (ErrDisabled), cancellation, or a transmit failure.
type Engine interface {
	Protocol() Protocol
	Run(ctx context.Context, p Pass) ([]Result, error)
}

// DefaultReplyTimeout is how long ARP, ICMP and UDP probes wait for a reply.
const DefaultReplyTimeout = time.Second

// Sweep is the address space of one interface's ARP sweep: the IPv4 host
// addresses of the networks (without the network and broadcast address of
// prefixes up to /30), less the excluded and the interface's own
// addresses. It is walked in a random order without being listed, so a
// wide sweep costs no memory.
type Sweep struct {
	set     netrange.Set
	applied []string
}

// NewSweep builds the sweep of networks; it remembers which exclude
// entries removed something.
func NewSweep(networks []netip.Prefix, excludes []config.AddrOrPrefix, own []netip.Addr) Sweep {
	var hosts []netrange.Range
	for _, n := range networks {
		if n.Addr().Is4() {
			hosts = append(hosts, netrange.Hosts(n))
		}
	}
	all := netrange.New(hosts...)
	var cut []netrange.Range
	var applied []string
	for _, e := range excludes {
		if !e.Addr().Is4() {
			continue
		}
		r := netrange.Of(e.Prefix)
		if all.Overlaps(r) {
			b, _ := e.MarshalText()
			applied = append(applied, string(b))
		}
		cut = append(cut, r)
	}
	for _, o := range own {
		if o.Is4() {
			cut = append(cut, netrange.Of(netip.PrefixFrom(o, 32)))
		}
	}
	sort.Strings(applied)
	return Sweep{set: all.Minus(cut...), applied: slices.Compact(applied)}
}

// Len is the number of addresses swept.
func (s Sweep) Len() int { return int(s.set.Len()) } //nolint:gosec // at most 2^32

// Contains reports whether ip is swept.
func (s Sweep) Contains(ip netip.Addr) bool { return s.set.Contains(ip.Unmap()) }

// Excluded returns the exclude entries that removed addresses.
func (s Sweep) Excluded() []string { return s.applied }

// Order returns the addresses in a random order.
func (s Sweep) Order(r *rand.Rand) iter.Seq[netip.Addr] {
	return func(yield func(netip.Addr) bool) { s.set.Shuffled(r, yield) }
}

// First returns up to n addresses in ascending order.
func (s Sweep) First(n int) []netip.Addr {
	n = min(n, s.Len())
	out := make([]netip.Addr, n)
	for i := range out {
		out[i] = s.set.At(uint64(i))
	}
	return out
}

// KnownTargets keeps the known addresses that are probe targets: IPv4,
// inside the networks, not own, not excluded.
func KnownTargets(known []netip.Addr, networks []netip.Prefix, excludes []config.AddrOrPrefix, own []netip.Addr) []netip.Addr {
	seen := map[netip.Addr]bool{}
	var out []netip.Addr
	for _, ip := range known {
		ip = ip.Unmap()
		if !ip.Is4() || seen[ip] || !Contains(networks, ip) || isOwn(own, ip) || Excluded(excludes, ip) {
			continue
		}
		seen[ip] = true
		out = append(out, ip)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	return out
}

func isOwn(own []netip.Addr, ip netip.Addr) bool {
	for _, o := range own {
		if o == ip {
			return true
		}
	}
	return false
}

// Shuffle randomises probe order (docs/ARCHITECTURE.md §5).
func Shuffle(r *rand.Rand, targets []netip.Addr) []netip.Addr {
	out := append([]netip.Addr(nil), targets...)
	r.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

// Backoff slows probing of unresponsive targets (NFR-SAFE-3). It is kept
// per interface, address, probe type and port (TCP) or probe (UDP), so one
// probe that goes unanswered never slows another: after three unanswered
// probes in a row that probe goes to the address at four times its
// interval. An answer to it ends the back-off; fresh evidence that the
// address is present (anything newer than the last unanswered probe: an
// answer to another probe, passive traffic, the neighbour table) eases it,
// so the next probe goes at the normal interval and one more unanswered
// probe brings the back-off back at once. ARP sweeps are not backed off.
type Backoff struct {
	mu    sync.Mutex
	state map[backoffKey]backoffState
}

type backoffKey struct {
	iface string
	proto Protocol
	ip    netip.Addr
	sub   string // the TCP port or UDP probe
}

type backoffState struct {
	timeouts int
	last     time.Time
}

// TimeoutsBeforeBackoff and BackoffFactor implement NFR-SAFE-3.
const (
	TimeoutsBeforeBackoff = 3
	BackoffFactor         = 4
)

// NewBackoff returns an empty tracker.
func NewBackoff() *Backoff { return &Backoff{state: map[backoffKey]backoffState{}} }

// Due reports whether a target should be probed at now given the engine's
// interval. sub tells apart the ports (TCP) or probes (UDP) of one host;
// lastSeen is the latest evidence that the address is present (zero: none).
func (b *Backoff) Due(iface string, p Protocol, ip netip.Addr, sub string, interval time.Duration, now, lastSeen time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	k := backoffKey{iface, p, ip, sub}
	s, ok := b.state[k]
	switch {
	case !ok || s.timeouts < TimeoutsBeforeBackoff:
		return true
	case lastSeen.After(s.last):
		s.timeouts = TimeoutsBeforeBackoff - 1 // eased: probed again, back at the next miss
		b.state[k] = s
		return true
	}
	return now.Sub(s.last) >= BackoffFactor*interval-interval/10
}

// Record notes a probe result: a timeout (or no reply) counts, anything
// else resets.
func (b *Backoff) Record(iface string, p Protocol, ip netip.Addr, sub string, timedOut bool, now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	k := backoffKey{iface, p, ip, sub}
	if !timedOut {
		delete(b.state, k)
		return
	}
	s := b.state[k]
	s.timeouts++
	s.last = now
	b.state[k] = s
}

// Replies tracks the probes of one pass that wait for a reply (ARP, ICMP):
// each holds its budget slots until its reply or the reply timeout. It
// remembers only the probes in flight and the targets that answered, so a
// wide sweep costs no more than a small one.
type Replies struct {
	pass     Pass
	isTarget func(netip.Addr) bool
	wg       sync.WaitGroup
	mu       sync.Mutex
	waiting  map[netip.Addr]chan struct{} // in flight; closed on the reply
	replied  map[netip.Addr]bool
}

// NewReplies prepares tracking for a pass. isTarget tells the pass's
// targets apart (nil: the pass's Targets): a reply from a target counts
// even after its timeout, as evidence.
func NewReplies(p Pass, isTarget func(netip.Addr) bool) *Replies {
	if isTarget == nil {
		set := make(map[netip.Addr]bool, len(p.Targets))
		for _, t := range p.Targets {
			set[t] = true
		}
		isTarget = func(ip netip.Addr) bool { return set[ip] }
	}
	return &Replies{pass: p, isTarget: isTarget, waiting: map[netip.Addr]chan struct{}{}, replied: map[netip.Addr]bool{}}
}

// Expect registers a probe to target before it is sent, so its reply can
// never arrive unannounced.
func (r *Replies) Expect(target netip.Addr) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.waiting[target] == nil {
		r.waiting[target] = make(chan struct{})
	}
}

// Hold keeps release until target replies, the reply timeout passes or ctx
// ends.
func (r *Replies) Hold(ctx context.Context, target netip.Addr, release func()) {
	r.mu.Lock()
	ch := r.waiting[target]
	r.mu.Unlock()
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		defer release()
		timeout, stop := r.pass.After(r.pass.Timeout())
		defer stop()
		select {
		case <-ch:
		case <-timeout:
		case <-ctx.Done():
		}
		r.mu.Lock()
		delete(r.waiting, target)
		r.mu.Unlock()
	}()
}

// Reply records a reply from ip and reports whether ip is a target of the
// pass.
func (r *Replies) Reply(ip netip.Addr) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	ch, inFlight := r.waiting[ip]
	if !inFlight && !r.isTarget(ip) {
		return false
	}
	if inFlight {
		select {
		case <-ch:
		default:
			close(ch)
		}
	}
	r.replied[ip] = true
	return true
}

// Wait returns once every held probe was answered or timed out.
func (r *Replies) Wait() { r.wg.Wait() }

// Responders returns the targets that answered, in address order.
func (r *Replies) Responders() []netip.Addr {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]netip.Addr, 0, len(r.replied))
	for ip := range r.replied {
		out = append(out, ip)
	}
	slices.SortFunc(out, func(a, b netip.Addr) int { return a.Compare(b) })
	return out
}

// Finish marks the sent probes that got a reply.
func (r *Replies) Finish(results []Result) []Result {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range results {
		if results[i].State == NoReply && r.replied[results[i].Target] {
			results[i].State = Reply
		}
	}
	return results
}
