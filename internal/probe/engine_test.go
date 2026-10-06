package probe

import (
	"context"
	"math/rand/v2"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"lan-sentinel/internal/clock"
	"lan-sentinel/internal/config"
)

func prefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

func excludes(ss ...string) []config.AddrOrPrefix {
	out := make([]config.AddrOrPrefix, len(ss))
	for i, s := range ss {
		if err := out[i].UnmarshalText([]byte(s)); err != nil {
			panic(err)
		}
	}
	return out
}

func TestLinkSourceAndOwn(t *testing.T) {
	l := Link{Name: "eth1", MAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, Addrs: prefixes("fe80::1/64", "192.168.110.10/24", "10.1.0.2/16")}
	if got := l.SourceFor(ip("192.168.110.77")); got != ip("192.168.110.10") {
		t.Errorf("SourceFor in subnet = %v", got)
	}
	if got := l.SourceFor(ip("172.16.0.1")); got != netip.IPv4Unspecified() {
		t.Errorf("SourceFor off subnet = %v, want 0.0.0.0 (ARP probe)", got)
	}
	if got := l.Own(); !slices.Equal(got, []netip.Addr{ip("192.168.110.10"), ip("10.1.0.2")}) {
		t.Errorf("Own = %v", got)
	}
}

func TestSweepTargets(t *testing.T) {
	tests := []struct {
		name     string
		networks []netip.Prefix
		excl     []config.AddrOrPrefix
		own      []netip.Addr
		count    int
		first    string
		last     string
		applied  []string
	}{
		{"a /24 without network and broadcast", prefixes("192.168.110.0/24"), nil, nil, 254, "192.168.110.1", "192.168.110.254", nil},
		{"own address and excludes", prefixes("192.168.110.0/24"), excludes("192.168.110.1", "192.168.110.240/28", "10.0.0.1"),
			[]netip.Addr{ip("192.168.110.10")}, 254 - 1 - 1 - 15, "192.168.110.2", "192.168.110.239", []string{"192.168.110.1", "192.168.110.240/28"}},
		{"a /31 has two hosts", prefixes("10.0.0.0/31"), nil, nil, 2, "10.0.0.0", "10.0.0.1", nil},
		{"a /32 is one host", prefixes("10.0.0.9/32"), nil, nil, 1, "10.0.0.9", "10.0.0.9", nil},
		{"unmasked network", prefixes("192.168.1.77/30"), nil, nil, 2, "192.168.1.77", "192.168.1.78", nil},
		{"overlapping networks once", prefixes("10.0.0.0/30", "10.0.0.0/29"), nil, nil, 6, "10.0.0.1", "10.0.0.6", nil},
		{"ipv6 never swept", prefixes("fd00::/120"), nil, nil, 0, "", "", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sw := NewSweep(tt.networks, tt.excl, tt.own)
			var got []netip.Addr
			for a := range sw.Order(rand.New(rand.NewPCG(1, 2))) {
				got = append(got, a)
			}
			slices.SortFunc(got, func(a, b netip.Addr) int { return a.Compare(b) })
			if len(got) != tt.count || sw.Len() != tt.count {
				t.Fatalf("%d targets (Len %d), want %d", len(got), sw.Len(), tt.count)
			}
			if tt.count > 0 && (got[0] != ip(tt.first) || got[len(got)-1] != ip(tt.last)) {
				t.Errorf("targets %v..%v, want %s..%s", got[0], got[len(got)-1], tt.first, tt.last)
			}
			if !slices.Equal(sw.Excluded(), tt.applied) && len(sw.Excluded())+len(tt.applied) > 0 {
				t.Errorf("applied excludes = %v, want %v", sw.Excluded(), tt.applied)
			}
			if first := sw.First(3); !slices.Equal(first, got[:min(3, len(got))]) {
				t.Errorf("First(3) = %v", first)
			}
			for _, a := range got {
				if !sw.Contains(a) {
					t.Errorf("Contains(%v) = false", a)
				}
			}
			for _, o := range tt.own {
				if sw.Contains(o) {
					t.Errorf("own %v swept", o)
				}
			}
		})
	}
	// A wide sweep is not listed: its size is known at once.
	if big := NewSweep(prefixes("10.0.0.0/8"), excludes("10.1.0.0/16"), nil); big.Len() != 1<<24-2-1<<16 {
		t.Errorf("a /8 less a /16 = %d targets", big.Len())
	}
}

func TestKnownTargets(t *testing.T) {
	known := []netip.Addr{
		ip("192.168.110.30"), ip("192.168.110.5"), ip("192.168.110.5"), netip.MustParseAddr("::ffff:192.168.110.6"),
		ip("192.168.111.1"), ip("192.168.110.1"), ip("192.168.110.10"), ip("fe80::1"),
	}
	got := KnownTargets(known, prefixes("192.168.110.0/24"), excludes("192.168.110.1"), []netip.Addr{ip("192.168.110.10")})
	want := []netip.Addr{ip("192.168.110.5"), ip("192.168.110.6"), ip("192.168.110.30")}
	if !slices.Equal(got, want) {
		t.Errorf("KnownTargets = %v, want %v", got, want)
	}
}

func TestShuffleIsAPermutation(t *testing.T) {
	in := hosts(50)
	out := Shuffle(rand.New(rand.NewPCG(1, 2)), in)
	if slices.Equal(in, out) {
		t.Error("order unchanged")
	}
	sorted := slices.Clone(out)
	slices.SortFunc(sorted, func(a, b netip.Addr) int { return a.Compare(b) })
	if !slices.Equal(sorted, in) {
		t.Error("not a permutation")
	}
	if !slices.Equal(in, hosts(50)) {
		t.Error("input modified")
	}
}

func TestBackoff(t *testing.T) {
	b := NewBackoff()
	h, iv := ip("10.0.0.5"), 5*time.Minute
	var none time.Time
	now := t0
	for i := range TimeoutsBeforeBackoff {
		if !b.Due("eth1", TCP, h, "502", iv, now, none) {
			t.Fatalf("not due after %d timeouts", i)
		}
		b.Record("eth1", TCP, h, "502", true, now)
		now = now.Add(iv)
	}
	last := now.Add(-iv)
	if b.Due("eth1", TCP, h, "502", iv, last.Add(iv), none) {
		t.Error("due one interval after the third timeout")
	}
	if !b.Due("eth1", TCP, h, "502", iv, last.Add(BackoffFactor*iv), none) {
		t.Error("not due after four intervals")
	}
	// Jitter may bring the pass slightly early.
	if !b.Due("eth1", TCP, h, "502", iv, last.Add(BackoffFactor*iv-iv/20), none) {
		t.Error("not due just before four intervals")
	}
	// Scoped per interface, address, probe type and port: one silent probe
	// slows no other.
	for _, other := range []struct {
		iface string
		p     Protocol
		ip    netip.Addr
		sub   string
	}{{"eth1", TCP, h, "80"}, {"eth1", ICMP, h, ""}, {"eth1", UDP, h, "ntp"}, {"eth2", TCP, h, "502"}, {"eth1", TCP, ip("10.0.0.6"), "502"}} {
		if !b.Due(other.iface, other.p, other.ip, other.sub, iv, last, none) {
			t.Errorf("back-off leaked to %+v", other)
		}
	}
	// Evidence older than the last miss changes nothing.
	if b.Due("eth1", TCP, h, "502", iv, last.Add(iv), last.Add(-time.Minute)) {
		t.Error("stale evidence eased the back-off")
	}
	b.Record("eth1", TCP, h, "502", false, last)
	if !b.Due("eth1", TCP, h, "502", iv, last, none) {
		t.Error("an answer did not reset the back-off")
	}
}

func TestBackoffEasedByFreshEvidence(t *testing.T) {
	b := NewBackoff()
	h, iv := ip("10.0.0.5"), 10*time.Minute
	var none time.Time
	now := t0
	for range TimeoutsBeforeBackoff {
		b.Record("eth1", ICMP, h, "", true, now)
		now = now.Add(iv)
	}
	if b.Due("eth1", ICMP, h, "", iv, now, none) {
		t.Fatal("not in back-off after three misses")
	}
	// The host showed up (passive traffic, another probe's answer): the
	// next echo goes at the normal interval...
	if !b.Due("eth1", ICMP, h, "", iv, now, now.Add(-time.Minute)) {
		t.Error("fresh evidence did not ease the back-off")
	}
	// ...and one more miss brings the back-off back at once.
	b.Record("eth1", ICMP, h, "", true, now)
	if b.Due("eth1", ICMP, h, "", iv, now.Add(iv), now.Add(-time.Minute)) {
		t.Error("one miss after easing did not restore the back-off")
	}
}

func TestReplies(t *testing.T) {
	targets := []netip.Addr{ip("10.0.0.1"), ip("10.0.0.2"), ip("10.0.0.3")}
	sim := clock.NewSim(t0)
	p := Pass{Targets: targets, Clock: sim, ReplyTimeout: time.Second}
	r := NewReplies(p, nil)
	released := make(chan netip.Addr, 3)
	ctx, cancel := context.WithCancel(context.Background())
	for _, tg := range targets[:2] {
		r.Expect(tg)
		r.Hold(ctx, tg, func() { released <- tg })
	}
	if !r.Reply(targets[0]) {
		t.Error("Reply of a target = false")
	}
	if !r.Reply(targets[0]) {
		t.Error("a second reply of a target = false")
	}
	if r.Reply(ip("10.9.9.9")) {
		t.Error("Reply of a stranger = true")
	}
	if got := <-released; got != targets[0] {
		t.Errorf("released %v first, want the answered target", got)
	}
	waitFor(t, func() bool { return sim.Waiters() == 1 })
	sim.Advance(time.Second)
	if got := <-released; got != targets[1] {
		t.Errorf("released %v on timeout", got)
	}
	r.Hold(ctx, targets[2], func() { released <- targets[2] }) // not expected: waits for the timeout or ctx
	cancel()
	<-released
	r.Wait()
	// A late reply from a target still counts; probes in flight are
	// forgotten once done.
	if !r.Reply(targets[1]) {
		t.Error("late reply of a target = false")
	}
	if len(r.waiting) != 0 {
		t.Errorf("%d probes still tracked after they ended", len(r.waiting))
	}
	if got := r.Responders(); !slices.Equal(got, targets[:2]) {
		t.Errorf("Responders = %v", got)
	}
	results := r.Finish([]Result{{Target: targets[0], State: NoReply}, {Target: targets[2], State: NoReply}, {Target: targets[2], State: Blocked}})
	if results[0].State != Reply || results[1].State != NoReply || results[2].State != Blocked {
		t.Errorf("Finish = %+v", results)
	}
	if (Result{}).N() != 1 || (Result{Count: 7}).N() != 7 {
		t.Error("Result.N")
	}
}

func TestPassDefaults(t *testing.T) {
	var p Pass
	if p.Timeout() != DefaultReplyTimeout {
		t.Errorf("Timeout = %v", p.Timeout())
	}
	if time.Since(p.Now()) > time.Minute || p.Now().Location() != time.UTC {
		t.Errorf("Now = %v", p.Now())
	}
	c, stop := p.After(time.Millisecond)
	<-c
	stop()
	sim := clock.NewSim(t0.In(time.FixedZone("x", 3600)))
	p.Clock = sim
	if !p.Now().Equal(t0) || p.Now().Location() != time.UTC {
		t.Errorf("Now on a sim clock = %v", p.Now())
	}
}
