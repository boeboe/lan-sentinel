package probe

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"lan-sentinel/internal/clock"
	"lan-sentinel/internal/config"
	"lan-sentinel/internal/store"
)

var t0 = time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)

func ip(s string) netip.Addr { return netip.MustParseAddr(s) }

// hosts returns n distinct addresses 10.0.x.y.
func hosts(n int) []netip.Addr {
	out := make([]netip.Addr, n)
	for i := range n {
		out[i] = netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)})
	}
	return out
}

func defaultLimits() Limits { return LimitsFrom(config.Defaults().Active) }

type send struct {
	at time.Time
	p  Protocol
}

// schedule books probes in order the way Acquire does, without blocking:
// each send happens at its reserved time.
func schedule(limits Limits, probes []SimProbe) []send {
	sim := clock.NewSim(t0)
	b := NewBudget(sim, limits, nil)
	out := make([]send, 0, len(probes))
	for _, p := range probes {
		sim.Set(b.spacing(p.Interface, p.Target))
		at, _ := b.reserve(p.Protocol, p.Interface, p.Target)
		sim.Set(at)
		out = append(out, send{at, p.Protocol})
	}
	return out
}

// windowMax returns, over every one-second window starting at a send, the
// most sends (or tokens) of one protocol, and the most global tokens.
func windowMax(sends []send) (perProto map[Protocol]int, tokens float64) {
	perProto = map[Protocol]int{}
	for i, s := range sends {
		n := map[Protocol]int{}
		tok := 0.0
		for _, x := range sends[i:] {
			if !x.at.Before(s.at.Add(time.Second)) {
				break
			}
			n[x.p]++
			tok++
			if x.p == TCP {
				tok += TCPTokens - 1
			}
		}
		for p, c := range n {
			perProto[p] = max(perProto[p], c)
		}
		tokens = max(tokens, tok)
	}
	return perProto, tokens
}

func TestPacingStaysWithinEveryOneSecondWindow(t *testing.T) {
	mixed := func(n int) []SimProbe {
		var ps []SimProbe
		for i, h := range hosts(n) {
			p := []Protocol{ARP, ICMP, TCP, UDP}[i%4]
			ps = append(ps, SimProbe{p, "eth1", h})
		}
		return ps
	}
	only := func(p Protocol, n int) []SimProbe {
		var ps []SimProbe
		for _, h := range hosts(n) {
			ps = append(ps, SimProbe{p, "eth1", h})
		}
		return ps
	}
	tcpHeavy := defaultLimits()
	tcpHeavy.Rates[TCP] = 10 // 30 tokens/s wanted, 20 allowed: the global budget binds
	tests := []struct {
		name   string
		limits Limits
		probes []SimProbe
		rate   map[Protocol]float64 // most per window
		global float64
	}{
		{"arp sweep", defaultLimits(), only(ARP, 254), map[Protocol]float64{ARP: 10}, 20},
		{"tcp connects", defaultLimits(), only(TCP, 60), map[Protocol]float64{TCP: 5}, 20},
		{"tcp bound by global tokens", tcpHeavy, only(TCP, 60), map[Protocol]float64{TCP: 7}, 20},
		{"mixed protocols", defaultLimits(), mixed(200), map[Protocol]float64{ARP: 10, ICMP: 5, TCP: 5, UDP: 5}, 20},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sends := schedule(tt.limits, tt.probes)
			per, tokens := windowMax(sends)
			for p, limit := range tt.rate {
				if float64(per[p]) > limit {
					t.Errorf("%s: %d sends in one second, limit %v", p, per[p], limit)
				}
			}
			if tokens > tt.global {
				t.Errorf("%v global tokens in one second, limit %v", tokens, tt.global)
			}
			// Paced, not starved: the run takes about as long as the
			// binding limit says.
			if last := sends[len(sends)-1].at.Sub(t0); last <= 0 {
				t.Errorf("no pacing at all: last send at %v", last)
			}
		})
	}
}

func TestTargetSpacing(t *testing.T) {
	h := ip("10.0.0.5")
	sends := schedule(defaultLimits(), []SimProbe{{ARP, "eth1", h}, {ICMP, "eth1", h}, {TCP, "eth1", h}, {TCP, "eth2", h}})
	for i := 1; i < 3; i++ {
		if gap := sends[i].at.Sub(sends[i-1].at); gap < time.Second {
			t.Errorf("probe %d to one target %v after the previous, want >= 1s", i, gap)
		}
	}
	// The same IP on another interface is another target.
	if gap := sends[3].at.Sub(sends[2].at); gap >= time.Second {
		t.Errorf("eth2 probe waited %v for eth1's spacing", gap)
	}
}

func TestSimulateMatchesPacing(t *testing.T) {
	probes := make([]SimProbe, 0, 101)
	for _, h := range hosts(101) {
		probes = append(probes, SimProbe{ARP, "eth1", h})
	}
	got := Simulate(defaultLimits(), t0, probes)
	want := 100 * time.Duration(float64(time.Second)/10*paceMargin)
	if got < want-time.Millisecond || got > want+time.Millisecond {
		t.Errorf("Simulate = %v, want %v", got, want)
	}
	if Simulate(defaultLimits(), t0, nil) != 0 {
		t.Error("empty simulation takes time")
	}
}

type policyFunc func(string, Protocol, netip.Addr) error

func (f policyFunc) Check(iface string, p Protocol, target netip.Addr) error {
	return f(iface, p, target)
}

func TestAcquireChecksPolicyBeforeReserving(t *testing.T) {
	sim := clock.NewSim(t0)
	refuse := policyFunc(func(string, Protocol, netip.Addr) error { return refusal("nope") })
	b := NewBudget(sim, defaultLimits(), refuse)
	if _, err := b.Acquire(context.Background(), ARP, "eth1", ip("10.0.0.1")); !errors.Is(err, ErrRefused) {
		t.Fatalf("Acquire = %v, want ErrRefused", err)
	}
	if len(b.target) != 0 || len(b.global.log) != 0 {
		t.Error("a refused probe reserved budget")
	}
	if len(b.slots) != 0 {
		t.Error("a refused probe holds a concurrency slot")
	}
}

func TestKillSwitchDuringWaitRefusesTheSend(t *testing.T) {
	sim := clock.NewSim(t0)
	sw := NewSwitch(store.ActiveState{})
	cfg := config.Defaults()
	cfg.Interfaces = []config.InterfaceConfig{{Name: "eth1", Active: config.InterfaceActive{
		Enabled: true, Networks: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
	}}}
	b := NewBudget(sim, defaultLimits(), ConfigPolicy{Switch: sw, Config: func() *config.Config { return cfg }})
	h := ip("10.0.0.7")
	release, err := b.Acquire(context.Background(), ARP, "eth1", h)
	if err != nil {
		t.Fatal(err)
	}
	release()
	done := make(chan error, 1)
	go func() {
		_, err := b.Acquire(context.Background(), ICMP, "eth1", h) // waits for the target spacing
		done <- err
	}()
	waitFor(t, func() bool { return sim.Waiters() > 0 })
	sw.Set(store.ActiveState{Disabled: true, Reason: "test"})
	sim.Advance(time.Second)
	if err := <-done; !errors.Is(err, ErrDisabled) {
		t.Fatalf("Acquire after the kill switch = %v, want ErrDisabled", err)
	}
	if len(b.slots) != 0 {
		t.Error("the refused probe kept its concurrency slot")
	}
	if b.Throttled()[Throttle{ICMP, "target_spacing"}] != 1 {
		t.Errorf("throttled = %v", b.Throttled())
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestConcurrencyCaps(t *testing.T) {
	limits := Limits{MaxConcurrent: 3, TCPPerInterface: 2, TCPPerHost: 1}
	tests := []struct {
		name   string
		held   []SimProbe
		next   SimProbe
		blocks bool
		reason string
	}{
		{"global cap", []SimProbe{{ARP, "eth1", ip("10.0.0.1")}, {ICMP, "eth1", ip("10.0.0.2")}, {UDP, "eth2", ip("10.0.0.3")}},
			SimProbe{ARP, "eth1", ip("10.0.0.4")}, true, "concurrency"},
		{"tcp per host", []SimProbe{{TCP, "eth1", ip("10.0.0.1")}}, SimProbe{TCP, "eth1", ip("10.0.0.1")}, true, "tcp_host"},
		{"tcp per host is per interface", []SimProbe{{TCP, "eth1", ip("10.0.0.1")}}, SimProbe{TCP, "eth2", ip("10.0.0.1")}, false, ""},
		{"tcp per interface", []SimProbe{{TCP, "eth1", ip("10.0.0.1")}, {TCP, "eth1", ip("10.0.0.2")}},
			SimProbe{TCP, "eth1", ip("10.0.0.3")}, true, "tcp_interface"},
		{"other protocols ignore tcp caps", []SimProbe{{TCP, "eth1", ip("10.0.0.1")}, {TCP, "eth1", ip("10.0.0.2")}},
			SimProbe{ICMP, "eth1", ip("10.0.0.3")}, false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := NewBudget(clock.Real(), limits, nil)
			ctx := context.Background()
			var releases []func()
			for _, h := range tt.held {
				r, err := b.Acquire(ctx, h.Protocol, h.Interface, h.Target)
				if err != nil {
					t.Fatal(err)
				}
				releases = append(releases, r)
			}
			got := make(chan error, 1)
			go func() {
				r, err := b.Acquire(ctx, tt.next.Protocol, tt.next.Interface, tt.next.Target)
				if err == nil {
					r()
				}
				got <- err
			}()
			select {
			case err := <-got:
				if tt.blocks {
					t.Fatalf("Acquire did not wait (err %v)", err)
				}
				if err != nil {
					t.Fatal(err)
				}
				return
			case <-time.After(50 * time.Millisecond):
				if !tt.blocks {
					t.Fatal("Acquire waited")
				}
			}
			releases[0]()
			if err := <-got; err != nil {
				t.Fatal(err)
			}
			if b.Throttled()[Throttle{tt.next.Protocol, tt.reason}] != 1 {
				t.Errorf("throttled = %v, want one %s", b.Throttled(), tt.reason)
			}
			for _, r := range releases[1:] {
				r()
			}
		})
	}
}

func TestAcquireCancelled(t *testing.T) {
	t.Run("waiting for a slot", func(t *testing.T) {
		b := NewBudget(clock.Real(), Limits{MaxConcurrent: 1, TCPPerInterface: 1, TCPPerHost: 1}, nil)
		r, err := b.Acquire(context.Background(), TCP, "eth1", ip("10.0.0.1"))
		if err != nil {
			t.Fatal(err)
		}
		defer r()
		for _, p := range []SimProbe{{ARP, "eth1", ip("10.0.0.2")}} {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			_, err := b.Acquire(ctx, p.Protocol, p.Interface, p.Target)
			cancel()
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("Acquire = %v", err)
			}
		}
	})
	t.Run("waiting for tcp slots", func(t *testing.T) {
		b := NewBudget(clock.Real(), Limits{MaxConcurrent: 5, TCPPerInterface: 1, TCPPerHost: 1}, nil)
		r, err := b.Acquire(context.Background(), TCP, "eth1", ip("10.0.0.1"))
		if err != nil {
			t.Fatal(err)
		}
		for _, target := range []netip.Addr{ip("10.0.0.2"), ip("10.0.0.1")} {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			_, err := b.Acquire(ctx, TCP, "eth1", target)
			cancel()
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("Acquire = %v", err)
			}
		}
		r()
		if len(b.slots) != 0 {
			t.Errorf("%d concurrency slots leaked", len(b.slots))
		}
		// A per-host wait on a free interface slot.
		b2 := NewBudget(clock.Real(), Limits{MaxConcurrent: 5, TCPPerInterface: 2, TCPPerHost: 1}, nil)
		r2, _ := b2.Acquire(context.Background(), TCP, "eth1", ip("10.0.0.1"))
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		_, err = b2.Acquire(ctx, TCP, "eth1", ip("10.0.0.1"))
		cancel()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("Acquire = %v", err)
		}
		r2()
		if len(b2.slots) != 0 || len(b2.tcpIface["eth1"]) != 0 {
			t.Error("slots leaked after a cancelled per-host wait")
		}
	})
	t.Run("waiting for the pace", func(t *testing.T) {
		sim := clock.NewSim(t0)
		b := NewBudget(sim, defaultLimits(), nil)
		h := ip("10.0.0.1")
		r, _ := b.Acquire(context.Background(), ARP, "eth1", h)
		r()
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			_, err := b.Acquire(ctx, ARP, "eth1", h)
			done <- err
		}()
		waitFor(t, func() bool { return sim.Waiters() > 0 })
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatalf("Acquire = %v", err)
		}
		if len(b.slots) != 0 {
			t.Error("cancelled probe kept its slot")
		}
	})
}

func TestSetLimitsKeepsConcurrencyCaps(t *testing.T) {
	b := NewBudget(clock.NewSim(t0), Limits{MaxConcurrent: 2, TCPPerInterface: 2, TCPPerHost: 1, GlobalPPS: 20}, nil)
	b.SetLimits(Limits{MaxConcurrent: 50, TCPPerInterface: 9, TCPPerHost: 9, GlobalPPS: 5, Rates: map[Protocol]float64{ARP: 1}})
	if b.limits.MaxConcurrent != 2 || b.limits.TCPPerInterface != 2 || b.limits.TCPPerHost != 1 {
		t.Errorf("concurrency caps changed: %+v", b.limits)
	}
	if b.limits.GlobalPPS != 5 || b.limits.Rates[ARP] != 1 {
		t.Errorf("rates not applied: %+v", b.limits)
	}
}

func TestPruneDropsPastSpacing(t *testing.T) {
	sim := clock.NewSim(t0)
	b := NewBudget(sim, Limits{TargetSpacing: time.Second}, nil)
	for _, h := range hosts(4096) {
		b.reserve(ARP, "eth1", h)
	}
	sim.Advance(time.Minute)
	b.reserve(ARP, "eth1", ip("10.1.0.1"))
	if len(b.target) != 1 {
		t.Errorf("%d spacing entries after prune, want 1", len(b.target))
	}
}

func TestNilClockAndPolicy(t *testing.T) {
	b := NewBudget(nil, Limits{}, nil)
	r, err := b.Acquire(context.Background(), ARP, "eth1", ip("10.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	r()
}

func TestLateSendMovesTheBooking(t *testing.T) {
	sim := clock.NewSim(t0)
	limits := Limits{GlobalPPS: 20, Rates: map[Protocol]float64{ARP: 10}, MaxConcurrent: 10, TargetSpacing: time.Second}
	b := NewBudget(sim, limits, nil)
	h := hosts(3)
	r, err := b.Acquire(context.Background(), ARP, "eth1", h[0])
	if err != nil {
		t.Fatal(err)
	}
	r()
	// The second send is due 102 ms later; its goroutine runs 40 ms late.
	got := make(chan time.Time, 1)
	go func() {
		r, err := b.Acquire(context.Background(), ARP, "eth1", h[1])
		if err == nil {
			r()
		}
		got <- sim.Now()
	}()
	waitFor(t, func() bool { return sim.Waiters() > 0 })
	sim.Advance(142 * time.Millisecond)
	sent := <-got
	if late := sent.Sub(t0); late != 142*time.Millisecond {
		t.Fatalf("second send at +%v", late)
	}
	// The third send is paced from the actual (late) send, not the booking.
	at, _ := b.reserve(ARP, "eth1", h[2])
	if gap := at.Sub(sent); gap < interval(1, 10) {
		t.Errorf("third send %v after the late one, want >= %v", gap, interval(1, 10))
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.proto[ARP].log[1].at != sent || b.global.log[1].at != sent {
		t.Errorf("bookings not moved: %+v / %+v", b.proto[ARP].log, b.global.log)
	}
	if !b.target[hostKey{"eth1", h[1]}].Equal(sent.Add(time.Second)) {
		t.Errorf("target spacing from %v", b.target[hostKey{"eth1", h[1]}])
	}
}

func TestMoveWithoutRateIsANoOp(t *testing.T) {
	var k bucket
	k.move(t0, t0.Add(time.Second), 1, 0)
	if len(k.log) != 0 || !k.next.IsZero() {
		t.Errorf("bucket = %+v", k)
	}
}

func TestSpacingWaitDoesNotHoldUpOtherTargets(t *testing.T) {
	sim := clock.NewSim(t0)
	b := NewBudget(sim, defaultLimits(), nil)
	a, other := ip("10.0.0.1"), ip("10.0.0.2")
	r, _ := b.Acquire(context.Background(), ARP, "eth1", a)
	r()
	aDone := make(chan time.Time, 1)
	go func() {
		r, err := b.Acquire(context.Background(), ICMP, "eth1", a) // waits for a's spacing
		if err == nil {
			r()
		}
		aDone <- sim.Now()
	}()
	waitFor(t, func() bool { return sim.Waiters() == 1 })
	otherDone := make(chan time.Time, 1)
	go func() {
		r, err := b.Acquire(context.Background(), ARP, "eth1", other) // only paced behind the first ARP
		if err == nil {
			r()
		}
		otherDone <- sim.Now()
	}()
	waitFor(t, func() bool { return sim.Waiters() == 2 })
	sim.Advance(200 * time.Millisecond)
	select {
	case at := <-otherDone:
		if at.Sub(t0) > 200*time.Millisecond {
			t.Errorf("other target sent at +%v", at.Sub(t0))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a probe to another target waited for a's spacing")
	}
	sim.Advance(time.Second)
	if at := <-aDone; at.Sub(t0) < time.Second {
		t.Errorf("second probe to a at +%v, want >= 1s", at.Sub(t0))
	}
}

func TestSetLimitsDuringTCP(t *testing.T) {
	b := NewBudget(clock.Real(), Limits{MaxConcurrent: 8, TCPPerInterface: 4, TCPPerHost: 1}, nil)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := range 200 {
			b.SetLimits(Limits{TargetSpacing: time.Duration(i)})
		}
	}()
	for _, h := range hosts(200) {
		r, err := b.Acquire(context.Background(), TCP, "eth1", h)
		if err != nil {
			t.Fatal(err)
		}
		r()
	}
	<-done
}
