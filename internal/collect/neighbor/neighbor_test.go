package neighbor

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"lan-sentinel/internal/clock"
	"lan-sentinel/internal/observation"
	"lan-sentinel/internal/platform"
	"lan-sentinel/internal/platform/fake"
)

var t0 = time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)

func nb(ip, mac, state string, ago time.Duration) platform.Neighbor {
	m, _ := net.ParseMAC(mac)
	return platform.Neighbor{Interface: "eth1", IP: netip.MustParseAddr(ip), MAC: m, State: state, ConfirmedAgo: ago}
}

// drain returns everything on the bus without blocking.
func drain(b *observation.Bus) []observation.Observation {
	var out []observation.Observation
	for {
		select {
		case m := <-b.C():
			out = append(out, m.Observation)
		default:
			return out
		}
	}
}

func TestEmitFiltersAndStampsConfirmedTime(t *testing.T) {
	sim := clock.NewSim(t0)
	bus := observation.NewBus(16)
	c := New(Options{Source: &fake.Neighbors{}, Bus: bus, Clock: sim, Interfaces: []string{"eth1"}})

	c.emit(nb("10.0.0.1", "00:1b:1b:00:00:01", "REACHABLE", 3*time.Second), t0)
	c.emit(nb("10.0.0.2", "00:1b:1b:00:00:02", "STALE", 2*time.Hour), t0)
	c.emit(nb("10.0.0.3", "", "INCOMPLETE", 0), t0)                                                                                                    // no MAC
	c.emit(nb("10.0.0.4", "00:1b:1b:00:00:04", "PERMANENT", 0), t0)                                                                                    // configuration
	c.emit(platform.Neighbor{Interface: "eth2", IP: netip.MustParseAddr("10.0.0.5"), MAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, State: "REACHABLE"}, t0) // not monitored

	got := drain(bus)
	if len(got) != 2 {
		t.Fatalf("emitted %d observations, want 2: %+v", len(got), got)
	}
	if !got[0].Time.Equal(t0.Add(-3*time.Second)) || got[0].NeighborState != "REACHABLE" || got[0].Source != observation.KernelNeighbor {
		t.Errorf("REACHABLE entry = %+v", got[0])
	}
	// A STALE entry carries its old confirmation time, not "now".
	if !got[1].Time.Equal(t0.Add(-2 * time.Hour)) {
		t.Errorf("STALE entry stamped %s, want its confirmation time", got[1].Time)
	}
}

func TestDuplicatesSkippedUntilReconfirmed(t *testing.T) {
	bus := observation.NewBus(16)
	c := New(Options{Source: &fake.Neighbors{}, Bus: bus, Clock: clock.NewSim(t0), Interfaces: []string{"eth1"}})

	c.emit(nb("10.0.0.1", "00:1b:1b:00:00:01", "STALE", time.Hour), t0)
	// The same entry read again a minute later: same confirmation time.
	c.emit(nb("10.0.0.1", "00:1b:1b:00:00:01", "STALE", time.Hour+time.Minute), t0.Add(time.Minute))
	if n := len(drain(bus)); n != 1 {
		t.Fatalf("unchanged entry emitted %d times, want 1", n)
	}
	// Reconfirmed: new evidence.
	c.emit(nb("10.0.0.1", "00:1b:1b:00:00:01", "REACHABLE", 0), t0.Add(2*time.Minute))
	// Different MAC behind the same IP: new evidence even with an old time.
	c.emit(nb("10.0.0.1", "00:1b:1b:00:00:09", "STALE", time.Hour), t0.Add(3*time.Minute))
	if n := len(drain(bus)); n != 2 {
		t.Fatalf("reconfirmation and MAC change emitted %d observations, want 2", n)
	}
}

func TestRunSnapshotWatchAndResync(t *testing.T) {
	sim := clock.NewSim(t0)
	bus := observation.NewBus(64)
	src := &fake.Neighbors{}
	src.SetTable([]platform.Neighbor{nb("10.0.0.1", "00:1b:1b:00:00:01", "REACHABLE", 0)})
	reg := platform.NewRegistry(sim.Now)
	c := New(Options{Source: src, Bus: bus, Clock: sim, Interfaces: []string{"eth1"}, Resync: 10 * time.Minute, Registry: reg})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { _ = c.Run(ctx); close(done) }()

	next := func() observation.Observation {
		t.Helper()
		select {
		case m := <-bus.C():
			return m.Observation
		case <-time.After(5 * time.Second):
			t.Fatal("no observation")
			return observation.Observation{}
		}
	}
	if o := next(); o.IP.String() != "10.0.0.1" {
		t.Fatalf("snapshot observation = %+v", o)
	}
	waitFor(t, func() bool { return len(reg.List()) == 1 && reg.List()[0].State == platform.StateRunning })

	src.Emit(platform.NeighborEvent{Neighbor: nb("10.0.0.2", "00:1b:1b:00:00:02", "REACHABLE", 0)})
	if o := next(); o.IP.String() != "10.0.0.2" {
		t.Fatalf("watch observation = %+v", o)
	}

	// A resync takes a fresh snapshot; only new evidence is emitted.
	src.SetTable([]platform.Neighbor{
		nb("10.0.0.1", "00:1b:1b:00:00:01", "REACHABLE", 0),
		nb("10.0.0.3", "00:1b:1b:00:00:03", "REACHABLE", 0),
	})
	sim.Advance(time.Minute)
	src.Emit(platform.NeighborEvent{Resync: true})
	if o := next(); o.IP.String() != "10.0.0.1" {
		t.Fatalf("resync re-confirmed entry = %+v", o)
	}
	if o := next(); o.IP.String() != "10.0.0.3" {
		t.Fatalf("resync new entry = %+v", o)
	}
	cancel()
	<-done
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
