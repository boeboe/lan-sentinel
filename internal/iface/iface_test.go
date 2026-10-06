package iface

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

func next(t *testing.T, bus *observation.Bus) observation.LinkState {
	t.Helper()
	select {
	case m := <-bus.C():
		if m.Link == nil {
			t.Fatalf("expected a link state, got %+v", m)
		}
		return *m.Link
	case <-time.After(5 * time.Second):
		t.Fatal("no link state")
		return observation.LinkState{}
	}
}

func TestManager(t *testing.T) {
	sim := clock.NewSim(time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC))
	bus := observation.NewBus(16)
	mon := &fake.Interfaces{}
	p24 := netip.MustParsePrefix("192.168.110.0/24")
	mon.SetLinks([]platform.Link{
		{Name: "eth1", Index: 2, Up: true, MAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, Prefixes: []netip.Prefix{p24}},
		{Name: "lo", Index: 1, Up: true},
	})
	reg := platform.NewRegistry(sim.Now)
	m := New(Options{Monitor: mon, Bus: bus, Clock: sim, Interfaces: []string{"eth1", "eth2"}, Registry: reg})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = m.Run(ctx); close(done) }()

	// Start-up: every configured interface, absent ones as not present.
	states := map[string]observation.LinkState{}
	for range 2 {
		ls := next(t, bus)
		states[ls.Interface] = ls
	}
	if ls := states["eth1"]; !ls.Present || !ls.Up || len(ls.Prefixes) != 1 || ls.Prefixes[0] != p24 {
		t.Errorf("eth1 = %+v", ls)
	}
	if ls := states["eth2"]; ls.Present {
		t.Errorf("absent eth2 reported present: %+v", ls)
	}
	links := m.Links()
	if l := links["eth1"]; !l.Present || !l.Up || l.MAC.String() != "02:00:00:00:00:01" || len(l.Prefixes) != 1 {
		t.Errorf("remembered eth1 = %+v", l)
	}
	if l, ok := links["eth2"]; !ok || l.Present {
		t.Errorf("remembered eth2 = %+v", l)
	}

	// Changes: down, unmonitored link ignored, removal.
	mon.Emit(platform.LinkEvent{Link: platform.Link{Name: "eth1", Index: 2, Up: false, Prefixes: []netip.Prefix{p24}}})
	if ls := next(t, bus); ls.Interface != "eth1" || ls.Up {
		t.Errorf("down event = %+v", ls)
	}
	mon.Emit(platform.LinkEvent{Link: platform.Link{Name: "docker0", Index: 7, Up: true}})
	mon.Emit(platform.LinkEvent{Link: platform.Link{Index: 2}, Removed: true})
	if ls := next(t, bus); ls.Interface != "eth1" || ls.Present {
		t.Errorf("removal = %+v", ls)
	}
	if l := m.Links()["eth1"]; l.Present {
		t.Errorf("removed eth1 remembered as present: %+v", l)
	}
	for _, s := range reg.List() {
		if s.State != platform.StateRunning {
			t.Errorf("registry %+v", s)
		}
	}
	cancel()
	<-done
}
