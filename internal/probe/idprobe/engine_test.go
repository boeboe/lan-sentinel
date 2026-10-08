package idprobe

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"lan-sentinel/internal/clock"
	"lan-sentinel/internal/config"
	"lan-sentinel/internal/observation"
	"lan-sentinel/internal/platform"
	"lan-sentinel/internal/probe"
)

type pipeTX struct {
	reply []byte
	dials int
	mu    sync.Mutex
}

func (t *pipeTX) Backend(string) string { return "test" }
func (t *pipeTX) Frames(context.Context, string, uint16) (platform.FrameConn, error) {
	return nil, io.ErrClosedPipe
}
func (t *pipeTX) DialUDP(context.Context, string, netip.AddrPort) (net.Conn, error) {
	return nil, io.ErrClosedPipe
}
func (t *pipeTX) ICMPConn(context.Context, string) (platform.EchoConn, error) {
	return nil, io.ErrClosedPipe
}

func (t *pipeTX) DialTCP(_ context.Context, _ string, _ netip.AddrPort, _ time.Duration) (net.Conn, error) {
	t.mu.Lock()
	t.dials++
	reply := t.reply
	t.mu.Unlock()
	c1, c2 := net.Pipe()
	go func() {
		defer c2.Close()
		buf := make([]byte, 64)
		if _, err := io.ReadFull(c2, buf[:11]); err != nil {
			return
		}
		_, _ = c2.Write(reply)
	}()
	return c1, nil
}

func TestEngineSuccessAndFailureLatch(t *testing.T) {
	reply := deviceIDReply(1, 1, false, 0, object(modbusObjVendor, "ACME"))
	tx := &pipeTX{reply: reply}
	e := &Engine{TX: tx}
	sim := clock.NewSim(time.Date(2026, 10, 8, 10, 0, 0, 0, time.UTC))
	var got []observation.Observation
	pass := probe.Pass{
		Link: probe.Link{Name: "eth1"},
		Identify: []probe.IdentifyJob{{
			HostID: "h1", IP: netip.MustParseAddr("192.168.110.50"), Probe: "modbus", UnitID: 1,
			Trigger: observation.TriggerScheduled,
		}},
		Budget: probe.NewBudget(sim, probe.Limits{MaxConcurrent: 4, Rates: map[probe.Protocol]float64{probe.TCP: 10}, GlobalPPS: 20}, nil),
		Emit:   func(o observation.Observation) { got = append(got, o) },
		Clock:  sim,
	}
	results, err := e.Run(context.Background(), pass)
	if err != nil || len(results) != 1 || results[0].State != observation.ResultOK {
		t.Fatalf("results = %+v err = %v", results, err)
	}
	if len(got) != 1 || got[0].Meta[observation.MetaResult] != observation.ResultOK ||
		got[0].Meta[observation.MetaIdentityPrefix+"vendor"] != "ACME" ||
		got[0].Service == nil || got[0].Service.State != observation.ServiceOpen {
		t.Errorf("obs = %+v", got)
	}
	if e.Attempts()[[2]string{"modbus", observation.ResultOK}] != 1 {
		t.Errorf("attempts = %v", e.Attempts())
	}
}

// The charge follows the write cap (ADR 0011): TCP setup and close plus
// one per write, a UDP probe one datagram per write. Raising a cap without
// the charge fails here. BudgetCostOf, which scan plan reads, is the same.
func TestBudgetCostFollowsLimits(t *testing.T) {
	for name, p := range Probes {
		want := p.Limits().MaxWrites
		if p.Protocol() == probe.TCP {
			want += probe.TCPTokens
		}
		if p.BudgetCost() != want {
			t.Errorf("%s BudgetCost = %d, want %d", name, p.BudgetCost(), want)
		}
		if got := BudgetCostOf(name); got != p.BudgetCost() {
			t.Errorf("BudgetCostOf(%s) = %d, want %d", name, got, p.BudgetCost())
		}
	}
	if got := BudgetCostOf("nope"); got != 0 {
		t.Errorf("BudgetCostOf(unknown) = %d, want 0", got)
	}
}

func TestProbesMatchNames(t *testing.T) {
	if len(Probes) != len(config.IdentifyProbeNames) {
		t.Errorf("Probes %d vs IdentifyProbeNames %d", len(Probes), len(config.IdentifyProbeNames))
	}
	for _, n := range config.IdentifyProbeNames {
		if _, ok := Probes[n]; !ok {
			t.Errorf("Probes missing %s", n)
		}
	}
}
