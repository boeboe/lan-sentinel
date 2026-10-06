// Package probetest has helpers for testing probe engines against the
// platform fakes: a pass with an unpaced budget and an observation sink.
package probetest

import (
	"net"
	"net/netip"
	"sync"
	"time"

	"lan-sentinel/internal/clock"
	"lan-sentinel/internal/observation"
	"lan-sentinel/internal/probe"
)

// OwnMAC is the MAC of the probing interface.
var OwnMAC = net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}

// Sink collects emitted observations.
type Sink struct {
	mu  sync.Mutex
	obs []observation.Observation
}

// Emit records o.
func (s *Sink) Emit(o observation.Observation) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.obs = append(s.obs, o)
}

// All returns what was emitted.
func (s *Sink) All() []observation.Observation {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]observation.Observation(nil), s.obs...)
}

// Pass returns a pass on eth1 (192.168.110.10/24) over targets with a
// budget that does not pace, so tests run fast, and the given policy.
func Pass(targets []netip.Addr, policy probe.Policy, sink *Sink) probe.Pass {
	return probe.Pass{
		Link:    probe.Link{Name: "eth1", MAC: OwnMAC, Addrs: []netip.Prefix{netip.MustParsePrefix("192.168.110.10/24")}},
		Targets: targets, Budget: probe.NewBudget(clock.Real(), probe.Limits{MaxConcurrent: 10, TCPPerInterface: 4, TCPPerHost: 1}, policy),
		Emit: sink.Emit, ReplyTimeout: 50 * time.Millisecond,
	}
}

// Addrs parses addresses.
func Addrs(ss ...string) []netip.Addr {
	out := make([]netip.Addr, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParseAddr(s)
	}
	return out
}

// PolicyFunc adapts a function to probe.Policy.
type PolicyFunc func(iface string, p probe.Protocol, target netip.Addr) error

// Check implements probe.Policy.
func (f PolicyFunc) Check(iface string, p probe.Protocol, target netip.Addr) error {
	return f(iface, p, target)
}

// Block refuses the given targets and, once Stop is closed, every probe
// with probe.ErrDisabled, as the kill switch would.
func Block(stop <-chan struct{}, blocked ...netip.Addr) PolicyFunc {
	return func(_ string, _ probe.Protocol, target netip.Addr) error {
		select {
		case <-stop:
			return probe.ErrDisabled
		default:
		}
		for _, b := range blocked {
			if b == target {
				return probe.ErrRefused
			}
		}
		return nil
	}
}
