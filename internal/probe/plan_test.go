package probe

import (
	"math"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"lan-sentinel/internal/store"
)

func planInput() PlanInput {
	return PlanInput{
		Config: testConfig(),
		Links:  map[string]Link{"eth1": {Name: "eth1", Addrs: prefixes("192.168.110.10/24")}},
		Known: map[string][]netip.Addr{"eth1": {
			ip("192.168.110.20"), ip("192.168.110.21"), ip("192.168.110.22"), ip("192.168.110.1"), ip("192.168.110.10"),
		}},
	}
}

func TestComputePlan(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*PlanInput)
		req     Request
		allowed bool
		reasons []string // substrings, in order
		check   func(t *testing.T, p Plan)
	}{
		{"default is an arp sweep of every active interface", nil, Request{}, true, nil, func(t *testing.T, p Plan) {
			if !p.Probes.ARP || p.Probes.ICMP || len(p.Probes.TCP)+len(p.Probes.UDP) > 0 {
				t.Errorf("probes = %+v", p.Probes)
			}
			if len(p.Interfaces) != 1 || p.Interfaces[0].Interface != "eth1" {
				t.Fatalf("interfaces = %+v", p.Interfaces)
			}
			ip := p.Interfaces[0]
			// 254 minus .1, .240/28 and the own .10.
			if ip.SweepTargets != 254-1-15-1 || ip.KnownTargets != 0 {
				t.Errorf("targets = %d sweep, %d known", ip.SweepTargets, ip.KnownTargets)
			}
			if !slices.Equal(ip.Excluded, []string{"192.168.110.1", "192.168.110.240/28"}) {
				t.Errorf("excluded = %v", ip.Excluded)
			}
			e := p.Estimate
			if e.ARPRequests != 237 || e.Packets != 237 {
				t.Errorf("estimate = %+v", e)
			}
			// 236 gaps at 10 pps (paced 2% below) plus the last reply wait.
			want := 236*0.1*paceMargin + 1
			if math.Abs(e.TypicalSeconds-want) > 0.01 || e.NoResponseSeconds != e.TypicalSeconds {
				t.Errorf("estimate %.3f s typical, %.3f s no-response, want %.3f", e.TypicalSeconds, e.NoResponseSeconds, want)
			}
			if len(p.Assumptions) != 3 || !strings.Contains(p.Assumptions[1], "the sweep waits its 1s reply timeout once") ||
				!strings.Contains(p.Assumptions[2], "(ARP 1s)") || !strings.Contains(p.Assumptions[0], "at least 1s apart per target") {
				t.Errorf("assumptions = %q", p.Assumptions)
			}
		}},
		{"profile with explicit probes", nil, Request{Profile: "modbus", TCP: []int{80, 502}, UDP: []string{"ntp"}, ICMP: true}, true, nil,
			func(t *testing.T, p Plan) {
				if !p.Probes.ARP || !p.Probes.ICMP || !slices.Equal(p.Probes.TCP, []int{80, 502}) || !slices.Equal(p.Probes.UDP, []string{"ntp"}) {
					t.Errorf("probes = %+v", p.Probes)
				}
				ip := p.Interfaces[0]
				if ip.KnownTargets != 3 {
					t.Errorf("known targets = %d, want 3 (excluded and own left out)", ip.KnownTargets)
				}
				if len(ip.TCP) != 2 || ip.TCP[0].Timeout.D() != DefaultTCPTimeout || ip.TCP[1].Name != "modbus" || ip.TCP[1].Timeout.D() != 750*time.Millisecond {
					t.Errorf("tcp targets = %+v", ip.TCP)
				}
				e := p.Estimate
				if e.ICMPEchoes != 3 || e.TCPConnects != 6 || e.UDPProbes != 3 || e.Packets != 237+3+18+3 {
					t.Errorf("estimate = %+v", e)
				}
			}},
		{"narrower network", nil, Request{Networks: prefixes("192.168.110.0/28")}, true, nil, func(t *testing.T, p Plan) {
			if got := p.Interfaces[0].SweepTargets; got != 14-1-1 {
				t.Errorf("sweep targets = %d", got)
			}
		}},
		{"only known-host probes and no known hosts", func(in *PlanInput) { in.Known = nil }, Request{ICMP: true}, false,
			[]string{"eth1: no targets left"}, nil},
		{"kill switch", func(in *PlanInput) { in.Active = store.ActiveState{Disabled: true, Reason: "PLC fault"} }, Request{}, false,
			[]string{"kill switch (PLC fault)"}, nil},
		{"kill switch without reason", func(in *PlanInput) { in.Active = store.ActiveState{Disabled: true} }, Request{}, false,
			[]string{"disabled by the kill switch"}, nil},
		{"unknown profile and probe", nil, Request{Profile: "nope", UDP: []string{"snmp"}, TCP: []int{0}}, false,
			[]string{`unknown profile "nope"`, "TCP port 0", `unknown UDP probe "snmp"`}, nil},
		{"interface not configured", nil, Request{Interfaces: []string{"eth7"}}, false, []string{"eth7: interface is not configured"}, nil},
		{"active disabled on interface", nil, Request{Interfaces: []string{"eth0"}}, false,
			[]string{"eth0: active discovery is disabled on the interface"}, nil},
		{"no active interface", func(in *PlanInput) { in.Config.Interfaces = in.Config.Interfaces[1:] }, Request{}, false,
			[]string{"no interface has active discovery enabled"}, nil},
		{"network outside", nil, Request{Networks: prefixes("10.0.0.0/24")}, false,
			[]string{"10.0.0.0/24 is outside the configured networks of eth1", "eth1: none of the requested networks"}, nil},
		{"ipv6 network", nil, Request{Networks: prefixes("fd00::/120")}, false, []string{"IPv4 networks only"}, nil},
		{"wider than the prefix guard", nil, Request{Networks: prefixes("192.168.0.0/16")}, false,
			[]string{"wider than max_auto_scan_prefix_v4 /24", "outside the configured networks"}, nil},
		{"wide scans allowed", func(in *PlanInput) {
			in.Config.Active.AllowWideScan = true
			in.Config.Interfaces[0].Active.Networks = prefixes("10.10.0.0/16")
		}, Request{Networks: prefixes("10.10.0.0/23")}, true, nil, nil},
		{"several interfaces named", nil, Request{Interfaces: []string{"eth1", "eth0"}, Networks: prefixes("10.0.0.0/24")}, false,
			[]string{"outside the configured networks of [eth1 eth0]"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := planInput()
			if tt.mutate != nil {
				tt.mutate(&in)
			}
			p := Compute(in, tt.req)
			if p.Allowed != tt.allowed {
				t.Fatalf("allowed = %v, reasons %q", p.Allowed, p.Reasons)
			}
			joined := strings.Join(p.Reasons, "\n")
			pos := 0
			for _, r := range tt.reasons {
				i := strings.Index(joined[pos:], r)
				if i < 0 {
					t.Fatalf("reasons %q lack %q (in order)", p.Reasons, r)
				}
				pos += i
			}
			if tt.check != nil {
				tt.check(t, p)
			}
			if p.Rates.GlobalPPS != 20 || p.Rates.Protocols[ARP] != 10 || p.Rates.TargetSpacingMS != 1000 {
				t.Errorf("rates = %+v", p.Rates)
			}
		})
	}
}

func TestEstimateTCPSpacing(t *testing.T) {
	// Two ports on one known host: the second connect waits for the
	// one-second target spacing; if nothing answers, each port also waits
	// for its timeout.
	in := planInput()
	in.Known = map[string][]netip.Addr{"eth1": {ip("192.168.110.20")}}
	p := Compute(in, Request{TCP: []int{502, 503}})
	if !p.Allowed {
		t.Fatal(p.Reasons)
	}
	if want := 1.0; math.Abs(p.Estimate.TypicalSeconds-want) > 0.01 {
		t.Errorf("typical %.3f s, want %.3f", p.Estimate.TypicalSeconds, want)
	}
	if want := 1.0 + 0.75 + DefaultTCPTimeout.Seconds(); math.Abs(p.Estimate.NoResponseSeconds-want) > 0.01 {
		t.Errorf("no-response %.3f s, want %.3f", p.Estimate.NoResponseSeconds, want)
	}
	as := strings.Join(p.Assumptions, "\n")
	if !strings.Contains(as, "typical: known hosts answer at once") || !strings.Contains(as, "tcp/502 750ms, tcp/503 1s") {
		t.Errorf("assumptions = %q", p.Assumptions)
	}
}

func TestWideSweeps(t *testing.T) {
	wide := func(maxTargets int) PlanInput {
		in := planInput()
		in.Config.Active.AllowWideScan = true
		in.Config.Active.MaxSweepTargets = maxTargets
		in.Config.Interfaces[0].Active.Networks = prefixes("10.0.0.0/14")
		in.Config.Interfaces[0].Active.Exclude = nil
		return in
	}
	// Beyond the default 65,536 the plan is a preview until acknowledged.
	p := Compute(wide(1<<20), Request{})
	if p.Allowed || !strings.Contains(strings.Join(p.Reasons, ";"), "more than 65536: review this plan, then repeat with --allow-wide") {
		t.Errorf("unacknowledged wide sweep: %v", p.Reasons)
	}
	if got := p.Interfaces[0].SweepTargets; got != 1<<18-2 {
		t.Errorf("sweep targets = %d", got)
	}
	p = Compute(wide(1<<20), Request{AllowWide: true, ICMP: true, ARP: true})
	if !p.Allowed {
		t.Fatalf("acknowledged wide sweep refused: %v", p.Reasons)
	}
	// The long sweep is extrapolated from its simulated start: about
	// 262,142 requests at 10 pps paced 2% below.
	want := float64(1<<18-3)*0.1*paceMargin + 1
	if got := p.Estimate.TypicalSeconds; math.Abs(got-want) > want*0.01 {
		t.Errorf("typical %.0f s, want about %.0f", got, want)
	}
	if !strings.Contains(strings.Join(p.Assumptions, ";"), "hosts that first answer the sweep are probed too") {
		t.Errorf("assumptions = %q", p.Assumptions)
	}
	// Never beyond max_sweep_targets, acknowledged or not.
	p = Compute(wide(1<<17), Request{AllowWide: true})
	if p.Allowed || !strings.Contains(strings.Join(p.Reasons, ";"), "more than active.max_sweep_targets (131072)") {
		t.Errorf("sweep over the limit: %v", p.Reasons)
	}
}
