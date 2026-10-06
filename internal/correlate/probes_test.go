package correlate

import (
	"database/sql"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"lan-sentinel/internal/observation"
)

const plc = "00:1b:1b:aa:bb:01"

// probeObs feeds a MAC-less probe result.
func (h *harness) probeObs(d time.Duration, o observation.Observation) {
	h.t.Helper()
	o.Time, o.Interface = h.at(d), "eth1"
	h.sim.Set(o.Time)
	h.c.Handle(h.ctx, observation.Message{Observation: o})
}

func (h *harness) hostSeen(id string) (string, time.Duration) {
	h.t.Helper()
	out := h.query(`SELECT presence, last_seen FROM hosts WHERE host_id = '`+id+`'`, func(r *sql.Rows) string {
		var p string
		var last int64
		if err := r.Scan(&p, &last); err != nil {
			h.t.Fatal(err)
		}
		return fmt.Sprintf("%s %d", p, last)
	})
	var p string
	var last int64
	fmt.Sscanf(out[0], "%s %d", &p, &last)
	return p, time.UnixMilli(last).UTC().Sub(t0)
}

func TestProbeResultsProvePresenceOnlyWhenAnswered(t *testing.T) {
	ip := netip.MustParseAddr("10.1.0.50")
	tcp := func(st observation.ServiceState) observation.Observation {
		return observation.Observation{Source: observation.TCPConnect, IP: ip, Service: &observation.ServiceResult{Proto: "tcp", Port: 502, State: st}}
	}
	tests := []struct {
		name     string
		o        observation.Observation
		presence bool
	}{
		{"tcp open", tcp(observation.ServiceOpen), true},
		{"tcp refused", tcp(observation.ServiceRefused), true},
		{"tcp timeout", tcp(observation.ServiceTimeout), false},
		{"tcp unreachable", tcp(observation.ServiceUnreachable), false},
		{"icmp reply", observation.Observation{Source: observation.ICMPScan, IP: ip}, true},
		{"udp reply", observation.Observation{Source: observation.UDPProbe, IP: ip,
			Service: &observation.ServiceResult{Proto: "udp", Port: 123, State: observation.ServiceOpen}, Meta: map[string]string{"probe": "ntp"}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			h.obs(0, observation.PassiveARP, "eth1", plc, "10.1.0.50")
			h.probeObs(3*time.Hour, tt.o)
			presence, last := h.hostSeen("host-01")
			if tt.presence != (last == 3*time.Hour) {
				t.Errorf("last_seen %v, presence %s", last, presence)
			}
			binding := h.query(`SELECT last_seen FROM addresses`, func(r *sql.Rows) string {
				var v int64
				_ = r.Scan(&v)
				return time.UnixMilli(v).UTC().Sub(t0).String()
			})
			if tt.presence != (binding[0] == "3h0m0s") {
				t.Errorf("binding last_seen %s", binding[0])
			}
			if tt.o.Service != nil {
				svc := h.query(`SELECT state FROM services`, func(r *sql.Rows) string {
					var s string
					_ = r.Scan(&s)
					return s
				})
				if len(svc) != 1 || svc[0] != string(tt.o.Service.State) {
					t.Errorf("services = %v: the result is recorded either way", svc)
				}
			}
		})
	}
}

func TestTimeoutDoesNotBringBackAMissingHost(t *testing.T) {
	h := newHarness(t)
	h.obs(0, observation.PassiveARP, "eth1", plc, "10.1.0.50")
	h.probeObs(2*time.Hour, observation.Observation{Source: observation.TCPConnect, IP: netip.MustParseAddr("10.1.0.50"),
		Service: &observation.ServiceResult{Proto: "tcp", Port: 502, State: observation.ServiceOpen}})
	// Missing after 24 h; a timeout one hour later is no evidence.
	h.probeObs(27*time.Hour, observation.Observation{Source: observation.TCPConnect, IP: netip.MustParseAddr("10.1.0.50"),
		Service: &observation.ServiceResult{Proto: "tcp", Port: 502, State: observation.ServiceTimeout}})
	ev := strings.Join(hostEvents(h.events()), "\n")
	if strings.Contains(ev, "HOST_REAPPEARED") || !strings.Contains(ev, "HOST_DISAPPEARED") || !strings.Contains(ev, "SERVICE_CLOSED host-01 tcp/502>TIMEOUT") {
		t.Errorf("events:\n%s", ev)
	}
}

func enipObs(name, devType string) observation.Observation {
	meta := map[string]string{
		observation.MetaProbe: "enip", "vendor_id": "1", "product_name": name,
		observation.MetaIdentityPrefix + "product": name, observation.MetaIdentityPrefix + "device_type": devType,
		observation.MetaIdentityPrefix + "empty": "",
	}
	return observation.Observation{Source: observation.UDPProbe, IP: netip.MustParseAddr("10.1.0.50"),
		Service: &observation.ServiceResult{Proto: "udp", Port: 44818, State: observation.ServiceOpen}, Meta: meta}
}

func TestProbeDetailsAndIdentity(t *testing.T) {
	h := newHarness(t)
	h.obs(0, observation.PassiveARP, "eth1", plc, "10.1.0.50")
	h.probeObs(time.Hour, enipObs("1756-L71", "Programmable Logic Controller"))
	h.probeObs(2*time.Hour, enipObs("1756-L71", "Programmable Logic Controller")) // same claims: no event
	h.probeObs(3*time.Hour, enipObs("1756-L83E", "Programmable Logic Controller"))
	h.probeObs(4*time.Hour, observation.Observation{Source: observation.UDPProbe, IP: netip.MustParseAddr("10.1.0.50"),
		Service: &observation.ServiceResult{Proto: "udp", Port: 123, State: observation.ServiceOpen},
		Meta:    map[string]string{observation.MetaProbe: "ntp", "stratum": "2"}})

	var vendor []string
	for _, e := range h.events() {
		if strings.Contains(e, "VENDOR_IDENTIFIED") {
			vendor = append(vendor, e)
		}
	}
	expect(t, "identification events", vendor, []string{
		"1h0m0s VENDOR_IDENTIFIED host-01 >device_type=Programmable Logic Controller",
		"1h0m0s VENDOR_IDENTIFIED host-01 >product=1756-L71",
		"3h0m0s VENDOR_IDENTIFIED host-01 product=1756-L71>product=1756-L83E",
	})
	details := h.query(`SELECT proto || '/' || port || ' ' || detail_json FROM services ORDER BY port`, func(r *sql.Rows) string {
		var s string
		_ = r.Scan(&s)
		return s
	})
	expect(t, "service details", details, []string{
		`udp/123 {"probe":"ntp","stratum":"2"}`,
		`udp/44818 {"probe":"enip","product_name":"1756-L83E","vendor_id":"1"}`,
	})
	ids := h.query(`SELECT field || '=' || value || ' ' || source || ' ' || confidence FROM identifications WHERE source = 'enip' ORDER BY id`,
		func(r *sql.Rows) string {
			var s string
			_ = r.Scan(&s)
			return s
		})
	expect(t, "identifications", ids, []string{
		"device_type=Programmable Logic Controller enip 0.9",
		"product=1756-L71 enip 0.9",
		"product=1756-L83E enip 0.9",
	})
	dt := h.query(`SELECT coalesce(device_type, '') FROM hosts`, func(r *sql.Rows) string {
		var s string
		_ = r.Scan(&s)
		return s
	})
	if dt[0] != "Programmable Logic Controller" {
		t.Errorf("hosts.device_type = %q", dt[0])
	}

	// After a restart the known claims are loaded: a repeat emits nothing.
	h.restart()
	h.link("eth1", true, "10.1.0.0/24")
	h.probeObs(5*time.Hour, enipObs("1756-L83E", "Programmable Logic Controller"))
	n := 0
	for _, e := range h.events() {
		if strings.Contains(e, "VENDOR_IDENTIFIED") {
			n++
		}
	}
	if n != 3 {
		t.Errorf("%d identification events after restart, want 3", n)
	}
}

func TestOperatorActions(t *testing.T) {
	h := newHarness(t)
	op := func(d time.Duration, o observation.Operator) {
		o.Time = h.at(d)
		h.sim.Set(o.Time)
		h.c.Handle(h.ctx, observation.Message{Operator: &o})
	}
	state := func() []string {
		return h.query(`SELECT value FROM runtime_state WHERE key = 'active_disabled'`, func(r *sql.Rows) string {
			var s string
			_ = r.Scan(&s)
			return s
		})
	}
	op(time.Minute, observation.Operator{Kind: observation.OpActiveDisabled, Actor: "env", Reason: "LAN_SENTINEL_ACTIVE_DISABLED=1"})
	if len(state()) != 0 {
		t.Error("the environment switch was persisted")
	}
	op(2*time.Minute, observation.Operator{Kind: observation.OpActiveDisabled, Actor: "bart", Reason: "PLC fault", Persist: true})
	if s := state(); len(s) != 1 || !strings.Contains(s[0], `"by":"bart"`) || !strings.Contains(s[0], `"reason":"PLC fault"`) || !strings.Contains(s[0], `"disabled":true`) {
		t.Errorf("runtime_state = %v", s)
	}
	op(3*time.Minute, observation.Operator{Kind: observation.OpActiveEnabled, Actor: "bart", Persist: true})
	if len(state()) != 0 {
		t.Errorf("runtime_state after enable = %v", state())
	}

	handle := &observation.ScanHandle{}
	sc := observation.Scan{Handle: handle, Interface: "eth1", Kind: "arp,tcp/502", Targets: 253, Summary: "operator scan arp,tcp/502: 253 addresses to sweep, 3 known hosts"}
	started := sc
	op(4*time.Minute, observation.Operator{Kind: observation.OpScanStarted, Actor: "bart", Scan: &started})
	if handle.ID != 1 {
		t.Errorf("scan id = %d", handle.ID)
	}
	done := sc
	done.Summary, done.Results = "operator scan done in 31s; arp 3 reply", map[string]any{"responders": 3}
	op(5*time.Minute, observation.Operator{Kind: observation.OpScanCompleted, Actor: "bart", Scan: &done})
	op(6*time.Minute, observation.Operator{Kind: observation.OpScanStarted, Scan: &observation.Scan{Handle: &observation.ScanHandle{}, Interface: "eth9"}})   // unknown interface: ignored
	op(6*time.Minute, observation.Operator{Kind: observation.OpScanStarted})                                                                                  // no scan: ignored
	op(6*time.Minute, observation.Operator{Kind: observation.OpScanStarted, Scan: &observation.Scan{Interface: "eth1"}})                                      // no handle: ignored
	op(6*time.Minute, observation.Operator{Kind: observation.OpScanCompleted, Scan: &observation.Scan{Handle: &observation.ScanHandle{}, Interface: "eth1"}}) // never started: ignored
	op(6*time.Minute, observation.Operator{Kind: observation.OpScanCompleted, Scan: &observation.Scan{Handle: handle, Interface: "eth1",
		Results: map[string]any{"bad": make(chan int)}}}) // unencodable results are recorded as an error

	var ops []string
	for _, e := range h.events() {
		if strings.Contains(e, "ACTIVE_") || strings.Contains(e, "SCAN_") {
			ops = append(ops, e)
		}
	}
	expect(t, "operator events", ops, []string{
		"1m0s ACTIVE_DISABLED - >active discovery disabled by env: LAN_SENTINEL_ACTIVE_DISABLED=1",
		"2m0s ACTIVE_DISABLED - >active discovery disabled by bart: PLC fault",
		"3m0s ACTIVE_ENABLED - >active discovery enabled by bart",
		"4m0s SCAN_STARTED - >operator scan arp,tcp/502: 253 addresses to sweep, 3 known hosts",
		"5m0s SCAN_COMPLETED - >operator scan done in 31s; arp 3 reply",
		"6m0s SCAN_COMPLETED - >",
	})
	scans := h.query(`SELECT id || ' ' || kind || ' ' || trigger || ' ' || targets || ' ' || results_json || ' ' || (finished_at IS NOT NULL) FROM scans`,
		func(r *sql.Rows) string {
			var s string
			_ = r.Scan(&s)
			return s
		})
	if len(scans) != 1 || !strings.HasPrefix(scans[0], "1 arp,tcp/502 operator 253 {\"error\"") || !strings.HasSuffix(scans[0], " 1") {
		t.Errorf("scans = %v", scans)
	}
	ev := h.query(`SELECT coalesce(c.interface, '-') || ' ' || e.cause || ' ' || e.evidence_json FROM events e LEFT JOIN network_contexts c ON c.id = e.context_id
		WHERE e.type IN ('SCAN_STARTED', 'ACTIVE_DISABLED') ORDER BY e.id`, func(r *sql.Rows) string {
		var s string
		_ = r.Scan(&s)
		return s
	})
	if len(ev) != 3 || !strings.HasPrefix(ev[0], "- operator ") || !strings.Contains(ev[1], `"actor":"bart"`) ||
		!strings.Contains(ev[1], `"reason":"PLC fault"`) || !strings.HasPrefix(ev[2], "eth1 operator") {
		t.Errorf("event provenance = %v", ev)
	}

	// A scan the daemon stopped in the middle of is closed at the next
	// start, and the next scan id follows the database.
	open := &observation.ScanHandle{}
	op(7*time.Minute, observation.Operator{Kind: observation.OpScanStarted, Scan: &observation.Scan{Handle: open, Interface: "eth1", Kind: "icmp"}})
	h.restart()
	closed := h.query(`SELECT id || ' ' || (finished_at = started_at) || ' ' || results_json FROM scans WHERE id = 2`, func(r *sql.Rows) string {
		var s string
		_ = r.Scan(&s)
		return s
	})
	if len(closed) != 1 || closed[0] != `2 1 {"aborted":"the daemon stopped during the scan"}` {
		t.Errorf("left-open scan = %v", closed)
	}
	if last := h.events(); !strings.Contains(last[len(last)-1], "SCAN_COMPLETED - >operator scan icmp aborted: the daemon stopped during the scan") {
		t.Errorf("last event = %s", last[len(last)-1])
	}
	next := &observation.ScanHandle{}
	op(8*time.Minute, observation.Operator{Kind: observation.OpScanStarted, Scan: &observation.Scan{Handle: next, Interface: "eth1", Kind: "arp"}})
	if next.ID != 3 {
		t.Errorf("scan id after restart = %d", next.ID)
	}
}
