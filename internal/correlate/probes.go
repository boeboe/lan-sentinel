package correlate

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"lan-sentinel/internal/config"
	"lan-sentinel/internal/events"
	"lan-sentinel/internal/observation"
)

// probeConfidence is the confidence of what a device says about itself in
// a protocol-specific probe reply (EtherNet/IP ListIdentity).
const probeConfidence = 0.9

// causeOperator is the cause of kill-switch and scan events.
const causeOperator = "operator"

// probeSources lists the UDP probe names as an SQL list, for loading the
// identifications the probes made.
var probeSources = func() string {
	q := make([]string, len(config.UDPProbeNames))
	for i, n := range config.UDPProbeNames {
		q[i] = "'" + n + "'"
	}
	return strings.Join(q, ", ")
}()

func identKey(field, source string) string { return field + "\x00" + source }

// probeDetails records what a protocol-specific probe learnt (§5.5): the
// service details in services.detail_json and the device's identity
// claims as identifications with the probe as source. A changed or new
// claim emits VENDOR_IDENTIFIED; a device type also sets
// hosts.device_type.
func (c *Correlator) probeDetails(ctx context.Context, h *host, o observation.Observation, obsID int64, ev events.Evidence) {
	src := o.Meta[observation.MetaProbe]
	details := map[string]string{}
	identity := map[string]string{}
	for k, v := range o.Meta {
		if f, ok := strings.CutPrefix(k, observation.MetaIdentityPrefix); ok {
			if f != "" && v != "" {
				identity[f] = v
			}
			continue
		}
		details[k] = v
	}
	b, _ := json.Marshal(details)
	c.exec(ctx, "service detail", `UPDATE services SET detail_json = ? WHERE host_id = ? AND proto = ? AND port = ?`,
		string(b), h.id, o.Service.Proto, o.Service.Port)

	fields := make([]string, 0, len(identity))
	for f := range identity {
		fields = append(fields, f)
	}
	sort.Strings(fields)
	evidence := make(map[string]any, len(details))
	for k, v := range details {
		evidence[k] = v
	}
	for _, f := range fields {
		v := identity[f]
		c.dbIdentification(ctx, h, f, v, probeConfidence, src, evidence, o.Time)
		key := identKey(f, src)
		old, known := h.idents[key]
		if known && old == v {
			continue
		}
		h.idents[key] = v
		if f == "device_type" {
			c.exec(ctx, "device type", `UPDATE hosts SET device_type = ? WHERE host_id = ?`, v, h.id)
		}
		e := hostEvent(events.VendorIdentified, o.Time, h, string(o.Source), ev)
		e.New, e.ObservationID = f+"="+v, obsID
		if known {
			e.Old = f + "=" + old
		}
		c.emit(ctx, e)
	}
}

// operator records an operator action (§7, §8): the kill switch in
// runtime_state, operator scans in scans, and their events.
func (c *Correlator) operator(ctx context.Context, op observation.Operator) {
	c.advance(ctx, op.Time)
	ev := events.Evidence{TS: op.Time.UTC(), Actor: op.Actor, Reason: op.Reason}
	switch op.Kind {
	case observation.OpActiveDisabled:
		if op.Persist {
			v, _ := json.Marshal(map[string]any{"disabled": true, "reason": op.Reason, "by": op.Actor, "at": op.Time.UTC()})
			c.exec(ctx, "kill switch", `INSERT INTO runtime_state (key, value, updated_at) VALUES ('active_disabled', ?, ?)
				ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`, string(v), ms(op.Time))
		}
		c.emit(ctx, events.Event{TS: op.Time, Type: events.ActiveDisabled, New: switchText("disabled", op), Cause: causeOperator, Evidence: ev})
	case observation.OpActiveEnabled:
		if op.Persist {
			c.exec(ctx, "kill switch", `DELETE FROM runtime_state WHERE key = 'active_disabled'`)
		}
		c.emit(ctx, events.Event{TS: op.Time, Type: events.ActiveEnabled, New: switchText("enabled", op), Cause: causeOperator, Evidence: ev})
	case observation.OpScanStarted, observation.OpScanCompleted:
		c.scan(ctx, op, ev)
	}
}

func switchText(what string, op observation.Operator) string {
	s := "active discovery " + what
	if op.Actor != "" {
		s += " by " + op.Actor
	}
	if op.Reason != "" {
		s += ": " + op.Reason
	}
	return s
}

func (c *Correlator) scan(ctx context.Context, op observation.Operator, ev events.Evidence) {
	sc := op.Scan
	if sc == nil {
		return
	}
	n := c.st.contexts[sc.Interface]
	if n == nil {
		return
	}
	if sc.Handle == nil {
		return
	}
	ev.Interface = n.iface
	e := events.Event{TS: op.Time, ContextID: n.id, Interface: n.iface, New: sc.Summary, Cause: causeOperator, Evidence: ev}
	if op.Kind == observation.OpScanStarted {
		c.st.nextScanID++
		sc.Handle.ID = c.st.nextScanID
		c.exec(ctx, "insert scan", `INSERT INTO scans (id, context_id, kind, trigger, started_at, targets) VALUES (?, ?, ?, 'operator', ?, ?)`,
			sc.Handle.ID, n.id, sc.Kind, ms(op.Time), sc.Targets)
		e.Type = events.ScanStarted
	} else {
		if sc.Handle.ID == 0 {
			return // its start was never recorded
		}
		results, err := json.Marshal(sc.Results)
		if err != nil {
			results = []byte(fmt.Sprintf(`{"error": %q}`, err.Error()))
		}
		c.exec(ctx, "finish scan", `UPDATE scans SET finished_at = ?, results_json = ? WHERE id = ?`, ms(op.Time), string(results), sc.Handle.ID)
		e.Type = events.ScanCompleted
	}
	c.emit(ctx, e)
}

// abortedScan is the result of a scan the daemon stopped in the middle of.
const abortedScan = "the daemon stopped during the scan"

// closeOpenScans finishes the scans a previous run left open (a crash or
// power loss mid-scan): finished at their start, aborted, with
// SCAN_COMPLETED so every start in the history has an end.
func (c *Correlator) closeOpenScans(ctx context.Context, now time.Time) {
	for _, sc := range c.st.openScans {
		n := c.st.contextsByID[sc.ctx]
		results, _ := json.Marshal(map[string]any{"aborted": abortedScan})
		c.exec(ctx, "close scan", `UPDATE scans SET finished_at = started_at, results_json = ? WHERE id = ?`, string(results), sc.id)
		if n == nil {
			continue
		}
		c.emit(ctx, events.Event{TS: now, Type: events.ScanCompleted, ContextID: n.id, Interface: n.iface,
			New: "operator scan " + sc.kind + " aborted: " + abortedScan, Cause: causeOperator,
			Evidence: events.Evidence{TS: now, Interface: n.iface, Reason: abortedScan}})
	}
	c.st.openScans = nil
}
