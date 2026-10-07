package correlate

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"lan-sentinel/internal/events"
	"lan-sentinel/internal/observation"
)

// proxyARPConfidence is the confidence of a proxy_arp identification: the
// behaviour is observed directly, but a host answering for a few others'
// addresses could also be misconfigured.
const proxyARPConfidence = 0.8

// isARPReply reports ARP answers: passive ARP replies and ARP scan results.
// Requests and gratuitous ARP announce the sender's own address and never
// count as proxy behaviour (they still raise duplicate-IP conflicts).
func isARPReply(o observation.Observation) bool {
	return o.Source == observation.PassiveARP && o.Meta["arp"] == "reply" || o.Source == observation.ARPScan
}

// proxyClaim applies proxy-ARP detection (docs/DATA_MODEL.md §5.2) to an
// ARP reply from h for ip and reports whether the reply must not touch
// bindings. A MAC is flagged proxy_arp once its replies within
// identity.address_expiry claim two or more addresses held by other live
// hosts, or more than identity.proxy_arp_threshold addresses; a single
// overlap stays an ordinary duplicate-IP conflict. A late reply is counted
// but never sets the flag, so the bindings it closes always started before
// it. A flagged host's replies only refresh addresses it holds on other
// evidence.
func (c *Correlator) proxyClaim(ctx context.Context, h *host, ip netip.Addr, o observation.Observation, obsID int64, ev events.Evidence, late bool) bool {
	if h.proxyARP {
		b := h.bindings[ip]
		return b == nil || b.arpOnly
	}
	id := c.cfg.Load().Identity
	since := o.Time.Add(-id.AddressExpiry.D())
	expireClaims(h.arpClaims, since)
	expireClaims(h.arpOverlaps, since)
	if _, ok := h.arpClaims[ip]; ok || len(h.arpClaims) <= id.ProxyARPThreshold {
		h.arpClaims[ip] = later(h.arpClaims[ip], o.Time)
	}
	for _, g := range c.st.holders[ipKey{h.ctx.id, ip}] {
		if g.host != h && c.presenceAt(g.host.lastSeen, o.Time).live() {
			h.arpOverlaps[ip] = later(h.arpOverlaps[ip], o.Time)
		}
	}
	if late || len(h.arpOverlaps) < 2 && len(h.arpClaims) <= id.ProxyARPThreshold {
		return false
	}
	c.flagProxyARP(ctx, h, o, obsID, ev)
	return true
}

// expireClaims forgets claims made before since.
func expireClaims(claims map[netip.Addr]time.Time, since time.Time) {
	for ip, t := range claims {
		if t.Before(since) {
			delete(claims, ip)
		}
	}
}

func later(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// flagProxyARP records the identification and closes the bindings that
// only proxy answers supported: they were never the host's own addresses.
func (c *Correlator) flagProxyARP(ctx context.Context, h *host, o observation.Observation, obsID int64, ev events.Evidence) {
	h.proxyARP = true
	overlaps := make([]string, 0, len(h.arpOverlaps))
	for ip := range h.arpOverlaps {
		overlaps = append(overlaps, ip.String())
	}
	slices.Sort(overlaps)
	reason := fmt.Sprintf("answered ARP for %d addresses, %d of them held by other live hosts", len(h.arpClaims), len(overlaps))
	h.arpClaims, h.arpOverlaps = nil, nil
	c.dbIdentification(ctx, h, "proxy_arp", "true", proxyARPConfidence, string(o.Source),
		map[string]any{"reason": reason, "contested": overlaps}, o.Time)
	c.dbCurrent(ctx, h, "proxy_arp", string(o.Source), "true")

	cause := string(o.Source)
	ev.Reason = reason
	e := hostEvent(events.VendorIdentified, o.Time, h, cause, ev)
	e.New, e.ObservationID = "proxy_arp=true", obsID
	c.emit(ctx, e)

	ev.Reason = "proxy ARP answer, not the host's own address"
	for _, b := range sortedBindings(h) {
		if !b.arpOnly {
			continue
		}
		c.close(b, o.Time)
		e := hostEvent(events.IPRemoved, o.Time, h, cause, ev)
		e.Old, e.ObservationID = b.ip.String(), obsID
		c.emit(ctx, e)
		c.resolve(ctx, ipKey{h.ctx.id, b.ip}, o.Time, cause, obsID, ev, h)
	}
}

func (c *Correlator) dbIdentification(ctx context.Context, h *host, field, value string, confidence float64, source string, evidence map[string]any, t time.Time) {
	b, _ := json.Marshal(evidence)
	c.exec(ctx, "identification", `INSERT INTO identifications (host_id, field, value, confidence, source, evidence_json, first_seen, last_seen)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (host_id, field, value, source) DO UPDATE SET last_seen = max(last_seen, excluded.last_seen),
			evidence_json = excluded.evidence_json, confidence = max(confidence, excluded.confidence)`,
		h.id, field, value, confidence, source, string(b), ms(t), ms(t))
}

// dbCurrent marks value as the current identification of h's field from
// source (§5.7).
func (c *Correlator) dbCurrent(ctx context.Context, h *host, field, source, value string) {
	c.exec(ctx, "current identification", `UPDATE identifications SET current = (value = ?) WHERE host_id = ? AND field = ? AND source = ?`,
		value, h.id, field, source)
}
