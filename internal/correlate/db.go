package correlate

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/netip"
	"time"

	"lan-sentinel/internal/observation"
)

// The correlator assigns row ids itself, so it can refer to rows it has
// queued but the writer has not committed yet. It is the only writer of
// these tables.

func (c *Correlator) exec(ctx context.Context, what, query string, args ...any) {
	err := c.store.Submit(ctx, func(ctx context.Context, tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, query, args...); err != nil {
			return fmt.Errorf("%s: %w", what, err)
		}
		return nil
	})
	if err != nil && ctx.Err() == nil {
		c.log.Error("correlator: queueing write failed", "what", what, "err", err)
	}
}

func (c *Correlator) dbInsertContext(ctx context.Context, n *netContext, t time.Time) {
	c.exec(ctx, "insert context", `INSERT INTO network_contexts (id, interface, first_seen, last_seen) VALUES (?, ?, ?, ?)`,
		n.id, n.iface, ms(t), ms(t))
}

func (c *Correlator) dbContextSeen(ctx context.Context, n *netContext) {
	c.exec(ctx, "update context", `UPDATE network_contexts SET last_seen = max(last_seen, ?) WHERE id = ?`, ms(n.lastSeen), n.id)
}

func (c *Correlator) dbOpenPrefix(ctx context.Context, n *netContext, id int64, p netip.Prefix, t time.Time) {
	c.exec(ctx, "open prefix", `INSERT INTO context_prefixes (id, context_id, prefix, first_seen, last_seen) VALUES (?, ?, ?, ?, ?)`,
		id, n.id, p.String(), ms(t), ms(t))
}

func (c *Correlator) dbClosePrefix(ctx context.Context, id int64, t time.Time) {
	c.exec(ctx, "close prefix", `UPDATE context_prefixes SET last_seen = max(last_seen, ?), ended_at = max(first_seen, ?) WHERE id = ?`,
		ms(t), ms(t), id)
}

func (c *Correlator) dbInsertHost(ctx context.Context, h *host, la bool) {
	c.exec(ctx, "insert host", `INSERT INTO hosts
		(host_id, context_id, mac, vendor, locally_administered, presence, manufacturer, first_seen, last_seen)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		h.id, h.ctx.id, h.mac.String(), nullString(h.vendor), boolInt(la), string(h.presence), nullString(h.vendor),
		ms(h.firstSeen), ms(h.lastSeen))
	if h.vendor != "" {
		evidence, _ := json.Marshal(map[string]string{"mac": h.mac.String(), "registry": "IEEE"})
		c.exec(ctx, "insert identification", `INSERT INTO identifications
			(host_id, field, value, confidence, source, evidence_json, first_seen, last_seen, current)
			VALUES (?, 'manufacturer', ?, ?, 'oui', ?, ?, ?, 1)`,
			h.id, h.vendor, ouiConfidence, string(evidence), ms(h.firstSeen), ms(h.firstSeen))
	}
}

func (c *Correlator) dbHostSeen(ctx context.Context, h *host) {
	c.exec(ctx, "update host", `UPDATE hosts SET last_seen = ?, presence = ? WHERE host_id = ?`,
		ms(h.lastSeen), string(h.presence), h.id)
}

func (c *Correlator) dbOpenBinding(ctx context.Context, b *binding, src observation.Source) {
	family := 4
	if b.ip.Is6() {
		family = 6
	}
	c.exec(ctx, "open address", `INSERT INTO addresses (id, context_id, host_id, ip, family, conflict, first_seen, last_seen)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		b.id, b.host.ctx.id, b.host.id, b.ip.String(), family, boolInt(b.conflict), ms(b.firstSeen), ms(b.lastSeen))
	c.dbSource(ctx, b, src, b.firstSeen)
}

func (c *Correlator) dbBindingSeen(ctx context.Context, b *binding, src observation.Source, t time.Time) {
	c.exec(ctx, "update address", `UPDATE addresses SET last_seen = max(last_seen, ?) WHERE id = ?`, ms(b.lastSeen), b.id)
	c.dbSource(ctx, b, src, t)
}

func (c *Correlator) dbSource(ctx context.Context, b *binding, src observation.Source, t time.Time) {
	c.exec(ctx, "address source", `INSERT INTO address_sources (address_id, source, first_seen, last_seen) VALUES (?, ?, ?, ?)
		ON CONFLICT (address_id, source) DO UPDATE SET
			first_seen = min(first_seen, excluded.first_seen), last_seen = max(last_seen, excluded.last_seen)`,
		b.id, string(src), ms(t), ms(t))
}

func (c *Correlator) dbCloseBinding(ctx context.Context, b *binding, endedAt time.Time) {
	c.exec(ctx, "close address", `UPDATE addresses SET last_seen = ?, ended_at = ?, conflict = ? WHERE id = ?`,
		ms(b.lastSeen), ms(endedAt), boolInt(b.conflict), b.id)
}

func (c *Correlator) dbConflict(ctx context.Context, b *binding) {
	c.exec(ctx, "address conflict", `UPDATE addresses SET conflict = ? WHERE id = ?`, boolInt(b.conflict), b.id)
}

func (c *Correlator) dbService(ctx context.Context, h *host, svc observation.ServiceResult, row *serviceRow, insert bool, t time.Time) {
	if insert {
		c.nextService()
		c.exec(ctx, "insert service", `INSERT INTO services (id, host_id, proto, port, state, first_seen, last_seen, last_result_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			c.st.nextServiceID, h.id, svc.Proto, svc.Port, string(row.state), ms(row.firstSeen), ms(row.lastSeen), ms(t))
		return
	}
	c.exec(ctx, "update service", `UPDATE services SET state = ?, last_seen = max(last_seen, ?), last_result_at = ?
		WHERE host_id = ? AND proto = ? AND port = ?`,
		string(row.state), ms(row.lastSeen), ms(t), h.id, svc.Proto, svc.Port)
}

func (c *Correlator) nextService() { c.st.nextServiceID++ }

func (c *Correlator) dbOpenName(ctx context.Context, h *host, n *nameRow) {
	c.exec(ctx, "open name", `INSERT INTO names (id, host_id, name, name_type, source, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		n.id, h.id, n.name, string(n.typ), string(n.source), ms(n.firstSeen), ms(n.lastSeen))
}

func (c *Correlator) dbNameSeen(ctx context.Context, n *nameRow) {
	c.exec(ctx, "update name", `UPDATE names SET last_seen = max(last_seen, ?) WHERE id = ?`, ms(n.lastSeen), n.id)
}

func (c *Correlator) dbCloseName(ctx context.Context, n *nameRow, endedAt time.Time) {
	c.exec(ctx, "close name", `UPDATE names SET last_seen = ?, ended_at = ? WHERE id = ?`, ms(n.lastSeen), ms(endedAt), n.id)
}

func (c *Correlator) dbPreferred(ctx context.Context, h *host) {
	c.exec(ctx, "preferred name", `UPDATE hosts SET preferred_name = ? WHERE host_id = ?`, nullString(h.preferred), h.id)
}

func (c *Correlator) dbObservation(ctx context.Context, id int64, ctxID int64, o observation.Observation, hostID string) {
	var mac, ip, svc, meta any
	if len(o.MAC) > 0 {
		mac = o.MAC.String()
	}
	if o.IP.IsValid() {
		ip = o.IP.String()
	}
	if o.Service != nil {
		b, _ := json.Marshal(o.Service)
		svc = string(b)
	}
	m := o.Meta
	if o.NeighborState != "" {
		m = make(map[string]string, len(o.Meta)+1)
		for k, v := range o.Meta {
			m[k] = v
		}
		m["neighbor_state"] = o.NeighborState
	}
	if len(m) > 0 {
		b, _ := json.Marshal(m)
		meta = string(b)
	}
	c.exec(ctx, "insert observation", `INSERT INTO observations
		(id, ts, context_id, source, mac, ip, hostname, name_type, service_json, meta_json, host_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, ms(o.Time), ctxID, string(o.Source), mac, ip, nullString(o.Hostname), nullString(string(o.NameType)), svc, meta, nullString(hostID))
}

func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
