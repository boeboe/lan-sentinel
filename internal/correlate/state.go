package correlate

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/netip"
	"time"

	"lan-sentinel/internal/events"
	"lan-sentinel/internal/observation"
)

// Presence is a host's presence state (docs/DATA_MODEL.md §6).
type Presence string

// Presence states.
const (
	Active  Presence = "ACTIVE"
	Recent  Presence = "RECENT"
	Stale   Presence = "STALE"
	Missing Presence = "MISSING"
)

// live reports whether a host in this state can hold an IP against a new
// claimant (ACTIVE or RECENT).
func (p Presence) live() bool { return p == Active || p == Recent }

type netContext struct {
	id       int64
	iface    string
	prefixes map[netip.Prefix]*prefixRow // open context_prefixes
	up       *bool                       // nil until the first link state
	lastSeen time.Time
	dirty    bool // lastSeen not yet written
}

type prefixRow struct {
	id        int64
	firstSeen time.Time
}

type host struct {
	id         string
	ctx        *netContext
	mac        net.HardwareAddr
	vendor     string
	presence   Presence
	firstSeen  time.Time
	lastSeen   time.Time
	lastChange time.Time // latest binding open/close on this host
	evidence   events.Evidence
	bindings   map[netip.Addr]*binding // open bindings
	services   map[string]*serviceRow
	names      map[observation.NameType]*nameRow // open name per type
	nameChange map[observation.NameType]time.Time
	preferred  string

	// Proxy-ARP detection (docs/DATA_MODEL.md §5.2): when this MAC last
	// answered ARP for each address, and for those held by another live host.
	proxyARP    bool
	arpClaims   map[netip.Addr]time.Time
	arpOverlaps map[netip.Addr]time.Time
}

type nameRow struct {
	id        int64
	name      string
	typ       observation.NameType
	source    observation.Source
	firstSeen time.Time
	lastSeen  time.Time
}

func newHost() *host {
	return &host{
		bindings: map[netip.Addr]*binding{}, services: map[string]*serviceRow{},
		names: map[observation.NameType]*nameRow{}, nameChange: map[observation.NameType]time.Time{},
		arpClaims: map[netip.Addr]time.Time{}, arpOverlaps: map[netip.Addr]time.Time{},
	}
}

type binding struct {
	id        int64
	host      *host
	ip        netip.Addr
	conflict  bool
	firstSeen time.Time
	lastSeen  time.Time
	// arpOnly: opened by an ARP reply and not confirmed by other evidence
	// since (bindings loaded at start-up count as confirmed).
	arpOnly bool
}

type serviceRow struct {
	state     observation.ServiceState
	firstSeen time.Time
	lastSeen  time.Time
}

// ipKey identifies an IP within a context.
type ipKey struct {
	ctx int64
	ip  netip.Addr
}

// state is the correlator's in-memory current state. Only the correlator
// goroutine touches it.
type state struct {
	contexts     map[string]*netContext
	contextsByID map[int64]*netContext
	hosts        map[int64]map[string]*host // context id → MAC → host
	hostsByMAC   map[string][]*host         // MAC → hosts on every context
	order        []*host                    // creation order, for deterministic timers
	holders      map[ipKey][]*binding       // open bindings per IP
	ipLastChange map[ipKey]time.Time

	nextContextID, nextPrefixID, nextAddressID, nextObservationID, nextServiceID, nextNameID int64
}

func newState() *state {
	return &state{
		contexts: map[string]*netContext{}, contextsByID: map[int64]*netContext{},
		hosts: map[int64]map[string]*host{}, hostsByMAC: map[string][]*host{},
		holders: map[ipKey][]*binding{}, ipLastChange: map[ipKey]time.Time{},
	}
}

func (s *state) addHost(h *host) {
	if s.hosts[h.ctx.id] == nil {
		s.hosts[h.ctx.id] = map[string]*host{}
	}
	key := h.mac.String()
	s.hosts[h.ctx.id][key] = h
	s.hostsByMAC[key] = append(s.hostsByMAC[key], h)
	s.order = append(s.order, h)
}

func (s *state) addBinding(b *binding) {
	b.host.bindings[b.ip] = b
	k := ipKey{b.host.ctx.id, b.ip}
	s.holders[k] = append(s.holders[k], b)
}

func (s *state) removeBinding(b *binding) {
	delete(b.host.bindings, b.ip)
	k := ipKey{b.host.ctx.id, b.ip}
	hs := s.holders[k]
	for i, x := range hs {
		if x == b {
			hs = append(hs[:i], hs[i+1:]...)
			break
		}
	}
	if len(hs) == 0 {
		delete(s.holders, k)
	} else {
		s.holders[k] = hs
	}
}

func (s *state) touchIP(k ipKey, t time.Time) {
	if t.After(s.ipLastChange[k]) {
		s.ipLastChange[k] = t
	}
}

func ms(t time.Time) int64 { return t.UnixMilli() }

func fromMS(v int64) time.Time { return time.UnixMilli(v).UTC() }

// load reads the current state from the database (open bindings only).
func (s *state) load(ctx context.Context, tx *sql.Tx) error {
	var err error
	q := func(query string, scan func(*sql.Rows) error) {
		if err != nil {
			return
		}
		var rows *sql.Rows
		rows, err = tx.QueryContext(ctx, query)
		if err != nil {
			err = fmt.Errorf("load state: %w", err)
			return
		}
		defer rows.Close()
		for rows.Next() {
			if err = scan(rows); err != nil {
				err = fmt.Errorf("load state: %w", err)
				return
			}
		}
		if err == nil {
			err = rows.Err()
		}
	}

	q(`SELECT id, interface, last_seen FROM network_contexts`, func(r *sql.Rows) error {
		c := &netContext{prefixes: map[netip.Prefix]*prefixRow{}}
		var last int64
		if err := r.Scan(&c.id, &c.iface, &last); err != nil {
			return err
		}
		c.lastSeen = fromMS(last)
		s.contexts[c.iface], s.contextsByID[c.id] = c, c
		return nil
	})
	q(`SELECT id, context_id, prefix, first_seen FROM context_prefixes WHERE ended_at IS NULL`, func(r *sql.Rows) error {
		var id, cid, first int64
		var text string
		if err := r.Scan(&id, &cid, &text, &first); err != nil {
			return err
		}
		p, err := netip.ParsePrefix(text)
		if err != nil {
			return err
		}
		if c := s.contextsByID[cid]; c != nil {
			c.prefixes[p] = &prefixRow{id: id, firstSeen: fromMS(first)}
		}
		return nil
	})
	byID := map[string]*host{}
	q(`SELECT host_id, context_id, mac, coalesce(vendor, ''), presence, coalesce(preferred_name, ''), first_seen, last_seen
		FROM hosts ORDER BY first_seen, host_id`, func(r *sql.Rows) error {
		h := newHost()
		var cid, first, last int64
		var mac, presence string
		if err := r.Scan(&h.id, &cid, &mac, &h.vendor, &presence, &h.preferred, &first, &last); err != nil {
			return err
		}
		var err error
		if h.mac, err = net.ParseMAC(mac); err != nil {
			return err
		}
		h.ctx = s.contextsByID[cid]
		if h.ctx == nil {
			return fmt.Errorf("host %s references unknown context %d", h.id, cid)
		}
		h.presence, h.firstSeen, h.lastSeen = Presence(presence), fromMS(first), fromMS(last)
		h.evidence = events.Evidence{TS: h.lastSeen, Interface: h.ctx.iface, MAC: mac}
		s.addHost(h)
		byID[h.id] = h
		return nil
	})
	q(`SELECT id, host_id, ip, conflict, first_seen, last_seen FROM addresses WHERE ended_at IS NULL`, func(r *sql.Rows) error {
		b := &binding{}
		var hid, ip string
		var conflict int
		var first, last int64
		if err := r.Scan(&b.id, &hid, &ip, &conflict, &first, &last); err != nil {
			return err
		}
		var err error
		if b.ip, err = netip.ParseAddr(ip); err != nil {
			return err
		}
		if b.host = byID[hid]; b.host == nil {
			return fmt.Errorf("address %d references unknown host %s", b.id, hid)
		}
		b.conflict, b.firstSeen, b.lastSeen = conflict == 1, fromMS(first), fromMS(last)
		s.addBinding(b)
		return nil
	})
	q(`SELECT host_id, context_id, ip, max(max(first_seen), max(coalesce(ended_at, 0))) FROM addresses GROUP BY host_id, context_id, ip`, func(r *sql.Rows) error {
		var hid, ip string
		var cid, t int64
		if err := r.Scan(&hid, &cid, &ip, &t); err != nil {
			return err
		}
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			return err
		}
		s.touchIP(ipKey{cid, addr}, fromMS(t))
		if h := byID[hid]; h != nil && fromMS(t).After(h.lastChange) {
			h.lastChange = fromMS(t)
		}
		return nil
	})
	q(`SELECT host_id, proto, port, state, first_seen, last_seen FROM services`, func(r *sql.Rows) error {
		var hid, proto, st string
		var port int
		var first, last int64
		if err := r.Scan(&hid, &proto, &port, &st, &first, &last); err != nil {
			return err
		}
		if h := byID[hid]; h != nil {
			key := observation.ServiceResult{Proto: proto, Port: port}.Key()
			h.services[key] = &serviceRow{state: observation.ServiceState(st), firstSeen: fromMS(first), lastSeen: fromMS(last)}
		}
		return nil
	})
	q(`SELECT id, host_id, name, name_type, source, first_seen, last_seen FROM names WHERE ended_at IS NULL`, func(r *sql.Rows) error {
		n := &nameRow{}
		var hid, typ, src string
		var first, last int64
		if err := r.Scan(&n.id, &hid, &n.name, &typ, &src, &first, &last); err != nil {
			return err
		}
		n.typ, n.source, n.firstSeen, n.lastSeen = observation.NameType(typ), observation.Source(src), fromMS(first), fromMS(last)
		if h := byID[hid]; h != nil {
			h.names[n.typ] = n
		}
		return nil
	})
	q(`SELECT DISTINCT host_id FROM identifications WHERE field = 'proxy_arp' AND value = 'true'`, func(r *sql.Rows) error {
		var hid string
		if err := r.Scan(&hid); err != nil {
			return err
		}
		if h := byID[hid]; h != nil {
			h.proxyARP = true
		}
		return nil
	})
	q(`SELECT host_id, name_type, max(max(first_seen), max(coalesce(ended_at, 0))) FROM names GROUP BY host_id, name_type`, func(r *sql.Rows) error {
		var hid, typ string
		var t int64
		if err := r.Scan(&hid, &typ, &t); err != nil {
			return err
		}
		if h := byID[hid]; h != nil {
			h.nameChange[observation.NameType(typ)] = fromMS(t)
		}
		return nil
	})
	for _, c := range []struct {
		table string
		dst   *int64
	}{
		{"network_contexts", &s.nextContextID}, {"context_prefixes", &s.nextPrefixID},
		{"addresses", &s.nextAddressID}, {"observations", &s.nextObservationID}, {"services", &s.nextServiceID},
		{"names", &s.nextNameID},
	} {
		q(`SELECT coalesce(max(id), 0) FROM `+c.table, func(r *sql.Rows) error { return r.Scan(c.dst) })
	}
	return err
}
