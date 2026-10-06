package correlate

import (
	"context"
	"net"
	"net/netip"
	"sort"
	"time"

	"lan-sentinel/internal/events"
	"lan-sentinel/internal/identify"
	"lan-sentinel/internal/observation"
)

// observe applies docs/DATA_MODEL.md §5 to one observation.
func (c *Correlator) observe(ctx context.Context, o observation.Observation) {
	n := c.st.contexts[o.Interface]
	if n == nil || o.Time.IsZero() {
		c.ignored.Add(1)
		return
	}
	c.advance(ctx, o.Time)

	mac := o.MAC
	if mac != nil && !identify.UnicastMAC(mac) {
		mac = nil
	}
	ip := o.IP.Unmap()
	if ip.IsValid() && !ip.IsGlobalUnicast() && !ip.IsLinkLocalUnicast() {
		ip = netip.Addr{}
	}
	if mac == nil && !ip.IsValid() {
		c.ignored.Add(1)
		return
	}
	if o.Time.After(n.lastSeen) {
		n.lastSeen, n.dirty = o.Time, true
	}
	c.st.nextObservationID++
	obsID := c.st.nextObservationID
	ev := events.EvidenceFrom(o)

	// §5.1: bind the observation to a host. A MAC-less name observation
	// (a DNS answer) describes the holder of the IP but is not evidence that
	// it is present or still holds the address.
	var h *host
	discovered, nameOnly := false, false
	if mac != nil {
		h, discovered = c.bindMAC(ctx, n, mac, o, obsID, ev)
	} else if hs := c.st.holders[ipKey{n.id, ip}]; len(hs) == 1 {
		h, nameOnly = hs[0].host, o.Source == observation.PassiveDNS
		if !nameOnly {
			c.seen(ctx, h, o, ev)
		}
	}
	hostID := ""
	if h != nil {
		hostID = h.id
	} else {
		c.unbound.Add(1)
	}
	c.dbObservation(ctx, obsID, n.id, o, hostID)
	if h == nil {
		return
	}
	if ip.IsValid() && !nameOnly {
		c.attribute(ctx, h, ip, o, obsID, ev, discovered)
	}
	if o.Service != nil {
		c.service(ctx, h, *o.Service, o, obsID, ev)
	}
	if o.Hostname != "" && validNameType(o.NameType) {
		c.name(ctx, h, o, obsID, ev)
	}
}

// bindMAC returns the host for (context, MAC), creating it if needed.
func (c *Correlator) bindMAC(ctx context.Context, n *netContext, mac net.HardwareAddr, o observation.Observation, obsID int64, ev events.Evidence) (*host, bool) {
	key := mac.String()
	if h := c.st.hosts[n.id][key]; h != nil {
		c.seen(ctx, h, o, ev)
		return h, false
	}
	h := newHost()
	h.id, h.ctx, h.mac, h.firstSeen, h.lastSeen, h.evidence = c.newID(), n, append(net.HardwareAddr(nil), mac...), o.Time, o.Time, ev
	if c.vendors != nil {
		h.vendor, _ = c.vendors.Lookup(mac)
	}
	h.presence = c.presenceAt(o.Time, c.refTime(o.Time))
	c.st.addHost(h)
	c.dbInsertHost(ctx, h, identify.LocallyAdministered(mac))

	e := hostEvent(events.HostDiscovered, o.Time, h, string(o.Source), ev)
	e.New, e.ObservationID = key, obsID
	c.emit(ctx, e)

	// The same MAC known on another interface is another host (§1).
	var other *host
	for _, x := range c.st.hostsByMAC[key] {
		if x != h && (other == nil || x.lastSeen.After(other.lastSeen)) {
			other = x
		}
	}
	if other != nil {
		e := hostEvent(events.MACMoved, o.Time, h, string(o.Source), ev)
		e.Old, e.New, e.RelatedHostID, e.ObservationID = other.ctx.iface, n.iface, other.id, obsID
		c.emit(ctx, e)
	}
	return h, true
}

// seen records that h was observed.
func (c *Correlator) seen(ctx context.Context, h *host, o observation.Observation, ev events.Evidence) {
	moved := false
	if o.Time.After(h.lastSeen) {
		h.lastSeen, h.evidence, moved = o.Time, ev, true
	}
	p := c.presenceAt(h.lastSeen, c.refTime(o.Time))
	if h.presence == Missing && p != Missing {
		e := hostEvent(events.HostReappeared, o.Time, h, string(o.Source), ev)
		e.Old, e.New = string(Missing), string(p)
		c.emit(ctx, e)
	}
	if moved || p != h.presence {
		h.presence = p
		c.dbHostSeen(ctx, h)
	}
}

// onLink implements §5.2.
func onLink(n *netContext, ip netip.Addr, src observation.Source) bool {
	for p := range n.prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	if ip.Is4() {
		switch src {
		case observation.PassiveARP, observation.ARPScan, observation.PassiveDHCP, observation.KernelNeighbor:
			return true
		}
		return false
	}
	if ip.IsLinkLocalUnicast() {
		return true
	}
	switch src {
	case observation.PassiveNDP, observation.NDPProbe, observation.KernelNeighbor:
		return true
	}
	return false
}

// notHostAddress reports the network and broadcast addresses of the
// context's IPv4 prefixes.
func notHostAddress(n *netContext, ip netip.Addr) bool {
	if !ip.Is4() {
		return false
	}
	for p := range n.prefixes {
		if !p.Addr().Is4() || p.Bits() >= 31 || !p.Contains(ip) {
			continue
		}
		if ip == p.Masked().Addr() || ip == lastAddr(p) {
			return true
		}
	}
	return false
}

func lastAddr(p netip.Prefix) netip.Addr {
	a := p.Masked().Addr().As4()
	host := uint32(1)<<(32-p.Bits()) - 1
	v := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	v |= host
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// attribute applies the address binding lifecycle (§5.3) for ip on h.
func (c *Correlator) attribute(ctx context.Context, h *host, ip netip.Addr, o observation.Observation, obsID int64, ev events.Evidence, discovered bool) {
	n := h.ctx
	if !onLink(n, ip, o.Source) || notHostAddress(n, ip) {
		return
	}
	k := ipKey{n.id, ip}
	// A late observation (older than the last change of the host or the IP)
	// only refreshes open bindings; it never changes them.
	late := o.Time.Before(h.lastChange) || o.Time.Before(c.st.ipLastChange[k])
	reply := isARPReply(o)
	if reply && c.proxyClaim(ctx, h, ip, o, obsID, ev, late) {
		return
	}
	if b := h.bindings[ip]; b != nil {
		if o.Time.After(b.lastSeen) {
			b.lastSeen = o.Time
		}
		b.arpOnly = b.arpOnly && reply
		c.dbBindingSeen(ctx, b, o.Source, o.Time)
		return
	}
	if late {
		return
	}
	cause := string(o.Source)
	idCfg := c.cfg.Load().Identity

	// Takeover from hosts that are no longer live; conflict with live ones.
	var rivals []*host
	for _, g := range append([]*binding(nil), c.st.holders[k]...) {
		if c.presenceAt(g.host.lastSeen, o.Time).live() {
			rivals = append(rivals, g.host)
			continue
		}
		c.close(g, o.Time)
		e := hostEvent(events.IPRemoved, o.Time, g.host, cause, ev)
		e.Old, e.RelatedHostID, e.ObservationID = ip.String(), h.id, obsID
		c.emit(ctx, e)
	}

	// Replacement (IPv4 only): older IPv4 bindings not confirmed within the
	// overlap window are closed.
	var replaced []*binding
	if ip.Is4() {
		for _, b := range h.bindings {
			if b.ip.Is4() && o.Time.Sub(b.lastSeen) >= idCfg.AddressOverlap.D() {
				replaced = append(replaced, b)
			}
		}
		sort.Slice(replaced, func(i, j int) bool {
			if !replaced[i].lastSeen.Equal(replaced[j].lastSeen) {
				return replaced[i].lastSeen.After(replaced[j].lastSeen)
			}
			return replaced[i].ip.Less(replaced[j].ip)
		})
		for _, b := range replaced {
			c.close(b, o.Time)
		}
	}

	c.st.nextAddressID++
	nb := &binding{id: c.st.nextAddressID, host: h, ip: ip, conflict: len(rivals) > 0, firstSeen: o.Time, lastSeen: o.Time, arpOnly: reply}
	c.st.addBinding(nb)
	c.dbOpenBinding(ctx, nb, o.Source)
	c.changed(h, k, o.Time)

	switch {
	case len(replaced) > 0:
		e := hostEvent(events.IPChanged, o.Time, h, cause, ev)
		e.Old, e.New, e.ObservationID = replaced[0].ip.String(), ip.String(), obsID
		c.emit(ctx, e)
		for _, b := range replaced[1:] {
			e := hostEvent(events.IPRemoved, o.Time, h, cause, ev)
			e.Old, e.ObservationID = b.ip.String(), obsID
			c.emit(ctx, e)
		}
	case !discovered:
		e := hostEvent(events.IPAdded, o.Time, h, cause, ev)
		e.New, e.ObservationID = ip.String(), obsID
		c.emit(ctx, e)
	}

	if len(rivals) > 0 {
		sort.Slice(rivals, func(i, j int) bool { return rivals[i].lastSeen.After(rivals[j].lastSeen) })
		for _, g := range c.st.holders[k] {
			if g != nb && !g.conflict {
				g.conflict = true
				c.dbConflict(ctx, g)
			}
		}
		e := hostEvent(events.DuplicateIPDetected, o.Time, h, cause, ev)
		e.New, e.RelatedHostID, e.ObservationID = ip.String(), rivals[0].id, obsID
		c.emit(ctx, e)
	}

	for _, b := range replaced {
		c.resolve(ctx, ipKey{n.id, b.ip}, o.Time, cause, obsID, ev, h)
	}
}

// close ends binding b at endedAt (queued write, no event).
func (c *Correlator) close(b *binding, endedAt time.Time) {
	c.st.removeBinding(b)
	c.dbCloseBinding(context.Background(), b, endedAt)
	c.changed(b.host, ipKey{b.host.ctx.id, b.ip}, endedAt)
}

func (c *Correlator) changed(h *host, k ipKey, t time.Time) {
	if t.After(h.lastChange) {
		h.lastChange = t
	}
	c.st.touchIP(k, t)
}

// resolve clears a conflict once a single binding for the IP remains.
func (c *Correlator) resolve(ctx context.Context, k ipKey, t time.Time, cause string, obsID int64, ev events.Evidence, leaving *host) {
	hs := c.st.holders[k]
	if len(hs) != 1 || !hs[0].conflict {
		return
	}
	b := hs[0]
	b.conflict = false
	c.dbConflict(ctx, b)
	e := hostEvent(events.DuplicateIPResolved, t, b.host, cause, ev)
	e.New, e.RelatedHostID, e.ObservationID = k.ip.String(), leaving.id, obsID
	c.emit(ctx, e)
}

// service applies §5.5.
func (c *Correlator) service(ctx context.Context, h *host, svc observation.ServiceResult, o observation.Observation, obsID int64, ev events.Evidence) {
	key := svc.Key()
	row := h.services[key]
	if row != nil && o.Time.Before(row.lastSeen) {
		return // late result
	}
	insert := row == nil
	var prev observation.ServiceState
	if insert {
		row = &serviceRow{state: svc.State, firstSeen: o.Time, lastSeen: o.Time}
		h.services[key] = row
	} else {
		prev, row.state, row.lastSeen = row.state, svc.State, o.Time
	}
	c.dbService(ctx, h, svc, row, insert, o.Time)
	switch {
	case svc.State == observation.ServiceOpen && prev != observation.ServiceOpen:
		e := hostEvent(events.ServiceOpened, o.Time, h, string(o.Source), ev)
		e.Old, e.New, e.ObservationID = string(prev), key, obsID
		c.emit(ctx, e)
	case prev == observation.ServiceOpen && svc.State != observation.ServiceOpen:
		e := hostEvent(events.ServiceClosed, o.Time, h, string(o.Source), ev)
		e.Old, e.New, e.ObservationID = key, string(svc.State), obsID
		c.emit(ctx, e)
	}
}

// advance evaluates presence (§6) and binding expiry (§5.3) up to now.
// Transitions are stamped with the moment the threshold was crossed.
func (c *Correlator) advance(ctx context.Context, now time.Time) {
	if !now.After(c.advancedTo) {
		return
	}
	c.advancedTo = now
	cfg := c.cfg.Load()
	stale, expiry := cfg.Presence.Stale.D(), cfg.Identity.AddressExpiry.D()

	for _, h := range c.st.order {
		// Expiry: unconfirmed for address_expiry while the host was seen since.
		for _, b := range sortedBindings(h) {
			if now.Sub(b.lastSeen) < expiry || !h.lastSeen.After(b.lastSeen) {
				continue
			}
			ended := b.lastSeen.Add(expiry)
			c.close(b, ended)
			ev := h.evidence
			ev.Reason = "address not confirmed for " + cfg.Identity.AddressExpiry.String()
			e := hostEvent(events.IPRemoved, ended, h, causeExpiry, ev)
			e.Old = b.ip.String()
			c.emit(ctx, e)
			c.resolve(ctx, ipKey{h.ctx.id, b.ip}, ended, causeExpiry, 0, ev, h)
		}

		p := c.presenceAt(h.lastSeen, now)
		if p == h.presence {
			continue
		}
		h.presence = p
		c.dbHostSeen(ctx, h)
		if p == Missing {
			ev := h.evidence
			ev.Reason = "no observation for " + cfg.Presence.Stale.String()
			// The state just before MISSING is always STALE (thresholds are
			// ordered), however coarsely presence was evaluated.
			e := hostEvent(events.HostDisappeared, h.lastSeen.Add(stale), h, causePresence, ev)
			e.Old, e.New = string(Stale), string(Missing)
			c.emit(ctx, e)
		}
	}
}

func sortedBindings(h *host) []*binding {
	out := make([]*binding, 0, len(h.bindings))
	for _, b := range h.bindings {
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ip.Less(out[j].ip) })
	return out
}

// link applies an interface state: INTERFACE_UP/DOWN on transitions and
// SUBNET_CHANGED for every prefix opened or closed.
func (c *Correlator) link(ctx context.Context, ls observation.LinkState) {
	n := c.st.contexts[ls.Interface]
	if n == nil {
		return
	}
	c.advance(ctx, ls.Time)
	up := ls.Present && ls.Up
	if n.up != nil && *n.up != up {
		t, state := events.InterfaceDown, "down"
		if up {
			t, state = events.InterfaceUp, "up"
		}
		c.emit(ctx, events.Event{TS: ls.Time, Type: t, ContextID: n.id, Interface: n.iface, New: state, Cause: causeIface,
			Evidence: events.Evidence{TS: ls.Time, Interface: n.iface}})
	}
	n.up = &up

	want := map[netip.Prefix]bool{}
	for _, p := range ls.Prefixes {
		want[p.Masked()] = true
	}
	var closed, opened []netip.Prefix
	for p := range n.prefixes {
		if !want[p] {
			closed = append(closed, p)
		}
	}
	for p := range want {
		if n.prefixes[p] == nil {
			opened = append(opened, p)
		}
	}
	sortPrefixes(closed)
	sortPrefixes(opened)
	for _, p := range closed {
		c.dbClosePrefix(ctx, n.prefixes[p].id, ls.Time)
		delete(n.prefixes, p)
		c.subnetEvent(ctx, n, ls.Time, describe(p), "")
	}
	for _, p := range opened {
		c.st.nextPrefixID++
		n.prefixes[p] = &prefixRow{id: c.st.nextPrefixID, firstSeen: ls.Time}
		c.dbOpenPrefix(ctx, n, c.st.nextPrefixID, p, ls.Time)
		c.subnetEvent(ctx, n, ls.Time, "", describe(p))
	}
}

func (c *Correlator) subnetEvent(ctx context.Context, n *netContext, t time.Time, old, new string) {
	c.emit(ctx, events.Event{TS: t, Type: events.SubnetChanged, ContextID: n.id, Interface: n.iface, Old: old, New: new,
		Cause: causeIface, Evidence: events.Evidence{TS: t, Interface: n.iface}})
}

func sortPrefixes(ps []netip.Prefix) {
	sort.Slice(ps, func(i, j int) bool {
		if c := ps[i].Addr().Compare(ps[j].Addr()); c != 0 {
			return c < 0
		}
		return ps[i].Bits() < ps[j].Bits()
	})
}
