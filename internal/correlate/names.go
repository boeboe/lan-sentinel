package correlate

import (
	"context"
	"slices"

	"lan-sentinel/internal/events"
	"lan-sentinel/internal/observation"
)

// nameTypes are the name types the schema accepts (names.name_type).
var nameTypes = []observation.NameType{
	observation.NameMDNS, observation.NameDHCP, observation.NameDNSPTR, observation.NameNetBIOS, observation.NameLLDP,
}

func validNameType(t observation.NameType) bool { return slices.Contains(nameTypes, t) }

// nameValue is the event text of a name: "type:name".
func nameValue(n *nameRow) string { return string(n.typ) + ":" + n.name }

// name applies docs/DATA_MODEL.md §5.4. Names are last-known attributes: a
// host has at most one open name per type, a new name of a type opens a
// binding (HOSTNAME_ADDED), and only a different name of the same type
// replaces it (HOSTNAME_CHANGED). Time alone never closes a name: not seeing
// a naming protocol again is not evidence that the name changed, whether
// the host stays visible or goes MISSING. identity.name_expiry only marks a
// name as stale when it is read. An observation older than the open name's
// last confirmation or the type's last change only refreshes, like late
// address observations.
func (c *Correlator) name(ctx context.Context, h *host, o observation.Observation, obsID int64, ev events.Evidence) {
	cur := h.names[o.NameType]
	if cur != nil && cur.name == o.Hostname {
		if o.Time.After(cur.lastSeen) {
			cur.lastSeen = o.Time
			c.dbNameSeen(ctx, cur)
		}
		return
	}
	if o.Time.Before(h.nameChange[o.NameType]) || cur != nil && o.Time.Before(cur.lastSeen) {
		return
	}
	c.st.nextNameID++
	n := &nameRow{id: c.st.nextNameID, name: o.Hostname, typ: o.NameType, source: o.Source, firstSeen: o.Time, lastSeen: o.Time}
	e := hostEvent(events.HostnameAdded, o.Time, h, string(o.Source), ev)
	if cur != nil {
		c.dbCloseName(ctx, cur, o.Time)
		e.Type, e.Old = events.HostnameChanged, nameValue(cur)
	}
	h.names[n.typ], h.nameChange[n.typ] = n, o.Time
	c.dbOpenName(ctx, h, n)
	e.New, e.ObservationID = nameValue(n), obsID
	c.emit(ctx, e)
	c.prefer(ctx, h)
}

// prefer recomputes preferred_name: the open name of the first type in
// identity.hostname_preference that the host has (FR-NM-2). Types missing
// from the list are never preferred.
func (c *Correlator) prefer(ctx context.Context, h *host) {
	preferred := ""
	for _, t := range c.cfg.Load().Identity.HostnamePreference {
		if n := h.names[observation.NameType(t)]; n != nil {
			preferred = n.name
			break
		}
	}
	if preferred != h.preferred {
		h.preferred = preferred
		c.dbPreferred(ctx, h)
	}
}
