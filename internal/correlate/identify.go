package correlate

import (
	"context"
	"strings"

	"lan-sentinel/internal/config"
	"lan-sentinel/internal/events"
	"lan-sentinel/internal/identify"
	"lan-sentinel/internal/observation"
)

// identifierSources lists the passive identifiers' source names as an SQL
// list, for loading their identifications.
var identifierSources = func() string {
	all := identify.Identifiers(config.IdentifierToggles{MDNS: true, DHCP: true, Hostname: true, LLDP: true})
	q := make([]string, len(all))
	for i, id := range all {
		q[i] = "'" + id.Name() + "'"
	}
	return strings.Join(q, ", ")
}()

// identify applies the passive identifiers (§5.7) to an observation of h.
func (c *Correlator) identify(ctx context.Context, h *host, o observation.Observation, obsID int64, ev events.Evidence) {
	ids := c.ids.Load()
	if ids == nil {
		return
	}
	for _, id := range *ids {
		for _, cl := range id.Identify(o) {
			c.claim(ctx, h, id.Name(), cl, o, obsID, ev)
		}
	}
}

// claim records an identifier's claim as an identification, whose
// confidence is the strongest evidence seen for that value. A source's
// current value for a field changes only to a more convincing claim, so a
// device whose packets say different things does not flip between them:
// the same value refreshes its row, and an equally or less confident other
// value is recorded but not adopted. Adopting a value marks it current and
// emits VENDOR_IDENTIFIED; a device type also updates hosts.device_type.
func (c *Correlator) claim(ctx context.Context, h *host, source string, cl identify.Claim, o observation.Observation, obsID int64, ev events.Evidence) {
	if cl.Field == "" || cl.Value == "" {
		return
	}
	evidence := make(map[string]any, len(cl.Evidence))
	for k, v := range cl.Evidence {
		evidence[k] = v
	}
	c.dbIdentification(ctx, h, cl.Field, cl.Value, cl.Confidence, source, evidence, o.Time)
	key := identKey(cl.Field, source)
	old, known := h.idents[key]
	switch {
	case known && old == cl.Value:
		if cl.Confidence > h.identConf[key] { // stronger evidence for the current value
			h.identConf[key] = cl.Confidence
			if cl.Field == identify.FieldDeviceType {
				c.updateDeviceType(ctx, h)
			}
		}
		return
	case known && cl.Confidence <= h.identConf[key]:
		return
	}
	h.idents[key], h.identConf[key] = cl.Value, cl.Confidence
	c.dbCurrent(ctx, h, cl.Field, source, cl.Value)
	e := hostEvent(events.VendorIdentified, o.Time, h, string(o.Source), ev)
	e.New, e.ObservationID = cl.Field+"="+cl.Value, obsID
	if known {
		e.Old = cl.Field + "=" + old
	}
	c.emit(ctx, e)
	if cl.Field == identify.FieldDeviceType {
		c.updateDeviceType(ctx, h)
	}
}

// updateDeviceType sets hosts.device_type to the most confident current
// device type claim of any source (a probe's 0.9 beats every passive
// identifier); between equals the source that sorts first.
func (c *Correlator) updateDeviceType(ctx context.Context, h *host) {
	best, bestSource, bestConf := "", "", -1.0
	for key, v := range h.idents {
		field, source, _ := strings.Cut(key, "\x00")
		if field != identify.FieldDeviceType {
			continue
		}
		if conf := h.identConf[key]; conf > bestConf || conf == bestConf && source < bestSource {
			best, bestSource, bestConf = v, source, conf
		}
	}
	if best != "" && best != h.deviceType {
		h.deviceType = best
		c.exec(ctx, "device type", `UPDATE hosts SET device_type = ? WHERE host_id = ?`, best, h.id)
	}
}
