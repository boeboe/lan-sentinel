package correlate

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/netip"
	"strings"
	"time"

	"lan-sentinel/internal/config"
	"lan-sentinel/internal/events"
	"lan-sentinel/internal/observation"
)

// DHCP server allowlist verdicts (docs/DATA_MODEL.md §5.6).
const (
	dhcpAllowed    = "allowed"
	dhcpUnexpected = "unexpected"
	dhcpUnchecked  = "unchecked" // no allowlist on the interface
)

// dhcpConfigKeys are the advertised settings DHCP_CONFIG_CHANGED compares.
var dhcpConfigKeys = []string{observation.MetaDNS, observation.MetaRouter, observation.MetaSubnetMask}

// dhcpServer is one dhcp_servers row: a server identity seen through one
// relay (or none) from one sender MAC.
type dhcpServer struct {
	id        int64
	key       dhcpKey
	ip        string
	hostID    string
	status    string
	config    map[string]string
	firstSeen time.Time
	lastSeen  time.Time
}

type dhcpKey struct {
	ctx      int64
	serverID string // option 54; "" when unknown
	relay    string // giaddr; "" when not relayed
	mac      string // the sender's
}

// identity names a server in events: its identifier ("unknown" without
// one), and the relay it was seen through.
func (k dhcpKey) identity() string {
	s := k.serverID
	if s == "" {
		s = "unknown"
	}
	if k.relay != "" {
		s += " via " + k.relay
	}
	return s
}

// dhcpStatus is the allowlist verdict for a server identifier on iface.
func dhcpStatus(cfg *config.Config, iface, serverID string) string {
	for _, ic := range cfg.Interfaces {
		if ic.Name != iface {
			continue
		}
		if !ic.DHCP.Checked() {
			return dhcpUnchecked
		}
		id, _ := netip.ParseAddr(serverID)
		if ic.DHCP.Allowed(id) {
			return dhcpAllowed
		}
		return dhcpUnexpected
	}
	return dhcpUnchecked
}

// dhcpServerReply applies §5.6 to the sender of a DHCP server reply: it
// records the server identity, relay and sender, and emits
// DHCP_SERVER_DISCOVERED for an identity new on the interface,
// DHCP_SERVER_MAC_CHANGED when a known identity replies from another
// sender MAC, DHCP_SERVER_UNEXPECTED when the allowlist does not hold it,
// and DHCP_CONFIG_CHANGED when an offer or lease ACK advertises a router,
// DNS servers or subnet mask other than the last one. An absent setting is
// no change: servers send only the options a client asked for.
func (c *Correlator) dhcpServerReply(ctx context.Context, h *host, o observation.Observation, obsID int64, ev events.Evidence) {
	typ := o.Meta[observation.MetaDHCP]
	if typ != "offer" && typ != "ack" && typ != "nak" {
		return
	}
	k := dhcpKey{ctx: h.ctx.id, serverID: o.Meta[observation.MetaServerID], relay: o.Meta[observation.MetaRelay], mac: h.mac.String()}
	status := dhcpStatus(c.cfg.Load(), h.ctx.iface, k.serverID)
	var advertised map[string]string
	if typ == "offer" || typ == "ack" && o.Meta[observation.MetaConfigOnly] == "" {
		advertised = map[string]string{}
		for _, key := range dhcpConfigKeys {
			if v := o.Meta[key]; v != "" {
				advertised[key] = v
			}
		}
	}
	ip := ""
	if o.IP.IsValid() {
		ip = o.IP.Unmap().String()
	}
	event := func(t events.Type, old, nw string) events.Event {
		e := hostEvent(t, o.Time, h, string(o.Source), ev)
		e.Old, e.New, e.ObservationID = old, nw, obsID
		return e
	}

	s := c.st.dhcpServers[k]
	if s == nil {
		s = &dhcpServer{key: k, ip: ip, hostID: h.id, status: status, config: map[string]string{}, firstSeen: o.Time, lastSeen: o.Time}
		for key, v := range advertised {
			s.config[key] = v
		}
		known, previous := c.st.dhcpPrevious(k)
		c.st.nextDHCPServerID++
		s.id = c.st.nextDHCPServerID
		c.st.dhcpServers[k] = s
		c.dbInsertDHCPServer(ctx, s)
		switch {
		case !known:
			c.emit(ctx, event(events.DHCPServerDiscovered, "", k.identity()))
		case previous != nil:
			e := event(events.DHCPServerMACChanged, previous.key.mac, k.mac)
			e.RelatedHostID, e.RelatedMAC = previous.hostID, previous.key.mac
			c.emit(ctx, e)
		}
		if status == dhcpUnexpected {
			c.emit(ctx, event(events.DHCPServerUnexpected, "", k.identity()))
		}
		return
	}
	if o.Time.Before(s.lastSeen) {
		return // older evidence: the row already says more
	}
	s.lastSeen, s.hostID = o.Time, h.id
	if ip != "" {
		s.ip = ip
	}
	if status != s.status {
		old := s.status
		s.status = status
		if status == dhcpUnexpected {
			c.emit(ctx, event(events.DHCPServerUnexpected, old, k.identity()))
		}
	}
	var olds, news []string
	for _, key := range dhcpConfigKeys {
		v, ok := advertised[key]
		if !ok {
			continue
		}
		if prev := s.config[key]; prev != "" && prev != v {
			olds, news = append(olds, key+"="+prev), append(news, key+"="+v)
		}
		s.config[key] = v
	}
	if len(news) > 0 {
		c.emit(ctx, event(events.DHCPConfigChanged, strings.Join(olds, " "), strings.Join(news, " ")))
	}
	c.dbUpdateDHCPServer(ctx, s)
}

// dhcpPrevious reports whether k's server identity is already known on the
// interface and, if it is known through the same relay from other sender
// MACs, the one seen last. A reply without an identifier is told apart by
// its sender alone, so it is never a MAC change.
func (s *state) dhcpPrevious(k dhcpKey) (known bool, previous *dhcpServer) {
	if k.serverID == "" {
		return false, nil
	}
	for x, row := range s.dhcpServers {
		if x.ctx != k.ctx || x.serverID != k.serverID {
			continue
		}
		known = true
		if x.relay == k.relay && x.mac != k.mac &&
			(previous == nil || row.lastSeen.After(previous.lastSeen) || row.lastSeen.Equal(previous.lastSeen) && row.id < previous.id) {
			previous = row
		}
	}
	return known, previous
}

func (c *Correlator) dbInsertDHCPServer(ctx context.Context, s *dhcpServer) {
	cfg, _ := json.Marshal(s.config)
	c.exec(ctx, "insert dhcp server", `INSERT INTO dhcp_servers
		(id, context_id, server_id, relay, mac, ip, host_id, status, config_json, first_seen, last_seen)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		s.id, s.key.ctx, s.key.serverID, s.key.relay, s.key.mac, s.ip, nullString(s.hostID), s.status, string(cfg),
		ms(s.firstSeen), ms(s.lastSeen))
}

func (c *Correlator) dbUpdateDHCPServer(ctx context.Context, s *dhcpServer) {
	cfg, _ := json.Marshal(s.config)
	c.exec(ctx, "update dhcp server", `UPDATE dhcp_servers SET ip = ?, host_id = ?, status = ?, config_json = ?, last_seen = ? WHERE id = ?`,
		s.ip, nullString(s.hostID), s.status, string(cfg), ms(s.lastSeen), s.id)
}

// loadDHCPServers reads dhcp_servers into the state.
func (s *state) loadDHCPServers(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, `SELECT id, context_id, server_id, relay, mac, ip, coalesce(host_id, ''), status, config_json,
		first_seen, last_seen FROM dhcp_servers ORDER BY id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		d := &dhcpServer{}
		var cfg string
		var first, last int64
		if err := rows.Scan(&d.id, &d.key.ctx, &d.key.serverID, &d.key.relay, &d.key.mac, &d.ip, &d.hostID, &d.status, &cfg,
			&first, &last); err != nil {
			return err
		}
		if err := json.Unmarshal([]byte(cfg), &d.config); err != nil || d.config == nil {
			d.config = map[string]string{}
		}
		d.firstSeen, d.lastSeen = fromMS(first), fromMS(last)
		s.dhcpServers[d.key] = d
		s.nextDHCPServerID = max(s.nextDHCPServerID, d.id)
	}
	return rows.Err()
}
