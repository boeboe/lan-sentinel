package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strings"
	"time"
)

// ErrNotFound is returned for an unknown host ID.
var ErrNotFound = errors.New("not found")

// ErrBadQuery is returned when a query does not match its explicit kind.
var ErrBadQuery = errors.New("invalid query")

func msOf(t time.Time) int64 { return t.UnixMilli() }

func timeOf(v int64) time.Time { return time.UnixMilli(v).UTC() }

func timePtr(v sql.NullInt64) *time.Time {
	if !v.Valid {
		return nil
	}
	t := timeOf(v.Int64)
	return &t
}

// where accumulates SQL conditions and their arguments.
type where struct {
	conds []string
	args  []any
}

func (w *where) add(cond string, args ...any) {
	w.conds = append(w.conds, cond)
	w.args = append(w.args, args...)
}

func (w *where) sql() string {
	if len(w.conds) == 0 {
		return ""
	}
	return " WHERE " + strings.Join(w.conds, " AND ")
}

const summaryColumns = `h.host_id, c.interface, h.mac, coalesce(h.vendor, ''), h.locally_administered, h.presence,
	coalesce(h.preferred_name, ''), coalesce(h.manufacturer, ''), coalesce(h.device_type, ''), h.first_seen, h.last_seen`

func scanSummary(rows interface{ Scan(...any) error }) (HostSummary, error) {
	var h HostSummary
	var la int
	var first, last int64
	err := rows.Scan(&h.HostID, &h.Interface, &h.MAC, &h.Vendor, &la, &h.Presence, &h.PreferredName, &h.Manufacturer,
		&h.DeviceType, &first, &last)
	h.LocallyAdministered, h.FirstSeen, h.LastSeen, h.IPs = la == 1, timeOf(first), timeOf(last), []string{}
	return h, err
}

// sortIPs orders addresses numerically, IPv4 first.
func sortIPs(ips []string) {
	sort.Slice(ips, func(i, j int) bool {
		a, errA := netip.ParseAddr(ips[i])
		b, errB := netip.ParseAddr(ips[j])
		if errA != nil || errB != nil {
			return ips[i] < ips[j]
		}
		return a.Less(b)
	})
}

// openIPs returns the open bindings of hosts, keyed by host ID.
func openIPs(ctx context.Context, tx *sql.Tx, hostIDs []string) (map[string][]string, error) {
	out := map[string][]string{}
	if len(hostIDs) == 0 {
		return out, nil
	}
	// One JSON parameter instead of one per host: SQLite limits bound
	// variables to 32766, and hosts are never pruned.
	ids, err := json.Marshal(hostIDs)
	if err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT host_id, ip FROM addresses
		WHERE ended_at IS NULL AND host_id IN (SELECT value FROM json_each(?))`, string(ids))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, ip string
		if err := rows.Scan(&id, &ip); err != nil {
			return nil, err
		}
		out[id] = append(out[id], ip)
	}
	for _, ips := range out {
		sortIPs(ips)
	}
	return out, rows.Err()
}

func placeholders(n int) string { return strings.TrimSuffix(strings.Repeat("?, ", n), ", ") }

func anys[T any](v []T) []any {
	out := make([]any, len(v))
	for i := range v {
		out[i] = v[i]
	}
	return out
}

// matchCondition restricts hosts h to those that ever matched a query.
func matchCondition(w *where, kind QueryKind, q string) {
	switch kind {
	case KindHost:
		w.add(`h.host_id = ?`, q)
	case KindMAC:
		w.add(`h.mac = ?`, q)
	case KindIP:
		w.add(`EXISTS (SELECT 1 FROM addresses a WHERE a.host_id = h.host_id AND a.ip = ?)`, q)
	case KindName:
		// preferred_name is always one of the host's names.
		w.add(`h.host_id IN (SELECT n.host_id FROM names n WHERE n.name = ? COLLATE NOCASE)`, q)
	}
}

// hostWhere builds the conditions of a host filter.
func hostWhere(f HostFilter) (where, error) {
	var w where
	if f.Interface != "" {
		w.add(`c.interface = ?`, f.Interface)
	}
	if f.Query != "" {
		kind, q, ok := Normalize(f.QueryKind, f.Query)
		if !ok {
			return w, fmt.Errorf("%w: %q is not a %s", ErrBadQuery, f.Query, f.QueryKind)
		}
		matchCondition(&w, kind, q)
	}
	switch {
	case f.Live && !f.NotLive:
		w.add(`h.presence IN ('ACTIVE', 'RECENT')`)
	case f.NotLive && !f.Live:
		w.add(`h.presence IN ('STALE', 'MISSING')`)
	}
	if f.Vendor != "" {
		w.add(`(instr(lower(coalesce(h.vendor, '')), lower(?)) > 0 OR instr(lower(coalesce(h.manufacturer, '')), lower(?)) > 0)`,
			f.Vendor, f.Vendor)
	}
	if f.Port > 0 {
		w.add(`EXISTS (SELECT 1 FROM services s WHERE s.host_id = h.host_id AND s.port = ? AND s.state = 'OPEN')`, f.Port)
	}
	if !f.SeenSince.IsZero() {
		w.add(`h.last_seen >= ?`, msOf(f.SeenSince))
	}
	return w, nil
}

// Hosts lists the inventory.
func (r *Reader) Hosts(ctx context.Context, f HostFilter) ([]HostSummary, error) {
	w, err := hostWhere(f)
	if err != nil {
		return nil, err
	}
	var out []HostSummary
	err = r.read(ctx, func(tx *sql.Tx) error {
		var err error
		out, err = hostsTx(ctx, tx, w)
		return err
	})
	return out, err
}

func hostsTx(ctx context.Context, tx *sql.Tx, w where) ([]HostSummary, error) {
	rows, err := tx.QueryContext(ctx, `SELECT `+summaryColumns+` FROM hosts h JOIN network_contexts c ON c.id = h.context_id`+
		w.sql()+` ORDER BY c.interface, h.mac`, w.args...)
	if err != nil {
		return nil, err
	}
	out := []HostSummary{}
	var ids []string
	for rows.Next() {
		h, err := scanSummary(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, h)
		ids = append(ids, h.HostID)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	ips, err := openIPs(ctx, tx, ids)
	if err != nil {
		return nil, err
	}
	for i := range out {
		if v := ips[out[i].HostID]; v != nil {
			out[i].IPs = v
		}
	}
	return out, nil
}

// Host returns the full record of one host: every address and name binding
// (closed ones too), services and identifications.
func (r *Reader) Host(ctx context.Context, id string) (Host, error) {
	var h Host
	err := r.read(ctx, func(tx *sql.Tx) error {
		var err error
		h, err = r.hostRecord(ctx, tx, id, nil, true)
		return err
	})
	return h, err
}

// hostRecord loads a host. With all, every binding; else the bindings in
// effect at at (or open now when at is nil).
func (r *Reader) hostRecord(ctx context.Context, tx *sql.Tx, id string, at *time.Time, all bool) (Host, error) {
	row := tx.QueryRowContext(ctx, `SELECT `+summaryColumns+` FROM hosts h JOIN network_contexts c ON c.id = h.context_id
		WHERE h.host_id = ?`, id)
	s, err := scanSummary(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Host{}, fmt.Errorf("host %s: %w", id, ErrNotFound)
	}
	if err != nil {
		return Host{}, err
	}
	h := Host{HostSummary: s, Addresses: []Binding{}, Names: []Name{}, Services: []Service{}, Identifications: []Identification{}}
	ips, err := openIPs(ctx, tx, []string{id})
	if err != nil {
		return Host{}, err
	}
	if v := ips[id]; v != nil {
		h.IPs = v
	}
	inEffect, args := `ended_at IS NULL`, []any{id}
	switch {
	case all:
		inEffect = `1`
	case at != nil:
		inEffect = `first_seen <= ? AND (ended_at IS NULL OR ended_at > ?)`
		args = append(args, msOf(*at), msOf(*at))
	}
	if h.Addresses, err = bindings(ctx, tx, `host_id = ? AND `+inEffect, args...); err != nil {
		return Host{}, err
	}
	if h.Names, err = r.names(ctx, tx, `host_id = ? AND `+inEffect, args...); err != nil {
		return Host{}, err
	}
	if h.Services, err = services(ctx, tx, id); err != nil {
		return Host{}, err
	}
	if h.Identifications, err = identifications(ctx, tx, id); err != nil {
		return Host{}, err
	}
	return h, nil
}

// bindings loads address bindings with their sources.
func bindings(ctx context.Context, tx *sql.Tx, cond string, args ...any) ([]Binding, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id, ip, first_seen, last_seen, ended_at, conflict FROM addresses WHERE `+cond+
		` ORDER BY first_seen, id`, args...)
	if err != nil {
		return nil, err
	}
	var out []Binding
	var ids []int64
	for rows.Next() {
		var b Binding
		var id, first, last int64
		var ended sql.NullInt64
		var conflict int
		if err := rows.Scan(&id, &b.IP, &first, &last, &ended, &conflict); err != nil {
			rows.Close()
			return nil, err
		}
		b.FirstSeen, b.LastSeen, b.EndedAt, b.Conflict = timeOf(first), timeOf(last), timePtr(ended), conflict == 1
		out = append(out, b)
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i, id := range ids {
		src, err := tx.QueryContext(ctx, `SELECT source, first_seen, last_seen FROM address_sources WHERE address_id = ? ORDER BY first_seen, source`, id)
		if err != nil {
			return nil, err
		}
		for src.Next() {
			var s SourceSeen
			var first, last int64
			if err := src.Scan(&s.Source, &first, &last); err != nil {
				src.Close()
				return nil, err
			}
			s.FirstSeen, s.LastSeen = timeOf(first), timeOf(last)
			out[i].Sources = append(out[i].Sources, s)
		}
		src.Close()
	}
	if out == nil {
		out = []Binding{}
	}
	return out, nil
}

func (r *Reader) names(ctx context.Context, tx *sql.Tx, cond string, args ...any) ([]Name, error) {
	rows, err := tx.QueryContext(ctx, `SELECT name, name_type, source, first_seen, last_seen, ended_at FROM names WHERE `+cond+
		` ORDER BY first_seen, id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Name{}
	now := r.now()
	for rows.Next() {
		var n Name
		var first, last int64
		var ended sql.NullInt64
		if err := rows.Scan(&n.Name, &n.Type, &n.Source, &first, &last, &ended); err != nil {
			return nil, err
		}
		n.FirstSeen, n.LastSeen, n.EndedAt = timeOf(first), timeOf(last), timePtr(ended)
		expiry := r.nameExpiryD()
		n.Stale = n.EndedAt == nil && expiry > 0 && now.Sub(n.LastSeen) >= expiry
		out = append(out, n)
	}
	return out, rows.Err()
}

func services(ctx context.Context, tx *sql.Tx, hostID string) ([]Service, error) {
	rows, err := tx.QueryContext(ctx, `SELECT proto, port, state, first_seen, last_seen, last_result_at FROM services
		WHERE host_id = ? ORDER BY proto, port`, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Service{}
	for rows.Next() {
		s, err := scanService(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func scanService(rows interface{ Scan(...any) error }, extra ...any) (Service, error) {
	var s Service
	var first, last, result int64
	err := rows.Scan(append([]any{&s.Proto, &s.Port, &s.State, &first, &last, &result}, extra...)...)
	s.FirstSeen, s.LastSeen, s.LastResultAt = timeOf(first), timeOf(last), timeOf(result)
	return s, err
}

func identifications(ctx context.Context, tx *sql.Tx, hostID string) ([]Identification, error) {
	rows, err := tx.QueryContext(ctx, `SELECT field, value, confidence, source, evidence_json, first_seen, last_seen
		FROM identifications WHERE host_id = ? ORDER BY first_seen, id`, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Identification{}
	for rows.Next() {
		var i Identification
		var ev string
		var first, last int64
		if err := rows.Scan(&i.Field, &i.Value, &i.Confidence, &i.Source, &ev, &first, &last); err != nil {
			return nil, err
		}
		i.Evidence, i.FirstSeen, i.LastSeen = []byte(ev), timeOf(first), timeOf(last)
		out = append(out, i)
	}
	return out, rows.Err()
}

type contextRow struct {
	id    int64
	iface string
}

func contexts(ctx context.Context, tx *sql.Tx, iface string) ([]contextRow, error) {
	var w where
	if iface != "" {
		w.add(`interface = ?`, iface)
	}
	rows, err := tx.QueryContext(ctx, `SELECT id, interface FROM network_contexts`+w.sql()+` ORDER BY interface`, w.args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []contextRow
	for rows.Next() {
		var c contextRow
		if err := rows.Scan(&c.id, &c.iface); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Find answers `hosts find` (docs/CLI.md §4, docs/DATA_MODEL.md §4).
func (r *Reader) Find(ctx context.Context, q FindQuery) (FindResult, error) {
	kind, norm, ok := Normalize(q.Kind, q.Query)
	if !ok {
		return FindResult{}, fmt.Errorf("%w: %q is not a %s", ErrBadQuery, q.Query, q.Kind)
	}
	if q.At != nil {
		at := q.At.UTC()
		q.At = &at
	}
	res := FindResult{Kind: kind, Query: norm, At: q.At, Hosts: []FoundHost{}}
	err := r.read(ctx, func(tx *sql.Tx) error {
		if kind == KindIP {
			return r.findIP(ctx, tx, &res, q.Interface)
		}
		ids, err := matchingHosts(ctx, tx, kind, norm, q.Interface, q.At)
		if err != nil {
			return err
		}
		for _, id := range ids {
			h, err := r.hostRecord(ctx, tx, id, q.At, false)
			if err != nil {
				return err
			}
			res.Hosts = append(res.Hosts, FoundHost{Host: h})
		}
		return nil
	})
	return res, err
}

// matchingHosts returns the hosts a MAC, name or host query matches now
// (open name) or at a time.
func matchingHosts(ctx context.Context, tx *sql.Tx, kind QueryKind, q, iface string, at *time.Time) ([]string, error) {
	var w where
	if iface != "" {
		w.add(`c.interface = ?`, iface)
	}
	switch kind {
	case KindName:
		inEffect, args := `n.ended_at IS NULL`, []any{q}
		if at != nil {
			inEffect = `n.first_seen <= ? AND (n.ended_at IS NULL OR n.ended_at > ?)`
			args = append(args, msOf(*at), msOf(*at))
		}
		w.add(`h.host_id IN (SELECT n.host_id FROM names n WHERE n.name = ? COLLATE NOCASE AND `+inEffect+`)`, args...)
	default:
		matchCondition(&w, kind, q)
		if at != nil {
			w.add(`h.first_seen <= ?`, msOf(*at))
		}
	}
	rows, err := tx.QueryContext(ctx, `SELECT h.host_id FROM hosts h JOIN network_contexts c ON c.id = h.context_id`+
		w.sql()+` ORDER BY c.interface, h.mac`, w.args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// holding is a binding row with its holder.
type holding struct {
	Holding
	id int64
}

func holdings(ctx context.Context, tx *sql.Tx, cond string, args ...any) ([]holding, error) {
	rows, err := tx.QueryContext(ctx, `SELECT a.id, c.interface, a.host_id, h.mac, a.ip, a.first_seen, a.last_seen, a.ended_at, a.conflict
		FROM addresses a JOIN network_contexts c ON c.id = a.context_id JOIN hosts h ON h.host_id = a.host_id WHERE `+cond, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []holding
	for rows.Next() {
		var x holding
		var first, last int64
		var ended sql.NullInt64
		var conflict int
		if err := rows.Scan(&x.id, &x.Interface, &x.HostID, &x.MAC, &x.Binding.IP, &first, &last, &ended, &conflict); err != nil {
			return nil, err
		}
		x.Binding.FirstSeen, x.Binding.LastSeen, x.Binding.EndedAt, x.Binding.Conflict = timeOf(first), timeOf(last), timePtr(ended), conflict == 1
		out = append(out, x)
	}
	return out, rows.Err()
}

func firstHolding(ctx context.Context, tx *sql.Tx, cond string, args ...any) (*Holding, error) {
	hs, err := holdings(ctx, tx, cond+` LIMIT 1`, args...)
	if err != nil || len(hs) == 0 {
		return nil, err
	}
	return &hs[0].Holding, nil
}

// findIP answers an address query: the open bindings, or the point-in-time
// holders with what replaced them, per interface.
func (r *Reader) findIP(ctx context.Context, tx *sql.Tx, res *FindResult, iface string) error {
	ctxs, err := contexts(ctx, tx, iface)
	if err != nil {
		return err
	}
	ip := res.Query
	for _, c := range ctxs {
		var hs []holding
		if res.At == nil {
			hs, err = holdings(ctx, tx, `a.context_id = ? AND a.ip = ? AND a.ended_at IS NULL ORDER BY a.last_seen DESC`, c.id, ip)
		} else {
			t := msOf(*res.At)
			hs, err = holdings(ctx, tx, `a.context_id = ? AND a.ip = ? AND a.first_seen <= ? AND (a.ended_at IS NULL OR a.ended_at > ?)
				ORDER BY a.last_seen DESC`, c.id, ip, t, t)
		}
		if err != nil {
			return err
		}
		if len(hs) == 0 {
			if res.At != nil {
				if err := neighbours(ctx, tx, res, c, ip); err != nil {
					return err
				}
			}
			continue
		}
		for _, x := range hs {
			fh, err := r.foundHolder(ctx, tx, res, c, x, len(hs) >= 2)
			if err != nil {
				return err
			}
			res.Hosts = append(res.Hosts, fh)
		}
	}
	return nil
}

func (r *Reader) foundHolder(ctx context.Context, tx *sql.Tx, res *FindResult, c contextRow, x holding, conflict bool) (FoundHost, error) {
	h, err := r.hostRecord(ctx, tx, x.HostID, res.At, false)
	if err != nil {
		return FoundHost{}, err
	}
	b := x.Binding
	if bs, err := bindings(ctx, tx, `id = ?`, x.id); err == nil && len(bs) == 1 {
		b = bs[0]
	} else if err != nil {
		return FoundHost{}, err
	}
	fh := FoundHost{Host: h, Binding: &b, Conflict: b.Conflict}
	if res.At == nil {
		return fh, nil
	}
	t := msOf(*res.At)
	fh.Conflict = conflict
	fh.Unconfirmed = res.At.After(b.LastSeen)
	// What replaced the binding: the first binding of the address by another
	// host that started when or after it ended (a claimant during the binding
	// is a conflict, not a successor), and the host's next address.
	if b.EndedAt != nil {
		end := msOf(*b.EndedAt)
		if fh.ReplacedBy, err = firstHolding(ctx, tx, `a.context_id = ? AND a.ip = ? AND a.host_id != ? AND a.first_seen >= ?
			ORDER BY a.first_seen, a.id`, c.id, res.Query, x.HostID, end); err != nil {
			return FoundHost{}, err
		}
		if fh.MovedTo, err = firstHolding(ctx, tx, `a.host_id = ? AND a.ip != ? AND a.first_seen >= ? ORDER BY a.first_seen, a.id`,
			x.HostID, res.Query, end); err != nil {
			return FoundHost{}, err
		}
	}
	if conflict {
		evs, err := queryEvents(ctx, tx, ` WHERE e.type = 'DUPLICATE_IP_DETECTED' AND e.context_id = ? AND e.new_value = ? AND e.ts <= ?
			ORDER BY e.ts DESC, e.id DESC LIMIT 1`, c.id, res.Query, t)
		if err != nil {
			return FoundHost{}, err
		}
		if len(evs) == 1 {
			fh.ConflictEvent = &evs[0]
		}
	}
	return fh, nil
}

// neighbours adds the bindings before and after At for an address with no
// holder at At (none if the address was never bound on that interface).
func neighbours(ctx context.Context, tx *sql.Tx, res *FindResult, c contextRow, ip string) error {
	t := msOf(*res.At)
	prev, err := firstHolding(ctx, tx, `a.context_id = ? AND a.ip = ? AND a.ended_at <= ? ORDER BY a.ended_at DESC, a.id DESC`, c.id, ip, t)
	if err != nil {
		return err
	}
	next, err := firstHolding(ctx, tx, `a.context_id = ? AND a.ip = ? AND a.first_seen > ? ORDER BY a.first_seen, a.id`, c.id, ip, t)
	if err != nil {
		return err
	}
	if prev != nil {
		res.Previous = append(res.Previous, *prev)
	}
	if next != nil {
		res.Next = append(res.Next, *next)
	}
	return nil
}

const eventColumns = `e.id, e.ts, e.type, e.severity, coalesce(c.interface, ''), coalesce(e.host_id, ''), coalesce(h.mac, ''),
	coalesce(e.related_host_id, ''), coalesce(rh.mac, ''), coalesce(e.old_value, ''), coalesce(e.new_value, ''), e.cause,
	coalesce(e.observation_id, 0), e.evidence_json, e.clock_synced`

const eventJoins = ` FROM events e LEFT JOIN network_contexts c ON c.id = e.context_id
	LEFT JOIN hosts h ON h.host_id = e.host_id LEFT JOIN hosts rh ON rh.host_id = e.related_host_id`

// queryEvents runs an event query; tail is the WHERE clause (if any) and
// the ordering.
func queryEvents(ctx context.Context, tx *sql.Tx, tail string, args ...any) ([]Event, error) {
	rows, err := tx.QueryContext(ctx, `SELECT `+eventColumns+eventJoins+tail, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Event{}
	for rows.Next() {
		var e Event
		var ts int64
		var ev string
		var synced int
		if err := rows.Scan(&e.ID, &ts, &e.Type, &e.Severity, &e.Interface, &e.HostID, &e.MAC, &e.RelatedHostID, &e.RelatedMAC,
			&e.Old, &e.New, &e.Cause, &e.ObservationID, &ev, &synced); err != nil {
			return nil, err
		}
		e.TS, e.Evidence, e.ClockSynced = timeOf(ts), []byte(ev), synced == 1
		out = append(out, e)
	}
	return out, rows.Err()
}

func timeRange(w *where, col string, since, until time.Time) {
	if !since.IsZero() {
		w.add(col+` >= ?`, msOf(since))
	}
	if !until.IsZero() {
		w.add(col+` <= ?`, msOf(until))
	}
}

// History returns a timeline in time order (docs/CLI.md §4): for a host or
// MAC every event of the host (or of each host with that MAC); for an IP
// every event whose old value, new value or evidence IP is that IP; for a
// name every event of the hosts that ever held it.
func (r *Reader) History(ctx context.Context, q HistoryQuery) ([]Event, error) {
	kind, norm, ok := Normalize(q.Kind, q.Query)
	if !ok {
		return nil, fmt.Errorf("%w: %q is not a %s", ErrBadQuery, q.Query, q.Kind)
	}
	var w where
	if kind == KindIP {
		w.add(`(e.old_value = ? OR e.new_value = ? OR json_extract(e.evidence_json, '$.ip') = ?)`, norm, norm, norm)
		if q.Interface != "" {
			w.add(`c.interface = ?`, q.Interface)
		}
	} else {
		var hw where
		if q.Interface != "" {
			hw.add(`c.interface = ?`, q.Interface)
		}
		matchCondition(&hw, kind, norm)
		sub := `SELECT h.host_id FROM hosts h JOIN network_contexts c ON c.id = h.context_id` + hw.sql()
		w.add(`(e.host_id IN (`+sub+`) OR e.related_host_id IN (`+sub+`))`, append(hw.args, hw.args...)...)
	}
	timeRange(&w, "e.ts", q.Since, q.Until)
	var out []Event
	err := r.read(ctx, func(tx *sql.Tx) error {
		var err error
		out, err = queryEvents(ctx, tx, w.sql()+` ORDER BY e.ts, e.id`, w.args...)
		return err
	})
	return out, err
}

// normalizeFilter returns a MAC or IP filter value in stored form; empty
// stays empty.
func normalizeFilter(kind QueryKind, v string) (string, error) {
	if v == "" {
		return "", nil
	}
	k, norm := Classify(v)
	if k != kind {
		return "", fmt.Errorf("%w: %q is not a %s", ErrBadQuery, v, kind)
	}
	return norm, nil
}

// DefaultEventLimit bounds an events query without a limit, so a request
// never loads two years of events at once.
const DefaultEventLimit = 10000

// Events lists the latest events matching f (at most f.Limit, default
// DefaultEventLimit), in time order.
func (r *Reader) Events(ctx context.Context, f EventFilter) ([]Event, error) {
	var err error
	if f.MAC, err = normalizeFilter(KindMAC, f.MAC); err != nil {
		return nil, err
	}
	if f.IP, err = normalizeFilter(KindIP, f.IP); err != nil {
		return nil, err
	}
	if f.Limit <= 0 {
		f.Limit = DefaultEventLimit
	}
	var w where
	timeRange(&w, "e.ts", f.Since, f.Until)
	if len(f.Types) > 0 {
		w.add(`e.type IN (`+placeholders(len(f.Types))+`)`, anys(f.Types)...)
	}
	if f.Interface != "" {
		w.add(`c.interface = ?`, f.Interface)
	}
	if f.MAC != "" {
		w.add(`(e.host_id IN (SELECT host_id FROM hosts WHERE mac = ?) OR e.related_host_id IN (SELECT host_id FROM hosts WHERE mac = ?))`, f.MAC, f.MAC)
	}
	if f.IP != "" {
		w.add(`(e.old_value = ? OR e.new_value = ? OR json_extract(e.evidence_json, '$.ip') = ?)`, f.IP, f.IP, f.IP)
	}
	if f.HostID != "" {
		w.add(`(e.host_id = ? OR e.related_host_id = ?)`, f.HostID, f.HostID)
	}
	order := fmt.Sprintf(` ORDER BY e.ts DESC, e.id DESC LIMIT %d`, f.Limit)
	var out []Event
	err = r.read(ctx, func(tx *sql.Tx) error {
		var err error
		out, err = queryEvents(ctx, tx, w.sql()+order, w.args...)
		return err
	})
	reverse(out)
	return out, err
}

func reverse[T any](s []T) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}

// DefaultObservationLimit is the default `observations list --limit`.
const DefaultObservationLimit = 1000

// normalize puts the MAC and IP filters in stored form.
func (f *ObservationFilter) normalize() error {
	var err error
	if f.MAC, err = normalizeFilter(KindMAC, f.MAC); err != nil {
		return err
	}
	f.IP, err = normalizeFilter(KindIP, f.IP)
	return err
}

// Observations lists the latest raw observations matching f, in time order.
// Filters other than the host and time walk the time index back from the
// latest observation until the limit is filled.
func (r *Reader) Observations(ctx context.Context, f ObservationFilter) ([]Observation, error) {
	if err := f.normalize(); err != nil {
		return nil, err
	}
	w := observationWhere(f, "o.ts")
	limit := f.Limit
	if limit <= 0 {
		limit = DefaultObservationLimit
	}
	out := []Observation{}
	err := r.read(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT o.id, o.ts, c.interface, o.source, coalesce(o.mac, ''), coalesce(o.ip, ''),
			coalesce(o.hostname, ''), coalesce(o.name_type, ''), coalesce(o.service_json, ''), coalesce(o.meta_json, ''), coalesce(o.host_id, '')
			FROM observations o JOIN network_contexts c ON c.id = o.context_id`+w.sql()+
			fmt.Sprintf(` ORDER BY o.ts DESC, o.id DESC LIMIT %d`, limit), w.args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var o Observation
			var ts int64
			var svc, meta string
			if err := rows.Scan(&o.ID, &ts, &o.Interface, &o.Source, &o.MAC, &o.IP, &o.Hostname, &o.NameType, &svc, &meta, &o.HostID); err != nil {
				return err
			}
			o.TS = timeOf(ts)
			if svc != "" {
				o.Service = []byte(svc)
			}
			if meta != "" {
				o.Meta = []byte(meta)
			}
			out = append(out, o)
		}
		return rows.Err()
	})
	reverse(out)
	return out, err
}

func observationWhere(f ObservationFilter, tsCol string) where {
	var w where
	timeRange(&w, tsCol, f.Since, f.Until)
	alias := strings.Split(tsCol, ".")[0]
	if f.HostID != "" {
		w.add(alias+`.host_id = ?`, f.HostID)
	}
	if f.Unbound {
		w.add(alias + `.host_id IS NULL`)
	}
	if f.Interface != "" {
		w.add(`c.interface = ?`, f.Interface)
	}
	if f.MAC != "" {
		w.add(alias+`.mac = ?`, f.MAC)
	}
	if f.IP != "" {
		w.add(alias+`.ip = ?`, f.IP)
	}
	if f.Source != "" {
		w.add(alias+`.source = ?`, f.Source)
	}
	return w
}

// Rollups lists the latest hourly roll-ups matching f (Since and Until
// apply to the hour), in time order.
func (r *Reader) Rollups(ctx context.Context, f ObservationFilter) ([]Rollup, error) {
	if err := f.normalize(); err != nil {
		return nil, err
	}
	w := observationWhere(f, "o.hour")
	limit := f.Limit
	if limit <= 0 {
		limit = DefaultObservationLimit
	}
	out := []Rollup{}
	err := r.read(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT o.hour, c.interface, coalesce(o.host_id, ''), o.source, coalesce(o.mac, ''), coalesce(o.ip, ''),
			o.count, o.first_ts, o.last_ts FROM observation_rollups o JOIN network_contexts c ON c.id = o.context_id`+w.sql()+
			fmt.Sprintf(` ORDER BY o.hour DESC, o.id DESC LIMIT %d`, limit), w.args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var x Rollup
			var hour, first, last int64
			if err := rows.Scan(&hour, &x.Interface, &x.HostID, &x.Source, &x.MAC, &x.IP, &x.Count, &first, &last); err != nil {
				return err
			}
			x.Hour, x.FirstTS, x.LastTS = timeOf(hour), timeOf(first), timeOf(last)
			out = append(out, x)
		}
		return rows.Err()
	})
	reverse(out)
	return out, err
}

// Services lists probe results with the host's current addresses.
func (r *Reader) Services(ctx context.Context, f ServiceFilter) ([]ServiceRow, error) {
	var w where
	if f.Port > 0 {
		w.add(`s.port = ?`, f.Port)
	}
	if f.State != "" {
		w.add(`s.state = ?`, strings.ToUpper(f.State))
	}
	if f.Interface != "" {
		w.add(`c.interface = ?`, f.Interface)
	}
	out := []ServiceRow{}
	err := r.read(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT s.proto, s.port, s.state, s.first_seen, s.last_seen, s.last_result_at, c.interface, h.host_id, h.mac
			FROM services s JOIN hosts h ON h.host_id = s.host_id JOIN network_contexts c ON c.id = h.context_id`+w.sql()+
			` ORDER BY s.port, s.proto, c.interface, h.mac`, w.args...)
		if err != nil {
			return err
		}
		var ids []string
		for rows.Next() {
			var row ServiceRow
			svc, err := scanService(rows, &row.Interface, &row.HostID, &row.MAC)
			if err != nil {
				rows.Close()
				return err
			}
			row.Service, row.IPs = svc, []string{}
			out = append(out, row)
			ids = append(ids, row.HostID)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		ips, err := openIPs(ctx, tx, ids)
		if err != nil {
			return err
		}
		for i := range out {
			if v := ips[out[i].HostID]; v != nil {
				out[i].IPs = v
			}
		}
		return nil
	})
	return out, err
}

// Interfaces lists the network contexts with their open prefixes, host
// counts and the state of their last INTERFACE_UP/DOWN event ("unknown"
// before any). The daemon replaces state and MAC with live values.
func (r *Reader) Interfaces(ctx context.Context) ([]InterfaceInfo, error) {
	out := []InterfaceInfo{}
	err := r.read(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT c.id, c.interface, c.first_seen, c.last_seen,
			(SELECT count(*) FROM hosts h WHERE h.context_id = c.id),
			coalesce((SELECT type FROM (
				SELECT * FROM (SELECT type, ts, id FROM events WHERE context_id = c.id AND type = 'INTERFACE_UP' ORDER BY ts DESC, id DESC LIMIT 1)
				UNION ALL
				SELECT * FROM (SELECT type, ts, id FROM events WHERE context_id = c.id AND type = 'INTERFACE_DOWN' ORDER BY ts DESC, id DESC LIMIT 1)
			) ORDER BY ts DESC, id DESC LIMIT 1), '')
			FROM network_contexts c ORDER BY c.interface`)
		if err != nil {
			return err
		}
		var ids []int64
		for rows.Next() {
			var i InterfaceInfo
			var id, first, last int64
			var ev string
			if err := rows.Scan(&id, &i.Name, &first, &last, &i.Hosts, &ev); err != nil {
				rows.Close()
				return err
			}
			i.FirstSeen, i.LastSeen, i.Prefixes = timeOf(first), timeOf(last), []string{}
			switch ev {
			case "INTERFACE_UP":
				i.State = "up"
			case "INTERFACE_DOWN":
				i.State = "down"
			default:
				i.State = "unknown"
			}
			out = append(out, i)
			ids = append(ids, id)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for k, id := range ids {
			ps, err := tx.QueryContext(ctx, `SELECT prefix FROM context_prefixes WHERE context_id = ? AND ended_at IS NULL ORDER BY prefix`, id)
			if err != nil {
				return err
			}
			for ps.Next() {
				var p string
				if err := ps.Scan(&p); err != nil {
					ps.Close()
					return err
				}
				out[k].Prefixes = append(out[k].Prefixes, p)
			}
			ps.Close()
		}
		return nil
	})
	return out, err
}

// countedTables are the tables `db info` counts.
var countedTables = []string{
	"network_contexts", "context_prefixes", "hosts", "addresses", "address_sources", "names", "services",
	"identifications", "observations", "observation_rollups", "events", "scans", "runtime_state",
}

// DBInfo describes the database file and counts the rows of every table.
func (r *Reader) DBInfo(ctx context.Context) (DBInfo, error) {
	return r.dbInfo(ctx, true)
}

// DBSummary is DBInfo without the row counts, which scan whole tables; it
// is cheap enough for every status request and metrics scrape.
func (r *Reader) DBSummary(ctx context.Context) (DBInfo, error) {
	return r.dbInfo(ctx, false)
}

func (r *Reader) dbInfo(ctx context.Context, rows bool) (DBInfo, error) {
	info := DBInfo{Path: r.path}
	if fi, err := os.Stat(r.path); err == nil {
		info.Size = fi.Size()
	}
	if fi, err := os.Stat(r.path + "-wal"); err == nil {
		info.WALSize = fi.Size()
	}
	err := r.read(ctx, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx, `PRAGMA journal_mode`).Scan(&info.JournalMode); err != nil {
			return err
		}
		if r.Immutable && walHeader(r.path) {
			// An immutable open reports "delete"; the file header says
			// the database is in WAL mode.
			info.JournalMode = "wal"
		}
		if err := tx.QueryRowContext(ctx, `SELECT coalesce(max(version), 0) FROM schema_migrations`).Scan(&info.SchemaVersion); err != nil {
			return err
		}
		if err := tx.QueryRowContext(ctx, `SELECT (page_count - freelist_count) * page_size
			FROM pragma_page_count(), pragma_freelist_count(), pragma_page_size()`).Scan(&info.UsedSize); err != nil {
			return err
		}
		if !rows {
			return nil
		}
		info.Rows = map[string]int64{}
		for _, t := range countedTables {
			var n int64
			if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM `+t).Scan(&n); err != nil {
				return err
			}
			info.Rows[t] = n
		}
		return nil
	})
	return info, err
}

// Check runs PRAGMA integrity_check (`db check`).
func (r *Reader) Check(ctx context.Context) (CheckResult, error) {
	var res CheckResult
	err := r.read(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `PRAGMA integrity_check`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				return err
			}
			if s != "ok" {
				res.Problems = append(res.Problems, s)
			}
		}
		return rows.Err()
	})
	res.OK = err == nil && len(res.Problems) == 0
	return res, err
}

// Evidence answers `hosts evidence` for one host.
func (r *Reader) Evidence(ctx context.Context, id string, since time.Time) (Evidence, error) {
	var ev Evidence
	err := r.read(ctx, func(tx *sql.Tx) error {
		var err error
		ev, err = r.evidenceTx(ctx, tx, id, since)
		return err
	})
	return ev, err
}

// EvidenceFor answers `hosts evidence` for every host that ever matched the
// filter, in one read transaction (one snapshot).
func (r *Reader) EvidenceFor(ctx context.Context, f HostFilter, since time.Time) ([]Evidence, error) {
	w, err := hostWhere(f)
	if err != nil {
		return nil, err
	}
	out := []Evidence{}
	err = r.read(ctx, func(tx *sql.Tx) error {
		hosts, err := hostsTx(ctx, tx, w)
		if err != nil {
			return err
		}
		for _, h := range hosts {
			ev, err := r.evidenceTx(ctx, tx, h.HostID, since)
			if err != nil {
				return err
			}
			out = append(out, ev)
		}
		return nil
	})
	return out, err
}

func (r *Reader) evidenceTx(ctx context.Context, tx *sql.Tx, id string, since time.Time) (Evidence, error) {
	ev := Evidence{Counts: []SourceCount{}}
	var err error
	if ev.Host, err = r.hostRecord(ctx, tx, id, nil, true); err != nil {
		return ev, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT source, ip, sum(n), min(first), max(last) FROM (
			SELECT source, coalesce(ip, '') AS ip, count(*) AS n, min(ts) AS first, max(ts) AS last
			FROM observations WHERE host_id = ? AND ts >= ? GROUP BY source, ip
			UNION ALL
			SELECT source, coalesce(ip, ''), sum(count), min(first_ts), max(last_ts)
			FROM observation_rollups WHERE host_id = ? AND last_ts >= ? GROUP BY source, ip
		) GROUP BY source, ip ORDER BY source, ip`, id, msOf(since), id, msOf(since))
	if err != nil {
		return ev, err
	}
	for rows.Next() {
		var c SourceCount
		var first, last int64
		if err := rows.Scan(&c.Source, &c.IP, &c.Count, &first, &last); err != nil {
			rows.Close()
			return ev, err
		}
		c.FirstSeen, c.LastSeen = timeOf(first), timeOf(last)
		ev.Counts = append(ev.Counts, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return ev, err
	}
	var w where
	w.add(`(e.host_id = ? OR e.related_host_id = ?)`, id, id)
	timeRange(&w, "e.ts", since, time.Time{})
	ev.Events, err = queryEvents(ctx, tx, w.sql()+` ORDER BY e.ts, e.id`, w.args...)
	return ev, err
}

// ActiveState is the active-discovery kill switch (docs/DATA_MODEL.md §8):
// the persisted runtime_state row, and whether LAN_SENTINEL_ACTIVE_DISABLED
// forces it regardless (Forced, set by the caller).
type ActiveState struct {
	Disabled bool       `json:"disabled"`
	Reason   string     `json:"reason,omitempty"`
	By       string     `json:"by,omitempty"`
	At       *time.Time `json:"at,omitempty"`
	Forced   bool       `json:"forced,omitempty"`
}

// ActiveState reads the persisted kill switch; no row means enabled.
func (r *Reader) ActiveState(ctx context.Context) (ActiveState, error) {
	var a ActiveState
	err := r.read(ctx, func(tx *sql.Tx) error {
		var v string
		err := tx.QueryRowContext(ctx, `SELECT value FROM runtime_state WHERE key = 'active_disabled'`).Scan(&v)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		return json.Unmarshal([]byte(v), &a)
	})
	return a, err
}

// HostCounts counts hosts per interface and presence.
func (r *Reader) HostCounts(ctx context.Context) (map[string]map[string]int, error) {
	out := map[string]map[string]int{}
	err := r.read(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT c.interface, h.presence, count(*) FROM hosts h
			JOIN network_contexts c ON c.id = h.context_id GROUP BY c.interface, h.presence`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var iface, presence string
			var n int
			if err := rows.Scan(&iface, &presence, &n); err != nil {
				return err
			}
			if out[iface] == nil {
				out[iface] = map[string]int{}
			}
			out[iface][presence] = n
		}
		return rows.Err()
	})
	return out, err
}

// walHeader reports whether the database file header marks WAL mode (read
// and write format versions 2, bytes 18 and 19).
func walHeader(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var h [20]byte
	if _, err := f.ReadAt(h[:], 0); err != nil {
		return false
	}
	return h[18] == 2 && h[19] == 2
}
