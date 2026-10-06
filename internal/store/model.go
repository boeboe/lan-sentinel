package store

import (
	"encoding/json"
	"net"
	"net/netip"
	"regexp"
	"strings"
	"time"
)

// The read model: what the API returns and the CLI prints. JSON field names
// are the API contract (docs/API.md).

// HostSummary is one row of the inventory.
type HostSummary struct {
	HostID              string    `json:"host_id"`
	Interface           string    `json:"interface"`
	MAC                 string    `json:"mac"`
	Vendor              string    `json:"vendor,omitempty"`
	LocallyAdministered bool      `json:"locally_administered"`
	Presence            string    `json:"presence"`
	PreferredName       string    `json:"preferred_name,omitempty"`
	Manufacturer        string    `json:"manufacturer,omitempty"`
	DeviceType          string    `json:"device_type,omitempty"`
	IPs                 []string  `json:"ips"` // open address bindings
	FirstSeen           time.Time `json:"first_seen"`
	LastSeen            time.Time `json:"last_seen"`
}

// Binding is an address binding with its interval (docs/DATA_MODEL.md §3).
type Binding struct {
	IP        string       `json:"ip"`
	FirstSeen time.Time    `json:"first_seen"`
	LastSeen  time.Time    `json:"last_seen"`
	EndedAt   *time.Time   `json:"ended_at"`
	Conflict  bool         `json:"conflict"`
	Sources   []SourceSeen `json:"sources,omitempty"`
}

// SourceSeen says when a source confirmed an attribute.
type SourceSeen struct {
	Source    string    `json:"source"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// Name is a hostname binding. Stale: not confirmed for identity.name_expiry
// (docs/DATA_MODEL.md §5.4); stale names stay in effect.
type Name struct {
	Name      string     `json:"name"`
	Type      string     `json:"type"`
	Source    string     `json:"source"`
	FirstSeen time.Time  `json:"first_seen"`
	LastSeen  time.Time  `json:"last_seen"`
	EndedAt   *time.Time `json:"ended_at"`
	Stale     bool       `json:"stale"`
}

// Service is the current probe result for one protocol/port.
type Service struct {
	Proto        string    `json:"proto"`
	Port         int       `json:"port"`
	State        string    `json:"state"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
	LastResultAt time.Time `json:"last_result_at"`
}

// Identification is a derived fact with confidence and evidence.
type Identification struct {
	Field      string          `json:"field"`
	Value      string          `json:"value"`
	Confidence float64         `json:"confidence"`
	Source     string          `json:"source"`
	Evidence   json.RawMessage `json:"evidence"`
	FirstSeen  time.Time       `json:"first_seen"`
	LastSeen   time.Time       `json:"last_seen"`
}

// Host is a full host record.
type Host struct {
	HostSummary
	Addresses       []Binding        `json:"addresses"`
	Names           []Name           `json:"names"`
	Services        []Service        `json:"services"`
	Identifications []Identification `json:"identifications"`
}

// Event is a stored event (docs/DATA_MODEL.md §7).
type Event struct {
	ID            int64           `json:"id,omitempty"`
	TS            time.Time       `json:"ts"`
	Type          string          `json:"type"`
	Severity      string          `json:"severity"`
	Interface     string          `json:"interface,omitempty"`
	HostID        string          `json:"host_id,omitempty"`
	MAC           string          `json:"mac,omitempty"`
	RelatedHostID string          `json:"related_host_id,omitempty"`
	RelatedMAC    string          `json:"related_mac,omitempty"`
	Old           string          `json:"old,omitempty"`
	New           string          `json:"new,omitempty"`
	Cause         string          `json:"cause"`
	ObservationID int64           `json:"observation_id,omitempty"`
	Evidence      json.RawMessage `json:"evidence"`
	ClockSynced   bool            `json:"clock_synced"`
}

// EvidenceIP returns the IP of the event's evidence snapshot.
func (e Event) EvidenceIP() string {
	var ev struct {
		IP string `json:"ip"`
	}
	_ = json.Unmarshal(e.Evidence, &ev)
	return ev.IP
}

// Observation is a stored raw observation.
type Observation struct {
	ID        int64           `json:"id"`
	TS        time.Time       `json:"ts"`
	Interface string          `json:"interface"`
	Source    string          `json:"source"`
	MAC       string          `json:"mac,omitempty"`
	IP        string          `json:"ip,omitempty"`
	Hostname  string          `json:"hostname,omitempty"`
	NameType  string          `json:"name_type,omitempty"`
	Service   json.RawMessage `json:"service,omitempty"`
	Meta      json.RawMessage `json:"meta,omitempty"`
	HostID    string          `json:"host_id,omitempty"`
}

// Rollup is an hourly roll-up of observations.
type Rollup struct {
	Hour      time.Time `json:"hour"`
	Interface string    `json:"interface"`
	HostID    string    `json:"host_id,omitempty"`
	Source    string    `json:"source"`
	MAC       string    `json:"mac,omitempty"`
	IP        string    `json:"ip,omitempty"`
	Count     int64     `json:"count"`
	FirstTS   time.Time `json:"first_ts"`
	LastTS    time.Time `json:"last_ts"`
}

// ServiceRow is one row of `services list`.
type ServiceRow struct {
	Service
	Interface string   `json:"interface"`
	HostID    string   `json:"host_id"`
	MAC       string   `json:"mac"`
	IPs       []string `json:"ips"`
}

// InterfaceInfo is one monitored interface (network context).
type InterfaceInfo struct {
	Name      string    `json:"name"`
	State     string    `json:"state"` // up, down or unknown
	MAC       string    `json:"mac,omitempty"`
	Prefixes  []string  `json:"prefixes"`
	Passive   bool      `json:"passive"`
	Active    bool      `json:"active"`
	Replay    bool      `json:"replay,omitempty"`
	Hosts     int       `json:"hosts"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// DBInfo describes the database (`db info`).
type DBInfo struct {
	Path          string           `json:"path"`
	SchemaVersion int              `json:"schema_version"`
	JournalMode   string           `json:"journal_mode"`
	Size          int64            `json:"size"`
	UsedSize      int64            `json:"used_size"`
	WALSize       int64            `json:"wal_size"`
	Rows          map[string]int64 `json:"rows,omitempty"`
}

// CheckResult is the outcome of `db check`.
type CheckResult struct {
	OK       bool     `json:"ok"`
	Problems []string `json:"problems,omitempty"`
}

// QueryKind classifies a host query (docs/CLI.md §4).
type QueryKind string

// Query kinds.
const (
	KindHost QueryKind = "host"
	KindMAC  QueryKind = "mac"
	KindIP   QueryKind = "ip"
	KindName QueryKind = "name"
)

var uuidRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// Classify detects the kind of a query: host UUID, MAC (aa:bb:.., aa-bb-..
// or aabb.ccdd.eeff), IPv4, IPv6, else hostname. It returns the query in
// the form the database stores.
func Classify(q string) (QueryKind, string) {
	q = strings.TrimSpace(q)
	if uuidRE.MatchString(q) {
		return KindHost, strings.ToLower(q)
	}
	if m, err := net.ParseMAC(q); err == nil && len(m) == 6 {
		return KindMAC, m.String()
	}
	if ip, err := netip.ParseAddr(q); err == nil {
		return KindIP, ip.Unmap().String()
	}
	return KindName, q
}

// Normalize returns q in stored form for an explicit kind, or classifies
// it when kind is empty. It reports false when q is not of that kind.
func Normalize(kind QueryKind, q string) (QueryKind, string, bool) {
	detected, norm := Classify(q)
	if kind == "" || kind == detected {
		return detected, norm, true
	}
	if kind == KindName {
		return KindName, strings.TrimSpace(q), true
	}
	return kind, q, false
}

// HostFilter selects hosts for `hosts list`.
type HostFilter struct {
	Interface string
	// Query restricts to hosts that ever matched it (any kind).
	Query     string
	QueryKind QueryKind
	Live      bool // ACTIVE or RECENT
	NotLive   bool // STALE or MISSING
	Vendor    string
	Port      int // an OPEN service on this TCP or UDP port
	SeenSince time.Time
}

// FindQuery is a `hosts find` query.
type FindQuery struct {
	Query     string
	Kind      QueryKind
	Interface string
	At        *time.Time
}

// FindResult answers `hosts find` (docs/CLI.md §4).
type FindResult struct {
	Kind  QueryKind   `json:"kind"`
	Query string      `json:"query"`
	At    *time.Time  `json:"at,omitempty"`
	Hosts []FoundHost `json:"hosts"`
	// For an IP with no holder at At: the binding before and after, per
	// interface.
	Previous []Holding `json:"previous,omitempty"`
	Next     []Holding `json:"next,omitempty"`
}

// FoundHost is one holder or match.
type FoundHost struct {
	Host
	// IP queries: the binding of the queried address.
	Binding     *Binding `json:"binding,omitempty"`
	Unconfirmed bool     `json:"unconfirmed,omitempty"`
	Conflict    bool     `json:"conflict,omitempty"`
	// With At: the next holder of the address and the host's next address.
	ReplacedBy    *Holding `json:"replaced_by,omitempty"`
	MovedTo       *Holding `json:"moved_to,omitempty"`
	ConflictEvent *Event   `json:"conflict_event,omitempty"`
}

// Holding is a binding with its holder.
type Holding struct {
	Interface string  `json:"interface"`
	HostID    string  `json:"host_id"`
	MAC       string  `json:"mac"`
	Binding   Binding `json:"binding"`
}

// HistoryQuery selects a timeline (`hosts history`).
type HistoryQuery struct {
	Query     string
	Kind      QueryKind
	Interface string
	Since     time.Time
	Until     time.Time
}

// EventFilter selects events (`events list`).
type EventFilter struct {
	Since, Until time.Time
	Types        []string // spec type names
	Interface    string
	MAC          string
	IP           string
	HostID       string
	Limit        int
}

// ObservationFilter selects observations (`observations list`).
type ObservationFilter struct {
	HostID       string
	Interface    string
	MAC          string
	IP           string
	Source       string
	Unbound      bool
	Since, Until time.Time
	Limit        int
}

// ServiceFilter selects services (`services list`).
type ServiceFilter struct {
	Port      int
	State     string
	Interface string
}

// Evidence answers `hosts evidence`: the host, per source and address the
// observation counts within roll-up retention, and the host's events with
// their evidence snapshots.
type Evidence struct {
	Host   Host          `json:"host"`
	Counts []SourceCount `json:"counts"`
	Events []Event       `json:"events"`
}

// SourceCount counts the observations of one source for one address.
type SourceCount struct {
	Source    string    `json:"source"`
	IP        string    `json:"ip,omitempty"`
	Count     int64     `json:"count"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}
