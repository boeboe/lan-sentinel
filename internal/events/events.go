// Package events defines the event catalogue (docs/DATA_MODEL.md §7) and the
// engine that writes each event to the events table and, as one structured
// entry, to the log (journald). Only the correlator emits events.
package events

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"lan-sentinel/internal/observation"
	"lan-sentinel/internal/service"
	"lan-sentinel/internal/store"
)

// Type is an event type.
type Type string

// Event types.
const (
	HostDiscovered      Type = "HOST_DISCOVERED"
	HostDisappeared     Type = "HOST_DISAPPEARED"
	HostReappeared      Type = "HOST_REAPPEARED"
	IPAdded             Type = "IP_ADDED"
	IPRemoved           Type = "IP_REMOVED"
	IPChanged           Type = "IP_CHANGED"
	MACMoved            Type = "MAC_MOVED"
	HostnameAdded       Type = "HOSTNAME_ADDED"
	HostnameChanged     Type = "HOSTNAME_CHANGED"
	HostnameRemoved     Type = "HOSTNAME_REMOVED"
	ServiceOpened       Type = "SERVICE_OPENED"
	ServiceClosed       Type = "SERVICE_CLOSED"
	VendorIdentified    Type = "VENDOR_IDENTIFIED"
	DuplicateIPDetected Type = "DUPLICATE_IP_DETECTED"
	DuplicateIPResolved Type = "DUPLICATE_IP_RESOLVED"
	ScanStarted         Type = "SCAN_STARTED"
	ScanCompleted       Type = "SCAN_COMPLETED"
	ActiveDisabled      Type = "ACTIVE_DISABLED"
	ActiveEnabled       Type = "ACTIVE_ENABLED"
	InterfaceUp         Type = "INTERFACE_UP"
	InterfaceDown       Type = "INTERFACE_DOWN"
	SubnetChanged       Type = "SUBNET_CHANGED"
)

// Severity is an event's severity.
type Severity string

// Severities.
const (
	Info    Severity = "info"
	Notice  Severity = "notice"
	Warning Severity = "warning"
)

// Spec describes one event type.
type Spec struct {
	Type     Type
	CLIName  string
	Severity Severity
}

var catalogue = map[Type]Spec{}

func init() {
	for _, s := range []Spec{
		{HostDiscovered, "discovered", Notice},
		{HostDisappeared, "disappeared", Notice},
		{HostReappeared, "reappeared", Notice},
		{IPAdded, "ip-added", Notice},
		{IPRemoved, "ip-removed", Notice},
		{IPChanged, "ip-changed", Notice},
		{MACMoved, "mac-moved", Warning},
		{HostnameAdded, "name-added", Notice},
		{HostnameChanged, "name-changed", Notice},
		{HostnameRemoved, "name-removed", Notice},
		{ServiceOpened, "service-opened", Notice},
		{ServiceClosed, "service-closed", Notice},
		{VendorIdentified, "vendor-identified", Info},
		{DuplicateIPDetected, "duplicate-ip", Warning},
		{DuplicateIPResolved, "duplicate-ip-resolved", Notice},
		{ScanStarted, "scan-started", Info},
		{ScanCompleted, "scan-completed", Info},
		{ActiveDisabled, "active-disabled", Warning},
		{ActiveEnabled, "active-enabled", Notice},
		{InterfaceUp, "interface-up", Notice},
		{InterfaceDown, "interface-down", Warning},
		{SubnetChanged, "subnet-changed", Notice},
	} {
		catalogue[s.Type] = s
	}
}

// Lookup returns the spec of t.
func Lookup(t Type) (Spec, bool) {
	s, ok := catalogue[t]
	return s, ok
}

// ByCLIName resolves a kebab-case CLI name such as "ip-changed".
func ByCLIName(name string) (Type, bool) {
	for _, s := range catalogue {
		if s.CLIName == name {
			return s.Type, true
		}
	}
	return "", false
}

// All returns the catalogue sorted by type.
func All() []Spec {
	out := make([]Spec, 0, len(catalogue))
	for _, s := range catalogue {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Type < out[j].Type })
	return out
}

// Evidence is the self-contained snapshot stored with every event
// (evidence_json), so provenance survives compaction of observations.
type Evidence struct {
	TS            time.Time                  `json:"ts"`
	Source        string                     `json:"source,omitempty"`
	Interface     string                     `json:"interface,omitempty"`
	MAC           string                     `json:"mac,omitempty"`
	IP            string                     `json:"ip,omitempty"`
	Hostname      string                     `json:"hostname,omitempty"`
	NameType      string                     `json:"name_type,omitempty"`
	Service       *observation.ServiceResult `json:"service,omitempty"`
	NeighborState string                     `json:"neighbor_state,omitempty"`
	Reason        string                     `json:"reason,omitempty"`
	Actor         string                     `json:"actor,omitempty"`
}

// EvidenceFrom snapshots an observation.
func EvidenceFrom(o observation.Observation) Evidence {
	e := Evidence{
		TS: o.Time.UTC(), Source: string(o.Source), Interface: o.Interface, Hostname: o.Hostname,
		NameType: string(o.NameType), Service: o.Service, NeighborState: o.NeighborState,
	}
	if len(o.MAC) > 0 {
		e.MAC = o.MAC.String()
	}
	if o.IP.IsValid() {
		e.IP = o.IP.String()
	}
	return e
}

// Event is one state transition.
type Event struct {
	TS            time.Time
	Type          Type
	ContextID     int64  // 0: not tied to a context
	Interface     string // for the log entry
	HostID        string
	RelatedHostID string
	MAC           string // for the log entry
	Old, New      string
	Cause         string // observation source or internal cause (presence, expiry, iface_monitor, ...)
	ObservationID int64  // 0: none
	Evidence      Evidence
}

// Engine writes events.
type Engine struct {
	store       *store.Store
	log         *slog.Logger
	clockSynced func() bool

	mu     sync.Mutex
	counts map[Type]uint64
}

// NewEngine returns an engine writing to st and log. clockSynced reports
// whether the system clock is synchronised (NFR-REL-2).
func NewEngine(st *store.Store, log *slog.Logger, clockSynced func() bool) *Engine {
	if clockSynced == nil {
		clockSynced = func() bool { return true }
	}
	return &Engine{store: st, log: log, clockSynced: clockSynced, counts: map[Type]uint64{}}
}

// Emit queues the event for the next store batch and logs it.
func (e *Engine) Emit(ctx context.Context, ev Event) error {
	spec, ok := catalogue[ev.Type]
	if !ok {
		return fmt.Errorf("unknown event type %q", ev.Type)
	}
	evidence, err := json.Marshal(ev.Evidence)
	if err != nil {
		return fmt.Errorf("event evidence: %w", err)
	}
	synced := e.clockSynced()
	err = e.store.Submit(ctx, func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO events
			(ts, type, severity, context_id, host_id, related_host_id, old_value, new_value, cause, observation_id, evidence_json, clock_synced)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			ev.TS.UnixMilli(), string(ev.Type), string(spec.Severity), nullInt(ev.ContextID), nullString(ev.HostID),
			nullString(ev.RelatedHostID), nullString(ev.Old), nullString(ev.New), ev.Cause, nullInt(ev.ObservationID),
			string(evidence), boolInt(synced))
		if err != nil {
			return fmt.Errorf("insert event %s: %w", ev.Type, err)
		}
		return nil
	})
	if err != nil {
		return err
	}
	e.mu.Lock()
	e.counts[ev.Type]++
	e.mu.Unlock()
	e.logEvent(ctx, spec, ev, synced)
	return nil
}

// Counts returns how many events of each type have been emitted.
func (e *Engine) Counts() map[Type]uint64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make(map[Type]uint64, len(e.counts))
	for k, v := range e.counts {
		out[k] = v
	}
	return out
}

// logEvent writes one structured entry; the journald handler turns the
// attributes into fields such as EVENT=ip_changed and IFACE=eth1.
func (e *Engine) logEvent(ctx context.Context, spec Spec, ev Event, synced bool) {
	level := slog.LevelInfo
	switch spec.Severity {
	case Notice:
		level = service.LevelNotice
	case Warning:
		level = slog.LevelWarn
	}
	attrs := []slog.Attr{
		slog.String("event", strings.ToLower(string(ev.Type))),
		slog.Time("ts", ev.TS),
	}
	add := func(k, v string) {
		if v != "" {
			attrs = append(attrs, slog.String(k, v))
		}
	}
	add("iface", ev.Interface)
	add("host_id", ev.HostID)
	add("mac", ev.MAC)
	add("ip", ev.Evidence.IP)
	add("old_value", ev.Old)
	add("new_value", ev.New)
	add("related_host_id", ev.RelatedHostID)
	add("source", ev.Cause)
	if !synced {
		attrs = append(attrs, slog.Bool("clock_synced", false))
	}
	e.log.LogAttrs(ctx, level, message(ev), attrs...)
}

func message(ev Event) string {
	parts := []string{string(ev.Type)}
	for _, p := range []string{ev.Interface, ev.MAC} {
		if p != "" {
			parts = append(parts, p)
		}
	}
	old, nw := ev.Old, ev.New
	if nw == ev.MAC { // HOST_DISCOVERED: the MAC is already in the message
		nw = ""
	}
	switch {
	case old != "" && nw != "":
		parts = append(parts, old+" -> "+nw)
	case nw != "":
		parts = append(parts, nw)
	case old != "":
		parts = append(parts, old)
	}
	if ev.Evidence.IP != "" && ev.Evidence.IP != ev.New && ev.Evidence.IP != ev.Old {
		parts = append(parts, ev.Evidence.IP)
	}
	return strings.Join(parts, " ")
}

func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullInt(v int64) any {
	if v == 0 {
		return nil
	}
	return v
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
