package platform

import (
	"sort"
	"sync"
	"time"
)

// State is a collector's availability (FR-STAT-1).
type State string

// Collector states.
const (
	StateRunning     State = "running"
	StateDisabled    State = "disabled"
	StateUnsupported State = "unsupported"
	StateFailed      State = "failed"
)

// Collector names used in status output and the lan_sentinel_collector_up
// metric.
const (
	CollectorCapture   = "capture"
	CollectorNeighbor  = "neighbor"
	CollectorInterface = "interface"
	CollectorReplay    = "replay"
	CollectorARP       = "arp"
	CollectorICMP      = "icmp"
	CollectorNDP       = "ndp"
	CollectorTCP       = "tcp"
	CollectorUDP       = "udp"
)

// CollectorStatus is the state of one collector on one interface.
type CollectorStatus struct {
	Interface string    `json:"interface"`
	Collector string    `json:"collector"`
	Backend   string    `json:"backend,omitempty"`
	State     State     `json:"state"`
	Error     string    `json:"error,omitempty"`
	Since     time.Time `json:"since"`
}

// Registry tracks collector availability for `daemon status` and metrics.
// Collectors report transitions; the registry keeps the latest per
// (interface, collector).
type Registry struct {
	mu  sync.Mutex
	now func() time.Time
	m   map[[2]string]CollectorStatus
}

// NewRegistry returns an empty registry using now for timestamps.
func NewRegistry(now func() time.Time) *Registry {
	return &Registry{now: now, m: map[[2]string]CollectorStatus{}}
}

// Set records a collector's state. err may be nil. Since only changes when
// the state or error changes.
func (r *Registry) Set(iface, collector, backend string, state State, err error) {
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	k := [2]string{iface, collector}
	prev, ok := r.m[k]
	if ok && prev.State == state && prev.Error == msg && prev.Backend == backend {
		return
	}
	r.m[k] = CollectorStatus{Interface: iface, Collector: collector, Backend: backend, State: state, Error: msg, Since: r.now()}
}

// List returns all statuses sorted by interface and collector.
func (r *Registry) List() []CollectorStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]CollectorStatus, 0, len(r.m))
	for _, s := range r.m {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Interface != out[j].Interface {
			return out[i].Interface < out[j].Interface
		}
		return out[i].Collector < out[j].Collector
	})
	return out
}

// Degraded reports whether any configured collector is not running.
// Disabled collectors were not configured and do not count.
func (r *Registry) Degraded() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.m {
		if s.State == StateFailed || s.State == StateUnsupported {
			return true
		}
	}
	return false
}
