package observation

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultBusSize is the bus capacity used by the daemon.
const DefaultBusSize = 4096

// LinkState is an interface's state as reported by the interface manager
// (or by replay, from config). It travels on the bus so the correlator
// applies it in order with observations.
type LinkState struct {
	Time      time.Time
	Interface string
	Present   bool           // false: the link was removed
	Up        bool           // operational state
	Prefixes  []netip.Prefix // the interface's own subnets (masked)
}

// Message is what the correlator receives: an observation, a link state, an
// operator action, or a barrier that the correlator closes once every
// message published before it has been processed.
type Message struct {
	Observation Observation
	Link        *LinkState
	Operator    *Operator
	Barrier     chan struct{}
}

// OperatorKind is an operator action the correlator records.
type OperatorKind string

// Operator actions (docs/DATA_MODEL.md §7, §8).
const (
	OpActiveDisabled OperatorKind = "active_disabled"
	OpActiveEnabled  OperatorKind = "active_enabled"
	OpScanStarted    OperatorKind = "scan_started"
	OpScanCompleted  OperatorKind = "scan_completed"
)

// Operator is an operator action: the kill switch set or cleared, or an
// operator scan started or completed on one interface. Probes and the API
// never write state; the correlator persists these and emits their events.
type Operator struct {
	Time   time.Time
	Kind   OperatorKind
	Actor  string // the Unix user, "env" for LAN_SENTINEL_ACTIVE_DISABLED
	Reason string
	// Persist writes the kill switch to runtime_state; false for the
	// environment variable, which is not persisted.
	Persist bool
	// Scan is the operator scan; the start and the completion each carry
	// their own copy, linked by the scan's Handle.
	Scan *Scan
}

// Scan is an operator scan on one interface (a scans row).
type Scan struct {
	// Handle links the completion to the start; only the correlator reads
	// or writes it.
	Handle    *ScanHandle
	Interface string
	Kind      string // the probes, e.g. "arp,tcp/502"
	Targets   int
	Summary   string         // SCAN_STARTED / SCAN_COMPLETED new_value
	Results   map[string]any // results_json
}

// ScanHandle is set by the correlator when it records a scan's start; a
// completion whose start was never recorded is ignored.
type ScanHandle struct {
	ID int64
}

// ErrBusClosed is returned by blocking publishes once the consumer has
// stopped (daemon shutdown).
var ErrBusClosed = errors.New("observation bus closed")

// Bus is the bounded channel from collectors to the correlator. Live
// collectors use Publish and never block: when the bus is full the
// observation is dropped and counted. Replay uses PublishWait, which blocks
// instead, so a replay is complete and deterministic.
type Bus struct {
	ch      chan Message
	dropped atomic.Uint64
	done    chan struct{}
	once    sync.Once
}

// NewBus returns a bus holding up to size messages.
func NewBus(size int) *Bus {
	if size <= 0 {
		size = DefaultBusSize
	}
	return &Bus{ch: make(chan Message, size), done: make(chan struct{})}
}

// Close tells blocking publishers that the consumer has stopped: they
// return ErrBusClosed instead of waiting forever. Publish keeps dropping.
func (b *Bus) Close() { b.once.Do(func() { close(b.done) }) }

// Publish enqueues o without blocking; it returns false (and counts a drop)
// if the bus is full.
func (b *Bus) Publish(o Observation) bool {
	select {
	case b.ch <- Message{Observation: o}:
		return true
	default:
		b.dropped.Add(1)
		return false
	}
}

// PublishWait enqueues o, blocking while the bus is full.
func (b *Bus) PublishWait(ctx context.Context, o Observation) error {
	select {
	case b.ch <- Message{Observation: o}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-b.done:
		return ErrBusClosed
	}
}

// PublishLink enqueues a link state, blocking while the bus is full: link
// changes are rare and must not be dropped.
func (b *Bus) PublishLink(ctx context.Context, l LinkState) error {
	select {
	case b.ch <- Message{Link: &l}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-b.done:
		return ErrBusClosed
	}
}

// PublishOperator enqueues an operator action and returns once the
// consumer has processed it.
func (b *Bus) PublishOperator(ctx context.Context, op Operator) error {
	select {
	case b.ch <- Message{Operator: &op}:
	case <-ctx.Done():
		return ctx.Err()
	case <-b.done:
		return ErrBusClosed
	}
	return b.Barrier(ctx)
}

// Barrier returns once the consumer has processed everything published
// before the call.
func (b *Bus) Barrier(ctx context.Context) error {
	done := make(chan struct{})
	select {
	case b.ch <- Message{Barrier: done}:
	case <-ctx.Done():
		return ctx.Err()
	case <-b.done:
		return ErrBusClosed
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-b.done:
		return ErrBusClosed
	}
}

// C is the consumer side.
func (b *Bus) C() <-chan Message { return b.ch }

// Dropped is how many observations Publish has dropped
// (lan_sentinel_bus_dropped_total).
func (b *Bus) Dropped() uint64 { return b.dropped.Load() }
