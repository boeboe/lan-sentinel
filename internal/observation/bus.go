package observation

import (
	"context"
	"net/netip"
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

// Message is what the correlator receives: an observation, a link state, or
// a barrier that the correlator closes once every message published before
// it has been processed.
type Message struct {
	Observation Observation
	Link        *LinkState
	Barrier     chan struct{}
}

// Bus is the bounded channel from collectors to the correlator. Live
// collectors use Publish and never block: when the bus is full the
// observation is dropped and counted. Replay uses PublishWait, which blocks
// instead, so a replay is complete and deterministic.
type Bus struct {
	ch      chan Message
	dropped atomic.Uint64
}

// NewBus returns a bus holding up to size messages.
func NewBus(size int) *Bus {
	if size <= 0 {
		size = DefaultBusSize
	}
	return &Bus{ch: make(chan Message, size)}
}

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
	}
}

// Barrier returns once the consumer has processed everything published
// before the call.
func (b *Bus) Barrier(ctx context.Context) error {
	done := make(chan struct{})
	select {
	case b.ch <- Message{Barrier: done}:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// C is the consumer side.
func (b *Bus) C() <-chan Message { return b.ch }

// Dropped is how many observations Publish has dropped
// (lan_sentinel_bus_dropped_total).
func (b *Bus) Dropped() uint64 { return b.dropped.Load() }
