// Package correlate is the identity engine: a single goroutine that turns
// observations into host state, address bindings and events following
// docs/DATA_MODEL.md §5–§6. It is the only writer of state and events.
//
// Time is data-driven: every rule is evaluated at the observation's time, and
// timer-driven transitions (presence, binding expiry) are stamped with the
// moment their threshold was crossed, so results do not depend on when the
// evaluation runs. A replay therefore produces the same database every time.
package correlate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"lan-sentinel/internal/clock"
	"lan-sentinel/internal/config"
	"lan-sentinel/internal/events"
	"lan-sentinel/internal/identify"
	"lan-sentinel/internal/observation"
	"lan-sentinel/internal/store"
)

// DefaultTick is how often live mode evaluates presence and expiry.
const DefaultTick = 15 * time.Second

// ouiConfidence is the confidence of a manufacturer derived from the OUI:
// it names the NIC maker, which is usually but not always the device maker.
const ouiConfidence = 0.7

// Internal event causes (docs/DATA_MODEL.md §2).
const (
	causePresence  = "presence"
	causeExpiry    = "expiry"
	causeIface     = "iface_monitor"
	causeIntegrity = "integrity_check"
)

// Options configures a Correlator.
type Options struct {
	Store   *store.Store
	Events  *events.Engine
	Vendors *identify.Vendors
	Clock   clock.Clock
	Logger  *slog.Logger
	Config  *config.Config
	// DataDriven disables the ticker: timers advance only with observation
	// times (replay).
	DataDriven bool
	Tick       time.Duration
	// NewID returns host ids; default UUIDv7.
	NewID func() string
	// Recovery, if set, is the corrupt database the store quarantined at
	// start-up; New records it as the new database's first event.
	Recovery *store.Recovery
}

// Correlator is the identity engine.
type Correlator struct {
	store   *store.Store
	events  *events.Engine
	vendors *identify.Vendors
	clock   clock.Clock
	log     *slog.Logger
	cfg     atomic.Pointer[config.Config]
	data    bool
	tick    time.Duration
	newID   func() string

	st         *state
	advancedTo time.Time

	unbound atomic.Uint64
	ignored atomic.Uint64
	// Per source: observations processed and those left unbound
	// (lan_sentinel_observations_total, lan_sentinel_observations_unbound_total).
	bySource        map[observation.Source]*atomic.Uint64
	unboundBySource map[observation.Source]*atomic.Uint64
}

// New loads the current state from the store and makes sure every
// configured interface has a network context.
func New(ctx context.Context, o Options) (*Correlator, error) {
	if o.Store == nil || o.Events == nil || o.Config == nil {
		return nil, errors.New("correlate: store, events and config are required")
	}
	if o.Clock == nil {
		o.Clock = clock.Real()
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	if o.Tick <= 0 {
		o.Tick = DefaultTick
	}
	if o.NewID == nil {
		o.NewID = func() string { return uuid.Must(uuid.NewV7()).String() }
	}
	c := &Correlator{
		store: o.Store, events: o.Events, vendors: o.Vendors, clock: o.Clock, log: o.Logger,
		data: o.DataDriven, tick: o.Tick, newID: o.NewID, st: newState(),
		bySource: map[observation.Source]*atomic.Uint64{}, unboundBySource: map[observation.Source]*atomic.Uint64{},
	}
	for _, src := range observation.Sources {
		c.bySource[src], c.unboundBySource[src] = new(atomic.Uint64), new(atomic.Uint64)
	}
	c.cfg.Store(o.Config)
	if err := o.Store.View(ctx, func(ctx context.Context, tx *sql.Tx) error { return c.st.load(ctx, tx) }); err != nil {
		return nil, err
	}
	now := c.clock.Now()
	if r := o.Recovery; r != nil {
		c.emit(ctx, events.Event{TS: now, Type: events.DatabaseRecreated, New: r.QuarantinedTo, Cause: causeIntegrity,
			Evidence: events.Evidence{TS: now, Reason: r.Reason}})
	}
	c.closeOpenScans(ctx, now)
	for _, ic := range o.Config.Interfaces {
		if _, ok := c.st.contexts[ic.Name]; ok {
			continue
		}
		c.st.nextContextID++
		n := &netContext{id: c.st.nextContextID, iface: ic.Name, prefixes: map[netip.Prefix]*prefixRow{}, lastSeen: now}
		c.st.contexts[n.iface], c.st.contextsByID[n.id] = n, n
		c.dbInsertContext(ctx, n, now)
	}
	return c, nil
}

// SetConfig applies a reloaded configuration (thresholds; interfaces are
// restart-only).
func (c *Correlator) SetConfig(cfg *config.Config) { c.cfg.Store(cfg) }

// Unbound is how many observations matched no host
// (lan_sentinel_observations_unbound_total).
func (c *Correlator) Unbound() uint64 { return c.unbound.Load() }

// Ignored is how many observations were dropped as unusable (unknown
// interface, no usable MAC or IP).
func (c *Correlator) Ignored() uint64 { return c.ignored.Load() }

// SourceCounts returns, per source, how many observations were processed
// and how many of them matched no host.
func (c *Correlator) SourceCounts() (processed, unbound map[observation.Source]uint64) {
	processed, unbound = map[observation.Source]uint64{}, map[observation.Source]uint64{}
	for src, n := range c.bySource {
		processed[src] = n.Load()
		unbound[src] = c.unboundBySource[src].Load()
	}
	return processed, unbound
}

func (c *Correlator) count(src observation.Source, counters map[observation.Source]*atomic.Uint64) {
	if n := counters[src]; n != nil {
		n.Add(1)
	}
}

// Run consumes the bus until ctx is cancelled.
func (c *Correlator) Run(ctx context.Context, bus *observation.Bus) error {
	var tick <-chan time.Time
	if !c.data {
		t := c.clock.NewTicker(c.tick)
		defer t.Stop()
		tick = t.C()
	}
	for {
		select {
		case <-ctx.Done():
			c.flushContexts(context.WithoutCancel(ctx))
			return nil
		case m := <-bus.C():
			c.Handle(ctx, m)
		case <-tick:
			c.advance(ctx, c.clock.Now())
			c.flushContexts(ctx)
		}
	}
}

// Handle processes one bus message. Run calls it; tests may call it
// directly.
func (c *Correlator) Handle(ctx context.Context, m observation.Message) {
	switch {
	case m.Barrier != nil:
		c.flushContexts(ctx)
		close(m.Barrier)
	case m.Link != nil:
		c.link(ctx, *m.Link)
	case m.Operator != nil:
		c.operator(ctx, *m.Operator)
	default:
		c.observe(ctx, m.Observation)
	}
}

func (c *Correlator) flushContexts(ctx context.Context) {
	for _, n := range c.st.contextsByID {
		if n.dirty {
			c.dbContextSeen(ctx, n)
			n.dirty = false
		}
	}
}

func (c *Correlator) emit(ctx context.Context, ev events.Event) {
	if err := c.events.Emit(ctx, ev); err != nil && ctx.Err() == nil {
		c.log.Error("correlator: emitting event failed", "type", ev.Type, "err", err)
	}
}

// hostEvent fills the host-related fields of an event.
func hostEvent(t events.Type, ts time.Time, h *host, cause string, ev events.Evidence) events.Event {
	return events.Event{
		TS: ts, Type: t, ContextID: h.ctx.id, Interface: h.ctx.iface, HostID: h.id, MAC: h.mac.String(),
		Cause: cause, Evidence: ev,
	}
}

// presenceAt computes presence from the time since the last observation.
func (c *Correlator) presenceAt(lastSeen, now time.Time) Presence {
	p := c.cfg.Load().Presence
	age := now.Sub(lastSeen)
	switch {
	case age < p.Active.D():
		return Active
	case age < p.Recent.D():
		return Recent
	case age < p.Stale.D():
		return Stale
	default:
		return Missing
	}
}

func (c *Correlator) refTime(t time.Time) time.Time {
	if c.advancedTo.After(t) {
		return c.advancedTo
	}
	return t
}

func describe(p netip.Prefix) string { return fmt.Sprint(p) }
