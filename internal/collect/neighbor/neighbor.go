// Package neighbor turns the kernel neighbour table into kernel_neighbor
// observations (FR-NL-1, FR-NL-2): a dump at start-up, rtnetlink
// notifications, and a fresh dump after notification loss and every
// neighbor.resync_interval.
//
// Each observation is stamped with the time the kernel last confirmed
// reachability, not the time it was read. A STALE entry that lingers in the
// table therefore adds no fresh evidence, so a switched-off device still
// becomes MISSING, and STALE is never read as offline either.
package neighbor

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"lan-sentinel/internal/clock"
	"lan-sentinel/internal/observation"
	"lan-sentinel/internal/platform"
)

// confirmTolerance absorbs the 10 ms granularity of the kernel's
// confirmation age between reads.
const confirmTolerance = time.Second

// retryDelay paces retries when the backend fails.
const retryDelay = 5 * time.Second

// Options configures a Collector.
type Options struct {
	Source     platform.NeighborSource
	Bus        *observation.Bus
	Clock      clock.Clock
	Interfaces []string
	Resync     time.Duration
	Registry   *platform.Registry
	Logger     *slog.Logger
}

// Collector emits kernel_neighbor observations.
type Collector struct {
	o       Options
	ifaces  map[string]bool
	emitted map[key]emission
}

type key struct {
	iface string
	ip    netip.Addr
}

type emission struct {
	mac       string
	confirmed time.Time
}

// New returns a collector.
func New(o Options) *Collector {
	if o.Clock == nil {
		o.Clock = clock.Real()
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	c := &Collector{o: o, ifaces: map[string]bool{}, emitted: map[key]emission{}}
	for _, i := range o.Interfaces {
		c.ifaces[i] = true
	}
	return c
}

func (c *Collector) report(state platform.State, err error) {
	if c.o.Registry == nil {
		return
	}
	for iface := range c.ifaces {
		c.o.Registry.Set(iface, platform.CollectorNeighbor, c.o.Source.Backend(), state, err)
	}
}

// Run collects until ctx is cancelled.
func (c *Collector) Run(ctx context.Context) error {
	resync := c.o.Clock.NewTicker(c.o.Resync)
	defer resync.Stop()
	for ctx.Err() == nil {
		events, err := c.o.Source.Watch(ctx)
		if err == nil {
			err = c.snapshot(ctx)
		}
		if err != nil {
			c.report(platform.StateFailed, err)
			c.o.Logger.Warn("neighbour collector failed; retrying", "err", err)
			if !wait(ctx, c.o.Clock, retryDelay) {
				return nil
			}
			continue
		}
		c.report(platform.StateRunning, nil)
		c.follow(ctx, events, resync)
	}
	return nil
}

// follow handles notifications until the watch ends or ctx is cancelled.
func (c *Collector) follow(ctx context.Context, events <-chan platform.NeighborEvent, resync clock.Ticker) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-events:
			if !ok {
				return
			}
			switch {
			case ev.Resync:
				_ = c.snapshot(ctx)
			case ev.Deleted:
				delete(c.emitted, key{ev.Neighbor.Interface, ev.Neighbor.IP})
			default:
				c.emit(ev.Neighbor, c.o.Clock.Now())
			}
		case <-resync.C():
			_ = c.snapshot(ctx)
		}
	}
}

func (c *Collector) snapshot(ctx context.Context) error {
	list, err := c.o.Source.Snapshot(ctx)
	if err != nil {
		return err
	}
	now := c.o.Clock.Now()
	for _, n := range list {
		c.emit(n, now)
	}
	return nil
}

// usable reports whether a neighbour entry is evidence of a host: resolved
// states only. INCOMPLETE and FAILED have no confirmed MAC; NOARP and
// PERMANENT are configuration, not observation.
func usable(n platform.Neighbor) bool {
	switch n.State {
	case "REACHABLE", "STALE", "DELAY", "PROBE":
		return len(n.MAC) > 0
	}
	return false
}

func (c *Collector) emit(n platform.Neighbor, now time.Time) {
	if !c.ifaces[n.Interface] || !usable(n) {
		return
	}
	confirmed := now.Add(-n.ConfirmedAgo).Truncate(time.Millisecond)
	k := key{n.Interface, n.IP}
	mac := n.MAC.String()
	if prev, ok := c.emitted[k]; ok && prev.mac == mac && !confirmed.After(prev.confirmed.Add(confirmTolerance)) {
		return // nothing new since the last observation
	}
	c.emitted[k] = emission{mac: mac, confirmed: confirmed}
	c.o.Bus.Publish(observation.Observation{
		Time: confirmed, Source: observation.KernelNeighbor, Interface: n.Interface,
		MAC: append(net.HardwareAddr(nil), n.MAC...), IP: n.IP, NeighborState: n.State,
	})
}

func wait(ctx context.Context, c clock.Clock, d time.Duration) bool {
	t := c.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C():
		return true
	case <-ctx.Done():
		return false
	}
}
