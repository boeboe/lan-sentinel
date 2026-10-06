// Package capture is the passive capture collector (FR-PA-1 to FR-PA-7):
// one receive-only AF_PACKET ring per interface through platform.Capturer,
// a kernel BPF filter limited to the discovery protocols, and the shared
// decoders. It never transmits and never touches state: decoded frames
// become observations on the bus, and when the bus is full they are dropped
// and counted, so capture never blocks on the correlator.
package capture

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"lan-sentinel/internal/clock"
	"lan-sentinel/internal/collect/capture/decoders"
	"lan-sentinel/internal/observation"
	"lan-sentinel/internal/platform"
)

// Reopen back-off after a failed open or a lost interface.
const (
	minRetry = time.Second
	maxRetry = 30 * time.Second
)

// Interface is one captured interface.
type Interface struct {
	Name        string
	Promiscuous bool
}

// Options configures a Collector.
type Options struct {
	Capturer   platform.Capturer
	Bus        *observation.Bus
	Clock      clock.Clock // paces retries
	Interfaces []Interface
	Protocols  decoders.Protocols
	RingSize   int
	Registry   *platform.Registry
	Logger     *slog.Logger
}

// Stats are one interface's capture counters since the collector started,
// across reopens.
type Stats struct {
	Interface    string
	Received     uint64 // frames that passed the kernel filter
	Dropped      uint64 // frames the kernel dropped because the ring was full
	Observations uint64 // observations published
	BusDropped   uint64 // observations dropped because the bus was full
}

// Collector captures on every configured interface.
type Collector struct {
	o     Options
	mu    sync.Mutex
	stats map[string]*ifaceStats
}

type ifaceStats struct {
	base         platform.CaptureStats // closed sources
	src          platform.FrameSource  // open source, if any
	observations uint64
	busDropped   uint64
}

// New returns a collector.
func New(o Options) *Collector {
	if o.Clock == nil {
		o.Clock = clock.Real()
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	c := &Collector{o: o, stats: map[string]*ifaceStats{}}
	for _, i := range o.Interfaces {
		c.stats[i.Name] = &ifaceStats{}
	}
	return c
}

// Run captures until ctx is cancelled.
func (c *Collector) Run(ctx context.Context) error {
	filter, err := Filter(c.o.Protocols)
	if err != nil {
		return err
	}
	var wg sync.WaitGroup
	for _, i := range c.o.Interfaces {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.run(ctx, i, platform.CaptureOptions{Filter: filter, Promiscuous: i.Promiscuous, RingSize: c.o.RingSize})
		}()
	}
	wg.Wait()
	return nil
}

// run keeps one interface captured: it opens the ring, reads until the
// interface goes away or fails, and opens it again with back-off. The
// back-off only starts over once a source has delivered frames, so an
// interface that opens and fails at once (e.g. administratively down) does
// not cycle every second. Only changes are logged, not every retry.
func (c *Collector) run(ctx context.Context, i Interface, opts platform.CaptureOptions) {
	retry := minRetry
	dec := NewDecoder(c.o.Protocols)
	logged, started := "", false
	for ctx.Err() == nil {
		src, err := c.o.Capturer.Open(ctx, i.Name, opts)
		if err == nil {
			c.report(i.Name, platform.StateRunning, nil)
			if !started {
				started = true
				c.o.Logger.Info("capture started", "interface", i.Name, "promiscuous", i.Promiscuous)
			}
			var frames int
			frames, err = c.read(ctx, i.Name, src, dec)
			if ctx.Err() != nil {
				return
			}
			if frames > 0 {
				retry, logged = minRetry, "" // it worked: the next failure is news
			}
		}
		c.report(i.Name, platform.StateFailed, err)
		if err.Error() != logged {
			logged, started = err.Error(), false
			c.o.Logger.Warn("capture unavailable; retrying", "interface", i.Name, "err", err)
		}
		t := c.o.Clock.NewTimer(retry)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C():
		}
		retry = min(2*retry, maxRetry)
	}
}

// read decodes frames from src until it fails and returns how many frames
// it read; it always closes src. An observation the full bus drops is
// forgotten by the decoder, so the next identical frame is not suppressed.
func (c *Collector) read(ctx context.Context, iface string, src platform.FrameSource, dec *Decoder) (int, error) {
	c.attach(iface, src)
	defer c.detach(iface, src)
	for n := 0; ; n++ {
		f, err := src.ReadFrame(ctx)
		if err != nil {
			return n, err
		}
		for _, o := range dec.Decode(f.Time, iface, f.Data) {
			ok := c.o.Bus.Publish(o)
			if !ok {
				dec.Forget(o)
			}
			c.count(iface, ok)
		}
	}
}

func (c *Collector) report(iface string, state platform.State, err error) {
	if c.o.Registry != nil {
		c.o.Registry.Set(iface, platform.CollectorCapture, c.o.Capturer.Backend(), state, err)
	}
}

func (c *Collector) attach(iface string, src platform.FrameSource) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stats[iface].src = src
}

// detach folds src's final counters into the totals, then closes it; Stats
// never sees the source closed but not yet counted.
func (c *Collector) detach(iface string, src platform.FrameSource) {
	c.mu.Lock()
	s := c.stats[iface]
	if st, err := src.Stats(); err == nil {
		s.base.Received += st.Received
		s.base.Dropped += st.Dropped
	}
	s.src = nil
	c.mu.Unlock()
	_ = src.Close()
}

func (c *Collector) count(iface string, published bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if published {
		c.stats[iface].observations++
	} else {
		c.stats[iface].busDropped++
	}
}

// Stats returns the counters of every interface
// (lan_sentinel_capture_drops_total).
func (c *Collector) Stats() []Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Stats, 0, len(c.o.Interfaces))
	for _, i := range c.o.Interfaces {
		s := c.stats[i.Name]
		st := Stats{Interface: i.Name, Received: s.base.Received, Dropped: s.base.Dropped,
			Observations: s.observations, BusDropped: s.busDropped}
		if s.src != nil {
			if cur, err := s.src.Stats(); err == nil {
				st.Received += cur.Received
				st.Dropped += cur.Dropped
			}
		}
		out = append(out, st)
	}
	return out
}
