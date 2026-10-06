// Package fake provides in-memory implementations of the platform interfaces
// so shared code (collectors, scheduler, daemon) is tested identically on
// every OS without touching the network.
package fake

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"lan-sentinel/internal/platform"
)

// ErrClosed is returned by a closed fake frame source.
var ErrClosed = errors.New("fake: closed")

// Capturer hands out frame sources fed through Inject.
type Capturer struct {
	mu      sync.Mutex
	sources map[string]*FrameSource
	opens   map[string]int
	// OpenErr, if set, is returned by Open.
	OpenErr error
	// startDown makes new sources fail with ErrLinkDown at once, like a
	// socket bound to an administratively down interface.
	startDown bool
}

// NewCapturer returns an empty fake capturer.
func NewCapturer() *Capturer {
	return &Capturer{sources: map[string]*FrameSource{}, opens: map[string]int{}}
}

// Backend implements platform.Capturer.
func (c *Capturer) Backend() string { return "fake" }

// Open implements platform.Capturer.
func (c *Capturer) Open(_ context.Context, iface string, o platform.CaptureOptions) (platform.FrameSource, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.opens[iface]++
	if c.OpenErr != nil {
		return nil, c.OpenErr
	}
	src := &FrameSource{iface: iface, Options: o, frames: make(chan platform.Frame, 64), done: make(chan struct{}),
		down: make(chan struct{})}
	if c.startDown {
		src.LinkDown()
	}
	c.sources[iface] = src
	return src, nil
}

// SetStartDown makes sources opened from now on fail with
// platform.ErrLinkDown at once (true) or work normally (false).
func (c *Capturer) SetStartDown(down bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.startDown = down
}

// SetOpenErr sets the error Open returns (nil to succeed again).
func (c *Capturer) SetOpenErr(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.OpenErr = err
}

// Source returns the frame source last opened for iface, or nil.
func (c *Capturer) Source(iface string) *FrameSource {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sources[iface]
}

// Opens returns how many times Open was called for iface.
func (c *Capturer) Opens(iface string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.opens[iface]
}

// FrameSource is a fake capture handle.
type FrameSource struct {
	iface     string
	Options   platform.CaptureOptions
	frames    chan platform.Frame
	done      chan struct{}
	down      chan struct{}
	closeOnce sync.Once
	downOnce  sync.Once
	mu        sync.Mutex
	stats     platform.CaptureStats
	closed    bool
}

// Inject delivers a frame to the reader, dropping it (and counting the drop)
// if the buffer is full, like a kernel ring.
func (s *FrameSource) Inject(t time.Time, data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.Received++
	select {
	case s.frames <- platform.Frame{Time: t, Interface: s.iface, Data: data}:
	default:
		s.stats.Dropped++
	}
}

// LinkDown makes ReadFrame return platform.ErrLinkDown once the frames
// already queued have been read.
func (s *FrameSource) LinkDown() { s.downOnce.Do(func() { close(s.down) }) }

// Closed reports whether Close was called.
func (s *FrameSource) Closed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// ReadFrame implements platform.FrameSource.
func (s *FrameSource) ReadFrame(ctx context.Context) (platform.Frame, error) {
	select {
	case f := <-s.frames:
		return f, nil
	default:
	}
	select {
	case f := <-s.frames:
		return f, nil
	case <-s.down:
		return platform.Frame{}, platform.ErrLinkDown
	case <-s.done:
		return platform.Frame{}, ErrClosed
	case <-ctx.Done():
		return platform.Frame{}, ctx.Err()
	}
}

// Stats implements platform.FrameSource.
func (s *FrameSource) Stats() (platform.CaptureStats, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stats, nil
}

// Close implements platform.FrameSource.
func (s *FrameSource) Close() error {
	s.closeOnce.Do(func() { close(s.done) })
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	return nil
}

// Neighbors is a fake neighbour table.
type Neighbors struct {
	mu      sync.Mutex
	table   []platform.Neighbor
	watches []chan platform.NeighborEvent
}

// Backend implements platform.NeighborSource.
func (n *Neighbors) Backend() string { return "fake" }

// SetTable replaces the snapshot contents.
func (n *Neighbors) SetTable(t []platform.Neighbor) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.table = append([]platform.Neighbor(nil), t...)
}

// Snapshot implements platform.NeighborSource.
func (n *Neighbors) Snapshot(context.Context) ([]platform.Neighbor, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]platform.Neighbor(nil), n.table...), nil
}

// Watch implements platform.NeighborSource.
func (n *Neighbors) Watch(ctx context.Context) (<-chan platform.NeighborEvent, error) {
	ch := make(chan platform.NeighborEvent, 64)
	n.mu.Lock()
	n.watches = append(n.watches, ch)
	n.mu.Unlock()
	go func() {
		<-ctx.Done()
		n.mu.Lock()
		defer n.mu.Unlock()
		for i, w := range n.watches {
			if w == ch {
				n.watches = append(n.watches[:i], n.watches[i+1:]...)
				break
			}
		}
		close(ch)
	}()
	return ch, nil
}

// Emit sends ev to every active watch.
func (n *Neighbors) Emit(ev platform.NeighborEvent) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, w := range n.watches {
		w <- ev
	}
}

// Interfaces is a fake interface monitor.
type Interfaces struct {
	mu      sync.Mutex
	links   []platform.Link
	watches []chan platform.LinkEvent
}

// Backend implements platform.InterfaceMonitor.
func (f *Interfaces) Backend() string { return "fake" }

// SetLinks replaces the listed interfaces.
func (f *Interfaces) SetLinks(l []platform.Link) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.links = append([]platform.Link(nil), l...)
}

// List implements platform.InterfaceMonitor.
func (f *Interfaces) List(context.Context) ([]platform.Link, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]platform.Link(nil), f.links...), nil
}

// Watch implements platform.InterfaceMonitor.
func (f *Interfaces) Watch(ctx context.Context) (<-chan platform.LinkEvent, error) {
	ch := make(chan platform.LinkEvent, 64)
	f.mu.Lock()
	f.watches = append(f.watches, ch)
	f.mu.Unlock()
	go func() {
		<-ctx.Done()
		f.mu.Lock()
		defer f.mu.Unlock()
		for i, w := range f.watches {
			if w == ch {
				f.watches = append(f.watches[:i], f.watches[i+1:]...)
				break
			}
		}
		close(ch)
	}()
	return ch, nil
}

// Emit sends ev to every active watch.
func (f *Interfaces) Emit(ev platform.LinkEvent) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, w := range f.watches {
		w <- ev
	}
}

// SentFrame is a frame recorded by Transmitter.
type SentFrame struct {
	Interface string
	Data      []byte
}

// Transmitter records frames and answers TCP dials from a table.
type Transmitter struct {
	mu     sync.Mutex
	frames []SentFrame
	dials  []netip.AddrPort
	// TCPResult maps a target to the error DialTCP returns; nil or missing
	// means the connection succeeds.
	TCPResult map[netip.AddrPort]error
}

// Backend implements platform.Transmitter.
func (t *Transmitter) Backend() string { return "fake" }

// SendFrame implements platform.Transmitter.
func (t *Transmitter) SendFrame(_ context.Context, iface string, frame []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.frames = append(t.frames, SentFrame{Interface: iface, Data: append([]byte(nil), frame...)})
	return nil
}

// DialTCP implements platform.Transmitter.
func (t *Transmitter) DialTCP(_ context.Context, _ string, addr netip.AddrPort, _ time.Duration) (net.Conn, error) {
	t.mu.Lock()
	t.dials = append(t.dials, addr)
	err := t.TCPResult[addr]
	t.mu.Unlock()
	if err != nil {
		return nil, err
	}
	c1, c2 := net.Pipe()
	_ = c2.Close()
	return c1, nil
}

// ICMPConn implements platform.Transmitter.
func (t *Transmitter) ICMPConn(context.Context, string, bool) (net.PacketConn, error) {
	return nil, errors.New("fake: ICMP not simulated")
}

// Frames returns every frame sent so far.
func (t *Transmitter) Frames() []SentFrame {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]SentFrame(nil), t.frames...)
}

// Dials returns every TCP target dialled so far.
func (t *Transmitter) Dials() []netip.AddrPort {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]netip.AddrPort(nil), t.dials...)
}

// Backends returns a full set of fakes.
func Backends() (platform.Backends, *Capturer, *Neighbors, *Interfaces, *Transmitter) {
	c, n, i, t := NewCapturer(), &Neighbors{}, &Interfaces{}, &Transmitter{}
	return platform.Backends{Capturer: c, Neighbors: n, Interfaces: i, Transmitter: t}, c, n, i, t
}

var (
	_ platform.Capturer         = (*Capturer)(nil)
	_ platform.NeighborSource   = (*Neighbors)(nil)
	_ platform.InterfaceMonitor = (*Interfaces)(nil)
	_ platform.Transmitter      = (*Transmitter)(nil)
)
