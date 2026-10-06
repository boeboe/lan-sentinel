// Package fake provides in-memory implementations of the platform interfaces
// so shared code (collectors, scheduler, daemon) is tested identically on
// every OS without touching the network.
package fake

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
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

// Transmitter records probes and answers them through scriptable
// responders, like the hosts on a network would.
type Transmitter struct {
	mu     sync.Mutex
	frames []SentFrame
	dials  []netip.AddrPort
	udp    []UDPDatagram
	echoes []netip.Addr
	// TCPResult maps a target to the error DialTCP returns; nil or missing
	// means the connection succeeds.
	TCPResult map[netip.AddrPort]error
	// FrameReply answers a frame written to a frame connection with frames
	// delivered to that connection's reader.
	FrameReply func(iface string, frame []byte) [][]byte
	// EchoReply answers an ICMP message sent to dst (nil: no reply).
	EchoReply func(dst netip.Addr, msg []byte) []byte
	// UDPReply answers a UDP payload sent to addr (nil: no reply).
	UDPReply func(addr netip.AddrPort, payload []byte) []byte
	// FramesErr and ICMPErr, if set, are returned when opening.
	FramesErr, ICMPErr error
}

// UDPDatagram is a UDP payload sent by a probe.
type UDPDatagram struct {
	Interface string
	Addr      netip.AddrPort
	Payload   []byte
}

// Backend implements platform.Transmitter.
func (t *Transmitter) Backend() string { return "fake" }

// Frames implements platform.Transmitter.
func (t *Transmitter) Frames(_ context.Context, iface string, _ uint16) (platform.FrameConn, error) {
	if t.FramesErr != nil {
		return nil, t.FramesErr
	}
	return &frameConn{t: t, iface: iface, in: make(chan platform.Frame, 1024), done: make(chan struct{})}, nil
}

type frameConn struct {
	t     *Transmitter
	iface string
	in    chan platform.Frame
	done  chan struct{}
	once  sync.Once
}

func (c *frameConn) WriteFrame(_ context.Context, frame []byte) error {
	select {
	case <-c.done:
		return net.ErrClosed
	default:
	}
	c.t.mu.Lock()
	c.t.frames = append(c.t.frames, SentFrame{Interface: c.iface, Data: append([]byte(nil), frame...)})
	reply := c.t.FrameReply
	c.t.mu.Unlock()
	if reply != nil {
		for _, r := range reply(c.iface, frame) {
			select {
			case c.in <- platform.Frame{Time: time.Now(), Interface: c.iface, Data: r}:
			default:
			}
		}
	}
	return nil
}

func (c *frameConn) ReadFrame(ctx context.Context) (platform.Frame, error) {
	select {
	case f := <-c.in:
		return f, nil
	case <-c.done:
		return platform.Frame{}, net.ErrClosed
	case <-ctx.Done():
		return platform.Frame{}, ctx.Err()
	}
}

func (c *frameConn) Close() error {
	c.once.Do(func() { close(c.done) })
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

// DialUDP implements platform.Transmitter.
func (t *Transmitter) DialUDP(_ context.Context, iface string, addr netip.AddrPort) (net.Conn, error) {
	return &udpConn{t: t, iface: iface, addr: addr, in: make(chan []byte, 4)}, nil
}

// udpConn is a connected UDP socket whose replies come from UDPReply.
type udpConn struct {
	net.Conn // unused methods
	t        *Transmitter
	iface    string
	addr     netip.AddrPort
	in       chan []byte
	deadline time.Time
}

func (u *udpConn) Write(p []byte) (int, error) {
	u.t.mu.Lock()
	u.t.udp = append(u.t.udp, UDPDatagram{Interface: u.iface, Addr: u.addr, Payload: append([]byte(nil), p...)})
	reply := u.t.UDPReply
	u.t.mu.Unlock()
	if reply != nil {
		if r := reply(u.addr, p); r != nil {
			u.in <- r
		}
	}
	return len(p), nil
}

func (u *udpConn) Read(p []byte) (int, error) {
	var timeout <-chan time.Time
	if !u.deadline.IsZero() {
		timer := time.NewTimer(time.Until(u.deadline))
		defer timer.Stop()
		timeout = timer.C
	}
	select {
	case r := <-u.in:
		return copy(p, r), nil
	case <-timeout:
		return 0, os.ErrDeadlineExceeded
	}
}

func (u *udpConn) SetReadDeadline(t time.Time) error { u.deadline = t; return nil }
func (u *udpConn) SetDeadline(t time.Time) error     { u.deadline = t; return nil }
func (u *udpConn) Close() error                      { return nil }

// ICMPConn implements platform.Transmitter: a ping socket answering from
// EchoReply.
func (t *Transmitter) ICMPConn(context.Context, string) (platform.EchoConn, error) {
	if t.ICMPErr != nil {
		return nil, t.ICMPErr
	}
	return &echoConn{t: t, in: make(chan echo, 64), done: make(chan struct{})}, nil
}

type echo struct {
	msg  []byte
	from netip.Addr
}

type echoConn struct {
	t    *Transmitter
	in   chan echo
	done chan struct{}
	once sync.Once
}

func (e *echoConn) Ping() bool { return true }

func (e *echoConn) WriteTo(msg []byte, dst netip.Addr) error {
	e.t.mu.Lock()
	e.t.echoes = append(e.t.echoes, dst)
	reply := e.t.EchoReply
	e.t.mu.Unlock()
	if reply != nil {
		if r := reply(dst, msg); r != nil {
			e.in <- echo{r, dst}
		}
	}
	return nil
}

func (e *echoConn) ReadFrom(ctx context.Context, buf []byte) (int, netip.Addr, error) {
	select {
	case r := <-e.in:
		return copy(buf, r.msg), r.from, nil
	case <-e.done:
		return 0, netip.Addr{}, net.ErrClosed
	case <-ctx.Done():
		return 0, netip.Addr{}, ctx.Err()
	}
}

func (e *echoConn) Close() error {
	e.once.Do(func() { close(e.done) })
	return nil
}

// SentFrames returns every frame sent so far.
func (t *Transmitter) SentFrames() []SentFrame {
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

// Datagrams returns every UDP probe payload sent so far.
func (t *Transmitter) Datagrams() []UDPDatagram {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]UDPDatagram(nil), t.udp...)
}

// Echoes returns every ICMP destination so far.
func (t *Transmitter) Echoes() []netip.Addr {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]netip.Addr(nil), t.echoes...)
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
