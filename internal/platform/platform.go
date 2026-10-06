// Package platform is the only boundary between LAN Sentinel and the
// kernel's networking facilities. Capture, neighbour monitoring, interface
// monitoring and probe transmission each sit behind one small interface,
// implemented with AF_PACKET, rtnetlink and raw or ping sockets (backends.go),
// so the rest of the daemon can be tested against fakes (platform/fake). See
// docs/ARCHITECTURE.md §3.
package platform

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	"golang.org/x/net/bpf"
)

// ErrNotImplemented is returned by backends that are planned but not built
// yet; the error says in which phase they land.
var ErrNotImplemented = errors.New("not implemented")

// Frame is one captured link-layer frame.
type Frame struct {
	Time      time.Time
	Interface string
	Data      []byte
}

// CaptureStats are kernel-reported capture counters. Received counts the
// frames that passed the filter, including those Dropped because the ring
// was full.
type CaptureStats struct {
	Received uint64
	Dropped  uint64
}

// ErrLinkDown is returned by ReadFrame when the interface went down or
// disappeared; the caller closes the source and opens it again later.
var ErrLinkDown = errors.New("interface is down or gone")

// DefaultRingSize is the capture ring size when CaptureOptions.RingSize is
// zero.
const DefaultRingSize = 2 << 20

// CaptureOptions configures a capture handle.
type CaptureOptions struct {
	// Filter is a classic-BPF program run by the kernel on every frame.
	Filter []bpf.RawInstruction
	// Promiscuous joins PACKET_MR_PROMISC (PACKET_ADD_MEMBERSHIP); it is
	// dropped with the socket.
	Promiscuous bool
	// RingSize is the TPACKET_V3 ring size in bytes, rounded down to whole
	// blocks; 0 means DefaultRingSize.
	RingSize int
}

// FrameSource delivers captured frames for one interface.
type FrameSource interface {
	// ReadFrame blocks until a frame arrives, ctx is cancelled or the source
	// is closed. It returns ErrLinkDown when the interface goes away.
	ReadFrame(ctx context.Context) (Frame, error)
	Stats() (CaptureStats, error)
	Close() error
}

// Capturer opens receive-only AF_PACKET capture handles. It never
// transmits.
type Capturer interface {
	Backend() string
	Open(ctx context.Context, iface string, o CaptureOptions) (FrameSource, error)
}

// Neighbor is one kernel neighbour-table entry.
type Neighbor struct {
	Interface string
	IP        netip.Addr
	MAC       net.HardwareAddr
	// State is the NUD state: REACHABLE, STALE, DELAY, PROBE, FAILED, ...
	State string
	// ConfirmedAgo is how long ago reachability was last confirmed.
	ConfirmedAgo time.Duration
}

// NeighborEvent is a change notification. Resync means notifications were
// lost and the consumer must take a fresh Snapshot.
type NeighborEvent struct {
	Time     time.Time
	Neighbor Neighbor
	Deleted  bool
	Resync   bool
}

// NeighborSource reads and follows the kernel neighbour table (rtnetlink).
type NeighborSource interface {
	Backend() string
	Snapshot(ctx context.Context) ([]Neighbor, error)
	// Watch streams changes until ctx is cancelled; the channel is closed
	// when the watch ends.
	Watch(ctx context.Context) (<-chan NeighborEvent, error)
}

// Link is a network interface with its own addresses.
type Link struct {
	Name  string
	Index int
	MAC   net.HardwareAddr
	Up    bool
	// Prefixes are the masked subnets of the interface's addresses
	// (loopback and link-local left out); Addrs are the addresses
	// themselves with their prefix length.
	Prefixes []netip.Prefix
	Addrs    []netip.Prefix
}

// LinkEvent is an interface change. Resync means notifications were lost.
type LinkEvent struct {
	Time    time.Time
	Link    Link
	Removed bool
	Resync  bool
}

// InterfaceMonitor lists interfaces and follows link and address changes.
type InterfaceMonitor interface {
	Backend() string
	List(ctx context.Context) ([]Link, error)
	Watch(ctx context.Context) (<-chan LinkEvent, error)
}

// FrameConn sends and receives the link-layer frames of one EtherType on
// one interface (ARP probes). It carries no protocol logic. Received frames
// carry their interface; the host's own outgoing frames are not returned.
type FrameConn interface {
	// WriteFrame sends a complete Ethernet frame out of the interface.
	WriteFrame(ctx context.Context, frame []byte) error
	// ReadFrame blocks until a frame arrives, ctx is done or the
	// connection is closed.
	ReadFrame(ctx context.Context) (Frame, error)
	Close() error
}

// EchoConn is an IPv4 ICMP socket bound to an interface: a kernel ping
// socket where net.ipv4.ping_group_range allows it, else a raw socket.
type EchoConn interface {
	// WriteTo sends an ICMP message (header and body) to dst.
	WriteTo(msg []byte, dst netip.Addr) error
	// ReadFrom returns the next ICMP message (without an IP header) and its
	// sender, until ctx is done.
	ReadFrom(ctx context.Context, buf []byte) (int, netip.Addr, error)
	// Ping reports a kernel ping socket: the kernel sets the echo
	// identifier and checksum and delivers only replies to this socket.
	Ping() bool
	Close() error
}

// Transmitter sends probes. Every probe leaves through the interface it was
// scheduled for, and only CAP_NET_RAW is needed.
type Transmitter interface {
	Backend() string
	// Frames opens a frame connection on iface for one EtherType.
	Frames(ctx context.Context, iface string, etherType uint16) (FrameConn, error)
	// DialTCP makes a plain connect() bound to iface (SO_BINDTODEVICE).
	// The caller closes the connection immediately and never writes.
	DialTCP(ctx context.Context, iface string, addr netip.AddrPort, timeout time.Duration) (net.Conn, error)
	// DialUDP opens a UDP socket bound to iface and connected to addr, for
	// protocol-specific probes.
	DialUDP(ctx context.Context, iface string, addr netip.AddrPort) (net.Conn, error)
	// ICMPConn opens an IPv4 ICMP echo socket bound to iface.
	ICMPConn(ctx context.Context, iface string) (EchoConn, error)
}

// Backends is the set of platform implementations.
type Backends struct {
	Capturer    Capturer
	Neighbors   NeighborSource
	Interfaces  InterfaceMonitor
	Transmitter Transmitter
}
