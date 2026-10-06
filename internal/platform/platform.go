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
	Name     string
	Index    int
	MAC      net.HardwareAddr
	Up       bool
	Prefixes []netip.Prefix
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

// Transmitter sends probes. Every probe leaves through the interface it was
// scheduled for.
type Transmitter interface {
	Backend() string
	// SendFrame writes a complete link-layer frame (ARP, NDP).
	SendFrame(ctx context.Context, iface string, frame []byte) error
	// DialTCP makes a plain connect() bound to iface. The caller closes the
	// connection immediately and never writes a payload.
	DialTCP(ctx context.Context, iface string, addr netip.AddrPort, timeout time.Duration) (net.Conn, error)
	// ICMPConn opens an ICMP echo socket bound to iface: a ping socket where
	// net.ipv4.ping_group_range allows it, else a raw socket.
	ICMPConn(ctx context.Context, iface string, ipv6 bool) (net.PacketConn, error)
}

// Backends is the set of platform implementations.
type Backends struct {
	Capturer    Capturer
	Neighbors   NeighborSource
	Interfaces  InterfaceMonitor
	Transmitter Transmitter
}
