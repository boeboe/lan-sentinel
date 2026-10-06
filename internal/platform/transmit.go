package platform

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// pollPeriod bounds how long a blocking read waits before it looks at its
// context again.
const pollPeriod = 200 * time.Millisecond

// socketTransmitter sends probes with sockets bound to an interface:
// AF_PACKET for frames, SO_BINDTODEVICE for TCP and UDP, ping or raw
// sockets for ICMP. All of it needs CAP_NET_RAW at most.
type socketTransmitter struct{}

// Backend implements Transmitter: afpacket for frames, a ping socket or a
// raw socket for ICMP (whichever ICMPConn gets), socket for TCP and UDP.
func (socketTransmitter) Backend(transport string) string {
	switch transport {
	case TransportFrames:
		return "afpacket"
	case TransportICMP:
		if pingSockets() {
			return "ping socket"
		}
		return "raw socket"
	}
	return "socket"
}

// pingSockets reports whether this process may open ICMP ping sockets
// (net.ipv4.ping_group_range), as ICMPConn finds out; it is checked once.
var pingSockets = sync.OnceValue(func() bool {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.IPPROTO_ICMP)
	if err != nil {
		return false
	}
	_ = unix.Close(fd)
	return true
})

func htons(v uint16) uint16 { return v<<8 | v>>8 }

// Frames opens an AF_PACKET socket bound to iface for one EtherType.
func (socketTransmitter) Frames(_ context.Context, iface string, etherType uint16) (FrameConn, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("frames on %s: %w", iface, err)
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(etherType)))
	if err != nil {
		return nil, fmt.Errorf("socket(AF_PACKET): %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(etherType), Ifindex: ifi.Index}); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("frames on %s: bind: %w", iface, err)
	}
	return &frameConn{fd: fd, iface: iface, index: ifi.Index, etherType: etherType, own: ifi.HardwareAddr}, nil
}

// frameConn is a packet socket for one EtherType. Reads hold the read lock
// so Close cannot release the descriptor under a read in progress.
type frameConn struct {
	mu        sync.RWMutex
	fd        int
	closed    bool
	iface     string
	index     int
	etherType uint16
	own       net.HardwareAddr
}

func (c *frameConn) WriteFrame(_ context.Context, frame []byte) error {
	if len(frame) < 14 {
		return fmt.Errorf("frames on %s: frame of %d bytes", c.iface, len(frame))
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.closed {
		return net.ErrClosed
	}
	to := &unix.SockaddrLinklayer{Protocol: htons(c.etherType), Ifindex: c.index, Halen: 6}
	copy(to.Addr[:], frame[:6])
	if err := unix.Sendto(c.fd, frame, 0, to); err != nil {
		return fmt.Errorf("frames on %s: send: %w", c.iface, err)
	}
	return nil
}

func (c *frameConn) ReadFrame(ctx context.Context) (Frame, error) {
	buf := make([]byte, 2048)
	for {
		if err := ctx.Err(); err != nil {
			return Frame{}, err
		}
		n, outgoing, err := c.recv(buf)
		switch {
		case errors.Is(err, unix.EAGAIN):
			continue
		case err != nil:
			return Frame{}, err
		case outgoing || n < 14 || bytes.Equal(buf[6:12], c.own):
			continue // the host's own frames (or a hairpin reflection)
		}
		return Frame{Time: time.Now().UTC(), Interface: c.iface, Data: bytes.Clone(buf[:n])}, nil
	}
}

// recv waits up to pollPeriod for one frame.
func (c *frameConn) recv(buf []byte) (int, bool, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.closed {
		return 0, false, net.ErrClosed
	}
	fds := []unix.PollFd{{Fd: int32(c.fd), Events: unix.POLLIN}}
	if n, err := unix.Poll(fds, int(pollPeriod.Milliseconds())); err != nil && !errors.Is(err, unix.EINTR) {
		return 0, false, fmt.Errorf("frames on %s: poll: %w", c.iface, err)
	} else if n == 0 {
		return 0, false, unix.EAGAIN
	}
	n, from, err := unix.Recvfrom(c.fd, buf, unix.MSG_DONTWAIT)
	if err != nil {
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
			return 0, false, unix.EAGAIN
		}
		return 0, false, fmt.Errorf("frames on %s: receive: %w", c.iface, err)
	}
	ll, _ := from.(*unix.SockaddrLinklayer)
	return n, ll != nil && ll.Pkttype == unix.PACKET_OUTGOING, nil
}

func (c *frameConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	return unix.Close(c.fd)
}

// bindToDevice is a dialer Control function that binds the socket to iface,
// so the probe leaves through that interface whatever the routing table
// says.
func bindToDevice(iface string) func(string, string, syscall.RawConn) error {
	return func(_, _ string, rc syscall.RawConn) error {
		var serr error
		if err := rc.Control(func(fd uintptr) { serr = unix.BindToDevice(int(fd), iface) }); err != nil {
			return err
		}
		if serr != nil {
			return fmt.Errorf("SO_BINDTODEVICE %s: %w", iface, serr)
		}
		return nil
	}
}

// SYNRetries caps the kernel's SYN retransmissions of a probe connect
// (TCP_SYNCNT): with the first SYN at most 3 leave, whatever the timeout
// (retries at 1 s and 3 s; the kernel gives up at about 7 s).
const SYNRetries = 2

func (socketTransmitter) DialTCP(ctx context.Context, iface string, addr netip.AddrPort, timeout time.Duration) (net.Conn, error) {
	bind := bindToDevice(iface)
	d := net.Dialer{Timeout: timeout, Control: func(netw, address string, rc syscall.RawConn) error {
		if err := bind(netw, address, rc); err != nil {
			return err
		}
		var serr error
		if err := rc.Control(func(fd uintptr) { serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_SYNCNT, SYNRetries) }); err != nil {
			return err
		}
		if serr != nil {
			return fmt.Errorf("TCP_SYNCNT: %w", serr)
		}
		return nil
	}}
	return d.DialContext(ctx, network("tcp", addr.Addr()), addr.String())
}

func (socketTransmitter) DialUDP(ctx context.Context, iface string, addr netip.AddrPort) (net.Conn, error) {
	d := net.Dialer{Control: bindToDevice(iface)}
	return d.DialContext(ctx, network("udp", addr.Addr()), addr.String())
}

func network(proto string, ip netip.Addr) string {
	if ip.Is4() {
		return proto + "4"
	}
	return proto + "6"
}

// ICMPConn opens a ping socket, or a raw ICMP socket where
// net.ipv4.ping_group_range does not allow ping sockets, bound to iface.
func (socketTransmitter) ICMPConn(_ context.Context, iface string) (EchoConn, error) {
	ping := true
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.IPPROTO_ICMP)
	if errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM) || errors.Is(err, unix.EPROTONOSUPPORT) {
		ping = false
		fd, err = unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_ICMP)
	}
	if err != nil {
		return nil, fmt.Errorf("ICMP socket: %w", err)
	}
	if err := unix.BindToDevice(fd, iface); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("ICMP socket: SO_BINDTODEVICE %s: %w", iface, err)
	}
	f := os.NewFile(uintptr(fd), "icmp")
	pc, err := net.FilePacketConn(f)
	_ = f.Close()
	if err != nil {
		return nil, fmt.Errorf("ICMP socket: %w", err)
	}
	return &echoConn{pc: pc, ping: ping}, nil
}

type echoConn struct {
	pc   net.PacketConn
	ping bool
}

func (e *echoConn) Ping() bool { return e.ping }

func (e *echoConn) WriteTo(msg []byte, dst netip.Addr) error {
	var to net.Addr = &net.IPAddr{IP: dst.AsSlice()}
	if e.ping {
		to = &net.UDPAddr{IP: dst.AsSlice()}
	}
	_, err := e.pc.WriteTo(msg, to)
	return err
}

func (e *echoConn) ReadFrom(ctx context.Context, buf []byte) (int, netip.Addr, error) {
	for {
		if err := ctx.Err(); err != nil {
			return 0, netip.Addr{}, err
		}
		_ = e.pc.SetReadDeadline(time.Now().Add(pollPeriod))
		n, from, err := e.pc.ReadFrom(buf)
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			continue
		}
		if err != nil {
			return 0, netip.Addr{}, err
		}
		var ip net.IP
		switch a := from.(type) {
		case *net.UDPAddr:
			ip = a.IP
		case *net.IPAddr:
			ip = a.IP
		}
		// A raw socket is a net.IPConn, which already strips the IPv4
		// header: both kinds deliver the bare ICMP message.
		addr, _ := netip.AddrFromSlice(ip)
		return n, addr.Unmap(), nil
	}
}

func (e *echoConn) Close() error { return e.pc.Close() }
