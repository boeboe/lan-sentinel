package platform

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// These run unprivileged in the dev container on the loopback interface;
// frame sockets and raw ICMP need CAP_NET_RAW and are tested in Docker
// (test/net).

func TestDialBoundToInterface(t *testing.T) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	addr := netip.MustParseAddrPort(l.Addr().String())
	tx := socketTransmitter{}
	c, err := tx.DialTCP(context.Background(), "lo", addr, time.Second)
	if err != nil {
		t.Skipf("SO_BINDTODEVICE not allowed here: %v", err)
	}
	// The SYN retransmissions are capped, so a timeout sends at most 3 SYNs.
	rc, err := c.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var syncnt int
	var serr error
	_ = rc.Control(func(fd uintptr) { syncnt, serr = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_SYNCNT) })
	if serr != nil || syncnt != SYNRetries {
		t.Errorf("TCP_SYNCNT = %d, %v; want %d", syncnt, serr, SYNRetries)
	}
	_ = c.Close()
	if _, err := tx.DialTCP(context.Background(), "nosuch0", addr, time.Second); err == nil || !strings.Contains(err.Error(), "SO_BINDTODEVICE") {
		t.Errorf("unknown interface: %v", err)
	}
	u, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	uc, err := tx.DialUDP(context.Background(), "lo", netip.MustParseAddrPort(u.LocalAddr().String()))
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	if _, err := uc.Write([]byte("probe")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	_ = u.SetReadDeadline(time.Now().Add(time.Second))
	if n, _, err := u.ReadFrom(buf); err != nil || string(buf[:n]) != "probe" {
		t.Errorf("udp: %q %v", buf[:n], err)
	}
	if network("tcp", netip.MustParseAddr("::1")) != "tcp6" {
		t.Error("IPv6 network")
	}
}

func TestPingSocketOnLoopback(t *testing.T) {
	ec, err := socketTransmitter{}.ICMPConn(context.Background(), "lo")
	if err != nil {
		t.Skipf("no ICMP socket here: %v", err)
	}
	defer ec.Close()
	// Echo request: type 8, code 0, checksum (the kernel computes it for
	// ping sockets), identifier, sequence 1.
	msg := []byte{8, 0, 0, 0, 0, 0, 0, 1, 'l', 's'}
	if !ec.Ping() {
		msg[2], msg[3] = checksumFor(msg)
	}
	if err := ec.WriteTo(msg, netip.MustParseAddr("127.0.0.1")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	buf := make([]byte, 128)
	for {
		n, from, err := ec.ReadFrom(ctx, buf)
		if err != nil {
			t.Fatal(err)
		}
		if buf[0] == 0 && n >= 8 { // echo reply
			if from != netip.MustParseAddr("127.0.0.1") {
				t.Errorf("reply from %s", from)
			}
			return
		}
	}
}

func checksumFor(b []byte) (byte, byte) {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	c := ^uint16(sum)
	return byte(c >> 8), byte(c)
}

func TestFramesUnprivileged(t *testing.T) {
	_, err := socketTransmitter{}.Frames(context.Background(), "lo", 0x0806)
	if err == nil {
		t.Skip("running with CAP_NET_RAW")
	}
	if !errors.Is(err, os.ErrPermission) {
		t.Errorf("frames without CAP_NET_RAW: %v", err)
	}
	if _, err := (socketTransmitter{}).Frames(context.Background(), "nosuch0", 0x0806); err == nil {
		t.Error("unknown interface accepted")
	}
}

func TestClosedFrameConn(t *testing.T) {
	c := &frameConn{fd: -1, closed: true, iface: "eth9"}
	if err := c.WriteFrame(context.Background(), make([]byte, 60)); !errors.Is(err, net.ErrClosed) {
		t.Errorf("write: %v", err)
	}
	if err := c.WriteFrame(context.Background(), []byte{1}); err == nil {
		t.Error("runt frame accepted")
	}
	if _, err := c.ReadFrame(context.Background()); !errors.Is(err, net.ErrClosed) {
		t.Errorf("read: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Errorf("close twice: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.ReadFrame(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("read after cancel: %v", err)
	}
}

func TestPeerUser(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.sock")
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		c, err := net.Dial("unix", path)
		if err == nil {
			defer c.Close()
			time.Sleep(100 * time.Millisecond)
		}
	}()
	c, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	uid := strconv.Itoa(os.Getuid())
	want := "uid " + uid // no passwd entry, as in the dev container
	if u, err := user.LookupId(uid); err == nil {
		want = u.Username
	}
	if got, err := PeerUser(c); err != nil || got != want {
		t.Errorf("PeerUser = %q, %v, want %q", got, err, want)
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if _, err := PeerUser(a); err == nil {
		t.Error("PeerUser of a pipe succeeded")
	}
}
