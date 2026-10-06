package fake

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"testing"
	"time"

	"lan-sentinel/internal/platform"
)

func TestCapturer(t *testing.T) {
	c := NewCapturer()
	ctx := context.Background()
	src, err := c.Open(ctx, "eth1", platform.CaptureOptions{Promiscuous: true, RingSize: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	fs := c.Source("eth1")
	if !fs.Options.Promiscuous || fs.Options.RingSize != 1<<20 || c.Opens("eth1") != 1 {
		t.Error("options or open count not recorded")
	}
	for range 70 { // buffer is 64: the rest are dropped like a full ring
		fs.Inject(time.Unix(1, 0), []byte{1})
	}
	st, _ := src.Stats()
	if st.Received != 70 || st.Dropped != 6 {
		t.Errorf("stats = %+v", st)
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	for range 64 {
		_, _ = src.ReadFrame(ctx)
	}
	if _, err := src.ReadFrame(cctx); !errors.Is(err, context.Canceled) {
		t.Errorf("ReadFrame after cancel = %v", err)
	}
	fs.Inject(time.Unix(2, 0), []byte{2})
	fs.LinkDown()
	if f, err := src.ReadFrame(ctx); err != nil || f.Data[0] != 2 {
		t.Errorf("queued frame before link down: %v, %v", f, err)
	}
	if _, err := src.ReadFrame(ctx); !errors.Is(err, platform.ErrLinkDown) {
		t.Errorf("ReadFrame after LinkDown = %v", err)
	}
	_ = src.Close()
	if !fs.Closed() {
		t.Error("Close not recorded")
	}
	c.SetOpenErr(errors.New("permission denied"))
	if _, err := c.Open(ctx, "eth2", platform.CaptureOptions{}); err == nil || c.Opens("eth2") != 1 {
		t.Error("OpenErr not returned or open not counted")
	}
}

func TestInterfacesAndNeighbors(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	i := &Interfaces{}
	i.SetLinks([]platform.Link{{Name: "eth1"}})
	if l, _ := i.List(ctx); len(l) != 1 || i.Backend() != "fake" {
		t.Errorf("List = %v", l)
	}
	ch, _ := i.Watch(ctx)
	i.Emit(platform.LinkEvent{Link: platform.Link{Name: "eth1"}})
	if ev := <-ch; ev.Link.Name != "eth1" {
		t.Errorf("event = %+v", ev)
	}
	n := &Neighbors{}
	n.SetTable([]platform.Neighbor{{Interface: "eth1"}})
	if l, _ := n.Snapshot(ctx); len(l) != 1 || n.Backend() != "fake" {
		t.Errorf("Snapshot = %v", l)
	}
	cancel()
	if _, ok := <-ch; ok {
		t.Error("watch channel not closed")
	}
}

func TestTransmitter(t *testing.T) {
	tx := &Transmitter{
		FrameReply: func(_ string, f []byte) [][]byte { return [][]byte{append([]byte("re:"), f...)} },
		EchoReply:  func(_ netip.Addr, msg []byte) []byte { return msg },
		UDPReply: func(a netip.AddrPort, p []byte) []byte {
			if a.Port() == 123 {
				return p
			}
			return nil
		},
	}
	ctx := context.Background()
	fc, err := tx.Frames(ctx, "eth1", 0x0806)
	if err != nil {
		t.Fatal(err)
	}
	if err := fc.WriteFrame(ctx, []byte("frame")); err != nil || len(tx.SentFrames()) != 1 || tx.SentFrames()[0].Interface != "eth1" {
		t.Errorf("WriteFrame: %v %+v", err, tx.SentFrames())
	}
	if f, err := fc.ReadFrame(ctx); err != nil || string(f.Data) != "re:frame" || f.Interface != "eth1" {
		t.Errorf("ReadFrame = %+v, %v", f, err)
	}
	_ = fc.Close()
	if _, err := fc.ReadFrame(ctx); err == nil || fc.WriteFrame(ctx, []byte("x")) == nil {
		t.Error("closed frame connection still works")
	}

	conn, err := tx.DialTCP(ctx, "eth1", netip.MustParseAddrPort("10.0.0.1:502"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()

	ec, err := tx.ICMPConn(ctx, "eth1")
	if err != nil || !ec.Ping() {
		t.Fatal(err)
	}
	dst := netip.MustParseAddr("10.0.0.1")
	_ = ec.WriteTo([]byte{8, 0}, dst)
	buf := make([]byte, 16)
	if n, from, err := ec.ReadFrom(ctx, buf); err != nil || n != 2 || from != dst || len(tx.Echoes()) != 1 {
		t.Errorf("echo: %d %v %v", n, from, err)
	}
	_ = ec.Close()
	if _, _, err := ec.ReadFrom(ctx, buf); err == nil {
		t.Error("closed echo connection still reads")
	}

	uc, _ := tx.DialUDP(ctx, "eth1", netip.MustParseAddrPort("10.0.0.1:123"))
	_, _ = uc.Write([]byte("ntp"))
	_ = uc.SetReadDeadline(time.Now().Add(time.Second))
	if n, err := uc.Read(buf); err != nil || string(buf[:n]) != "ntp" {
		t.Errorf("udp reply: %q %v", buf[:n], err)
	}
	silent, _ := tx.DialUDP(ctx, "eth1", netip.MustParseAddrPort("10.0.0.1:44818"))
	_, _ = silent.Write([]byte("enip"))
	_ = silent.SetDeadline(time.Now().Add(10 * time.Millisecond))
	if _, err := silent.Read(buf); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("silent udp: %v", err)
	}
	_ = silent.Close()
	if len(tx.Datagrams()) != 2 || tx.Backend() != "fake" {
		t.Errorf("datagrams = %+v", tx.Datagrams())
	}
	tx.FramesErr, tx.ICMPErr = errors.New("eperm"), errors.New("eperm")
	if _, err := tx.Frames(ctx, "eth1", 0x0806); err == nil {
		t.Error("FramesErr ignored")
	}
	if _, err := tx.ICMPConn(ctx, "eth1"); err == nil {
		t.Error("ICMPErr ignored")
	}
}
