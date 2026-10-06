package fake

import (
	"context"
	"errors"
	"net/netip"
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
	tx := &Transmitter{}
	ctx := context.Background()
	if err := tx.SendFrame(ctx, "eth1", []byte{1, 2}); err != nil || len(tx.Frames()) != 1 || tx.Frames()[0].Interface != "eth1" {
		t.Errorf("SendFrame: %v %+v", err, tx.Frames())
	}
	conn, err := tx.DialTCP(ctx, "eth1", netip.MustParseAddrPort("10.0.0.1:502"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if _, err := tx.ICMPConn(ctx, "eth1", false); err == nil {
		t.Error("ICMPConn should not be simulated")
	}
	if tx.Backend() != "fake" {
		t.Error("backend name")
	}
}
