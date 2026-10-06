package platform_test

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"lan-sentinel/internal/platform"
	"lan-sentinel/internal/platform/fake"
)

func TestNewBackends(t *testing.T) {
	b := platform.New()
	if b.Capturer.Backend() != "afpacket" || b.Transmitter.Backend() != "socket" || b.Neighbors.Backend() != "netlink" {
		t.Errorf("backends = %s %s %s", b.Capturer.Backend(), b.Transmitter.Backend(), b.Neighbors.Backend())
	}
}

func TestRegistry(t *testing.T) {
	now := time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)
	r := platform.NewRegistry(func() time.Time { return now })
	r.Set("eth1", platform.CollectorCapture, "afpacket", platform.StateRunning, nil)
	r.Set("eth1", platform.CollectorTCP, "afpacket", platform.StateDisabled, nil)
	if r.Degraded() {
		t.Fatal("running + disabled must not be degraded")
	}
	now = now.Add(time.Minute)
	r.Set("eth0", platform.CollectorCapture, "afpacket", platform.StateFailed, errors.New("permission denied"))
	if !r.Degraded() {
		t.Fatal("failed collector must make the registry degraded")
	}
	// Re-reporting the same state keeps the original Since.
	now = now.Add(time.Minute)
	r.Set("eth0", platform.CollectorCapture, "afpacket", platform.StateFailed, errors.New("permission denied"))

	got := r.List()
	if len(got) != 3 || got[0].Interface != "eth0" || got[1].Collector != platform.CollectorCapture || got[2].Collector != platform.CollectorTCP {
		t.Fatalf("List order = %+v", got)
	}
	if got[0].Error != "permission denied" || !got[0].Since.Equal(time.Date(2026, 10, 1, 10, 1, 0, 0, time.UTC)) {
		t.Errorf("eth0 status = %+v", got[0])
	}
}

func TestFakes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b, capt, neigh, _, tx := fake.Backends()

	src, err := b.Capturer.Open(ctx, "eth1", platform.CaptureOptions{Promiscuous: true})
	if err != nil {
		t.Fatal(err)
	}
	capt.Source("eth1").Inject(time.Unix(1, 0), []byte{1, 2, 3})
	f, err := src.ReadFrame(ctx)
	if err != nil || f.Interface != "eth1" || len(f.Data) != 3 {
		t.Fatalf("ReadFrame = %+v, %v", f, err)
	}
	_ = src.Close()
	if _, err := src.ReadFrame(ctx); !errors.Is(err, fake.ErrClosed) {
		t.Errorf("ReadFrame after Close = %v", err)
	}

	ch, err := b.Neighbors.Watch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ip := netip.MustParseAddr("192.168.110.50")
	neigh.Emit(platform.NeighborEvent{Neighbor: platform.Neighbor{Interface: "eth1", IP: ip, State: "REACHABLE"}})
	if ev := <-ch; ev.Neighbor.IP != ip {
		t.Errorf("event = %+v", ev)
	}

	target := netip.MustParseAddrPort("192.168.110.50:502")
	tx.TCPResult = map[netip.AddrPort]error{target: errors.New("connection refused")}
	if _, err := b.Transmitter.DialTCP(ctx, "eth1", target, time.Second); err == nil {
		t.Error("expected refused dial")
	}
	if d := tx.Dials(); len(d) != 1 || d[0] != target {
		t.Errorf("dials = %v", d)
	}
	cancel()
	if _, ok := <-ch; ok {
		t.Error("watch channel not closed after cancel")
	}
}
