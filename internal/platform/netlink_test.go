package platform

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// These tests use the real kernel in the test's own network namespace (the
// dev container): listing, dumping and subscribing need no privileges.

func TestNetlinkListInterfaces(t *testing.T) {
	links, err := netlinkInterfaces{}.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var lo *Link
	for i := range links {
		if links[i].Name == "lo" {
			lo = &links[i]
		}
		for _, p := range links[i].Prefixes {
			if p != p.Masked() || p.Addr().IsLoopback() || p.Addr().IsLinkLocalUnicast() {
				t.Errorf("%s: prefix %s should be masked and not loopback or link-local", links[i].Name, p)
			}
		}
	}
	if lo == nil || !lo.Up || len(lo.Prefixes) != 0 {
		t.Errorf("lo = %+v, want up with no own prefixes (loopback is excluded)", lo)
	}
}

// ipv4Subnet returns a non-loopback interface with an IPv4 prefix, if any.
func ipv4Subnet(t *testing.T) (Link, netip.Prefix) {
	t.Helper()
	links, err := netlinkInterfaces{}.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range links {
		for _, p := range l.Prefixes {
			if p.Addr().Is4() && p.Bits() <= 30 && l.Up {
				return l, p
			}
		}
	}
	t.Skip("no IPv4 subnet in this network namespace")
	return Link{}, netip.Prefix{}
}

func TestNetlinkNeighborEvent(t *testing.T) {
	link, prefix := ipv4Subnet(t)
	// An address in the subnet that nobody uses: sending to it makes the
	// kernel create an INCOMPLETE neighbour entry and announce it.
	target := lastUsable(prefix)
	n := &netlinkNeighbors{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch, err := n.Watch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: target.AsSlice(), Port: 9})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	deadline := time.After(10 * time.Second)
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	_, _ = conn.Write([]byte("lan-sentinel"))
	for {
		select {
		case ev := <-ch:
			if ev.Neighbor.IP != target {
				continue
			}
			if ev.Neighbor.Interface != link.Name || ev.Neighbor.State == "" {
				t.Errorf("event = %+v", ev)
			}
			list, err := n.Snapshot(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.ContainsFunc(list, func(nb Neighbor) bool { return nb.IP == target }) {
				t.Errorf("snapshot lacks %s", target)
			}
			return
		case <-tick.C:
			_, _ = conn.Write([]byte("lan-sentinel"))
		case <-deadline:
			t.Fatalf("no neighbour event for %s", target)
		}
	}
}

func lastUsable(p netip.Prefix) netip.Addr {
	a := p.Masked().Addr().As4()
	v := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	v |= uint32(1)<<(32-p.Bits()) - 2
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

func TestNetlinkWatchInterfacesSubscribes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ch, err := netlinkInterfaces{}.Watch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	for range ch { // closes after cancel
	}
}

// fakeSubs hands out subscriptions whose channels the test controls.
type fakeSubs[U any] struct {
	chans chan chan U
	fails int
}

func (f *fakeSubs[U]) sub() (subscription[U], error) {
	if f.fails > 0 {
		f.fails--
		return subscription[U]{}, unix.ENOBUFS
	}
	ch := make(chan U, 8)
	f.chans <- ch
	return subscription[U]{updates: ch, stop: func() {}}, nil
}

func TestNeighborWatchResubscribes(t *testing.T) {
	resubscribeDelay = time.Millisecond
	defer func() { resubscribeDelay = time.Second }()
	f := &fakeSubs[netlink.NeighUpdate]{chans: make(chan chan netlink.NeighUpdate, 4), fails: 1}
	// The first subscription succeeds; after it fails, one retry fails, the
	// next succeeds.
	f.fails = 0
	n := &netlinkNeighbors{subscribe: f.sub, links: linkNames{names: map[int]string{7: "eth7"}}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch, err := n.Watch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	first := <-f.chans
	mac := net.HardwareAddr{0, 0x1b, 0x1b, 0, 0, 1}
	first <- netlink.NeighUpdate{Type: unix.RTM_NEWNEIGH, Neigh: netlink.Neigh{LinkIndex: 7, IP: net.ParseIP("10.0.0.1"),
		HardwareAddr: mac, State: netlink.NUD_REACHABLE, Confirmed: 150}}
	first <- netlink.NeighUpdate{Type: unix.RTM_NEWNEIGH, Neigh: netlink.Neigh{LinkIndex: 99, IP: net.ParseIP("10.0.0.9")}} // unknown link: dropped
	ev := <-ch
	if ev.Neighbor.Interface != "eth7" || ev.Neighbor.State != "REACHABLE" || ev.Neighbor.ConfirmedAgo != 1500*time.Millisecond {
		t.Fatalf("event = %+v", ev)
	}
	f.fails = 1
	close(first) // subscription lost
	if ev := <-ch; !ev.Resync {
		t.Fatalf("want a resync event, got %+v", ev)
	}
	second := <-f.chans
	second <- netlink.NeighUpdate{Type: unix.RTM_DELNEIGH, Neigh: netlink.Neigh{LinkIndex: 7, IP: net.ParseIP("10.0.0.1")}}
	if ev := <-ch; !ev.Deleted || ev.Neighbor.IP != netip.MustParseAddr("10.0.0.1") {
		t.Fatalf("after resubscribing: %+v", ev)
	}
}

func TestInterfaceWatchResubscribes(t *testing.T) {
	resubscribeDelay = time.Millisecond
	defer func() { resubscribeDelay = time.Second }()
	f := &fakeSubs[linkChange]{chans: make(chan chan linkChange, 4)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch, err := netlinkInterfaces{subscribe: f.sub}.Watch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	first := <-f.chans
	first <- linkChange{index: lo.Attrs().Index}
	if ev := <-ch; ev.Link.Name != "lo" || ev.Removed {
		t.Fatalf("change event = %+v", ev)
	}
	first <- linkChange{index: 4242, removed: true}
	if ev := <-ch; !ev.Removed || ev.Link.Index != 4242 {
		t.Fatalf("removal = %+v", ev)
	}
	first <- linkChange{index: 4343} // no such link: reported as removed
	if ev := <-ch; !ev.Removed || ev.Link.Index != 4343 {
		t.Fatalf("missing link = %+v", ev)
	}
	close(first)
	if ev := <-ch; !ev.Resync {
		t.Fatalf("want a resync event, got %+v", ev)
	}
	<-f.chans // resubscribed
}

func TestWatchSubscribeError(t *testing.T) {
	f := &fakeSubs[linkChange]{chans: make(chan chan linkChange, 1), fails: 1}
	if _, err := (netlinkInterfaces{subscribe: f.sub}).Watch(context.Background()); err == nil {
		t.Error("interface watch: subscribe error not returned")
	}
	g := &fakeSubs[netlink.NeighUpdate]{chans: make(chan chan netlink.NeighUpdate, 1), fails: 1}
	if _, err := (&netlinkNeighbors{subscribe: g.sub}).Watch(context.Background()); err == nil {
		t.Error("neighbour watch: subscribe error not returned")
	}
}

func TestNUDStateAndPrefixes(t *testing.T) {
	for state, want := range map[int]string{
		netlink.NUD_INCOMPLETE: "INCOMPLETE", netlink.NUD_REACHABLE: "REACHABLE", netlink.NUD_STALE: "STALE",
		netlink.NUD_DELAY: "DELAY", netlink.NUD_PROBE: "PROBE", netlink.NUD_FAILED: "FAILED",
		netlink.NUD_NOARP: "NOARP", netlink.NUD_PERMANENT: "PERMANENT", netlink.NUD_NONE: "NONE", 0x300: "0x300",
	} {
		if got := nudState(state); got != want {
			t.Errorf("nudState(%#x) = %q, want %q", state, got, want)
		}
	}
	addr := func(cidr string) netlink.Addr {
		ip, n, _ := net.ParseCIDR(cidr)
		return netlink.Addr{IPNet: &net.IPNet{IP: ip, Mask: n.Mask}}
	}
	got := ownPrefixes([]netlink.Addr{
		addr("192.168.110.10/24"), addr("192.168.110.11/24"), addr("127.0.0.1/8"),
		addr("fe80::1/64"), addr("fd00::5/64"), {},
	})
	want := []netip.Prefix{netip.MustParsePrefix("192.168.110.0/24"), netip.MustParsePrefix("fd00::/64")}
	if !slices.Equal(got, want) {
		t.Errorf("ownPrefixes = %v, want %v", got, want)
	}
}
