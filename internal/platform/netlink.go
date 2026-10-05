package platform

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// userHZ converts the kernel's "clock ticks ago" neighbour cache times
// (nda_cacheinfo, scaled to USER_HZ) to durations. USER_HZ is 100 on Linux.
const userHZ = 100

// resubscribeDelay paces resubscription after a netlink receive error.
var resubscribeDelay = time.Second

// linkNames caches ifindex → interface name.
type linkNames struct {
	mu    sync.Mutex
	names map[int]string
}

func (l *linkNames) name(index int) string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if n, ok := l.names[index]; ok {
		return n
	}
	link, err := netlink.LinkByIndex(index)
	if err != nil {
		return ""
	}
	if l.names == nil {
		l.names = map[int]string{}
	}
	l.names[index] = link.Attrs().Name
	return l.names[index]
}

// nudState names a NUD state.
func nudState(s int) string {
	switch s {
	case netlink.NUD_INCOMPLETE:
		return "INCOMPLETE"
	case netlink.NUD_REACHABLE:
		return "REACHABLE"
	case netlink.NUD_STALE:
		return "STALE"
	case netlink.NUD_DELAY:
		return "DELAY"
	case netlink.NUD_PROBE:
		return "PROBE"
	case netlink.NUD_FAILED:
		return "FAILED"
	case netlink.NUD_NOARP:
		return "NOARP"
	case netlink.NUD_PERMANENT:
		return "PERMANENT"
	case netlink.NUD_NONE:
		return "NONE"
	}
	return fmt.Sprintf("0x%x", s)
}

// subscription is a running netlink subscription: its update channel
// closes when the subscription fails; stop ends it.
type subscription[U any] struct {
	updates <-chan U
	stop    func()
}

// resubscribing forwards updates from sub to handle until ctx is cancelled.
// When a subscription fails (its channel closes, e.g. after ENOBUFS) it
// calls resync and subscribes again, pacing retries by resubscribeDelay.
func resubscribing[U any](ctx context.Context, first subscription[U], sub func() (subscription[U], error), handle func(U), resync func()) {
	s := first
	for {
		select {
		case <-ctx.Done():
			s.stop()
			return
		case u, ok := <-s.updates:
			if ok {
				handle(u)
				continue
			}
			s.stop()
			resync()
			for {
				if !sleep(ctx, resubscribeDelay) {
					return
				}
				next, err := sub()
				if err == nil {
					s = next
					break
				}
			}
		}
	}
}

// netlinkNeighbors reads and follows the kernel neighbour table.
type netlinkNeighbors struct {
	links linkNames
	// subscribe starts a neighbour subscription; nil means rtnetlink.
	subscribe func() (subscription[netlink.NeighUpdate], error)
}

func (*netlinkNeighbors) Backend() string { return "netlink" }

func (n *netlinkNeighbors) convert(ne netlink.Neigh) (Neighbor, bool) {
	ip, ok := netip.AddrFromSlice(ne.IP)
	name := n.links.name(ne.LinkIndex)
	if !ok || name == "" {
		return Neighbor{}, false
	}
	return Neighbor{
		Interface:    name,
		IP:           ip.Unmap(),
		MAC:          append(net.HardwareAddr(nil), ne.HardwareAddr...),
		State:        nudState(ne.State),
		ConfirmedAgo: time.Duration(ne.Confirmed) * time.Second / userHZ,
	}, true
}

func (n *netlinkNeighbors) Snapshot(context.Context) ([]Neighbor, error) {
	list, err := netlink.NeighList(0, netlink.FAMILY_ALL)
	if err != nil {
		return nil, fmt.Errorf("neighbour dump: %w", err)
	}
	out := make([]Neighbor, 0, len(list))
	for _, ne := range list {
		if nb, ok := n.convert(ne); ok {
			out = append(out, nb)
		}
	}
	return out, nil
}

func subscribeNeighbors() (subscription[netlink.NeighUpdate], error) {
	ch, done := make(chan netlink.NeighUpdate, 256), make(chan struct{})
	err := netlink.NeighSubscribeWithOptions(ch, done, netlink.NeighSubscribeOptions{
		ErrorCallback:     func(error) {},
		ReceiveBufferSize: 1 << 20,
	})
	if err != nil {
		return subscription[netlink.NeighUpdate]{}, fmt.Errorf("neighbour subscribe: %w", err)
	}
	return subscription[netlink.NeighUpdate]{updates: ch, stop: closer(done)}, nil
}

// Watch subscribes to RTM_NEWNEIGH/RTM_DELNEIGH. When the subscription
// fails it emits a Resync event and resubscribes, so the consumer takes a
// fresh Snapshot.
func (n *netlinkNeighbors) Watch(ctx context.Context) (<-chan NeighborEvent, error) {
	sub := n.subscribe
	if sub == nil {
		sub = subscribeNeighbors
	}
	first, err := sub()
	if err != nil {
		return nil, err
	}
	out := make(chan NeighborEvent, 256)
	go func() {
		defer close(out)
		resubscribing(ctx, first, sub, func(u netlink.NeighUpdate) {
			if nb, ok := n.convert(u.Neigh); ok {
				send(ctx, out, NeighborEvent{Time: time.Now(), Neighbor: nb, Deleted: u.Type == unix.RTM_DELNEIGH})
			}
		}, func() { send(ctx, out, NeighborEvent{Time: time.Now(), Resync: true}) })
	}()
	return out, nil
}

// netlinkInterfaces lists links and follows link and address changes.
type netlinkInterfaces struct {
	// subscribe starts a link and address subscription; nil means rtnetlink.
	subscribe func() (subscription[linkChange], error)
}

// linkChange says that the link with this index changed or was removed.
type linkChange struct {
	index   int
	removed bool
}

func (netlinkInterfaces) Backend() string { return "netlink" }

func linkInfo(l netlink.Link) (Link, error) {
	a := l.Attrs()
	up := a.OperState == netlink.OperUp ||
		(a.OperState == netlink.OperUnknown && a.Flags&net.FlagUp != 0)
	addrs, err := netlink.AddrList(l, netlink.FAMILY_ALL)
	if err != nil {
		return Link{}, fmt.Errorf("addresses of %s: %w", a.Name, err)
	}
	return Link{Name: a.Name, Index: a.Index, MAC: a.HardwareAddr, Up: up, Prefixes: ownPrefixes(addrs)}, nil
}

// ownPrefixes returns the masked subnets of an interface's addresses,
// leaving out link-local and loopback addresses.
func ownPrefixes(addrs []netlink.Addr) []netip.Prefix {
	seen := map[netip.Prefix]bool{}
	var prefixes []netip.Prefix
	for _, ad := range addrs {
		if ad.IPNet == nil {
			continue
		}
		ip, ok := netip.AddrFromSlice(ad.IP)
		if !ok {
			continue
		}
		ip = ip.Unmap()
		if ip.IsLinkLocalUnicast() || ip.IsLoopback() {
			continue
		}
		bits, _ := ad.Mask.Size()
		p := netip.PrefixFrom(ip, bits).Masked()
		if !seen[p] {
			seen[p] = true
			prefixes = append(prefixes, p)
		}
	}
	sort.Slice(prefixes, func(i, j int) bool { return prefixes[i].String() < prefixes[j].String() })
	return prefixes
}

func (netlinkInterfaces) List(context.Context) ([]Link, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, fmt.Errorf("link list: %w", err)
	}
	out := make([]Link, 0, len(links))
	for _, l := range links {
		li, err := linkInfo(l)
		if err != nil {
			return nil, err
		}
		out = append(out, li)
	}
	return out, nil
}

// subscribeLinks merges link and address subscriptions into one stream of
// changed link indexes; it closes when either subscription fails.
func subscribeLinks() (subscription[linkChange], error) {
	links, addrs, done := make(chan netlink.LinkUpdate, 64), make(chan netlink.AddrUpdate, 64), make(chan struct{})
	stop := closer(done)
	if err := netlink.LinkSubscribeWithOptions(links, done, netlink.LinkSubscribeOptions{ErrorCallback: func(error) {}}); err != nil {
		stop()
		return subscription[linkChange]{}, fmt.Errorf("link subscribe: %w", err)
	}
	if err := netlink.AddrSubscribeWithOptions(addrs, done, netlink.AddrSubscribeOptions{ErrorCallback: func(error) {}}); err != nil {
		stop()
		return subscription[linkChange]{}, fmt.Errorf("address subscribe: %w", err)
	}
	out := make(chan linkChange, 64)
	go func() {
		defer close(out)
		for {
			var c linkChange
			select {
			case <-done:
				return
			case u, ok := <-links:
				if !ok {
					return
				}
				c = linkChange{index: int(u.Index), removed: u.Header.Type == unix.RTM_DELLINK}
			case u, ok := <-addrs:
				if !ok {
					return
				}
				c = linkChange{index: u.LinkIndex}
			}
			select {
			case out <- c:
			case <-done:
				return
			}
		}
	}()
	return subscription[linkChange]{updates: out, stop: stop}, nil
}

// Watch follows link and address changes; each change re-reads the link so
// events carry its complete state. Subscription errors produce a Resync
// event and a resubscription.
func (n netlinkInterfaces) Watch(ctx context.Context) (<-chan LinkEvent, error) {
	sub := n.subscribe
	if sub == nil {
		sub = subscribeLinks
	}
	first, err := sub()
	if err != nil {
		return nil, err
	}
	out := make(chan LinkEvent, 64)
	go func() {
		defer close(out)
		resubscribing(ctx, first, sub, func(c linkChange) {
			if ev, ok := reread(c); ok {
				send(ctx, out, ev)
			}
		}, func() { send(ctx, out, LinkEvent{Time: time.Now(), Resync: true}) })
	}()
	return out, nil
}

// reread turns a link change into an event with the link's current state.
func reread(c linkChange) (LinkEvent, bool) {
	removed := LinkEvent{Time: time.Now(), Link: Link{Index: c.index}, Removed: true}
	if c.removed {
		return removed, true
	}
	l, err := netlink.LinkByIndex(c.index)
	if err != nil {
		var nf netlink.LinkNotFoundError
		return removed, errors.As(err, &nf)
	}
	li, err := linkInfo(l)
	if err != nil {
		return LinkEvent{}, false
	}
	return LinkEvent{Time: time.Now(), Link: li}, true
}

// closer returns an idempotent close of done.
func closer(done chan struct{}) func() {
	var once sync.Once
	return func() { once.Do(func() { close(done) }) }
}

func send[T any](ctx context.Context, ch chan<- T, v T) {
	select {
	case ch <- v:
	case <-ctx.Done():
	}
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}
