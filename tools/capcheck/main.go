// Command capcheck is the phase 0 privilege and feasibility check. It runs
// every kernel operation LAN Sentinel's collectors and probes need, under the
// identity it is started with, and reports PASS, FAIL or SKIP per operation
// (docs/ARCHITECTURE.md §8).
//
// It never transmits unless a target is given (--arp-target, --ndp-target,
// --icmp-target, --tcp-target), and then sends exactly one probe per target.
//
// Run it the way the daemon runs: as the lan-sentinel user with only
// CAP_NET_RAW (see README.md). `make test-net` runs it that way in a Docker
// container on a test network.
package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"os/user"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"text/tabwriter"
	"time"

	"golang.org/x/net/bpf"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

type status string

const (
	pass status = "PASS"
	fail status = "FAIL"
	skip status = "SKIP"
)

type result struct {
	Name     string `json:"name"`
	Status   status `json:"status"`
	Expected string `json:"expected"` // privilege the design expects
	Detail   string `json:"detail,omitempty"`
	Error    string `json:"error,omitempty"`
}

type options struct {
	iface         string
	promisc       bool
	arpTarget     netip.Addr
	ndpTarget     netip.Addr
	icmpTarget    netip.Addr
	tcpTarget     netip.AddrPort
	capture       time.Duration
	watch         time.Duration
	snapshotEvery time.Duration
	jsonOut       bool
	verbose       bool
}

type report struct {
	Tool      string    `json:"tool"`
	Time      time.Time `json:"time"`
	Platform  string    `json:"platform"`
	OS        string    `json:"os"`
	User      string    `json:"user"`
	Groups    []string  `json:"groups"`
	Privilege string    `json:"privilege"`
	Interface string    `json:"interface"`
	Results   []result  `json:"results"`
}

// iface describes the interface under test.
type ifaceInfo struct {
	name  string
	index int
	mac   net.HardwareAddr
	ipv4  netip.Addr
	ll6   netip.Addr
}

func main() {
	var o options
	var arp, ndp, icmpT, tcp string
	flag.StringVar(&o.iface, "interface", "", "interface to test (required)")
	flag.BoolVar(&o.promisc, "promisc", true, "test promiscuous mode (enabled briefly, then restored)")
	flag.StringVar(&arp, "arp-target", "", "send one ARP request for this IPv4 address")
	flag.StringVar(&ndp, "ndp-target", "", "send one neighbour solicitation for this IPv6 address")
	flag.StringVar(&icmpT, "icmp-target", "", "send one ICMP echo to this IPv4 address")
	flag.StringVar(&tcp, "tcp-target", "", "connect once to this IPv4 address:port, bound to the interface")
	flag.DurationVar(&o.capture, "capture", 5*time.Second, "how long to capture frames")
	flag.DurationVar(&o.watch, "watch", 0, "watch neighbour notifications this long and compare with snapshots (0 = skip)")
	flag.DurationVar(&o.snapshotEvery, "snapshot-every", 5*time.Second, "snapshot interval during --watch")
	flag.BoolVar(&o.jsonOut, "json", false, "print JSON")
	flag.BoolVar(&o.verbose, "verbose", false, "during --watch, log every notification and snapshot change to stderr")
	flag.Parse()

	if o.iface == "" {
		fmt.Fprintln(os.Stderr, "capcheck: --interface is required")
		flag.Usage()
		os.Exit(64)
	}
	var err error
	parse := func(s string, into *netip.Addr) {
		if s != "" && err == nil {
			*into, err = netip.ParseAddr(s)
		}
	}
	parse(arp, &o.arpTarget)
	parse(ndp, &o.ndpTarget)
	parse(icmpT, &o.icmpTarget)
	if tcp != "" && err == nil {
		o.tcpTarget, err = netip.ParseAddrPort(tcp)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "capcheck:", err)
		os.Exit(64)
	}

	ifi, err := lookupInterface(o.iface)
	if err != nil {
		fmt.Fprintln(os.Stderr, "capcheck:", err)
		os.Exit(2)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	rep := report{
		Tool: "lan-sentinel capcheck", Time: time.Now().UTC(), Platform: runtime.GOOS + "/" + runtime.GOARCH,
		OS: osVersion(), Privilege: privilegeSummary(), Interface: o.iface,
	}
	if u, err := user.Current(); err == nil {
		rep.User = fmt.Sprintf("%s (uid %s)", u.Username, u.Uid)
		if gids, err := u.GroupIds(); err == nil {
			for _, g := range gids {
				if grp, err := user.LookupGroupId(g); err == nil {
					rep.Groups = append(rep.Groups, grp.Name)
				}
			}
			sort.Strings(rep.Groups)
		}
	}
	rep.Results = runChecks(ctx, o, ifi)
	if o.watch > 0 {
		rep.Results = append(rep.Results, measureNeighbours(ctx, o, ifi))
	}

	if o.jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
	} else {
		printReport(rep)
	}
	for _, r := range rep.Results {
		if r.Status == fail {
			os.Exit(1)
		}
	}
}

func printReport(r report) {
	fmt.Printf("%s — %s\n", r.Tool, r.Time.Format(time.RFC3339))
	fmt.Printf("platform:   %s, %s\nuser:       %s\ngroups:     %s\nprivilege:  %s\ninterface:  %s\n\n",
		r.Platform, r.OS, r.User, strings.Join(r.Groups, ", "), r.Privilege, r.Interface)
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "OPERATION\tRESULT\tEXPECTED PRIVILEGE\tDETAIL")
	for _, res := range r.Results {
		d := res.Detail
		if res.Error != "" {
			d = strings.TrimSpace(d + " error: " + res.Error)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", res.Name, res.Status, res.Expected, d)
	}
	_ = tw.Flush()
}

func lookupInterface(name string) (ifaceInfo, error) {
	ni, err := net.InterfaceByName(name)
	if err != nil {
		return ifaceInfo{}, fmt.Errorf("interface %s: %w", name, err)
	}
	info := ifaceInfo{name: ni.Name, index: ni.Index, mac: ni.HardwareAddr}
	addrs, err := ni.Addrs()
	if err != nil {
		return info, fmt.Errorf("interface %s addresses: %w", name, err)
	}
	for _, a := range addrs {
		pfx, err := netip.ParsePrefix(a.String())
		if err != nil {
			continue
		}
		ip := pfx.Addr().Unmap()
		switch {
		case ip.Is4() && !info.ipv4.IsValid():
			info.ipv4 = ip
		case ip.Is6() && ip.IsLinkLocalUnicast() && !info.ll6.IsValid():
			info.ll6 = ip.WithZone("")
		}
	}
	return info, nil
}

// check runs fn and converts its outcome to a result.
func check(name, expected string, fn func() (string, error)) result {
	detail, err := fn()
	r := result{Name: name, Expected: expected, Detail: detail, Status: pass}
	var s skipErr
	switch {
	case errors.As(err, &s):
		r.Status, r.Detail = skip, string(s)
	case err != nil:
		r.Status, r.Error = fail, err.Error()
	}
	return r
}

type skipErr string

func (s skipErr) Error() string { return string(s) }

// captureFilter accepts the discovery protocols the daemon captures: ARP,
// IPv4 and IPv6 (header learning, DHCP, mDNS, DNS, NDP) and LLDP.
func captureFilter() ([]bpf.RawInstruction, error) {
	return bpf.Assemble([]bpf.Instruction{
		bpf.LoadAbsolute{Off: 12, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0806, SkipTrue: 4},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800, SkipTrue: 3},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x86dd, SkipTrue: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x88cc, SkipTrue: 1},
		bpf.RetConstant{Val: 0},
		bpf.RetConstant{Val: 0x40000},
	})
}

// frameStats counts captured frames by EtherType.
type frameStats struct {
	total, arp, ipv4, ipv6, lldp int
}

func (s *frameStats) add(frame []byte) {
	s.total++
	if len(frame) < 14 {
		return
	}
	switch binary.BigEndian.Uint16(frame[12:14]) {
	case 0x0806:
		s.arp++
	case 0x0800:
		s.ipv4++
	case 0x86dd:
		s.ipv6++
	case 0x88cc:
		s.lldp++
	}
}

func (s frameStats) String() string {
	return fmt.Sprintf("%d frames (arp %d, ipv4 %d, ipv6 %d, lldp %d)", s.total, s.arp, s.ipv4, s.ipv6, s.lldp)
}

// arpRequest builds a broadcast ARP request frame.
func arpRequest(ifi ifaceInfo, target netip.Addr) ([]byte, error) {
	if !ifi.ipv4.IsValid() || len(ifi.mac) != 6 {
		return nil, fmt.Errorf("interface %s has no IPv4 address or Ethernet MAC", ifi.name)
	}
	f := make([]byte, 42)
	copy(f[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(f[6:12], ifi.mac)
	binary.BigEndian.PutUint16(f[12:], 0x0806)
	binary.BigEndian.PutUint16(f[14:], 1)      // Ethernet
	binary.BigEndian.PutUint16(f[16:], 0x0800) // IPv4
	f[18], f[19] = 6, 4
	binary.BigEndian.PutUint16(f[20:], 1) // request
	copy(f[22:28], ifi.mac)
	src := ifi.ipv4.As4()
	copy(f[28:32], src[:])
	dst := target.As4()
	copy(f[38:42], dst[:])
	return f, nil
}

// neighborSolicitation builds an NDP NS frame to the target's
// solicited-node multicast address.
func neighborSolicitation(ifi ifaceInfo, target netip.Addr) ([]byte, error) {
	if !ifi.ll6.IsValid() || len(ifi.mac) != 6 {
		return nil, fmt.Errorf("interface %s has no IPv6 link-local address or Ethernet MAC", ifi.name)
	}
	t := target.As16()
	dst := netip.AddrFrom16([16]byte{0xff, 0x02, 10: 0, 11: 0x01, 12: 0xff, 13: t[13], 14: t[14], 15: t[15]})
	body := make([]byte, 32) // type, code, csum, reserved, target, SLLA option
	body[0] = 135
	copy(body[8:24], t[:])
	body[24], body[25] = 1, 1 // source link-layer address option, 8 bytes
	copy(body[26:32], ifi.mac)

	src := ifi.ll6.As16()
	d := dst.As16()
	ps := make([]byte, 0, 40+len(body))
	ps = append(ps, src[:]...)
	ps = append(ps, d[:]...)
	ps = binary.BigEndian.AppendUint32(ps, uint32(len(body)))
	ps = append(ps, 0, 0, 0, 58)
	ps = append(ps, body...)
	binary.BigEndian.PutUint16(body[2:], checksum(ps))

	f := make([]byte, 14+40+len(body))
	copy(f[0:6], []byte{0x33, 0x33, 0xff, t[13], t[14], t[15]})
	copy(f[6:12], ifi.mac)
	binary.BigEndian.PutUint16(f[12:], 0x86dd)
	ip := f[14:54]
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:], uint16(len(body)))
	ip[6], ip[7] = 58, 255 // ICMPv6, hop limit 255
	copy(ip[8:24], src[:])
	copy(ip[24:40], d[:])
	copy(f[54:], body)
	return f, nil
}

func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

// pingSocket opens an unprivileged datagram ICMP socket ("udp4" network in
// x/net/icmp) and, with a target, sends one echo and waits for the reply.
func pingSocket(target netip.Addr) (string, error) {
	c, err := icmp.ListenPacket("udp4", "0.0.0.0")
	if err != nil {
		return "", err
	}
	defer c.Close()
	if !target.IsValid() {
		return "socket opened (no --icmp-target, nothing sent)", nil
	}
	return echo(c, &net.UDPAddr{IP: target.AsSlice()})
}

func echo(c *icmp.PacketConn, dst net.Addr) (string, error) {
	msg := icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{ID: os.Getpid() & 0xffff, Seq: 1, Data: []byte("lan-sentinel capcheck")}}
	b, err := msg.Marshal(nil)
	if err != nil {
		return "", err
	}
	start := time.Now()
	if _, err := c.WriteTo(b, dst); err != nil {
		return "", fmt.Errorf("send echo: %w", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	for {
		n, _, err := c.ReadFrom(buf)
		if err != nil {
			return "echo sent, no reply within 2s", nil
		}
		if m, err := icmp.ParseMessage(1, buf[:n]); err == nil && m.Type == ipv4.ICMPTypeEchoReply {
			return fmt.Sprintf("echo reply in %s", time.Since(start).Round(time.Microsecond)), nil
		}
	}
}

// tcpConnect dials target with control bound to the interface.
func tcpConnect(ctx context.Context, target netip.AddrPort, bind func(fd uintptr) error) (string, error) {
	if !target.IsValid() {
		return "", skipErr("no --tcp-target")
	}
	var bindErr error
	d := net.Dialer{Timeout: 2 * time.Second, Control: func(_, _ string, rc syscall.RawConn) error {
		return rc.Control(func(fd uintptr) { bindErr = bind(fd) })
	}}
	conn, err := d.DialContext(ctx, "tcp", target.String())
	if bindErr != nil {
		return "", fmt.Errorf("bind to interface: %w", bindErr)
	}
	switch {
	case err == nil:
		_ = conn.Close()
		return "OPEN (closed immediately, no payload)", nil
	case strings.Contains(err.Error(), "refused"):
		return "REFUSED (live IP stack)", nil
	case errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "timeout"):
		return "TIMEOUT", nil
	default:
		return "UNREACHABLE: " + err.Error(), nil
	}
}

type neighEvent struct {
	kind    string // RTM_NEWNEIGH or RTM_DELNEIGH
	t       time.Time
	ip      netip.Addr
	mac     string
	deleted bool
}

// measureNeighbours follows rtnetlink neighbour notifications for o.watch
// and takes a snapshot every o.snapshotEvery. Every change between
// consecutive snapshots counts as covered if a notification for that IP
// arrived in the same window, else as missed. The miss rate decides how
// short neighbor.resync_interval must be.
func measureNeighbours(ctx context.Context, o options, ifi ifaceInfo) result {
	name := "neighbour notification coverage (" + o.watch.String() + ")"
	expected := "none"
	snap0, err := snapshotNeighbours(ifi)
	if err != nil {
		return result{Name: name, Expected: expected, Status: fail, Error: "snapshot: " + err.Error()}
	}
	var mu sync.Mutex
	var events []neighEvent
	wctx, cancel := context.WithTimeout(ctx, o.watch)
	defer cancel()
	werr := make(chan error, 1)
	go func() {
		werr <- watchNeighbours(wctx, ifi, func(e neighEvent) {
			if o.verbose {
				fmt.Fprintf(os.Stderr, "%s notify   %-11s ip=%-15s mac=%-17s deleted=%v\n", e.t.Format("15:04:05.000"), e.kind, e.ip, e.mac, e.deleted)
			}
			mu.Lock()
			events = append(events, e)
			mu.Unlock()
		})
	}()

	covered, missed := 0, 0
	var missedIPs []string
	prev, prevT := snap0, time.Now()
	tick := time.NewTicker(o.snapshotEvery)
	defer tick.Stop()
loop:
	for {
		select {
		case <-wctx.Done():
			break loop
		case <-tick.C:
		}
		cur, err := snapshotNeighbours(ifi)
		if err != nil {
			return result{Name: name, Expected: expected, Status: fail, Error: "snapshot: " + err.Error()}
		}
		now := time.Now()
		mu.Lock()
		seen := map[netip.Addr]bool{}
		for _, e := range events {
			if !e.t.Before(prevT.Add(-time.Second)) {
				seen[e.ip] = true
			}
		}
		mu.Unlock()
		for ip := range diffNeighbours(prev, cur) {
			if o.verbose {
				fmt.Fprintf(os.Stderr, "%s snapshot ip=%-15s %q -> %q notified=%v\n", now.Format("15:04:05.000"), ip, prev[ip], cur[ip], seen[ip])
			}
			if seen[ip] {
				covered++
			} else {
				missed++
				missedIPs = append(missedIPs, ip.String())
			}
		}
		prev, prevT = cur, now
	}
	if err := <-werr; err != nil && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		return result{Name: name, Expected: expected, Status: fail, Error: "watch: " + err.Error()}
	}
	mu.Lock()
	n := len(events)
	mu.Unlock()
	detail := fmt.Sprintf("%d notifications; %d entries at start; snapshot changes: %d covered, %d missed", n, len(snap0), covered, missed)
	if missed > 0 {
		sort.Strings(missedIPs)
		detail += " (" + strings.Join(missedIPs, ", ") + ")"
	}
	return result{Name: name, Expected: expected, Status: pass, Detail: detail}
}

func diffNeighbours(a, b map[netip.Addr]string) map[netip.Addr]bool {
	d := map[netip.Addr]bool{}
	for ip, mac := range a {
		if b[ip] != mac {
			d[ip] = true
		}
	}
	for ip := range b {
		if _, ok := a[ip]; !ok {
			d[ip] = true
		}
	}
	return d
}
