package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/net/bpf"
	"golang.org/x/net/icmp"
	"golang.org/x/sys/unix"
)

const ethPAll = 0x0003

func htons(v uint16) uint16 { return v<<8 | v>>8 }

func osVersion() string {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return "linux (uname failed)"
	}
	return "Linux " + unix.ByteSliceToString(u.Release[:]) + " " + unix.ByteSliceToString(u.Machine[:])
}

// privilegeSummary reports the effective capabilities that matter.
func privilegeSummary() string {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return "unknown (" + err.Error() + ")"
	}
	for _, line := range strings.Split(string(data), "\n") {
		hex, ok := strings.CutPrefix(line, "CapEff:")
		if !ok {
			continue
		}
		v, err := strconv.ParseUint(strings.TrimSpace(hex), 16, 64)
		if err != nil {
			return "CapEff unreadable"
		}
		var caps []string
		if os.Geteuid() == 0 {
			caps = append(caps, "euid 0 (root!)")
		}
		for bit, name := range map[uint]string{unix.CAP_NET_RAW: "CAP_NET_RAW", unix.CAP_NET_ADMIN: "CAP_NET_ADMIN", unix.CAP_SYS_ADMIN: "CAP_SYS_ADMIN"} {
			if v&(1<<bit) != 0 {
				caps = append(caps, name)
			}
		}
		if len(caps) == 0 {
			return fmt.Sprintf("CapEff=%#x (no network capabilities)", v)
		}
		return fmt.Sprintf("CapEff=%#x: %s", v, strings.Join(caps, ", "))
	}
	return "CapEff not found"
}

func packetSocket(ifi ifaceInfo) (int, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(ethPAll)))
	if err != nil {
		return -1, fmt.Errorf("socket(AF_PACKET): %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(ethPAll), Ifindex: ifi.index}); err != nil {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("bind: %w", err)
	}
	return fd, nil
}

func attachFilter(fd int, prog []bpf.RawInstruction) error {
	f := make([]unix.SockFilter, len(prog))
	for i, ins := range prog {
		f[i] = unix.SockFilter{Code: ins.Op, Jt: ins.Jt, Jf: ins.Jf, K: ins.K}
	}
	return unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &unix.SockFprog{Len: uint16(len(f)), Filter: &f[0]})
}

func runChecks(ctx context.Context, o options, ifi ifaceInfo) []result {
	const raw = "CAP_NET_RAW"
	filter, ferr := captureFilter()
	var rs []result

	rs = append(rs, check("AF_PACKET socket bound to interface", raw, func() (string, error) {
		fd, err := packetSocket(ifi)
		if err != nil {
			return "", err
		}
		return "ok", unix.Close(fd)
	}))

	rs = append(rs, check("TPACKET_V3 ring + mmap", raw, func() (string, error) {
		fd, err := packetSocket(ifi)
		if err != nil {
			return "", err
		}
		defer unix.Close(fd)
		if err := unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_VERSION, unix.TPACKET_V3); err != nil {
			return "", fmt.Errorf("PACKET_VERSION: %w", err)
		}
		req := unix.TpacketReq3{Block_size: 1 << 18, Block_nr: 4, Frame_size: 1 << 11, Retire_blk_tov: 100}
		req.Frame_nr = req.Block_size * req.Block_nr / req.Frame_size
		if err := unix.SetsockoptTpacketReq3(fd, unix.SOL_PACKET, unix.PACKET_RX_RING, &req); err != nil {
			return "", fmt.Errorf("PACKET_RX_RING: %w", err)
		}
		size := int(req.Block_size * req.Block_nr)
		mem, err := unix.Mmap(fd, 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
		if err != nil {
			return "", fmt.Errorf("mmap: %w", err)
		}
		return fmt.Sprintf("%d KiB ring", size/1024), unix.Munmap(mem)
	}))

	rs = append(rs, check("BPF filter attach (SO_ATTACH_FILTER)", raw, func() (string, error) {
		if ferr != nil {
			return "", ferr
		}
		fd, err := packetSocket(ifi)
		if err != nil {
			return "", err
		}
		defer unix.Close(fd)
		return fmt.Sprintf("%d instructions", len(filter)), attachFilter(fd, filter)
	}))

	rs = append(rs, check("capture frames ("+o.capture.String()+")", raw, func() (string, error) {
		if ferr != nil {
			return "", ferr
		}
		fd, err := packetSocket(ifi)
		if err != nil {
			return "", err
		}
		defer unix.Close(fd)
		if err := attachFilter(fd, filter); err != nil {
			return "", err
		}
		tv := unix.NsecToTimeval(int64(200 * time.Millisecond))
		if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
			return "", err
		}
		var st frameStats
		buf := make([]byte, 65536)
		deadline := time.Now().Add(o.capture)
		for time.Now().Before(deadline) && ctx.Err() == nil {
			n, _, err := unix.Recvfrom(fd, buf, 0)
			if err != nil {
				if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
					continue
				}
				return st.String(), err
			}
			st.add(buf[:n])
		}
		return st.String(), nil
	}))

	rs = append(rs, check("promiscuous mode (PACKET_ADD_MEMBERSHIP)", raw, func() (string, error) {
		if !o.promisc {
			return "", skipErr("--promisc=false")
		}
		fd, err := packetSocket(ifi)
		if err != nil {
			return "", err
		}
		defer unix.Close(fd)
		mreq := unix.PacketMreq{Ifindex: int32(ifi.index), Type: unix.PACKET_MR_PROMISC}
		if err := unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, &mreq); err != nil {
			return "", err
		}
		detail := "membership added"
		if b, err := os.ReadFile("/sys/class/net/" + ifi.name + "/flags"); err == nil {
			if v, err := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(string(b), "0x")), 16, 32); err == nil {
				detail += fmt.Sprintf("; IFF_PROMISC=%v", v&unix.IFF_PROMISC != 0)
			}
		}
		if err := unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, unix.PACKET_DROP_MEMBERSHIP, &mreq); err != nil {
			return detail, fmt.Errorf("drop membership: %w", err)
		}
		return detail + "; restored", nil
	}))

	rs = append(rs, check("ARP transmit (AF_PACKET)", raw, func() (string, error) {
		if !o.arpTarget.IsValid() {
			return "", skipErr("no --arp-target")
		}
		frame, err := arpRequest(ifi, o.arpTarget)
		if err != nil {
			return "", err
		}
		return sendFrame(ifi, frame, "ARP request for "+o.arpTarget.String())
	}))

	rs = append(rs, check("NDP transmit (AF_PACKET)", raw, func() (string, error) {
		if !o.ndpTarget.IsValid() {
			return "", skipErr("no --ndp-target")
		}
		frame, err := neighborSolicitation(ifi, o.ndpTarget)
		if err != nil {
			return "", err
		}
		return sendFrame(ifi, frame, "neighbour solicitation for "+o.ndpTarget.String())
	}))

	rs = append(rs, check("ICMP via ping socket", "none if GID in net.ipv4.ping_group_range", func() (string, error) {
		rng, _ := os.ReadFile("/proc/sys/net/ipv4/ping_group_range")
		d, err := pingSocket(o.icmpTarget)
		return strings.TrimSpace(d + "; ping_group_range=" + strings.Join(strings.Fields(string(rng)), "-")), err
	}))
	rs = append(rs, check("ICMP via raw socket", raw, rawICMPSocket))

	rs = append(rs, check("rtnetlink dump (links, addresses, neighbours)", "none", func() (string, error) {
		links, err := netlink.LinkList()
		if err != nil {
			return "", fmt.Errorf("links: %w", err)
		}
		addrs, err := netlink.AddrList(nil, netlink.FAMILY_ALL)
		if err != nil {
			return "", fmt.Errorf("addresses: %w", err)
		}
		neigh, err := netlink.NeighList(ifi.index, netlink.FAMILY_ALL)
		if err != nil {
			return "", fmt.Errorf("neighbours: %w", err)
		}
		return fmt.Sprintf("%d links, %d addresses, %d neighbours on %s", len(links), len(addrs), len(neigh), ifi.name), nil
	}))

	rs = append(rs, check("rtnetlink subscribe (NEIGH, LINK, IFADDR groups)", "none", func() (string, error) {
		done := make(chan struct{})
		defer close(done)
		if err := netlink.NeighSubscribe(make(chan netlink.NeighUpdate, 16), done); err != nil {
			return "", fmt.Errorf("neighbours: %w", err)
		}
		if err := netlink.LinkSubscribe(make(chan netlink.LinkUpdate, 16), done); err != nil {
			return "", fmt.Errorf("links: %w", err)
		}
		if err := netlink.AddrSubscribe(make(chan netlink.AddrUpdate, 16), done); err != nil {
			return "", fmt.Errorf("addresses: %w", err)
		}
		return "subscribed", nil
	}))

	bind := func(fd uintptr) error {
		return unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, ifi.name)
	}
	rs = append(rs, check("SO_BINDTODEVICE on a TCP socket", "CAP_NET_RAW (< 5.7), none on newer kernels", func() (string, error) {
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return "", err
		}
		defer unix.Close(fd)
		return "ok", bind(uintptr(fd))
	}))
	rs = append(rs, check("TCP connect() bound to interface", "none", func() (string, error) {
		return tcpConnect(ctx, o.tcpTarget, bind)
	}))
	rs = append(rs, check("adjtimex read (clock sync state, NFR-REL-2)", "none", clockState))
	return rs
}

// clockState reads the kernel's NTP status the way the daemon does: a
// read-only adjtimex (modes 0), which needs no capability but must be
// allowed by the unit's system call filter.
func clockState() (string, error) {
	var tx unix.Timex
	state, err := unix.Adjtimex(&tx)
	if err != nil {
		return "", fmt.Errorf("adjtimex: %w", err)
	}
	const timeError, staUnsync, staClockErr = 5, 0x0040, 0x1000
	if state == timeError || tx.Status&(staUnsync|staClockErr) != 0 {
		return "readable: clock not synchronised", nil
	}
	return "readable: clock synchronised", nil
}

func sendFrame(ifi ifaceInfo, frame []byte, what string) (string, error) {
	fd, err := packetSocket(ifi)
	if err != nil {
		return "", err
	}
	defer unix.Close(fd)
	sa := &unix.SockaddrLinklayer{Ifindex: ifi.index, Halen: 6, Protocol: htons(ethPAll)}
	copy(sa.Addr[:], frame[0:6])
	if err := unix.Sendto(fd, frame, 0, sa); err != nil {
		return "", fmt.Errorf("sendto: %w", err)
	}
	return "sent one " + what, nil
}

func snapshotNeighbours(ifi ifaceInfo) (map[netip.Addr]string, error) {
	list, err := netlink.NeighList(ifi.index, netlink.FAMILY_ALL)
	if err != nil {
		return nil, err
	}
	m := map[netip.Addr]string{}
	for _, n := range list {
		ip, ok := netip.AddrFromSlice(n.IP)
		if !ok || len(n.HardwareAddr) == 0 || n.State&(netlink.NUD_INCOMPLETE|netlink.NUD_FAILED) != 0 {
			continue
		}
		m[ip.Unmap()] = n.HardwareAddr.String()
	}
	return m, nil
}

func watchNeighbours(ctx context.Context, ifi ifaceInfo, emit func(neighEvent)) error {
	ch := make(chan netlink.NeighUpdate, 256)
	done := make(chan struct{})
	defer close(done)
	if err := netlink.NeighSubscribeWithOptions(ch, done, netlink.NeighSubscribeOptions{
		ErrorCallback: func(err error) {},
	}); err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case u, ok := <-ch:
			if !ok {
				return errors.New("neighbour subscription closed")
			}
			if u.LinkIndex != ifi.index {
				continue
			}
			ip, ok := netip.AddrFromSlice(u.IP)
			if !ok {
				continue
			}
			kind := "RTM_NEWNEIGH"
			if u.Type == unix.RTM_DELNEIGH {
				kind = "RTM_DELNEIGH"
			}
			emit(neighEvent{kind: kind, t: time.Now(), ip: ip.Unmap(), mac: u.HardwareAddr.String(), deleted: u.Type == unix.RTM_DELNEIGH})
		}
	}
}

// rawICMPSocket opens a raw ICMP socket.
func rawICMPSocket() (string, error) {
	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return "", err
	}
	_ = c.Close()
	return "socket opened", nil
}
