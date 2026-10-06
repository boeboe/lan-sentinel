// Command inject writes the frames of a pcap file onto an interface through
// an AF_PACKET socket, for the Docker network tests (test/net/run.sh): it
// puts frames with other hosts' source MACs on the test network, as a real
// site's broadcast and multicast traffic would arrive. It runs in its own
// container, never in the runner.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/gopacket/gopacket/pcapgo"
	"golang.org/x/sys/unix"
)

func main() {
	iface := flag.String("i", "eth0", "interface to send on")
	file := flag.String("f", "", "pcap file with the frames")
	repeat := flag.Int("repeat", 1, "send the file's frames this many times")
	flag.Parse()
	n, err := inject(*iface, *file, *repeat)
	if err != nil {
		fmt.Fprintln(os.Stderr, "inject:", err)
		os.Exit(1)
	}
	fmt.Printf("inject: sent %d frames on %s\n", n, *iface)
}

func inject(iface, file string, repeat int) (int, error) {
	f, err := os.Open(file)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	r, err := pcapgo.NewReader(f)
	if err != nil {
		return 0, err
	}
	var frames [][]byte
	for {
		data, _, err := r.ReadPacketData()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return 0, err
		}
		frames = append(frames, data)
	}
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return 0, err
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, 0) // protocol 0: transmit only
	if err != nil {
		return 0, fmt.Errorf("socket(AF_PACKET): %w", err)
	}
	defer unix.Close(fd)
	sent := 0
	for range repeat {
		for _, fr := range frames {
			addr := &unix.SockaddrLinklayer{Ifindex: ifi.Index, Halen: 6}
			copy(addr.Addr[:], fr[:6])
			for {
				err := unix.Sendto(fd, fr, 0, addr)
				if errors.Is(err, unix.ENOBUFS) {
					time.Sleep(time.Millisecond) // transmit queue full
					continue
				}
				if err != nil {
					return sent, fmt.Errorf("send: %w", err)
				}
				break
			}
			sent++
		}
	}
	return sent, nil
}
