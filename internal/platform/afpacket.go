package platform

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/gopacket/gopacket/afpacket"
	"golang.org/x/sys/unix"
)

// Ring geometry. TPACKET_V3 packs frames of any length into blocks, so the
// frame size only sets the frame count; 128 KiB blocks are page aligned for
// 4, 16 and 64 KiB pages. A partly filled block is handed over after
// ringBlockTimeout, which bounds capture latency on quiet links.
const (
	ringBlockSize     = 128 << 10
	ringFrameSize     = 2048
	ringMinBlocks     = 2
	ringBlockTimeout  = 100 * time.Millisecond
	capturePollPeriod = 200 * time.Millisecond
)

// ErrCaptureClosed is returned by ReadFrame after Close.
var ErrCaptureClosed = errors.New("capture closed")

// ringBlocks converts a ring size in bytes to whole blocks.
func ringBlocks(size int) int {
	if size <= 0 {
		size = DefaultRingSize
	}
	return max(size/ringBlockSize, ringMinBlocks)
}

// afpacketCapturer opens receive-only TPACKET_V3 rings (gopacket/afpacket).
// It needs CAP_NET_RAW only: promiscuous mode uses PACKET_ADD_MEMBERSHIP,
// not SIOCSIFFLAGS.
type afpacketCapturer struct{}

func (afpacketCapturer) Backend() string { return "afpacket" }

// Open opens a ring on iface. An interface that is administratively down is
// refused with ErrLinkDown: a socket bound to it only reports ENETDOWN, and
// joining promiscuous mode on it would toggle the flag for nothing.
func (afpacketCapturer) Open(_ context.Context, iface string, o CaptureOptions) (FrameSource, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("capture on %s: %w", iface, err)
	}
	if ifi.Flags&net.FlagUp == 0 {
		return nil, fmt.Errorf("capture on %s: %w", iface, ErrLinkDown)
	}
	tp, err := afpacket.NewTPacket(
		afpacket.OptInterface(iface),
		afpacket.TPacketVersion3,
		afpacket.OptFrameSize(ringFrameSize),
		afpacket.OptBlockSize(ringBlockSize),
		afpacket.OptNumBlocks(ringBlocks(o.RingSize)),
		afpacket.OptBlockTimeout(ringBlockTimeout),
		afpacket.OptPollTimeout(capturePollPeriod),
	)
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			return nil, fmt.Errorf("socket(AF_PACKET): %w", err)
		}
		return nil, fmt.Errorf("capture on %s: %w", iface, err)
	}
	// gopacket binds and maps the ring before the filter can be attached, so
	// frames that arrived in between are skipped by their timestamp.
	if len(o.Filter) > 0 {
		if err := tp.SetBPF(o.Filter); err != nil {
			tp.Close()
			return nil, fmt.Errorf("capture on %s: attach filter: %w", iface, err)
		}
	}
	filtered := time.Now()
	if o.Promiscuous {
		if err := tp.SetPromiscuous(true); err != nil {
			tp.Close()
			return nil, fmt.Errorf("capture on %s: PACKET_ADD_MEMBERSHIP: %w", iface, err)
		}
	}
	return &afpacketSource{iface: iface, tp: tp, own: ifi.HardwareAddr, filtered: filtered}, nil
}

// afpacketSource reads one ring. The handle must not be closed while a read
// is in progress (the ring is unmapped), so reads hold the read lock and
// return at least every capturePollPeriod to notice cancellation.
//
// The host's own frames are not evidence about other hosts. The filter
// drops what the kernel marks PACKET_OUTGOING, and the source also skips
// incoming frames from the interface's own MAC: a bridge port in hairpin
// mode reflects the host's broadcasts back to it.
type afpacketSource struct {
	iface    string
	own      net.HardwareAddr
	filtered time.Time // frames received before this passed no filter
	mu       sync.RWMutex
	tp       *afpacket.TPacket
	closed   bool

	// gopacket keeps the kernel counters in uint32s that wrap; totals adds
	// up the wrapping differences.
	statsMu  sync.Mutex
	last     [2]uint32
	received uint64
	dropped  uint64
}

func (s *afpacketSource) ReadFrame(ctx context.Context) (Frame, error) {
	for {
		if err := ctx.Err(); err != nil {
			return Frame{}, err
		}
		f, err := s.read()
		switch {
		case err == nil && (s.ownFrame(f.Data) || f.Time.Before(s.filtered)):
			continue
		case err == nil:
			return f, nil
		case errors.Is(err, afpacket.ErrTimeout):
			continue
		case errors.Is(err, afpacket.ErrPoll):
			// POLLERR: the kernel reports ENETDOWN once the interface goes
			// down or is removed, and keeps doing so; start over.
			return Frame{}, fmt.Errorf("capture on %s: %w", s.iface, ErrLinkDown)
		default:
			return Frame{}, fmt.Errorf("capture on %s: %w", s.iface, err)
		}
	}
}

func (s *afpacketSource) ownFrame(data []byte) bool {
	return len(s.own) == 6 && len(data) >= 12 && bytes.Equal(data[6:12], s.own)
}

func (s *afpacketSource) read() (Frame, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return Frame{}, ErrCaptureClosed
	}
	data, ci, err := s.tp.ZeroCopyReadPacketData()
	if err != nil {
		return Frame{}, err
	}
	return Frame{Time: ci.Timestamp.UTC(), Interface: s.iface, Data: bytes.Clone(data)}, nil
}

func (s *afpacketSource) Stats() (CaptureStats, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return CaptureStats{}, ErrCaptureClosed
	}
	_, v3, err := s.tp.SocketStats()
	if err != nil {
		return CaptureStats{}, fmt.Errorf("capture on %s: statistics: %w", s.iface, err)
	}
	return s.totals(uint32(v3.Packets()), uint32(v3.Drops())), nil
}

func (s *afpacketSource) totals(packets, drops uint32) CaptureStats {
	s.statsMu.Lock()
	defer s.statsMu.Unlock()
	s.received += uint64(packets - s.last[0])
	s.dropped += uint64(drops - s.last[1])
	s.last = [2]uint32{packets, drops}
	return CaptureStats{Received: s.received, Dropped: s.dropped}
}

// Close releases the ring and the socket; the kernel drops the promiscuous
// membership with the socket.
func (s *afpacketSource) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.closed = true
		s.tp.Close()
	}
	return nil
}
