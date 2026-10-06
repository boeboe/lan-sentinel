package platform

import (
	"context"
	"errors"
	"math"
	"net"
	"strings"
	"testing"
)

func TestRingBlocks(t *testing.T) {
	for size, want := range map[int]int{
		0:              DefaultRingSize / ringBlockSize,
		-1:             DefaultRingSize / ringBlockSize,
		1:              ringMinBlocks,
		ringBlockSize:  ringMinBlocks,
		8 << 20:        64,
		8<<20 + 100000: 64,
	} {
		if got := ringBlocks(size); got != want {
			t.Errorf("ringBlocks(%d) = %d, want %d", size, got, want)
		}
	}
}

func TestCaptureStatsWrap(t *testing.T) {
	s := &afpacketSource{}
	s.totals(math.MaxUint32-1, 10)
	got := s.totals(3, 12) // the uint32 counter wrapped: 5 more packets
	if got.Received != math.MaxUint32+4 || got.Dropped != 12 {
		t.Errorf("totals = %+v", got)
	}
}

// The unit tests run without CAP_NET_RAW; the capture path itself is tested
// in Docker (test/net).
func TestOpenWithoutPrivilege(t *testing.T) {
	_, err := afpacketCapturer{}.Open(context.Background(), "lo", CaptureOptions{})
	if err == nil {
		t.Skip("running with CAP_NET_RAW")
	}
	if err.Error() != "socket(AF_PACKET): operation not permitted" {
		t.Errorf("err = %v", err)
	}
	if _, err := (afpacketCapturer{}).Open(context.Background(), "nosuch0", CaptureOptions{}); err == nil ||
		!strings.Contains(err.Error(), "capture on nosuch0") {
		t.Errorf("missing interface: %v", err)
	}
}

func TestClosedSource(t *testing.T) {
	s := &afpacketSource{iface: "eth9", closed: true}
	if _, err := s.ReadFrame(context.Background()); !errors.Is(err, ErrCaptureClosed) {
		t.Errorf("ReadFrame = %v", err)
	}
	if _, err := s.Stats(); !errors.Is(err, ErrCaptureClosed) {
		t.Errorf("Stats = %v", err)
	}
	if err := s.Close(); err != nil {
		t.Errorf("Close = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.ReadFrame(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("ReadFrame after cancel = %v", err)
	}
}

func TestOwnFrame(t *testing.T) {
	own := net.HardwareAddr{2, 0, 0, 0, 0, 1}
	s := &afpacketSource{own: own}
	frame := append(append(make([]byte, 6), own...), 0x08, 0x06)
	if !s.ownFrame(frame) {
		t.Error("frame from the interface's MAC not recognised")
	}
	frame[11] = 2
	if s.ownFrame(frame) || s.ownFrame([]byte{1, 2, 3}) || (&afpacketSource{}).ownFrame(frame) {
		t.Error("other frames treated as own")
	}
}
