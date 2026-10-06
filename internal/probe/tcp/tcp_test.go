package tcp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"lan-sentinel/internal/config"
	"lan-sentinel/internal/observation"
	"lan-sentinel/internal/platform/fake"
	"lan-sentinel/internal/probe"
	"lan-sentinel/internal/probe/probetest"
)

func TestClassify(t *testing.T) {
	tests := []struct {
		err  error
		want observation.ServiceState
	}{
		{nil, observation.ServiceOpen},
		{&net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}, observation.ServiceRefused},
		{context.DeadlineExceeded, observation.ServiceTimeout},
		{&net.OpError{Op: "dial", Err: os.ErrDeadlineExceeded}, observation.ServiceTimeout},
		{fmt.Errorf("dial: %w", syscall.EHOSTUNREACH), observation.ServiceUnreachable},
		{syscall.ENETUNREACH, observation.ServiceUnreachable},
		{syscall.EHOSTDOWN, observation.ServiceUnreachable},
		{syscall.ECONNRESET, observation.ServiceRefused},
		{fmt.Errorf("SO_BINDTODEVICE eth1: %w", syscall.EPERM), observation.ServiceUnknown},
		{errors.New("something else"), observation.ServiceUnknown},
	}
	for _, tt := range tests {
		if got := Classify(tt.err); got != tt.want {
			t.Errorf("Classify(%v) = %s, want %s", tt.err, got, tt.want)
		}
	}
}

func ap(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

func TestConnect(t *testing.T) {
	tx := &fake.Transmitter{TCPResult: map[netip.AddrPort]error{
		ap("192.168.110.21:502"): syscall.ECONNREFUSED,
		ap("192.168.110.22:502"): context.DeadlineExceeded,
		ap("192.168.110.23:502"): syscall.EHOSTUNREACH,
		ap("192.168.110.21:80"):  syscall.ECONNREFUSED,
	}}
	sink := &probetest.Sink{}
	targets := probetest.Addrs("192.168.110.20", "192.168.110.21", "192.168.110.22", "192.168.110.23", "192.168.110.24")
	block := probetest.Block(nil, targets[4])
	var mu sync.Mutex
	var checked []netip.Addr // the policy is asked in send order
	pass := probetest.Pass(targets, probetest.PolicyFunc(func(iface string, p probe.Protocol, target netip.Addr) error {
		mu.Lock()
		checked = append(checked, target)
		mu.Unlock()
		return block(iface, p, target)
	}), sink)
	pass.TCP = []config.TCPTarget{{Port: 502, Timeout: config.Duration(750 * time.Millisecond)}, {Port: 80}}
	results, err := Engine{TX: tx}.Run(context.Background(), pass)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, r := range results {
		got[netip.AddrPortFrom(r.Target, uint16(r.Port)).String()] = r.State
	}
	want := map[string]string{
		"192.168.110.20:502": "OPEN", "192.168.110.21:502": "REFUSED", "192.168.110.22:502": "TIMEOUT",
		"192.168.110.23:502": "UNREACHABLE", "192.168.110.24:502": probe.Blocked,
		"192.168.110.20:80": "OPEN", "192.168.110.21:80": "REFUSED", "192.168.110.22:80": "OPEN",
		"192.168.110.23:80": "OPEN", "192.168.110.24:80": probe.Blocked,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %q, want %q", k, got[k], v)
		}
	}
	// Port by port: every host is asked for 502 before any host for 80.
	if len(tx.Dials()) != 8 {
		t.Errorf("dials = %v", tx.Dials())
	}
	first24, seen20 := -1, 0
	for i, a := range checked {
		if a == targets[4] && first24 < 0 {
			first24 = i
		}
		if a == targets[0] {
			if seen20++; seen20 == 3 && (first24 < 0 || first24 > i) {
				t.Errorf("host .20 probed again before .24 was asked once: %v", checked)
			}
		}
	}
	obs := sink.All()
	if len(obs) != 8 {
		t.Fatalf("%d observations, want one per connect", len(obs))
	}
	for _, o := range obs {
		if o.Source != observation.TCPConnect || o.MAC != nil || o.Service == nil || o.Service.Proto != "tcp" ||
			string(o.Service.State) != got[netip.AddrPortFrom(o.IP, uint16(o.Service.Port)).String()] {
			t.Errorf("observation %+v", o)
		}
	}
	if (Engine{}).Protocol() != probe.TCP {
		t.Error("protocol")
	}
}

// slowTX makes connects take a while, so cancellation lands mid-connect.
type slowTX struct {
	*fake.Transmitter
	started chan struct{}
}

func (s slowTX) DialTCP(ctx context.Context, iface string, addr netip.AddrPort, d time.Duration) (net.Conn, error) {
	close(s.started)
	<-ctx.Done()
	return s.Transmitter.DialTCP(ctx, iface, addr, d)
}

func TestConnectCancelledAndStopped(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	tx := slowTX{&fake.Transmitter{}, make(chan struct{})}
	sink := &probetest.Sink{}
	pass := probetest.Pass(probetest.Addrs("192.168.110.20"), nil, sink)
	pass.TCP = []config.TCPTarget{{Port: 502}}
	go func() {
		<-tx.started
		cancel()
	}()
	results, err := Engine{TX: tx}.Run(ctx, pass)
	if err != nil || len(results) != 0 || len(sink.All()) != 0 {
		t.Errorf("cancelled connect: %+v, %v, %d observations", results, err, len(sink.All()))
	}

	stop := make(chan struct{})
	close(stop)
	pass = probetest.Pass(probetest.Addrs("192.168.110.20"), probetest.Block(stop), sink)
	pass.TCP = []config.TCPTarget{{Port: 502}}
	if _, err := (Engine{TX: &fake.Transmitter{}}).Run(context.Background(), pass); !errors.Is(err, probe.ErrDisabled) {
		t.Errorf("kill switch: %v", err)
	}
}

// lingerConn records how it was closed.
type lingerConn struct {
	net.Conn
	linger *int
}

func (l lingerConn) SetLinger(sec int) error { *l.linger = sec; return nil }

type lingerTX struct {
	*fake.Transmitter
	linger *int
}

func (l lingerTX) DialTCP(ctx context.Context, iface string, addr netip.AddrPort, d time.Duration) (net.Conn, error) {
	c, err := l.Transmitter.DialTCP(ctx, iface, addr, d)
	return lingerConn{c, l.linger}, err
}

func TestConnectClosesWithReset(t *testing.T) {
	linger := -1
	pass := probetest.Pass(probetest.Addrs("192.168.110.20"), nil, &probetest.Sink{})
	pass.TCP = []config.TCPTarget{{Port: 502}}
	results, err := Engine{TX: lingerTX{&fake.Transmitter{}, &linger}}.Run(context.Background(), pass)
	if err != nil || len(results) != 1 || results[0].State != "OPEN" {
		t.Fatalf("%+v, %v", results, err)
	}
	if linger != 0 {
		t.Errorf("SO_LINGER = %d, want 0 (close with RST)", linger)
	}
}

func TestLocalFailureIsNoResult(t *testing.T) {
	tx := &fake.Transmitter{TCPResult: map[netip.AddrPort]error{
		ap("192.168.110.21:502"): fmt.Errorf("dial: %w", syscall.EMFILE),
	}}
	sink := &probetest.Sink{}
	pass := probetest.Pass(probetest.Addrs("192.168.110.20", "192.168.110.21"), nil, sink)
	pass.TCP = []config.TCPTarget{{Port: 502}}
	results, err := Engine{TX: tx}.Run(context.Background(), pass)
	if err == nil || !errors.Is(err, syscall.EMFILE) {
		t.Errorf("Run error = %v, want the local failure", err)
	}
	if len(results) != 2 {
		t.Errorf("results = %+v", results)
	}
	obs := sink.All()
	if len(obs) != 1 || obs[0].IP.String() != "192.168.110.20" {
		t.Errorf("observations = %+v (a local failure must not reach the correlator)", obs)
	}
}
