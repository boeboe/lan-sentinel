package replay

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lan-sentinel/internal/clock"
	"lan-sentinel/internal/observation"
)

func write(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func line(ts, ip string) string {
	return `{"time":"` + ts + `","source":"passive_arp","mac":"00:1b:1b:00:00:01","ip":"` + ip + `"}` + "\n"
}

// consume plays p and returns what the correlator side would receive.
func consume(t *testing.T, p *Player, speed float64) ([]observation.Message, error) {
	t.Helper()
	bus := observation.NewBus(4)
	ctx, cancel := context.WithCancel(context.Background())
	var got []observation.Message
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-ctx.Done():
				return
			case m := <-bus.C():
				if m.Barrier != nil {
					close(m.Barrier)
					return
				}
				got = append(got, m)
			}
		}
	}()
	p.speed = speed
	err := p.Run(ctx, bus)
	if err != nil {
		cancel()
	}
	<-done
	cancel()
	return got, err
}

func TestMergeInTimeOrder(t *testing.T) {
	a := write(t, "eth1.jsonl", line("2026-10-01T10:00:00Z", "10.0.0.1")+line("2026-10-01T10:00:02Z", "10.0.0.3"))
	b := write(t, "eth2.jsonl", line("2026-10-01T10:00:01Z", "10.1.0.2")+"\n"+line("2026-10-01T10:00:03Z", "10.1.0.4"))
	p, err := Open(Options{Sources: []Source{
		{Interface: "eth1", File: a, Prefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}},
		{Interface: "eth2", File: b},
	}})
	if err != nil {
		t.Fatal(err)
	}
	first := time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)
	if !p.First().Equal(first) {
		t.Fatalf("First = %v", p.First())
	}
	sim := clock.NewSim(first)
	p.SetClock(sim)
	got, err := consume(t, p, 0)
	if err != nil {
		t.Fatal(err)
	}
	var order []string
	for _, m := range got {
		if m.Link != nil {
			order = append(order, "link "+m.Link.Interface)
			continue
		}
		order = append(order, m.Observation.Interface+" "+m.Observation.IP.String())
	}
	want := "link eth1|link eth2|eth1 10.0.0.1|eth2 10.1.0.2|eth1 10.0.0.3|eth2 10.1.0.4"
	if strings.Join(order, "|") != want {
		t.Errorf("order = %s\nwant    %s", strings.Join(order, "|"), want)
	}
	if !sim.Now().Equal(first.Add(3 * time.Second)) {
		t.Errorf("clock = %v, want the last observation's time", sim.Now())
	}
}

func TestRealTimeSpeed(t *testing.T) {
	// One simulated minute at speed 1200 takes 50 ms of wall time.
	f := write(t, "eth1.jsonl", line("2026-10-01T10:00:00Z", "10.0.0.1")+line("2026-10-01T10:01:00Z", "10.0.0.2"))
	p, err := Open(Options{Sources: []Source{{Interface: "eth1", File: f}}})
	if err != nil {
		t.Fatal(err)
	}
	p.SetClock(clock.NewSim(p.First()))
	start := time.Now()
	if _, err := consume(t, p, 1200); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d < 40*time.Millisecond || d > 5*time.Second {
		t.Errorf("real-time replay took %v, want about 50ms", d)
	}
}

func TestErrors(t *testing.T) {
	tests := []struct {
		name, file, content, wantErr string
		atRun                        bool
	}{
		{"pcap not yet supported", "x.pcapng", "", "phase 2", false},
		{"missing file", "", "", "no such file", false},
		{"bad first line", "x.jsonl", "{", "line 1", false},
		{"interface mismatch", "x.jsonl", line("2026-10-01T10:00:00Z", "10.0.0.1") +
			`{"time":"2026-10-01T10:00:01Z","source":"passive_arp","interface":"eth9","ip":"10.0.0.2"}` + "\n",
			"observation for eth9 in the replay file of eth1", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "missing.jsonl")
			if tt.file != "" {
				path = write(t, tt.file, tt.content)
			}
			p, err := Open(Options{Sources: []Source{{Interface: "eth1", File: path}}})
			if tt.atRun {
				if err != nil {
					t.Fatal(err)
				}
				p.SetClock(clock.NewSim(p.First()))
				_, err = consume(t, p, 0)
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("err = %v, want %q", err, tt.wantErr)
			}
		})
	}
}
