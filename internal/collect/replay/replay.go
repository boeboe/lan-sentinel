// Package replay feeds recorded observations through the daemon (FR-RP-1,
// FR-RP-2). It merges every replay file into one time-ordered stream and
// drives the simulated clock: as fast as possible (speed 0) or in real time
// scaled by a speed factor. Observations are published with PublishWait,
// never dropped, so a replay is complete and deterministic.
package replay

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"lan-sentinel/internal/clock"
	"lan-sentinel/internal/observation"
	"lan-sentinel/internal/platform"
)

// step is how often a real-time replay advances the simulated clock.
const step = 50 * time.Millisecond

// Source is one replay file for one interface.
type Source struct {
	Interface string
	File      string
	Prefixes  []netip.Prefix
}

// Player replays sources.
type Player struct {
	sources  []Source
	readers  []*reader
	sim      *clock.Sim
	speed    float64
	registry *platform.Registry
	log      *slog.Logger
	first    time.Time
}

// Options configures a Player.
type Options struct {
	Sources  []Source
	Speed    float64
	Registry *platform.Registry
	Logger   *slog.Logger
}

// Open opens every source and reads ahead to the first observation, so the
// caller can start the simulated clock there (First).
func Open(o Options) (*Player, error) {
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	p := &Player{sources: o.Sources, speed: o.Speed, registry: o.Registry, log: o.Logger}
	for _, s := range o.Sources {
		r, err := openReader(s)
		if err != nil {
			p.Close()
			p.report(s.Interface, platform.StateFailed, err)
			return nil, err
		}
		p.readers = append(p.readers, r)
		if r.next != nil && (p.first.IsZero() || r.next.Time.Before(p.first)) {
			p.first = r.next.Time
		}
	}
	if p.first.IsZero() {
		p.first = time.Now().UTC()
	}
	return p, nil
}

// First is the time of the earliest observation (or now if all files are
// empty).
func (p *Player) First() time.Time { return p.first }

// SetClock attaches the simulated clock the daemon runs on.
func (p *Player) SetClock(sim *clock.Sim) { p.sim = sim }

// SetRegistry attaches the collector registry and logger.
func (p *Player) SetRegistry(r *platform.Registry, log *slog.Logger) {
	p.registry, p.log = r, log
}

// Close closes every file.
func (p *Player) Close() {
	for _, r := range p.readers {
		_ = r.f.Close()
	}
}

func (p *Player) report(iface string, state platform.State, err error) {
	if p.registry != nil {
		p.registry.Set(iface, platform.CollectorReplay, "file", state, err)
	}
}

// Run publishes the interfaces' prefixes, then every observation in time
// order, and finally waits until the correlator has processed them all.
func (p *Player) Run(ctx context.Context, bus *observation.Bus) error {
	defer p.Close()
	if p.sim == nil {
		return errors.New("replay: no simulated clock")
	}
	p.sim.Set(p.first)
	for _, s := range p.sources {
		p.report(s.Interface, platform.StateRunning, nil)
		ls := observation.LinkState{Time: p.first, Interface: s.Interface, Present: true, Up: true, Prefixes: s.Prefixes}
		if err := bus.PublishLink(ctx, ls); err != nil {
			return nil
		}
	}
	wallStart, simStart := time.Now(), p.first
	n := 0
	for {
		r := p.earliest()
		if r == nil {
			break
		}
		o := *r.next
		if err := r.advance(); err != nil {
			p.report(r.src.Interface, platform.StateFailed, err)
			return fmt.Errorf("replay %s: %w", r.src.File, err)
		}
		if p.speed > 0 && !p.waitUntil(ctx, o.Time, wallStart, simStart) {
			return nil
		}
		p.sim.Set(o.Time)
		if err := bus.PublishWait(ctx, o); err != nil {
			return nil
		}
		n++
	}
	if err := bus.Barrier(ctx); err != nil {
		return nil
	}
	for _, s := range p.sources {
		p.report(s.Interface, platform.StateRunning, nil)
	}
	p.log.Info("replay finished", "observations", n, "until", p.sim.Now())
	return nil
}

// waitUntil advances the simulated clock in real time × speed until t.
func (p *Player) waitUntil(ctx context.Context, t, wallStart, simStart time.Time) bool {
	ticker := time.NewTicker(step)
	defer ticker.Stop()
	for {
		target := simStart.Add(time.Duration(float64(time.Since(wallStart)) * p.speed))
		if !target.Before(t) {
			return true
		}
		p.sim.Set(target)
		select {
		case <-ctx.Done():
			return false
		case <-ticker.C:
		}
	}
}

func (p *Player) earliest() *reader {
	var best *reader
	for _, r := range p.readers {
		if r.next != nil && (best == nil || r.next.Time.Before(best.next.Time)) {
			best = r
		}
	}
	return best
}

// reader reads one JSONL file one observation ahead.
type reader struct {
	src  Source
	f    *os.File
	sc   *bufio.Scanner
	line int
	next *observation.Observation
}

func openReader(s Source) (*reader, error) {
	switch filepath.Ext(s.File) {
	case ".jsonl":
	case ".pcap", ".pcapng":
		return nil, fmt.Errorf("replay %s: pcap input arrives with the decoders in phase 2", s.File)
	default:
		return nil, fmt.Errorf("replay %s: unsupported file type", s.File)
	}
	f, err := os.Open(s.File)
	if err != nil {
		return nil, fmt.Errorf("replay: %w", err)
	}
	r := &reader{src: s, f: f, sc: bufio.NewScanner(f)}
	r.sc.Buffer(make([]byte, 64*1024), 1<<20)
	if err := r.advance(); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("replay %s: %w", s.File, err)
	}
	return r, nil
}

// advance reads the next observation (nil at end of file).
func (r *reader) advance() error {
	r.next = nil
	for r.sc.Scan() {
		r.line++
		b := bytes.TrimSpace(r.sc.Bytes())
		if len(b) == 0 {
			continue
		}
		var o observation.Observation
		if err := json.Unmarshal(b, &o); err != nil {
			return fmt.Errorf("line %d: %w", r.line, err)
		}
		switch o.Interface {
		case "":
			o.Interface = r.src.Interface
		case r.src.Interface:
		default:
			return fmt.Errorf("line %d: observation for %s in the replay file of %s", r.line, o.Interface, r.src.Interface)
		}
		r.next = &o
		return nil
	}
	if err := r.sc.Err(); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("line %d: %w", r.line+1, err)
	}
	return nil
}
