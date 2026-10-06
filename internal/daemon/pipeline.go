package daemon

import (
	"context"
	"fmt"
	"sync"
	"time"

	"lan-sentinel/internal/collect/capture"
	"lan-sentinel/internal/collect/capture/decoders"
	"lan-sentinel/internal/collect/neighbor"
	"lan-sentinel/internal/collect/replay"
	"lan-sentinel/internal/config"
	"lan-sentinel/internal/correlate"
	"lan-sentinel/internal/events"
	"lan-sentinel/internal/identify"
	"lan-sentinel/internal/iface"
	"lan-sentinel/internal/observation"
	"lan-sentinel/internal/platform"
)

// drainTimeout bounds how long shutdown waits for the correlator to process
// what is already on the bus.
const drainTimeout = 10 * time.Second

func openReplay(cfg *config.Config) (*replay.Player, error) {
	var sources []replay.Source
	speed := 0.0
	for _, ic := range cfg.Interfaces {
		sources = append(sources, replay.Source{Interface: ic.Name, File: ic.Replay.File, Prefixes: ic.Prefixes})
		speed = ic.Replay.Speed
	}
	return replay.Open(replay.Options{Sources: sources, Speed: speed, Protocols: decoders.Protocols(cfg.Passive.Protocols)})
}

// startPipeline starts the correlator and the collectors. d.stop shuts them
// down in order: collectors first, then the correlator once it has drained
// the bus.
func (d *Daemon) startPipeline(ctx context.Context) error {
	cfg := d.cfg.Load()
	vendors, err := identify.Load(cfg.Identity.OUIOverride)
	if err != nil {
		return err
	}
	d.log.Info("vendor table loaded", "assignments", vendors.Len())
	d.bus = observation.NewBus(observation.DefaultBusSize)
	engine := events.NewEngine(d.store, d.log, nil)
	d.correlator, err = correlate.New(ctx, correlate.Options{
		Store: d.store, Events: engine, Vendors: vendors, Clock: d.clock, Logger: d.log, Config: cfg,
		DataDriven: cfg.ReplayMode(), Recovery: d.store.Recovery(),
	})
	if err != nil {
		return fmt.Errorf("start correlator: %w", err)
	}

	// The correlator outlives ctx so it can drain the bus during shutdown.
	corrCtx, corrCancel := context.WithCancel(context.WithoutCancel(ctx))
	corrDone := make(chan struct{})
	go func() {
		defer close(corrDone)
		_ = d.correlator.Run(corrCtx, d.bus)
	}()

	collCtx, collCancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	start := func(name string, run func(context.Context) error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := run(collCtx); err != nil {
				d.log.Error("collector stopped", "collector", name, "err", err)
			}
		}()
	}

	if d.player != nil {
		d.player.SetRegistry(d.registry, d.log)
		start(platform.CollectorReplay, func(ctx context.Context) error {
			if err := d.player.Run(ctx, d.bus); err != nil {
				return err
			}
			if ctx.Err() == nil {
				_ = d.store.Flush(ctx)
				if cfg.Replay.ExitWhenDone {
					d.replayDone <- struct{}{}
				}
			}
			return nil
		})
	} else {
		var live []string
		for _, ic := range cfg.Interfaces {
			live = append(live, ic.Name)
		}
		mgr := iface.New(iface.Options{Monitor: d.backends.Interfaces, Bus: d.bus, Clock: d.clock, Interfaces: live,
			Registry: d.registry, Logger: d.log})
		start(platform.CollectorInterface, mgr.Run)
		nb := neighbor.New(neighbor.Options{Source: d.backends.Neighbors, Bus: d.bus, Clock: d.clock, Interfaces: live,
			Resync: cfg.Neighbor.ResyncInterval.D(), Registry: d.registry, Logger: d.log})
		start(platform.CollectorNeighbor, nb.Run)
		var captured []capture.Interface
		for _, ic := range cfg.Interfaces {
			if ic.PassiveEnabled() {
				captured = append(captured, capture.Interface{Name: ic.Name, Promiscuous: ic.Passive.Promiscuous})
			} else {
				d.registry.Set(ic.Name, platform.CollectorCapture, d.backends.Capturer.Backend(), platform.StateDisabled, nil)
			}
		}
		if len(captured) > 0 {
			d.capture = capture.New(capture.Options{Capturer: d.backends.Capturer, Bus: d.bus, Clock: d.clock,
				Interfaces: captured, Protocols: decoders.Protocols(cfg.Passive.Protocols), RingSize: int(cfg.Passive.RingSize),
				Registry: d.registry, Logger: d.log})
			start(platform.CollectorCapture, d.capture.Run)
		}
		d.reportPending(cfg)
	}

	d.stop = func() {
		collCancel()
		wg.Wait()
		dctx, cancel := context.WithTimeout(context.Background(), drainTimeout)
		if err := d.bus.Barrier(dctx); err != nil {
			d.log.Warn("correlator did not drain the bus before shutdown", "err", err)
		}
		cancel()
		corrCancel()
		<-corrDone
		if n := d.bus.Dropped(); n > 0 {
			d.log.Warn("observations dropped because the bus was full", "dropped", n)
		}
	}
	return nil
}

// reportPending records collectors whose implementation lands in a later
// phase: the probe engines (phase 4).
func (d *Daemon) reportPending(cfg *config.Config) {
	backend := d.backends.Transmitter.Backend()
	for _, ic := range cfg.Interfaces {
		for _, p := range []struct {
			name    string
			enabled bool
		}{
			{platform.CollectorARP, cfg.Active.ARP.Enabled},
			{platform.CollectorICMP, cfg.Active.ICMP.Enabled},
			{platform.CollectorTCP, cfg.Active.TCP.Enabled},
		} {
			if !ic.Active.Enabled || !p.enabled {
				d.registry.Set(ic.Name, p.name, backend, platform.StateDisabled, nil)
				continue
			}
			err := fmt.Errorf("probe engine: %w (planned for phase 4)", platform.ErrNotImplemented)
			d.log.Warn("collector unavailable", "interface", ic.Name, "collector", p.name, "backend", backend, "err", err)
			d.registry.Set(ic.Name, p.name, backend, platform.StateFailed, err)
		}
	}
}
