// Package daemon runs the LAN Sentinel service: it loads configuration,
// opens the store, reports collector availability, talks to the service
// manager and handles SIGHUP reloads and graceful shutdown.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"reflect"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"lan-sentinel/internal/buildinfo"
	"lan-sentinel/internal/clock"
	"lan-sentinel/internal/config"
	"lan-sentinel/internal/logging"
	"lan-sentinel/internal/platform"
	"lan-sentinel/internal/service"
	"lan-sentinel/internal/store"
)

// Options configures Run. Zero values select production defaults.
type Options struct {
	// Load is how the configuration is (re)loaded; the path and overrides
	// stay the same across SIGHUP reloads.
	Load config.LoadOptions

	Stderr           io.Writer
	StderrIsTerminal bool

	Clock    clock.Clock
	Backends *platform.Backends
	Notifier service.Notifier
	// Signals delivers SIGHUP, SIGTERM and SIGINT. Default: signal.Notify.
	Signals <-chan os.Signal
}

// Daemon is a running service instance.
type Daemon struct {
	opts     Options
	log      *slog.Logger
	level    *slog.LevelVar
	cfg      atomic.Pointer[config.Config]
	loaded   *config.Loaded
	store    *store.Store
	registry *platform.Registry
	clock    clock.Clock
	notifier service.Notifier
	backends platform.Backends
	ready    chan struct{}
}

// Ready is closed once the daemon has signalled readiness.
func (d *Daemon) Ready() <-chan struct{} { return d.ready }

// Run is New followed by Daemon.Run.
func Run(ctx context.Context, o Options) error {
	d, err := New(o)
	if err != nil {
		return err
	}
	return d.Run(ctx)
}

// New loads and validates the configuration and sets up logging.
func New(o Options) (*Daemon, error) {
	if o.Stderr == nil {
		o.Stderr = os.Stderr
	}
	if o.Clock == nil {
		o.Clock = clock.Real()
	}
	if o.Notifier == nil {
		o.Notifier = service.NewNotifier()
	}
	if o.Backends == nil {
		b := platform.New()
		o.Backends = &b
	}
	loaded, err := config.Load(o.Load)
	if err != nil {
		return nil, err
	}
	d := &Daemon{
		opts: o, loaded: loaded, clock: o.Clock, notifier: o.Notifier, backends: *o.Backends,
		level: new(slog.LevelVar), registry: platform.NewRegistry(o.Clock.Now), ready: make(chan struct{}),
	}
	d.cfg.Store(loaded.Config)
	if err := d.setupLogging(); err != nil {
		return nil, err
	}
	return d, nil
}

// Run opens the store, reports collector states, signals readiness and
// blocks until ctx is cancelled or SIGTERM/SIGINT arrives, then shuts down
// cleanly. It returns an error if startup fails.
func (d *Daemon) Run(ctx context.Context) error {
	if d.opts.Signals == nil {
		ch := make(chan os.Signal, 4)
		signal.Notify(ch, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGINT)
		defer signal.Stop(ch)
		d.opts.Signals = ch
	}
	loaded := d.loaded
	bi := buildinfo.Get()
	d.log.Info("lan-sentinel starting", "version", bi.Version, "commit", bi.Commit, "platform", bi.Platform,
		"config", loaded.Path)

	st, err := store.Open(ctx, store.Options{Path: loaded.Config.Storage.Path, Clock: d.clock, Logger: d.log})
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	d.store = st
	d.log.Info("database ready", "path", st.Path(), "schema_version", st.SchemaVersion())

	d.startCollectors(ctx)

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	if iv, ok := d.notifier.WatchdogInterval(); ok {
		interval := time.Duration(iv)
		ticker := d.clock.NewTicker(interval / 2) // armed before readiness
		wg.Add(1)
		go func() {
			defer wg.Done()
			d.watchdog(runCtx, ticker, interval)
		}()
	}

	d.notify("ready", d.notifier.Ready)
	d.notify("status", func() error { return d.notifier.Status("running") })
	d.log.Info("lan-sentinel running")
	close(d.ready)

	reason := d.loop(runCtx)

	d.log.Info("lan-sentinel stopping", "reason", reason)
	d.notify("stopping", d.notifier.Stopping)
	cancel()
	wg.Wait()
	if err := d.store.Close(); err != nil {
		d.log.Error("closing database", "err", err)
		return fmt.Errorf("close store: %w", err)
	}
	d.log.Info("lan-sentinel stopped")
	return nil
}

func (d *Daemon) loop(ctx context.Context) string {
	for {
		select {
		case <-ctx.Done():
			return "context cancelled"
		case sig := <-d.opts.Signals:
			switch sig {
			case syscall.SIGHUP:
				d.reload()
			default:
				return "signal " + sig.String()
			}
		}
	}
}

// setupLogging picks the handler. A compiled-default format falls back to
// text on a terminal, and journald falls back to text when its socket is
// unreachable (e.g. `daemon run` outside systemd).
func (d *Daemon) setupLogging() error {
	cfg := d.cfg.Load()
	lvl, err := logging.ParseLevel(cfg.Logging.Level)
	if err != nil {
		return err
	}
	d.level.Set(lvl)

	format := cfg.Logging.Format
	fallback := ""
	switch {
	case d.loaded.SourceOf("logging.format") == "default" && d.opts.StderrIsTerminal:
		format = "text"
	case format == "journald" && !service.JournalAvailable():
		format, fallback = "text", "journald socket not available"
	}
	h, err := logging.New(logging.Options{Format: format, Level: d.level, Writer: d.opts.Stderr})
	if err != nil {
		return err
	}
	d.log = slog.New(h)
	if fallback != "" {
		d.log.Warn("logging to stderr instead of journald", "reason", fallback)
	}
	return nil
}

// startCollectors records the availability of every configured collector.
// The collectors themselves land in later phases; until then their backends
// report ErrNotImplemented and show as failed.
func (d *Daemon) startCollectors(ctx context.Context) {
	cfg := d.cfg.Load()
	b := d.backends
	report := func(iface, collector, backend string, err error) {
		state := platform.StateRunning
		if err != nil {
			state = platform.StateFailed
			d.log.Warn("collector unavailable", "interface", iface, "collector", collector, "backend", backend, "err", err)
		}
		d.registry.Set(iface, collector, backend, state, err)
	}
	for _, ic := range cfg.Interfaces {
		if ic.IsReplay() {
			report(ic.Name, platform.CollectorReplay, "file",
				fmt.Errorf("replay collector: %w (planned for phase 1)", platform.ErrNotImplemented))
			continue
		}
		_, err := b.Interfaces.List(ctx)
		report(ic.Name, platform.CollectorInterface, b.Interfaces.Backend(), err)
		_, err = b.Neighbors.Snapshot(ctx)
		report(ic.Name, platform.CollectorNeighbor, b.Neighbors.Backend(), err)
		if ic.PassiveEnabled() {
			src, err := b.Capturer.Open(ctx, ic.Name, nil, ic.Passive.Promiscuous)
			if err == nil {
				_ = src.Close()
			}
			report(ic.Name, platform.CollectorCapture, b.Capturer.Backend(), err)
		} else {
			d.registry.Set(ic.Name, platform.CollectorCapture, b.Capturer.Backend(), platform.StateDisabled, nil)
		}
		for _, p := range []struct {
			name    string
			enabled bool
		}{
			{platform.CollectorARP, cfg.Active.ARP.Enabled},
			{platform.CollectorICMP, cfg.Active.ICMP.Enabled},
			{platform.CollectorTCP, cfg.Active.TCP.Enabled},
		} {
			if !ic.Active.Enabled || !p.enabled {
				d.registry.Set(ic.Name, p.name, b.Transmitter.Backend(), platform.StateDisabled, nil)
				continue
			}
			report(ic.Name, p.name, b.Transmitter.Backend(),
				fmt.Errorf("probe engine: %w (planned for phase 4)", platform.ErrNotImplemented))
		}
	}
}

// Collectors returns the current collector states.
func (d *Daemon) Collectors() []platform.CollectorStatus { return d.registry.List() }

// restartOnly lists config sections that SIGHUP cannot change (FR-CFG-3).
// keep copies the running value into the newly loaded config.
var restartOnly = []struct {
	key  string
	get  func(*config.Config) any
	keep func(old, next *config.Config)
}{
	{"interfaces", func(c *config.Config) any { return c.Interfaces }, func(o, n *config.Config) { n.Interfaces = o.Interfaces }},
	{"passive", func(c *config.Config) any { return c.Passive }, func(o, n *config.Config) { n.Passive = o.Passive }},
	{"storage", func(c *config.Config) any { return c.Storage }, func(o, n *config.Config) { n.Storage = o.Storage }},
	{"api", func(c *config.Config) any { return c.API }, func(o, n *config.Config) { n.API = o.API }},
	{"metrics", func(c *config.Config) any { return c.Metrics }, func(o, n *config.Config) { n.Metrics = o.Metrics }},
	{"logging.format", func(c *config.Config) any { return c.Logging.Format }, func(o, n *config.Config) { n.Logging.Format = o.Logging.Format }},
	{"replay", func(c *config.Config) any { return c.Replay }, func(o, n *config.Config) { n.Replay = o.Replay }},
}

// reload re-reads the configuration on SIGHUP. Probes, intervals, thresholds
// and the log level take effect; restart-only sections keep their running
// values and a warning names them. An invalid file is rejected as a whole.
func (d *Daemon) reload() {
	d.notify("reloading", d.notifier.Reloading)
	defer d.notify("ready", d.notifier.Ready)

	loaded, err := config.Load(d.opts.Load)
	if err != nil {
		var ve *config.ValidationError
		if errors.As(err, &ve) {
			msgs := make([]string, len(ve.Errors))
			for i, fe := range ve.Errors {
				msgs[i] = fe.String()
			}
			d.log.Error("configuration reload rejected; keeping the running configuration", "path", ve.Path, "errors", msgs)
			return
		}
		d.log.Error("configuration reload failed; keeping the running configuration", "err", err)
		return
	}
	old, next := d.cfg.Load(), loaded.Config
	var ignored []string
	for _, r := range restartOnly {
		if !reflect.DeepEqual(r.get(old), r.get(next)) {
			ignored = append(ignored, r.key)
			r.keep(old, next)
		}
	}
	if len(ignored) > 0 {
		d.log.Warn("configuration changes need a restart and were not applied", "keys", ignored)
	}
	lvl, err := logging.ParseLevel(next.Logging.Level)
	if err != nil { // already validated; defensive
		d.log.Error("configuration reload: bad log level", "err", err)
		return
	}
	d.level.Set(lvl)
	d.cfg.Store(next)
	d.log.Info("configuration reloaded", "path", loaded.Path, "log_level", next.Logging.Level)
}

// Config returns the configuration currently in effect.
func (d *Daemon) Config() *config.Config { return d.cfg.Load() }

// watchdog pings systemd at half the watchdog interval, but only while the
// store's writer goroutine is responsive, so a wedged writer gets the
// process restarted.
func (d *Daemon) watchdog(ctx context.Context, t clock.Ticker, interval time.Duration) {
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C():
			pctx, cancel := context.WithTimeout(ctx, interval/4)
			err := d.store.Ping(pctx)
			cancel()
			if err != nil {
				if ctx.Err() == nil {
					d.log.Error("watchdog: store writer not responding; withholding keep-alive", "err", err)
				}
				continue
			}
			d.notify("watchdog", d.notifier.Watchdog)
		}
	}
}

func (d *Daemon) notify(what string, fn func() error) {
	if err := fn(); err != nil {
		d.log.Warn("service manager notification failed", "notification", what, "err", err)
	}
}
