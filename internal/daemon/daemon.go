// Package daemon runs the LAN Sentinel service: it loads configuration,
// opens the store, runs the collection pipeline (collectors → bus →
// correlator → store and journald), talks to systemd and handles SIGHUP
// reloads and graceful shutdown.
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
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"lan-sentinel/internal/api"
	"lan-sentinel/internal/buildinfo"
	"lan-sentinel/internal/clock"
	"lan-sentinel/internal/collect/capture"
	"lan-sentinel/internal/collect/replay"
	"lan-sentinel/internal/config"
	"lan-sentinel/internal/correlate"
	"lan-sentinel/internal/events"
	"lan-sentinel/internal/iface"
	"lan-sentinel/internal/logging"
	"lan-sentinel/internal/observation"
	"lan-sentinel/internal/platform"
	"lan-sentinel/internal/probe"
	"lan-sentinel/internal/probe/scheduler"
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

	player     *replay.Player     // replay mode only
	capture    *capture.Collector // live mode with passive capture
	ifaces     *iface.Manager     // live mode only
	events     *events.Engine
	reader     *store.Reader
	api        *api.Server
	started    time.Time
	bus        *observation.Bus
	correlator *correlate.Correlator
	replayDone chan struct{}
	stop       func() // stops the pipeline: collectors, drain, correlator

	sw       *probe.Switch        // the kill switch
	switchMu sync.Mutex           // serialises kill-switch changes
	reloadMu sync.Mutex           // serialises reloads (SIGHUP and the API)
	budget   *probe.Budget        // live mode only
	sched    *scheduler.Scheduler // live mode only
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
	// Replay runs the whole daemon on recorded time: a simulated clock that
	// starts at the first observation.
	var player *replay.Player
	if loaded.Config.ReplayMode() {
		if player, err = openReplay(loaded.Config); err != nil {
			return nil, err
		}
		sim, ok := o.Clock.(*clock.Sim)
		if !ok {
			sim = clock.NewSim(player.First())
		}
		player.SetClock(sim)
		o.Clock = sim
	}
	d := &Daemon{
		player: player, replayDone: make(chan struct{}, 1),
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
	if r := st.Recovery(); r != nil {
		d.log.Error("database was corrupt; quarantined it and created a new one",
			"quarantined", r.QuarantinedTo, "reason", r.Reason)
	}
	d.log.Info("database ready", "path", st.Path(), "schema_version", st.SchemaVersion())

	if d.reader, err = st.Reader(loaded.Config.Identity.NameExpiry.D()); err != nil {
		_ = d.store.Close()
		return err
	}
	if err := d.initSwitch(ctx); err != nil {
		_ = d.reader.Close()
		_ = d.store.Close()
		return fmt.Errorf("read the kill switch: %w", err)
	}
	if err := d.startPipeline(ctx); err != nil {
		_ = d.reader.Close()
		_ = d.store.Close()
		return err
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	d.started = time.Now()
	if err := d.startAPI(runCtx); err != nil {
		cancel()
		d.stop()
		_ = d.store.Close()
		return err
	}
	var wg sync.WaitGroup
	// A replay does not compact: its database should depend only on the
	// recorded data, not on when the simulated clock's ticks were handled.
	if !d.cfg.Load().ReplayMode() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d.store.RunCompaction(runCtx, d.clock, compactionInterval, d.retention, d.log)
		}()
	}
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
	d.log.Info("active discovery: " + d.activeText(d.cfg.Load()))
	d.log.Info("lan-sentinel running")
	close(d.ready)

	reason := d.loop(runCtx)

	d.log.Info("lan-sentinel stopping", "reason", reason)
	d.notify("stopping", d.notifier.Stopping)
	cancel()
	wg.Wait()
	d.stopAPI()
	d.stop()
	if err := d.store.Close(); err != nil {
		d.log.Error("closing database", "err", err)
		return fmt.Errorf("close store: %w", err)
	}
	d.log.Info("lan-sentinel stopped")
	return nil
}

// compactionInterval is how often retention and the size cap are applied
// (docs/DATA_MODEL.md §9).
const compactionInterval = time.Hour

func (d *Daemon) retention() store.Retention {
	r := d.cfg.Load().Storage.Retention
	return store.Retention{Observations: r.Observations.D(), Rollups: r.Rollups.D(), Events: r.Events.D(), MaxDBSize: int64(r.MaxDBSize)}
}

func (d *Daemon) loop(ctx context.Context) string {
	for {
		select {
		case <-ctx.Done():
			return "context cancelled"
		case <-d.replayDone:
			return "replay finished"
		case sig := <-d.opts.Signals:
			switch sig {
			case syscall.SIGHUP:
				_, _ = d.reload("SIGHUP") // the outcome is logged
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

// Collectors returns the current collector states.
func (d *Daemon) Collectors() []platform.CollectorStatus { return d.registry.List() }

// restartOnly lists config sections that a reload cannot change
// (FR-CFG-3). keep copies the running value into the newly loaded config.
var restartOnly = []struct {
	key  string
	get  func(*config.Config) any
	keep func(old, next *config.Config)
}{
	{"interfaces", func(c *config.Config) any { return interfaceShape(c.Interfaces) }, keepInterfaces},
	{"passive", func(c *config.Config) any { return c.Passive }, func(o, n *config.Config) { n.Passive = o.Passive }},
	{"storage", func(c *config.Config) any { return c.Storage }, func(o, n *config.Config) { n.Storage = o.Storage }},
	{"api", func(c *config.Config) any { return c.API }, func(o, n *config.Config) { n.API = o.API }},
	{"metrics", func(c *config.Config) any { return c.Metrics }, func(o, n *config.Config) { n.Metrics = o.Metrics }},
	{"logging.format", func(c *config.Config) any { return c.Logging.Format }, func(o, n *config.Config) { n.Logging.Format = o.Logging.Format }},
	{"replay", func(c *config.Config) any { return c.Replay }, func(o, n *config.Config) { n.Replay = o.Replay }},
}

// interfaceShape is the restart-only part of the interfaces: all but each
// interface's active and dhcp settings, which a reload applies.
func interfaceShape(ics []config.InterfaceConfig) []config.InterfaceConfig {
	out := slices.Clone(ics)
	for i := range out {
		out[i].Active, out[i].DHCP = config.InterfaceActive{}, config.InterfaceDHCP{}
	}
	return out
}

// keepInterfaces keeps the running interfaces, each with its active and
// dhcp settings from the new file if the file still has it.
func keepInterfaces(old, next *config.Config) {
	byName := make(map[string]config.InterfaceConfig, len(next.Interfaces))
	for _, ic := range next.Interfaces {
		byName[ic.Name] = ic
	}
	kept := slices.Clone(old.Interfaces)
	for i := range kept {
		if ic, ok := byName[kept[i].Name]; ok {
			kept[i].Active, kept[i].DHCP = ic.Active, ic.DHCP
		}
	}
	next.Interfaces = kept
}

// ReloadConfig implements api.Control: the reload SIGHUP triggers, on an
// operator request, answering what changed.
func (d *Daemon) ReloadConfig(_ context.Context, actor string) (api.ReloadResult, error) {
	return d.reload(actor)
}

// reload re-reads the configuration file. Probes (each interface's active
// settings included), DHCP allowlists, intervals, thresholds and the log
// level take effect;
// restart-only sections keep their running values and are reported as not
// applied. A file that does not load or validate, or whose kept running
// values would not validate with the rest of it, is rejected as a whole and
// changes nothing.
func (d *Daemon) reload(actor string) (api.ReloadResult, error) {
	d.reloadMu.Lock()
	defer d.reloadMu.Unlock()
	d.notify("reloading", d.notifier.Reloading)
	defer d.notify("ready", d.notifier.Ready)

	loaded, err := config.Load(d.opts.Load)
	if err != nil {
		return api.ReloadResult{}, d.rejected(actor, err)
	}
	old, next := d.cfg.Load(), loaded.Config
	file := *next
	var ignored []string
	for _, r := range restartOnly {
		if !reflect.DeepEqual(r.get(old), r.get(next)) {
			ignored = append(ignored, r.key)
			r.keep(old, next)
		}
	}
	if len(ignored) > 0 {
		if errs := config.Validate(next); len(errs) > 0 {
			return api.ReloadResult{}, d.rejected(actor, &config.ValidationError{Path: loaded.Path, Errors: errs})
		}
	}
	res := api.ReloadResult{Path: loaded.Path}
	if res.Applied, err = config.Diff(old, next); err == nil {
		res.NotApplied, err = config.Diff(next, &file)
	}
	if err != nil {
		d.log.Error("configuration reload failed; keeping the running configuration", "err", err, "actor", actor)
		return api.ReloadResult{}, err
	}
	lvl, err := logging.ParseLevel(next.Logging.Level)
	if err != nil { // already validated; defensive
		return api.ReloadResult{}, d.rejected(actor, err)
	}
	if len(ignored) > 0 {
		d.log.Warn("configuration changes need a restart and were not applied", "keys", ignored)
	}
	d.level.Set(lvl)
	d.cfg.Store(next)
	if d.correlator != nil {
		d.correlator.SetConfig(next)
	}
	if d.reader != nil {
		d.reader.SetNameExpiry(next.Identity.NameExpiry.D())
	}
	if d.sched != nil {
		d.sched.Reload()
	}
	applied := make([]string, len(res.Applied))
	for i, c := range res.Applied {
		applied[i] = c.Key
	}
	d.log.Info("configuration reloaded; active discovery: "+d.activeText(next), "path", loaded.Path, "actor", actor, "applied", applied,
		"log_level", next.Logging.Level)
	return res, nil
}

// rejected logs a configuration that cannot be applied and returns the
// error for the API.
func (d *Daemon) rejected(actor string, err error) error {
	var ve *config.ValidationError
	if errors.As(err, &ve) {
		msgs := make([]string, len(ve.Errors))
		for i, fe := range ve.Errors {
			msgs[i] = fe.String()
		}
		d.log.Error("configuration reload rejected; keeping the running configuration", "path", ve.Path, "actor", actor, "errors", msgs)
	} else {
		d.log.Error("configuration reload failed; keeping the running configuration", "actor", actor, "err", err)
	}
	return fmt.Errorf("%w: %w", api.ErrConfigRejected, err)
}

// activeText says what active discovery runs under cfg, for the log line
// at start-up and on reload (never per pass).
func (d *Daemon) activeText(cfg *config.Config) string {
	if cfg.ReplayMode() {
		return "off (replay)"
	}
	s := config.Summarize(cfg).ActiveText()
	if s != "off" && d.sw != nil && d.sw.Disabled() {
		s = "stopped by the kill switch (" + s + ")"
	}
	return s
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
