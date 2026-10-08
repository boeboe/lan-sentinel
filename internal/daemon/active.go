package daemon

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"lan-sentinel/internal/api"
	"lan-sentinel/internal/config"
	"lan-sentinel/internal/observation"
	"lan-sentinel/internal/probe"
	"lan-sentinel/internal/probe/arp"
	"lan-sentinel/internal/probe/icmp"
	"lan-sentinel/internal/probe/idprobe"
	"lan-sentinel/internal/probe/scheduler"
	"lan-sentinel/internal/probe/tcp"
	"lan-sentinel/internal/probe/udp"
	"lan-sentinel/internal/store"
)

// envActor is the actor of a kill switch forced by the environment.
const envActor = "env"

// envForced reports whether LAN_SENTINEL_ACTIVE_DISABLED=1 is set.
func (d *Daemon) envForced() bool {
	return slices.Contains(d.opts.Load.Environ, config.EnvActiveDisabled+"=1")
}

// initSwitch loads the persisted kill switch and applies the environment.
func (d *Daemon) initSwitch(ctx context.Context) error {
	st, err := d.reader.ActiveState(ctx)
	if err != nil {
		return err
	}
	if d.envForced() {
		if !st.Disabled {
			now := d.clock.Now().UTC()
			st = store.ActiveState{Disabled: true, Reason: config.EnvActiveDisabled + "=1", By: envActor, At: &now}
		}
		st.Forced = true
	}
	d.sw = probe.NewSwitch(st)
	return nil
}

// startScheduler starts the probe engines (live mode). An environment
// kill switch is recorded first, as an ACTIVE_DISABLED event that is not
// persisted.
func (d *Daemon) startScheduler(ctx context.Context, start func(string, func(context.Context) error)) error {
	cfg := d.cfg.Load()
	if d.envForced() {
		if err := d.bus.PublishOperator(ctx, observation.Operator{
			Time: d.clock.Now(), Kind: observation.OpActiveDisabled, Actor: envActor, Reason: config.EnvActiveDisabled + "=1",
		}); err != nil {
			return err
		}
	}
	tx := d.backends.Transmitter
	d.budget = probe.NewBudget(d.clock, probe.LimitsFrom(cfg.Active), probe.ConfigPolicy{Switch: d.sw, Config: d.cfg.Load})
	kh := knownHosts{d.reader}
	d.identify = &idprobe.Engine{TX: tx}
	d.sched = scheduler.New(scheduler.Options{
		Config: d.cfg.Load, Links: d.probeLinks, Known: kh, Identify: kh,
		Engines: map[probe.Protocol]probe.Engine{
			probe.ARP: arp.Engine{TX: tx}, probe.ICMP: icmp.Engine{TX: tx},
			probe.TCP: tcp.Engine{TX: tx}, probe.UDP: udp.Engine{TX: tx},
			probe.Identify: d.identify,
		},
		Budget: d.budget, Switch: d.sw, Emit: d.emitObservation,
		Operator: d.bus.PublishOperator, Registry: d.registry, Backend: tx.Backend, Clock: d.clock, Logger: d.log,
	})
	start("scheduler", d.sched.Run)
	return nil
}

// knownHosts serves the scheduler the open bindings from the database.
type knownHosts struct{ r *store.Reader }

func (k knownHosts) Known(ctx context.Context, iface string) ([]scheduler.Known, error) {
	addrs, err := k.r.KnownIPv4(ctx, iface)
	out := make([]scheduler.Known, len(addrs))
	for i, a := range addrs {
		out[i] = scheduler.Known{IP: a.IP, LastSeen: a.LastSeen}
	}
	return out, err
}

func (k knownHosts) IdentifyTargets(ctx context.Context, iface, probe string, since time.Time) ([]store.IdentifyCandidate, error) {
	return k.r.IdentifyTargets(ctx, iface, probe, since)
}

// probeLinks returns the interfaces that are present and up.
func (d *Daemon) probeLinks() map[string]probe.Link {
	out := map[string]probe.Link{}
	if d.ifaces == nil {
		return out
	}
	for name, l := range d.ifaces.Links() {
		if l.Present && l.Up && len(l.MAC) == 6 {
			out[name] = probe.Link{Name: name, MAC: l.MAC, Addrs: l.Addrs}
		}
	}
	return out
}

// persistTimeout bounds recording a kill-switch change. The change is
// recorded even when the client gives up, but never waits for a correlator
// that has stopped.
const persistTimeout = 10 * time.Second

// DisableActive implements api.Control: probes stop at once; the switch
// is persisted and recorded by the correlator, then committed. Changes of
// the switch are serialised, so memory and database cannot disagree.
func (d *Daemon) DisableActive(ctx context.Context, actor, reason string) (store.ActiveState, error) {
	d.switchMu.Lock()
	defer d.switchMu.Unlock()
	now := d.clock.Now().UTC()
	st := store.ActiveState{Disabled: true, Reason: reason, By: actor, At: &now, Forced: d.envForced()}
	d.sw.Set(st)
	return st, d.record(ctx, observation.Operator{
		Time: now, Kind: observation.OpActiveDisabled, Actor: actor, Reason: reason, Persist: true,
	})
}

// EnableActive implements api.Control. It refuses while the environment
// forces the switch, and resumes probing only once the cleared switch is
// committed.
func (d *Daemon) EnableActive(ctx context.Context, actor, reason string) (store.ActiveState, error) {
	d.switchMu.Lock()
	defer d.switchMu.Unlock()
	if d.envForced() {
		return d.sw.State(), api.ErrForced
	}
	if !d.sw.Disabled() {
		return d.sw.State(), nil
	}
	if err := d.record(ctx, observation.Operator{
		Time: d.clock.Now(), Kind: observation.OpActiveEnabled, Actor: actor, Reason: reason, Persist: true,
	}); err != nil {
		return d.sw.State(), err
	}
	d.sw.Set(store.ActiveState{})
	return store.ActiveState{}, nil
}

// record hands an operator action to the correlator and returns once it is
// committed.
func (d *Daemon) record(ctx context.Context, op observation.Operator) error {
	pctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), persistTimeout)
	defer cancel()
	if err := d.bus.PublishOperator(pctx, op); err != nil {
		return err
	}
	return d.store.Flush(pctx)
}

// PlanScan implements api.Control.
func (d *Daemon) PlanScan(ctx context.Context, req probe.Request) (probe.Plan, error) {
	if d.sched == nil {
		return probe.Plan{}, api.ErrNoScanner
	}
	return d.sched.Plan(ctx, req)
}

// Scan implements api.Control.
func (d *Daemon) Scan(ctx context.Context, req probe.Request, actor string) (scheduler.ScanResult, error) {
	if d.sched == nil {
		return scheduler.ScanResult{}, api.ErrNoScanner
	}
	res, err := d.sched.Scan(ctx, req, actor)
	if ferr := d.store.Flush(context.WithoutCancel(ctx)); ferr != nil && err == nil {
		err = ferr
	}
	return res, err
}

// DescribeHost implements api.Control: the correlator records the change
// (HOST_DESCRIBED) and it is committed before the answer. A host must be
// committed to be found: one discovered in the last few seconds may not be
// yet.
func (d *Daemon) DescribeHost(ctx context.Context, actor, hostID, description string) (store.HostSummary, error) {
	if _, err := d.reader.Host(ctx, hostID); err != nil {
		return store.HostSummary{}, err
	}
	if err := d.record(ctx, observation.Operator{
		Time: d.clock.Now(), Kind: observation.OpHostDescribed, Actor: actor, HostID: hostID, Description: description,
	}); err != nil {
		return store.HostSummary{}, err
	}
	h, err := d.reader.Host(ctx, hostID)
	return h.HostSummary, err
}

// emitObservation puts a probe observation on the bus. Identification
// observations are the once-per-MAC latch (ADR 0011): they must not drop
// when the bus is full. Other sources stay on the dropping Publish.
func (d *Daemon) emitObservation(o observation.Observation) {
	if o.Source != observation.IdentifyProbe {
		d.bus.Publish(o)
		return
	}
	// Background: PublishWait also returns when the bus is closed.
	_ = d.bus.PublishWait(context.Background(), o)
}

// IdentifyRun implements api.Control: one forced identification exchange
// (ADR 0011). It bypasses only the once-per-MAC latch.
func (d *Daemon) IdentifyRun(ctx context.Context, actor, hostID, probeName, sni string) (store.IdentifyAttempt, error) {
	if d.sched == nil {
		return store.IdentifyAttempt{}, api.ErrNoScanner
	}
	h, err := d.reader.Host(ctx, hostID)
	if err != nil {
		return store.IdentifyAttempt{}, err
	}
	cfg := d.cfg.Load()
	ic, ok := probe.InterfaceConfig(cfg, h.Interface)
	if !ok {
		return store.IdentifyAttempt{}, fmt.Errorf("%w: interface %s is not configured", api.ErrIdentifyRefused, h.Interface)
	}
	if !ic.Active.Enabled {
		return store.IdentifyAttempt{}, fmt.Errorf("%w: active discovery is disabled on %s", api.ErrIdentifyRefused, h.Interface)
	}
	var entry config.InterfaceIdentify
	found := false
	for _, e := range ic.Active.Identify {
		if e.Name == probeName {
			entry, found = e, true
			break
		}
	}
	if !found {
		return store.IdentifyAttempt{}, fmt.Errorf("%w: %s is not enabled on %s", api.ErrIdentifyRefused, probeName, h.Interface)
	}
	since := d.clock.Now().Add(-cfg.Active.Identify.HostMaxAge.D())
	cands, err := d.reader.IdentifyTargets(ctx, h.Interface, probeName, since)
	if err != nil {
		return store.IdentifyAttempt{}, err
	}
	var cand store.IdentifyCandidate
	matched := false
	for _, c := range cands {
		if c.HostID == hostID {
			cand, matched = c, true
			break
		}
	}
	if !matched {
		return store.IdentifyAttempt{}, fmt.Errorf("%w: no open IPv4 binding", api.ErrIdentifyRefused)
	}
	if cand.Suppress != "" && cand.Suppress != store.IdentifyAttempted {
		return store.IdentifyAttempt{}, fmt.Errorf("%w: %s", api.ErrIdentifyRefused, cand.Suppress)
	}
	job := probe.IdentifyJob{
		HostID: hostID, IP: cand.IP, Probe: probeName,
		UnitID:    uint8(cfg.Active.Identify.UnitIDOf(entry)), //nolint:gosec // validated 1–255
		Community: cfg.Active.Identify.CommunityOf(entry),
		SNI:       config.ResolveSNI(cfg.Active.Identify.SNIModeOf(entry), cand.PreferredName, sni),
		Force:     true, Trigger: observation.TriggerOperator, Actor: actor,
	}
	results, err := d.sched.IdentifyRun(ctx, h.Interface, job)
	if err != nil {
		if errors.Is(err, probe.ErrDisabled) || errors.Is(err, probe.ErrRefused) {
			return store.IdentifyAttempt{}, fmt.Errorf("%w: %w", api.ErrIdentifyRefused, err)
		}
		return store.IdentifyAttempt{}, err
	}
	if len(results) == 1 && results[0].State == probe.Blocked {
		return store.IdentifyAttempt{}, fmt.Errorf("%w: probe blocked by policy", api.ErrIdentifyRefused)
	}
	pctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), persistTimeout)
	defer cancel()
	if err := d.bus.Barrier(pctx); err != nil {
		return store.IdentifyAttempt{}, err
	}
	if err := d.store.Flush(pctx); err != nil {
		return store.IdentifyAttempt{}, err
	}
	return d.reader.IdentifyAttemptOf(pctx, hostID, probeName)
}

var _ api.Control = (*Daemon)(nil)
