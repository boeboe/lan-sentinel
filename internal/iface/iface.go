// Package iface is the interface manager: it follows the configured
// interfaces through netlink and publishes their state (present, up, own
// prefixes) on the bus. The correlator turns changes into network-context
// prefix history and INTERFACE_UP/DOWN and SUBNET_CHANGED events.
package iface

import (
	"context"
	"log/slog"
	"time"

	"lan-sentinel/internal/clock"
	"lan-sentinel/internal/observation"
	"lan-sentinel/internal/platform"
)

const retryDelay = 5 * time.Second

// Options configures a Manager.
type Options struct {
	Monitor    platform.InterfaceMonitor
	Bus        *observation.Bus
	Clock      clock.Clock
	Interfaces []string
	Registry   *platform.Registry
	Logger     *slog.Logger
}

// Manager publishes link states for the configured interfaces.
type Manager struct {
	o       Options
	ifaces  map[string]bool
	byIndex map[int]string
}

// New returns a manager.
func New(o Options) *Manager {
	if o.Clock == nil {
		o.Clock = clock.Real()
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	m := &Manager{o: o, ifaces: map[string]bool{}, byIndex: map[int]string{}}
	for _, i := range o.Interfaces {
		m.ifaces[i] = true
	}
	return m
}

func (m *Manager) report(state platform.State, err error) {
	if m.o.Registry == nil {
		return
	}
	for iface := range m.ifaces {
		m.o.Registry.Set(iface, platform.CollectorInterface, m.o.Monitor.Backend(), state, err)
	}
}

// Run publishes the current state, then follows changes until ctx is
// cancelled.
func (m *Manager) Run(ctx context.Context) error {
	for ctx.Err() == nil {
		events, err := m.o.Monitor.Watch(ctx)
		if err == nil {
			err = m.publishAll(ctx)
		}
		if err != nil {
			m.report(platform.StateFailed, err)
			m.o.Logger.Warn("interface manager failed; retrying", "err", err)
			if !wait(ctx, m.o.Clock, retryDelay) {
				return nil
			}
			continue
		}
		m.report(platform.StateRunning, nil)
		for ev := range events {
			switch {
			case ev.Resync:
				_ = m.publishAll(ctx)
			case ev.Removed:
				if name, ok := m.byIndex[ev.Link.Index]; ok {
					delete(m.byIndex, ev.Link.Index)
					m.publish(ctx, observation.LinkState{Time: m.o.Clock.Now(), Interface: name, Present: false})
				}
			case m.ifaces[ev.Link.Name]:
				m.byIndex[ev.Link.Index] = ev.Link.Name
				m.publish(ctx, state(ev.Link, m.o.Clock.Now()))
			}
		}
	}
	return nil
}

func state(l platform.Link, t time.Time) observation.LinkState {
	return observation.LinkState{Time: t, Interface: l.Name, Present: true, Up: l.Up, Prefixes: l.Prefixes}
}

// publishAll publishes every configured interface, absent ones as removed.
func (m *Manager) publishAll(ctx context.Context) error {
	links, err := m.o.Monitor.List(ctx)
	if err != nil {
		return err
	}
	now := m.o.Clock.Now()
	found := map[string]bool{}
	for _, l := range links {
		if !m.ifaces[l.Name] {
			continue
		}
		found[l.Name] = true
		m.byIndex[l.Index] = l.Name
		m.publish(ctx, state(l, now))
	}
	for name := range m.ifaces {
		if !found[name] {
			m.o.Logger.Warn("configured interface not present", "interface", name)
			m.publish(ctx, observation.LinkState{Time: now, Interface: name, Present: false})
		}
	}
	return nil
}

func (m *Manager) publish(ctx context.Context, ls observation.LinkState) {
	if err := m.o.Bus.PublishLink(ctx, ls); err != nil && ctx.Err() == nil {
		m.o.Logger.Error("publishing interface state failed", "interface", ls.Interface, "err", err)
	}
}

func wait(ctx context.Context, c clock.Clock, d time.Duration) bool {
	t := c.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C():
		return true
	case <-ctx.Done():
		return false
	}
}
