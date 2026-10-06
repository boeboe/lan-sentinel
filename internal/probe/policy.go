package probe

import (
	"net/netip"
	"sync"

	"lan-sentinel/internal/config"
	"lan-sentinel/internal/store"
)

// Switch is the kill switch (FR-CFG-4): the persisted state plus whether
// LAN_SENTINEL_ACTIVE_DISABLED forces it. Engines see a change at their
// next send; the scheduler cancels running probes on Changed.
type Switch struct {
	mu      sync.Mutex
	state   store.ActiveState
	changed chan struct{}
}

// NewSwitch returns a switch in the given state.
func NewSwitch(initial store.ActiveState) *Switch {
	return &Switch{state: initial, changed: make(chan struct{})}
}

// State returns the current state.
func (s *Switch) State() store.ActiveState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

// Disabled reports whether active discovery is stopped.
func (s *Switch) Disabled() bool { return s.State().Disabled }

// Set changes the state and wakes everyone waiting on Changed.
func (s *Switch) Set(st store.ActiveState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = st
	close(s.changed)
	s.changed = make(chan struct{})
}

// Changed is closed at the next Set.
func (s *Switch) Changed() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.changed
}

// ConfigPolicy is the policy checked before every probe: the kill switch,
// active discovery enabled on the interface, the target inside the
// interface's configured networks, IPv4, and not excluded
// (docs/ARCHITECTURE.md §5).
type ConfigPolicy struct {
	Switch *Switch
	Config func() *config.Config
}

// Check implements Policy.
func (p ConfigPolicy) Check(iface string, _ Protocol, target netip.Addr) error {
	if p.Switch != nil && p.Switch.Disabled() {
		return ErrDisabled
	}
	ic, ok := InterfaceConfig(p.Config(), iface)
	switch {
	case !ok || !ic.Active.Enabled:
		return refusal("active discovery is disabled on %s", iface)
	case !target.Is4():
		return refusal("%s: v1 probes IPv4 only", target)
	case !Contains(ic.Active.Networks, target):
		return refusal("%s is outside the configured networks of %s", target, iface)
	case Excluded(ic.Active.Exclude, target):
		return refusal("%s is excluded", target)
	}
	return nil
}

// InterfaceConfig returns the configuration of iface.
func InterfaceConfig(cfg *config.Config, iface string) (config.InterfaceConfig, bool) {
	for _, ic := range cfg.Interfaces {
		if ic.Name == iface {
			return ic, true
		}
	}
	return config.InterfaceConfig{}, false
}

// Contains reports whether ip is inside one of the networks.
func Contains(networks []netip.Prefix, ip netip.Addr) bool {
	for _, n := range networks {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Excluded reports whether ip matches an exclude entry.
func Excluded(excludes []config.AddrOrPrefix, ip netip.Addr) bool {
	for _, e := range excludes {
		if e.Contains(ip) {
			return true
		}
	}
	return false
}
