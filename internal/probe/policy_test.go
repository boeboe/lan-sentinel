package probe

import (
	"errors"
	"net/netip"
	"testing"

	"lan-sentinel/internal/config"
	"lan-sentinel/internal/store"
)

func testConfig() *config.Config {
	cfg := config.Defaults()
	var excl config.AddrOrPrefix
	_ = excl.UnmarshalText([]byte("192.168.110.1"))
	var exclNet config.AddrOrPrefix
	_ = exclNet.UnmarshalText([]byte("192.168.110.240/28"))
	cfg.Interfaces = []config.InterfaceConfig{
		{Name: "eth1", Active: config.InterfaceActive{
			Enabled: true, Networks: []netip.Prefix{netip.MustParsePrefix("192.168.110.0/24")},
			Exclude: []config.AddrOrPrefix{excl, exclNet},
		}},
		{Name: "eth0"},
	}
	cfg.Profiles = map[string]config.ProfileConfig{
		"modbus":   {ARP: true, TCP: []int{502}},
		"identify": {UDP: []string{"enip"}},
	}
	cfg.Active.TCP.Targets = []config.TCPTarget{{Port: 502, Name: "modbus", Timeout: config.Duration(750e6)}}
	return cfg
}

func TestConfigPolicy(t *testing.T) {
	cfg := testConfig()
	sw := NewSwitch(store.ActiveState{})
	p := ConfigPolicy{Switch: sw, Config: func() *config.Config { return cfg }}
	tests := []struct {
		name   string
		iface  string
		target string
		want   error
	}{
		{"allowed", "eth1", "192.168.110.20", nil},
		{"unknown interface", "eth9", "192.168.110.20", ErrRefused},
		{"active disabled on interface", "eth0", "192.168.110.20", ErrRefused},
		{"ipv6", "eth1", "fe80::1", ErrRefused},
		{"outside networks", "eth1", "192.168.111.20", ErrRefused},
		{"excluded address", "eth1", "192.168.110.1", ErrRefused},
		{"excluded range", "eth1", "192.168.110.245", ErrRefused},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := p.Check(tt.iface, ARP, netip.MustParseAddr(tt.target))
			if !errors.Is(err, tt.want) || (tt.want == nil) != (err == nil) {
				t.Errorf("Check = %v, want %v", err, tt.want)
			}
		})
	}
	ch := sw.Changed()
	sw.Set(store.ActiveState{Disabled: true})
	select {
	case <-ch:
	default:
		t.Error("Changed not closed by Set")
	}
	if err := p.Check("eth1", ARP, netip.MustParseAddr("192.168.110.20")); !errors.Is(err, ErrDisabled) {
		t.Errorf("Check with the kill switch = %v", err)
	}
	if !sw.Disabled() || !sw.State().Disabled {
		t.Error("switch state")
	}
}
