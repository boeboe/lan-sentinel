package netrange

import (
	"math/rand/v2"
	"net/netip"
	"slices"
	"testing"
)

func pfx(s string) netip.Prefix { return netip.MustParsePrefix(s) }
func addr(s string) netip.Addr  { return netip.MustParseAddr(s) }
func one(s string) Range        { v := toU32(addr(s)); return Range{v, v} }

func TestSetArithmetic(t *testing.T) {
	tests := []struct {
		name  string
		set   Set
		len   uint64
		first string
		last  string
	}{
		{"/24 hosts", New(Hosts(pfx("192.168.1.0/24"))), 254, "192.168.1.1", "192.168.1.254"},
		{"/31 and /32 keep every address", New(Hosts(pfx("10.0.0.0/31")), Hosts(pfx("10.0.0.9/32"))), 3, "10.0.0.0", "10.0.0.9"},
		{"overlapping and adjacent networks merge", New(Of(pfx("10.0.0.0/25")), Of(pfx("10.0.0.128/25")), Of(pfx("10.0.0.0/24"))), 256, "10.0.0.0", "10.0.0.255"},
		{"excludes and own address", New(Hosts(pfx("192.168.1.0/24"))).Minus(one("192.168.1.1"), Of(pfx("192.168.1.240/28")), one("192.168.1.10"), Of(pfx("10.0.0.0/8"))),
			254 - 1 - 15 - 1, "192.168.1.2", "192.168.1.239"},
		{"exclude covering everything", New(Hosts(pfx("10.0.0.0/30"))).Minus(Of(pfx("10.0.0.0/24"))), 0, "", ""},
		{"exclude splitting a range", New(Of(pfx("10.0.0.0/29"))).Minus(one("10.0.0.3"), one("10.0.0.5")), 6, "10.0.0.0", "10.0.0.7"},
		{"a /8", New(Hosts(pfx("10.0.0.0/8"))), 1<<24 - 2, "10.0.0.1", "10.255.255.254"},
		{"the whole space", New(Of(pfx("0.0.0.0/0"))), 1 << 32, "0.0.0.0", "255.255.255.255"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.set.Len() != tt.len {
				t.Fatalf("Len = %d, want %d (ranges %v)", tt.set.Len(), tt.len, tt.set.Ranges())
			}
			if tt.len == 0 {
				return
			}
			if got := tt.set.At(0); got != addr(tt.first) {
				t.Errorf("At(0) = %v", got)
			}
			if got := tt.set.At(tt.len - 1); got != addr(tt.last) {
				t.Errorf("At(last) = %v", got)
			}
		})
	}
	s := New(Of(pfx("10.0.0.0/29"))).Minus(one("10.0.0.3"))
	for ip, want := range map[string]bool{"10.0.0.2": true, "10.0.0.3": false, "10.0.0.7": true, "10.0.0.8": false, "9.255.255.255": false} {
		if s.Contains(addr(ip)) != want {
			t.Errorf("Contains(%s) = %v", ip, !want)
		}
	}
	if s.Contains(addr("fd00::1")) {
		t.Error("an IPv6 address is in an IPv4 set")
	}
	if !s.Overlaps(one("10.0.0.4")) || s.Overlaps(one("10.0.0.3")) || s.Overlaps(Of(pfx("10.0.1.0/24"))) {
		t.Error("Overlaps")
	}
}

func TestShuffledVisitsEachAddressOnce(t *testing.T) {
	for _, set := range []Set{
		New(Hosts(pfx("192.168.1.0/24"))).Minus(one("192.168.1.7")),
		New(one("10.0.0.1")),
		New(Of(pfx("10.0.0.0/30")), Of(pfx("10.1.0.0/23"))),
		{cum: []uint64{0}},
	} {
		var got []netip.Addr
		set.Shuffled(rand.New(rand.NewPCG(1, 2)), func(a netip.Addr) bool { got = append(got, a); return true })
		if uint64(len(got)) != set.Len() {
			t.Fatalf("visited %d of %d", len(got), set.Len())
		}
		sorted := slices.Clone(got)
		slices.SortFunc(sorted, func(a, b netip.Addr) int { return a.Compare(b) })
		for i := range sorted {
			if sorted[i] != set.At(uint64(i)) {
				t.Fatalf("not a permutation: %v", sorted)
			}
		}
		if len(got) > 10 && slices.IsSortedFunc(got, func(a, b netip.Addr) int { return a.Compare(b) }) {
			t.Error("not shuffled")
		}
	}
	// Stopping early.
	n := 0
	New(Hosts(pfx("10.0.0.0/16"))).Shuffled(rand.New(rand.NewPCG(3, 4)), func(netip.Addr) bool { n++; return n < 5 })
	if n != 5 {
		t.Errorf("visited %d after stopping", n)
	}
}

func TestShuffledLargeSetIsCheap(t *testing.T) {
	s := New(Hosts(pfx("10.0.0.0/12")))
	seen := map[netip.Addr]bool{}
	i := 0
	s.Shuffled(rand.New(rand.NewPCG(5, 6)), func(a netip.Addr) bool {
		if seen[a] || !s.Contains(a) {
			t.Fatalf("address %v repeated or outside", a)
		}
		seen[a] = true
		i++
		return i < 100000
	})
}
