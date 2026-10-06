// Package netrange is IPv4 address-range arithmetic for ARP sweeps: the
// host addresses of networks, minus excludes and the interface's own
// addresses, as sorted disjoint ranges that can be counted, searched and
// walked in a random order without listing every address.
package netrange

import (
	"math/bits"
	"math/rand/v2"
	"net/netip"
	"sort"
)

// Range is an inclusive range of IPv4 addresses as integers.
type Range struct{ First, Last uint32 }

func toU32(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func toAddr(v uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// Of returns the range of p's addresses (IPv4 only).
func Of(p netip.Prefix) Range {
	p = p.Masked()
	first := toU32(p.Addr())
	return Range{first, first | uint32(uint64(1)<<(32-p.Bits())-1)}
}

// Hosts returns the host addresses of an IPv4 network: without the network
// and broadcast address for prefixes up to /30.
func Hosts(p netip.Prefix) Range {
	r := Of(p)
	if p.Bits() <= 30 {
		r.First, r.Last = r.First+1, r.Last-1
	}
	return r
}

// Set is a set of IPv4 addresses as sorted, disjoint, non-adjacent ranges.
type Set struct {
	rs  []Range
	cum []uint64 // cum[i]: addresses in rs[:i]
}

// New returns the union of the ranges.
func New(rs ...Range) Set {
	sorted := append([]Range(nil), rs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].First < sorted[j].First })
	var out []Range
	for _, r := range sorted {
		if r.Last < r.First {
			continue
		}
		if n := len(out); n > 0 && uint64(r.First) <= uint64(out[n-1].Last)+1 {
			out[n-1].Last = max(out[n-1].Last, r.Last)
			continue
		}
		out = append(out, r)
	}
	return build(out)
}

func build(rs []Range) Set {
	s := Set{rs: rs, cum: make([]uint64, len(rs)+1)}
	for i, r := range rs {
		s.cum[i+1] = s.cum[i] + uint64(r.Last-r.First) + 1
	}
	return s
}

// Minus returns the addresses of s that are in none of the ranges.
func (s Set) Minus(rs ...Range) Set {
	cut := New(rs...).rs
	var out []Range
	for _, r := range s.rs {
		cur := r
		keep := true
		for _, c := range cut {
			if c.Last < cur.First || c.First > cur.Last {
				continue
			}
			if c.First > cur.First {
				out = append(out, Range{cur.First, c.First - 1})
			}
			if c.Last >= cur.Last {
				keep = false
				break
			}
			cur.First = c.Last + 1
		}
		if keep {
			out = append(out, cur)
		}
	}
	return build(out)
}

// Len is the number of addresses.
func (s Set) Len() uint64 { return s.cum[len(s.cum)-1] }

// Ranges returns the ranges (do not modify).
func (s Set) Ranges() []Range { return s.rs }

// Contains reports whether ip is in the set.
func (s Set) Contains(ip netip.Addr) bool {
	if !ip.Is4() {
		return false
	}
	v := toU32(ip)
	i := sort.Search(len(s.rs), func(i int) bool { return s.rs[i].Last >= v })
	return i < len(s.rs) && s.rs[i].First <= v
}

// Overlaps reports whether any address of r is in the set.
func (s Set) Overlaps(r Range) bool {
	i := sort.Search(len(s.rs), func(i int) bool { return s.rs[i].Last >= r.First })
	return i < len(s.rs) && s.rs[i].First <= r.Last
}

// At returns the i-th address in ascending order (0 <= i < Len).
func (s Set) At(i uint64) netip.Addr {
	k := sort.Search(len(s.rs), func(k int) bool { return s.cum[k+1] > i })
	return toAddr(s.rs[k].First + uint32(i-s.cum[k]))
}

// Shuffled walks the set in a random order, each address once, without
// listing it: a random bijection of [0, Len) (a four-round Feistel network
// on the next power of two, cycle-walking past Len), so even a sweep of
// millions of addresses needs constant memory. yield returning false stops.
func (s Set) Shuffled(r *rand.Rand, yield func(netip.Addr) bool) {
	n := s.Len()
	if n == 0 {
		return
	}
	p := newPermutation(r, n)
	for i := uint64(0); i < n; i++ {
		if !yield(s.At(p.at(i))) {
			return
		}
	}
}

type permutation struct {
	n          uint64
	half, mask uint64
	keys       [4]uint64
}

func newPermutation(r *rand.Rand, n uint64) permutation {
	w := uint64(bits.Len64(n - 1)) // bits for values below n
	if w < 2 {
		w = 2
	}
	if w%2 == 1 {
		w++
	}
	p := permutation{n: n, half: w / 2, mask: uint64(1)<<(w/2) - 1}
	for i := range p.keys {
		p.keys[i] = r.Uint64()
	}
	return p
}

// at maps i to a distinct value below n.
func (p permutation) at(i uint64) uint64 {
	v := i
	for {
		v = p.feistel(v)
		if v < p.n {
			return v
		}
	}
}

func (p permutation) feistel(v uint64) uint64 {
	l, r := v>>p.half, v&p.mask
	for _, k := range p.keys {
		f := (r*0x9e3779b97f4a7c15 ^ k) * 0xbf58476d1ce4e5b9
		f ^= f >> 31
		l, r = r, (l^f)&p.mask
	}
	return l<<p.half | r
}
