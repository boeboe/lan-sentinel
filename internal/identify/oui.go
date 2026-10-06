// Package identify derives facts about hosts from their evidence. In v1 that
// is the manufacturer from the MAC's IEEE assignment (MA-L, MA-M, MA-S) and
// the locally-administered flag; identification plugins arrive in phase 6.
package identify

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"

	"lan-sentinel/data/oui"
	"lan-sentinel/internal/ouitable"
)

// prefix lengths in bits, longest first: MA-S, MA-M, MA-L.
var prefixBits = ouitable.PrefixBits

// Vendors maps MAC prefixes to organisation names: the embedded registry,
// searched in place, and parsed entries (an override file) that take
// precedence over it at the same prefix length.
type Vendors struct {
	table *ouitable.Table // nil for a parsed table
	byLen [len(prefixBits)]map[uint64]string
}

func newVendors() *Vendors {
	v := &Vendors{}
	for i := range v.byLen {
		v.byLen[i] = map[uint64]string{}
	}
	return v
}

var embedded = sync.OnceValues(func() (*Vendors, error) {
	t, err := ouitable.Decode(oui.Data)
	if err != nil {
		return nil, fmt.Errorf("embedded OUI table: %w", err)
	}
	v := newVendors()
	v.table = t
	return v, nil
})

// Embedded returns the registry compiled into the binary. It is searched in
// place: nothing is parsed or copied.
func Embedded() (*Vendors, error) { return embedded() }

// Load returns the embedded registry with the override file applied on top,
// if path is not empty.
func Load(overridePath string) (*Vendors, error) {
	base, err := Embedded()
	if err != nil {
		return nil, err
	}
	if overridePath == "" {
		return base, nil
	}
	f, err := os.Open(overridePath)
	if err != nil {
		return nil, fmt.Errorf("OUI override: %w", err)
	}
	defer f.Close()
	ov, err := Parse(f)
	if err != nil {
		return nil, fmt.Errorf("OUI override %s: %w", overridePath, err)
	}
	return base.With(ov), nil
}

// Parse reads "PREFIX NAME" lines. PREFIX is hex with optional ':', '-' or
// '.' separators and an optional "/bits" (24, 28 or 36; by default four
// bits per hex digit). The name is the rest of the line. Blank lines and
// lines starting with '#' are ignored.
func Parse(r io.Reader) (*Vendors, error) {
	v := newVendors()
	names := map[string]string{} // interning: many prefixes share a name
	sc := bufio.NewScanner(r)
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		field, name, ok := strings.Cut(text, "\t")
		if !ok {
			field, name, ok = strings.Cut(text, " ")
		}
		name = strings.TrimSpace(name)
		if !ok || name == "" {
			return nil, fmt.Errorf("line %d: want PREFIX NAME", line)
		}
		key, idx, err := parsePrefix(field)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		if n, ok := names[name]; ok {
			name = n
		} else {
			names[name] = name
		}
		v.byLen[idx][key] = name
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return v, nil
}

func parsePrefix(s string) (key uint64, idx int, err error) {
	digits, bitsText, hasBits := strings.Cut(s, "/")
	digits = strings.NewReplacer(":", "", "-", "", ".", "").Replace(digits)
	if _, err := hex.DecodeString(digits + strings.Repeat("0", len(digits)%2)); err != nil || digits == "" {
		return 0, 0, fmt.Errorf("invalid prefix %q", s)
	}
	bits := len(digits) * 4
	if hasBits {
		if bits, err = strconv.Atoi(bitsText); err != nil {
			return 0, 0, fmt.Errorf("invalid prefix length in %q", s)
		}
	}
	idx = -1
	for i, b := range prefixBits {
		if b == bits {
			idx = i
		}
	}
	if idx < 0 || len(digits)*4 < bits {
		return 0, 0, fmt.Errorf("prefix %q: length must be 24, 28 or 36 bits", s)
	}
	v, err := strconv.ParseUint(digits, 16, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid prefix %q", s)
	}
	return v >> (len(digits)*4 - bits), idx, nil
}

// With returns a copy of v with ov's parsed entries taking precedence.
func (v *Vendors) With(ov *Vendors) *Vendors {
	out := newVendors()
	out.table = v.table
	for i := range v.byLen {
		for k, n := range v.byLen[i] {
			out.byLen[i][k] = n
		}
		for k, n := range ov.byLen[i] {
			out.byLen[i][k] = n
		}
	}
	return out
}

// Len is the number of assignments.
func (v *Vendors) Len() int {
	n := 0
	if v.table != nil {
		n = v.table.Len()
	}
	for i, m := range v.byLen {
		for k := range m {
			if v.table == nil {
				n++
			} else if _, ok := v.table.Find(i, k); !ok {
				n++
			}
		}
	}
	return n
}

// Lookup returns the organisation for mac, longest prefix first.
func (v *Vendors) Lookup(mac net.HardwareAddr) (string, bool) {
	if v == nil || len(mac) != 6 {
		return "", false
	}
	var m uint64
	for _, b := range mac {
		m = m<<8 | uint64(b)
	}
	for i, bits := range prefixBits {
		key := m >> (48 - bits)
		if name, ok := v.byLen[i][key]; ok {
			return name, true
		}
		if v.table != nil {
			if name, ok := v.table.Find(i, key); ok {
				return name, true
			}
		}
	}
	return "", false
}

// LocallyAdministered reports whether the MAC's U/L bit is set.
func LocallyAdministered(mac net.HardwareAddr) bool { return len(mac) > 0 && mac[0]&0x02 != 0 }

// UnicastMAC reports whether mac is a usable host MAC: 6 bytes, not
// multicast or broadcast, not all zero.
func UnicastMAC(mac net.HardwareAddr) bool {
	if len(mac) != 6 || mac[0]&0x01 != 0 {
		return false
	}
	for _, b := range mac {
		if b != 0 {
			return true
		}
	}
	return false
}
