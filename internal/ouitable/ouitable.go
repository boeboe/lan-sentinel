// Package ouitable is the format of the precomputed OUI table
// (data/oui/oui.bin): written by `make oui` (data/oui/gen) from the IEEE
// registries and searched in place by internal/identify, so start-up
// parses nothing and the table costs no heap.
package ouitable

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strconv"
)

// All integers are big-endian:
//
//	magic "LSOUI\x00" and version uint16 (1)                       8 bytes
//	entry counts n36, n28, n24 and the names' size, uint32 each   16 bytes
//	keys: n36 × uint64, then n28 × uint32, then n24 × uint32, each class ascending
//	name offsets into names: n36 + n28 + n24 × uint32, in key order
//	names: one length byte and the bytes of each distinct name
//
// Classes are ordered like PrefixBits: MA-S (36 bits), MA-M (28), MA-L (24).
var tableMagic = []byte("LSOUI\x00\x00\x01")

// PrefixBits are the prefix lengths of the classes, longest first: MA-S,
// MA-M, MA-L.
var PrefixBits = [...]int{36, 28, 24}

const tableHeader = 24

// keyWidth is the size of a key in each class.
var keyWidth = [len(PrefixBits)]int{8, 4, 4}

// Table is a decoded view of the precomputed registry.
type Table struct {
	n     [len(PrefixBits)]int
	keys  [len(PrefixBits)][]byte
	offs  [len(PrefixBits)][]byte
	names []byte
}

// ErrMalformed is returned for a table that does not decode.
var ErrMalformed = errors.New("malformed OUI table")

// Decode checks the header and sizes and slices the sections; it does not
// copy or parse the entries, and the table refers to b.
func Decode(b []byte) (*Table, error) {
	if len(b) < tableHeader || !bytes.Equal(b[:len(tableMagic)], tableMagic) {
		return nil, fmt.Errorf("%w: bad header", ErrMalformed)
	}
	t := &Table{}
	size := tableHeader
	for i := range t.n {
		t.n[i] = int(binary.BigEndian.Uint32(b[8+4*i:]))
		size += t.n[i] * (keyWidth[i] + 4)
	}
	namesLen := int(binary.BigEndian.Uint32(b[20:]))
	if size+namesLen != len(b) {
		return nil, fmt.Errorf("%w: %d bytes, the header says %d", ErrMalformed, len(b), size+namesLen)
	}
	at := tableHeader
	for i := range t.n {
		t.keys[i] = b[at : at+t.n[i]*keyWidth[i]]
		at += t.n[i] * keyWidth[i]
	}
	for i := range t.n {
		t.offs[i] = b[at : at+t.n[i]*4]
		at += t.n[i] * 4
	}
	t.names = b[at:]
	return t, nil
}

// Len is the number of entries.
func (t *Table) Len() int { return t.n[0] + t.n[1] + t.n[2] }

func (t *Table) key(class, j int) uint64 {
	k := t.keys[class][j*keyWidth[class]:]
	if keyWidth[class] == 8 {
		return binary.BigEndian.Uint64(k)
	}
	return uint64(binary.BigEndian.Uint32(k))
}

// Find returns the name of an exact prefix in one class (an index into
// PrefixBits); key is the prefix's leading bits.
func (t *Table) Find(class int, key uint64) (string, bool) {
	n := t.n[class]
	j := sort.Search(n, func(j int) bool { return t.key(class, j) >= key })
	if j == n || t.key(class, j) != key {
		return "", false
	}
	off := int(binary.BigEndian.Uint32(t.offs[class][4*j:]))
	if off >= len(t.names) || off+1+int(t.names[off]) > len(t.names) {
		return "", false
	}
	return string(t.names[off+1 : off+1+int(t.names[off])]), true
}

// Encode writes registry entries (prefix as 6, 7 or 9 hex digits for MA-L,
// MA-M and MA-S → organisation name) in the table format. The output
// depends only on the entries.
func Encode(entries map[string]string) ([]byte, error) {
	type entry struct {
		key  uint64
		name string
	}
	var classes [len(PrefixBits)][]entry
	for prefix, name := range entries {
		class := -1
		for i, bits := range PrefixBits {
			if len(prefix)*4 == bits {
				class = i
			}
		}
		key, err := strconv.ParseUint(prefix, 16, 64)
		if class < 0 || err != nil {
			return nil, fmt.Errorf("prefix %q: want 6, 7 or 9 hex digits", prefix)
		}
		if name == "" || len(name) > 255 {
			return nil, fmt.Errorf("prefix %s: the name must be 1 to 255 bytes, got %d", prefix, len(name))
		}
		classes[class] = append(classes[class], entry{key, name})
	}
	var head, keys, offs, names bytes.Buffer
	head.Write(tableMagic)
	nameAt := map[string]uint32{}
	for i := range classes {
		sort.Slice(classes[i], func(a, b int) bool { return classes[i][a].key < classes[i][b].key })
		head.Write(binary.BigEndian.AppendUint32(nil, uint32(len(classes[i])))) //nolint:gosec // fewer than 2^32 entries
		for _, e := range classes[i] {
			if keyWidth[i] == 8 {
				keys.Write(binary.BigEndian.AppendUint64(nil, e.key))
			} else {
				keys.Write(binary.BigEndian.AppendUint32(nil, uint32(e.key))) //nolint:gosec // 24 or 28 bits
			}
			at, ok := nameAt[e.name]
			if !ok {
				at = uint32(names.Len()) //nolint:gosec // names stay far below 4 GiB
				nameAt[e.name] = at
				names.WriteByte(byte(len(e.name)))
				names.WriteString(e.name)
			}
			offs.Write(binary.BigEndian.AppendUint32(nil, at))
		}
	}
	head.Write(binary.BigEndian.AppendUint32(nil, uint32(names.Len()))) //nolint:gosec // see above
	return bytes.Join([][]byte{head.Bytes(), keys.Bytes(), offs.Bytes(), names.Bytes()}, nil), nil
}
