package ouitable

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

var entries = map[string]string{
	"001B1B":    "Siemens AG",
	"000C26":    "Weintek Labs. Inc.",
	"F8B568":    "Siemens AG", // a name shared by two prefixes is stored once
	"70B3D5":    "IEEE Registration Authority",
	"70B3D5123": "Small Block GmbH",
	"8C1F64":    "IEEE Registration Authority",
	"8C1F640":   "Medium Block Ltd",
}

func TestRoundTrip(t *testing.T) {
	b, err := Encode(entries)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := Encode(entries)
	if !bytes.Equal(b, again) {
		t.Fatal("encoding is not deterministic")
	}
	if n := bytes.Count(b, []byte("Siemens AG")); n != 1 {
		t.Errorf("a shared name is stored %d times", n)
	}
	tb, err := Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	if tb.Len() != len(entries) {
		t.Errorf("Len = %d", tb.Len())
	}
	for _, tt := range []struct {
		class int
		key   uint64
		want  string
	}{
		{0, 0x70B3D5123, "Small Block GmbH"},
		{1, 0x8C1F640, "Medium Block Ltd"},
		{2, 0x001B1B, "Siemens AG"},
		{2, 0x000C26, "Weintek Labs. Inc."},
		{2, 0xF8B568, "Siemens AG"},
		{2, 0x000000, ""}, // before the first key
		{2, 0xFFFFFF, ""}, // after the last
		{2, 0x001B1C, ""}, // between
		{1, 0x001B1B, ""}, // another class
	} {
		got, ok := tb.Find(tt.class, tt.key)
		if got != tt.want || ok != (tt.want != "") {
			t.Errorf("Find(%d, %x) = %q, %v; want %q", tt.class, tt.key, got, ok, tt.want)
		}
	}
	empty, err := Encode(nil)
	if err != nil {
		t.Fatal(err)
	}
	if et, err := Decode(empty); err != nil || et.Len() != 0 {
		t.Errorf("empty table = %v, %v", et, err)
	} else if _, ok := et.Find(2, 0x001B1B); ok {
		t.Error("found an entry in an empty table")
	}
}

func TestEncodeRefuses(t *testing.T) {
	for name, in := range map[string]map[string]string{
		"eight digits": {"001B1B12": "x"},
		"not hex":      {"00ZZ1B": "x"},
		"empty name":   {"001B1B": ""},
		"long name":    {"001B1B": strings.Repeat("x", 256)},
	} {
		if _, err := Encode(in); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestDecodeRefuses(t *testing.T) {
	good, _ := Encode(entries)
	bad := func(f func([]byte) []byte) []byte { return f(bytes.Clone(good)) }
	for name, b := range map[string][]byte{
		"short":           good[:10],
		"bad magic":       bad(func(b []byte) []byte { b[0] = 'X'; return b }),
		"truncated":       good[:len(good)-1],
		"trailing bytes":  append(bytes.Clone(good), 0),
		"count too large": bad(func(b []byte) []byte { binary.BigEndian.PutUint32(b[16:], 1<<20); return b }),
	} {
		if _, err := Decode(b); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A name offset outside the names finds nothing rather than panicking.
	b := bytes.Clone(good)
	tb, _ := Decode(b)
	binary.BigEndian.PutUint32(tb.offs[2], uint32(len(tb.names)+5))
	if _, ok := tb.Find(2, tb.key(2, 0)); ok {
		t.Error("a corrupt offset was followed")
	}
	tb, _ = Decode(bytes.Clone(good))
	tb.names[0] = 255 // a length past the end
	if _, ok := tb.Find(0, tb.key(0, 0)); ok {
		t.Error("a corrupt length was followed")
	}
}

func FuzzDecode(f *testing.F) {
	good, _ := Encode(entries)
	f.Add(good)
	f.Fuzz(func(t *testing.T, b []byte) {
		tb, err := Decode(b)
		if err != nil {
			return
		}
		for c := range PrefixBits {
			for j := range tb.n[c] {
				_, _ = tb.Find(c, tb.key(c, j))
			}
			_, _ = tb.Find(c, 0x123456)
		}
	})
}
