package identify

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"lan-sentinel/data/oui"
	"lan-sentinel/internal/ouitable"
)

func mac(t *testing.T, s string) net.HardwareAddr {
	t.Helper()
	m, err := net.ParseMAC(s)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestEmbedded(t *testing.T) {
	v, err := Embedded()
	if err != nil {
		t.Fatal(err)
	}
	if v.Len() < 50000 {
		t.Fatalf("embedded table has %d assignments, want > 50000", v.Len())
	}
	for addr, want := range map[string]string{
		"00:1b:1b:12:34:56": "Siemens AG",
		"00:0c:26:8e:1b:d6": "Weintek Labs. Inc.",
	} {
		if got, ok := v.Lookup(mac(t, addr)); !ok || got != want {
			t.Errorf("Lookup(%s) = %q, %v; want %q", addr, got, ok, want)
		}
	}
}

func TestLongestPrefixAndOverride(t *testing.T) {
	v, err := Parse(strings.NewReader(`# test table
001122	Large Block Inc
0011223	Medium Block Ltd
001122334	Small Block GmbH
`))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		mac, want string
		ok        bool
	}{
		{"00:11:22:33:45:00", "Small Block GmbH", true}, // 36-bit match
		{"00:11:22:35:00:00", "Medium Block Ltd", true}, // 28-bit match
		{"00:11:22:f0:00:00", "Large Block Inc", true},  // 24-bit match only
		{"00:11:23:00:00:00", "", false},                // no match
		{"00:11:22:33:45", "", false},                   // not 6 bytes
	}
	for _, tt := range tests {
		m, _ := net.ParseMAC(tt.mac)
		if len(m) == 0 {
			m = net.HardwareAddr{0, 0x11, 0x22, 0x33, 0x45}
		}
		if got, ok := v.Lookup(m); got != tt.want || ok != tt.ok {
			t.Errorf("Lookup(%s) = %q, %v; want %q, %v", tt.mac, got, ok, tt.want, tt.ok)
		}
	}

	path := filepath.Join(t.TempDir(), "override.txt")
	if err := os.WriteFile(path, []byte("00:1B:1B Site PLC vendor\n02-42-AC-1F/24 Docker test network\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ov, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := ov.Lookup(mac(t, "00:1b:1b:12:34:56")); got != "Site PLC vendor" {
		t.Errorf("override not applied: %q", got)
	}
	if got, _ := ov.Lookup(mac(t, "02:42:ac:1f:fa:0a")); got != "Docker test network" {
		t.Errorf("override with explicit length: %q", got)
	}
	if base, _ := Embedded(); func() string { s, _ := base.Lookup(mac(t, "00:1b:1b:12:34:56")); return s }() != "Siemens AG" {
		t.Error("override modified the embedded table")
	}
}

func TestParseErrors(t *testing.T) {
	for _, in := range []string{"zzzzzz Name", "001122", "0011 Two Bytes", "001122/20 Bad Length", "001122/x Name"} {
		if _, err := Parse(strings.NewReader(in)); err == nil {
			t.Errorf("Parse(%q) accepted", in)
		}
	}
}

func TestMACFlags(t *testing.T) {
	tests := []struct {
		mac          string
		unicast, laa bool
	}{
		{"00:1b:1b:12:34:56", true, false},
		{"02:42:ac:1f:fa:0a", true, true},
		{"ff:ff:ff:ff:ff:ff", false, true},
		{"01:00:5e:00:00:fb", false, false},
		{"00:00:00:00:00:00", false, false},
	}
	for _, tt := range tests {
		m := mac(t, tt.mac)
		if UnicastMAC(m) != tt.unicast || LocallyAdministered(m) != tt.laa {
			t.Errorf("%s: unicast=%v laa=%v", tt.mac, UnicastMAC(m), LocallyAdministered(m))
		}
	}
}

// registry reads the committed readable registry (data/oui/oui.tsv.gz).
func registry(t *testing.T) map[string]string {
	t.Helper()
	f, err := os.Open("../../data/oui/oui.tsv.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	entries := map[string]string{}
	sc := bufio.NewScanner(zr)
	for sc.Scan() {
		if prefix, name, ok := strings.Cut(sc.Text(), "\t"); ok && !strings.HasPrefix(prefix, "#") {
			entries[prefix] = name
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return entries
}

// The embedded table is the committed registry, encoded: `make oui` keeps
// them in step, and every lookup answers as parsing the registry did.
func TestEmbeddedMatchesRegistry(t *testing.T) {
	entries := registry(t)
	want, err := ouitable.Encode(entries)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want, oui.Data) {
		t.Fatal("data/oui/oui.bin is not data/oui/oui.tsv.gz encoded: run make oui (or go run ./data/oui/gen -from-tsv data/oui/oui.tsv.gz)")
	}
	var text strings.Builder
	for prefix, name := range entries {
		fmt.Fprintf(&text, "%s\t%s\n", prefix, name)
	}
	parsed, err := Parse(strings.NewReader(text.String()))
	if err != nil {
		t.Fatal(err)
	}
	table, err := Embedded()
	if err != nil {
		t.Fatal(err)
	}
	if table.Len() != parsed.Len() || table.Len() != len(entries) {
		t.Fatalf("Len = %d, parsed %d, registry %d", table.Len(), parsed.Len(), len(entries))
	}
	agree := func(m net.HardwareAddr) {
		t.Helper()
		got, gok := table.Lookup(m)
		want, wok := parsed.Lookup(m)
		if got != want || gok != wok {
			t.Fatalf("Lookup(%s) = %q, %v; parsing gives %q, %v", m, got, gok, want, wok)
		}
	}
	for prefix := range entries {
		digits := prefix + strings.Repeat("0", 12-len(prefix))
		var m net.HardwareAddr
		for i := 0; i < 12; i += 2 {
			b, _ := strconv.ParseUint(digits[i:i+2], 16, 8)
			m = append(m, byte(b))
		}
		agree(m)
		m[5] ^= 0xff // elsewhere in the block
		agree(m)
	}
	rnd := rand.New(rand.NewPCG(1, 2))
	for range 200000 {
		m := make(net.HardwareAddr, 6)
		v := rnd.Uint64()
		for i := range m {
			m[i] = byte(v >> (8 * i))
		}
		agree(m)
	}
}

// Start-up no longer parses the registry: getting the embedded table
// allocates (almost) nothing.
func TestEmbeddedIsNotParsed(t *testing.T) {
	if _, err := Embedded(); err != nil {
		t.Fatal(err)
	}
	if n := testing.AllocsPerRun(10, func() { _, _ = Embedded() }); n != 0 {
		t.Errorf("Embedded allocates %v times per call", n)
	}
	v, _ := Embedded()
	if n := testing.AllocsPerRun(100, func() { _, _ = v.Lookup(net.HardwareAddr{0, 0x1b, 0x1b, 1, 2, 3}) }); n > 1 {
		t.Errorf("Lookup allocates %v times", n)
	}
}
