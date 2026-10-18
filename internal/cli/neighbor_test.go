package cli

import (
	"testing"

	"lan-sentinel/internal/store"
)

// interfaces list shows the first LLDP/CDP neighbour, by name and port,
// and counts the others.
func TestNeighborText(t *testing.T) {
	tests := []struct {
		ns   []store.Neighbor
		want string
	}{
		{nil, "-"},
		{[]store.Neighbor{{Name: "plant-sw-01", Port: "ge-0/0/23"}}, "plant-sw-01 ge-0/0/23"},
		{[]store.Neighbor{{MAC: "00:1e:c9:00:00:01"}}, "00:1e:c9:00:00:01"},
		{[]store.Neighbor{{Name: "a", Port: "1"}, {Name: "b"}, {Name: "c"}}, "a 1 (+2)"},
	}
	for _, tt := range tests {
		if got := neighborText(tt.ns); got != tt.want {
			t.Errorf("neighborText(%+v) = %q, want %q", tt.ns, got, tt.want)
		}
	}
}
