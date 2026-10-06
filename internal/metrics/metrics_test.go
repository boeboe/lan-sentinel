package metrics

import (
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWrite(t *testing.T) {
	var b strings.Builder
	err := Write(&b, []Family{
		{Name: "lan_sentinel_hosts", Help: "Hosts by presence.\nSecond line", Type: Gauge, Samples: []Sample{
			{Labels: L("interface", "eth1", "presence", "ACTIVE"), Value: 3},
			{Labels: L("interface", `we"ird\`, "presence", "MISSING"), Value: 0},
		}},
		{Name: "lan_sentinel_bus_dropped_total", Help: "Dropped.", Type: Counter, Samples: []Sample{{Value: 1.5}}},
		{Name: "lan_sentinel_special", Help: "x", Type: Gauge, Samples: []Sample{{Value: math.Inf(1)}, {Value: math.Inf(-1)}, {Value: math.NaN()}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `# HELP lan_sentinel_hosts Hosts by presence.\nSecond line
# TYPE lan_sentinel_hosts gauge
lan_sentinel_hosts{interface="eth1",presence="ACTIVE"} 3
lan_sentinel_hosts{interface="we\"ird\\",presence="MISSING"} 0
# HELP lan_sentinel_bus_dropped_total Dropped.
# TYPE lan_sentinel_bus_dropped_total counter
lan_sentinel_bus_dropped_total 1.5
# HELP lan_sentinel_special x
# TYPE lan_sentinel_special gauge
lan_sentinel_special +Inf
lan_sentinel_special -Inf
lan_sentinel_special NaN
`
	if b.String() != want {
		t.Errorf("got:\n%s\nwant:\n%s", b.String(), want)
	}
}

// High-cardinality labels and bad names are refused (CLAUDE.md rule 9).
func TestValidateRefusesHighCardinality(t *testing.T) {
	for _, f := range []Family{
		{Name: "lan_sentinel_x", Type: Gauge, Samples: []Sample{{Labels: L("mac", "00:1b:1b:00:00:01")}}},
		{Name: "lan_sentinel_x", Type: Gauge, Samples: []Sample{{Labels: L("ip", "10.0.0.1")}}},
		{Name: "lan_sentinel_x", Type: Gauge, Samples: []Sample{{Labels: L("host_id", "x")}}},
		{Name: "lan_sentinel_x", Type: Gauge, Samples: []Sample{{Labels: L("hostname", "plc")}}},
		{Name: "other_metric", Type: Gauge},
		{Name: "lan_sentinel_Bad", Type: Gauge},
		{Name: "lan_sentinel_x", Type: "histogram"},
	} {
		if Validate(f) == nil {
			t.Errorf("accepted %+v", f)
		}
	}
	var b strings.Builder
	err := Write(&b, []Family{{Name: "lan_sentinel_ok", Type: Gauge, Samples: []Sample{{Value: 1}}},
		{Name: "lan_sentinel_x", Type: Gauge, Samples: []Sample{{Labels: L("mac", "x")}}}})
	if err == nil || !strings.Contains(b.String(), "lan_sentinel_ok 1") || strings.Contains(b.String(), "mac=") {
		t.Errorf("write with an invalid family: %v\n%s", err, b.String())
	}
}

func TestHandler(t *testing.T) {
	h := Handler(func(*http.Request) []Family {
		return []Family{{Name: "lan_sentinel_up", Help: "Up.", Type: Gauge, Samples: []Sample{{Value: 1}}}}
	})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain; version=0.0.4") || !strings.Contains(rec.Body.String(), "lan_sentinel_up 1") {
		t.Errorf("response %q: %s", ct, rec.Body.String())
	}
}
