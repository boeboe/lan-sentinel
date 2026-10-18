package api

import (
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"lan-sentinel/internal/store"
)

// Every HostFilter field travels from the client to the server, so online
// reads filter as --offline ones do (AGENTS.md §6). A new field fails here
// until both sides carry it.
func TestHostFilterRoundTrip(t *testing.T) {
	for _, live := range []bool{true, false} {
		var want store.HostFilter
		v := reflect.ValueOf(&want).Elem()
		for i := range v.NumField() {
			switch f := v.Field(i); f.Kind() {
			case reflect.String:
				f.SetString("x" + v.Type().Field(i).Name)
			case reflect.Int:
				f.SetInt(502)
			case reflect.Bool: // Live and NotLive are one parameter
			default:
				if f.Type() != reflect.TypeOf(time.Time{}) {
					t.Fatalf("field %s of kind %s: extend this test", v.Type().Field(i).Name, f.Kind())
				}
				f.Set(reflect.ValueOf(time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)))
			}
		}
		want.QueryKind = store.KindIP
		want.Live, want.NotLive = live, !live

		r := httptest.NewRequest("GET", "/v1/hosts?"+hostQuery(want).Encode(), nil)
		p := &params{r: r}
		got := hostFilter(p)
		if p.err != nil {
			t.Fatal(p.err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("round trip:\n got %+v\nwant %+v", got, want)
		}
	}
}
