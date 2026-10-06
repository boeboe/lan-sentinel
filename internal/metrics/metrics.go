// Package metrics writes Prometheus metrics in the text exposition format
// (docs/ARCHITECTURE.md §3). Values are gathered at scrape time by the
// daemon. Labels are low-cardinality only: never a MAC, IP, hostname or host
// ID (CLAUDE.md rule 9), which AllowedLabels enforces.
package metrics

import (
	"fmt"
	"io"
	"math"
	"net/http"
	"slices"
	"strconv"
	"strings"
)

// Prefix starts every metric name.
const Prefix = "lan_sentinel_"

// AllowedLabels are the only label names a metric may use.
var AllowedLabels = []string{"interface", "presence", "type", "source", "protocol", "port", "result", "reason", "collector", "status"}

// Metric types.
const (
	Counter = "counter"
	Gauge   = "gauge"
)

// Family is one metric with its samples.
type Family struct {
	Name    string
	Help    string
	Type    string
	Samples []Sample
}

// Sample is one labelled value.
type Sample struct {
	Labels []Label
	Value  float64
}

// Label is a label name and value.
type Label struct{ Name, Value string }

// L builds labels from name/value pairs.
func L(pairs ...string) []Label {
	out := make([]Label, 0, len(pairs)/2)
	for i := 0; i+1 < len(pairs); i += 2 {
		out = append(out, Label{pairs[i], pairs[i+1]})
	}
	return out
}

// Validate checks names, types and labels.
func Validate(f Family) error {
	if !strings.HasPrefix(f.Name, Prefix) || strings.ContainsFunc(f.Name, func(r rune) bool {
		return r != '_' && (r < 'a' || r > 'z') && (r < '0' || r > '9')
	}) {
		return fmt.Errorf("metric %q: name must be %s followed by [a-z0-9_]", f.Name, Prefix)
	}
	if f.Type != Counter && f.Type != Gauge {
		return fmt.Errorf("metric %s: unknown type %q", f.Name, f.Type)
	}
	for _, s := range f.Samples {
		for _, l := range s.Labels {
			if !slices.Contains(AllowedLabels, l.Name) {
				return fmt.Errorf("metric %s: label %q is not allowed (high cardinality)", f.Name, l.Name)
			}
		}
	}
	return nil
}

// Write writes families in the text exposition format. Families that fail
// Validate are skipped and reported in the returned error after the rest is
// written.
func Write(w io.Writer, fams []Family) error {
	var bw strings.Builder
	var bad []string
	for _, f := range fams {
		if err := Validate(f); err != nil {
			bad = append(bad, err.Error())
			continue
		}
		fmt.Fprintf(&bw, "# HELP %s %s\n# TYPE %s %s\n", f.Name, escapeHelp(f.Help), f.Name, f.Type)
		for _, s := range f.Samples {
			bw.WriteString(f.Name)
			if len(s.Labels) > 0 {
				bw.WriteByte('{')
				for i, l := range s.Labels {
					if i > 0 {
						bw.WriteByte(',')
					}
					fmt.Fprintf(&bw, "%s=\"%s\"", l.Name, escapeValue(l.Value))
				}
				bw.WriteByte('}')
			}
			bw.WriteByte(' ')
			bw.WriteString(formatValue(s.Value))
			bw.WriteByte('\n')
		}
	}
	if _, err := io.WriteString(w, bw.String()); err != nil {
		return fmt.Errorf("write metrics: %w", err)
	}
	if len(bad) > 0 {
		return fmt.Errorf("invalid metrics: %s", strings.Join(bad, "; "))
	}
	return nil
}

func escapeHelp(s string) string {
	return strings.NewReplacer(`\`, `\\`, "\n", `\n`).Replace(s)
}

func escapeValue(s string) string {
	return strings.NewReplacer(`\`, `\\`, "\n", `\n`, `"`, `\"`).Replace(s)
}

func formatValue(v float64) string {
	switch {
	case math.IsInf(v, 1):
		return "+Inf"
	case math.IsInf(v, -1):
		return "-Inf"
	case math.IsNaN(v):
		return "NaN"
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}

// Handler serves the families gather returns at every scrape.
func Handler(gather func(*http.Request) []Family) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_ = Write(w, gather(r))
	})
}
