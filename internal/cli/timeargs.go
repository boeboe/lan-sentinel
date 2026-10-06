package cli

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Time arguments (docs/CLI.md §4): --since and --seen-within take a
// duration (24h, 7d, 90m) counted back from now or a timestamp; --at and
// --until take YYYY-MM-DD, YYYY-MM-DD HH:MM[:SS] (local time) or RFC 3339.

var localLayouts = []string{"2006-01-02 15:04:05", "2006-01-02 15:04", "2006-01-02T15:04:05", "2006-01-02T15:04", "2006-01-02"}

// parseTimestamp parses an absolute time.
func parseTimestamp(s string, loc *time.Location) (time.Time, error) {
	s = strings.TrimSpace(s)
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, nil
	}
	for _, layout := range localLayouts {
		if t, err := time.ParseInLocation(layout, s, loc); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid time %q: use YYYY-MM-DD, YYYY-MM-DD HH:MM[:SS] or RFC 3339", s)
}

// parseAgo parses a duration back from now (with a "d" unit for days) or
// an absolute time.
func parseAgo(s string, now time.Time, loc *time.Location) (time.Time, error) {
	if d, err := parseDuration(s); err == nil {
		return now.Add(-d), nil
	}
	if t, err := parseTimestamp(s, loc); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("invalid time %q: use a duration (24h, 7d) or a timestamp", s)
}

// parseDuration is time.ParseDuration plus whole days ("7d").
func parseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil || n < 0 {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d < 0 {
		return 0, fmt.Errorf("invalid duration %q", s)
	}
	return d, nil
}

// timeFlags parses the time flags of a command, reporting usage errors.
type timeFlags struct {
	a   *app
	err error
}

func (t *timeFlags) ago(name, v string) time.Time {
	if v == "" || t.err != nil {
		return time.Time{}
	}
	ts, err := parseAgo(v, t.a.env.now(), t.a.env.loc())
	if err != nil {
		t.err = failf(ExitUsage, "--%s: %v", name, err)
	}
	return ts
}

func (t *timeFlags) at(name, v string) time.Time {
	if v == "" || t.err != nil {
		return time.Time{}
	}
	ts, err := parseTimestamp(v, t.a.env.loc())
	if err != nil {
		t.err = failf(ExitUsage, "--%s: %v", name, err)
	}
	return ts
}

// formatting of times in tables: local time, and ages relative to now.

func (a *app) stamp(t time.Time) string { return t.In(a.env.loc()).Format("2006-01-02 15:04:05") }

func (a *app) clockTime(t time.Time) string { return t.In(a.env.loc()).Format("15:04:05") }

// ago renders how long before now t was: "12s ago", "14m ago", "3h ago",
// "12d ago".
func (a *app) ago(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := a.env.now().Sub(t)
	switch {
	case d < 0:
		return "in the future"
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

// uptime renders a duration as "3d 4h", "2h 5m" or "45s".
func uptime(d time.Duration) string {
	switch {
	case d >= 24*time.Hour:
		return fmt.Sprintf("%dd %dh", int(d.Hours())/24, int(d.Hours())%24)
	case d >= time.Hour:
		return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
	case d >= time.Minute:
		return fmt.Sprintf("%dm %ds", int(d.Minutes()), int(d.Seconds())%60)
	default:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
}
