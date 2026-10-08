package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"lan-sentinel/internal/api"
	"lan-sentinel/internal/platform"
	"lan-sentinel/internal/probe/scheduler"
	"lan-sentinel/internal/store"
)

func (a *app) daemonStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "status",
		Short:   "Daemon health, interfaces and per-interface collector state",
		Example: "  sudo lan-sentinel daemon status",
		Long: "Exit 0 when healthy, 1 when degraded (a configured collector is not running),\n" +
			"2 when unhealthy (the database does not answer), 3 when the daemon is\n" +
			"unreachable. --quiet prints nothing.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := onlyFormats(a.g.output, "table", "json"); err != nil {
				return err
			}
			if a.g.offline {
				return failf(ExitUsage, "%s needs the running daemon; it does not work with --offline", cmd.CommandPath())
			}
			st, err := a.client().Status(cmd.Context())
			if err != nil {
				return a.failed(err)
			}
			if a.g.output == "json" {
				if err := writeJSON(a.output(), st); err != nil {
					return err
				}
			} else {
				a.statusText(a.output(), st)
			}
			switch st.State {
			case api.StateOK:
				return nil
			case api.StateDegraded:
				return silent(ExitDegraded)
			}
			return silent(ExitError)
		},
	}
}

func (a *app) statusText(w io.Writer, st api.Status) {
	mode := ""
	if st.Replay {
		mode = "   replay"
	}
	fmt.Fprintf(w, "Version:    %s (%s)   PID %d   up %s%s\n", st.Version, st.Platform, st.PID, uptime(st.Now.Sub(st.Started)), mode)
	db := "ok"
	if !st.Database.OK {
		db = "FAILED: " + st.Database.Error
	}
	fmt.Fprintf(w, "Database:   %s  %s  %s\n", st.Database.Path, db, humanBytes(st.Database.Size+st.Database.WALSize))
	active := "enabled"
	if st.Active.Disabled {
		active = "DISABLED"
		if st.Active.Forced {
			active += " (" + "LAN_SENTINEL_ACTIVE_DISABLED=1)"
		} else if st.Active.Reason != "" {
			active += " (" + st.Active.Reason + ")"
		}
	}
	fmt.Fprintf(w, "Active:     %s\n", active)
	clock := string(st.Clock)
	switch st.Clock {
	case platform.ClockUnsynced:
		clock += " (events are marked until the clock is synchronised)"
	case "":
		clock = string(platform.ClockUnknown)
	}
	fmt.Fprintf(w, "Clock:      %s\n", clock)
	last := "never"
	if ls := st.LastScan; ls != nil {
		last = fmt.Sprintf("%s  %s  %s (%s)", a.stamp(ls.Started), ls.Interface, ls.Kind, ls.Trigger)
		if ls.Finished == nil {
			last += "  running"
		}
	}
	fmt.Fprintf(w, "Last scan:  %s\n", last)
	fmt.Fprintln(w, "Interfaces:")
	for _, i := range st.Interfaces {
		fmt.Fprintf(w, "  %-6s %-7s %s\n", i.Name, i.State, strings.Join(i.Prefixes, " "))
		if counts := st.Hosts[i.Name]; len(counts) > 0 {
			var parts []string
			for _, p := range []string{"ACTIVE", "RECENT", "STALE", "MISSING"} {
				if counts[p] > 0 {
					parts = append(parts, fmt.Sprintf("%d %s", counts[p], strings.ToLower(p)))
				}
			}
			fmt.Fprintf(w, "         hosts      %s\n", strings.Join(parts, ", "))
		}
		for _, c := range i.Collectors {
			detail := c.Backend
			if c.Error != "" {
				detail = c.Error
			} else if p := c.LastPass; p != nil {
				detail = fmt.Sprintf("%-11s %s", detail, a.lastPass(c.Collector, *p))
			}
			fmt.Fprintf(w, "         %-10s %-11s %s\n", c.Collector, c.State, strings.TrimRight(detail, " "))
		}
	}
	fmt.Fprintf(w, "State:      %s\n", strings.ToUpper(st.State))
	for _, p := range st.Problems {
		fmt.Fprintf(w, "  - %s\n", p)
	}
}

func humanBytes(n int64) string {
	switch {
	case n >= 1e9:
		return fmt.Sprintf("%.1f GB", float64(n)/1e9)
	case n >= 1e6:
		return fmt.Sprintf("%.0f MB", float64(n)/1e6)
	case n >= 1e3:
		return fmt.Sprintf("%.0f KB", float64(n)/1e3)
	}
	return fmt.Sprintf("%d B", n)
}

func (a *app) watchCmd() *cobra.Command {
	var iface string
	var types []string
	var port int
	c := &cobra.Command{
		Use:     "watch",
		Short:   "Live event stream (Ctrl-C to stop)",
		Example: "  sudo lan-sentinel watch --interface eth0",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := onlyFormats(a.g.output, "table", "jsonl", "json"); err != nil {
				return err
			}
			if a.g.offline {
				return failf(ExitUsage, "%s needs the running daemon; it does not work with --offline", cmd.CommandPath())
			}
			ts, err := eventTypes(types)
			if err != nil {
				return err
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			w := a.output()
			err = a.client().Stream(ctx, iface, ts, port, func(e store.Event) error {
				if a.g.output != "table" {
					return writeJSONL(w, []store.Event{e})
				}
				_, err := fmt.Fprintf(w, "%s  %-22s %-6s %s  %s\n", a.clockTime(e.TS), e.Type, dash(e.Interface), eventValue(e), e.MAC)
				return err
			})
			return a.failed(err)
		},
	}
	fl := c.Flags()
	fl.StringVar(&iface, "interface", "", "only this interface")
	fl.StringSliceVar(&types, "type", nil, "only these event types (repeatable)")
	fl.IntVar(&port, "port", 0, "only service events of this port")
	return c
}

func (a *app) dbCmd() *cobra.Command {
	c := &cobra.Command{Use: "db", Short: "Inspect the database"}
	c.AddCommand(&cobra.Command{
		Use:     "info",
		Short:   "Path, schema version, journal mode, size, WAL size, row counts",
		Example: "  sudo lan-sentinel db info",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := onlyFormats(a.g.output, "table", "json"); err != nil {
				return err
			}
			return a.run(cmd, false, func(ctx context.Context, b backend) error {
				info, err := b.DBInfo(ctx)
				if err != nil {
					return err
				}
				w := a.output()
				if a.g.output == "json" {
					return writeJSON(w, info)
				}
				fmt.Fprintf(w, "Path:      %s\nSchema:    %d\nJournal:   %s\nSize:      %s (data %s)\nWAL:       %s\n\n",
					info.Path, info.SchemaVersion, info.JournalMode, humanBytes(info.Size), humanBytes(info.UsedSize), humanBytes(info.WALSize))
				tables := make([]string, 0, len(info.Rows))
				for t := range info.Rows {
					tables = append(tables, t)
				}
				sort.Strings(tables)
				rows := make([][]string, 0, len(tables))
				for _, t := range tables {
					rows = append(rows, []string{t, fmt.Sprint(info.Rows[t])})
				}
				return writeTable(w, []string{"TABLE", "ROWS"}, rows)
			})
		},
	}, &cobra.Command{
		Use:     "check",
		Short:   "SQLite integrity check (exit 2 if it fails)",
		Example: "  sudo lan-sentinel db check",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := onlyFormats(a.g.output, "table", "json"); err != nil {
				return err
			}
			return a.run(cmd, false, func(ctx context.Context, b backend) error {
				res, err := b.DBCheck(ctx)
				if err != nil {
					return err
				}
				w := a.output()
				if a.g.output == "json" {
					err = writeJSON(w, res)
				} else if res.OK {
					fmt.Fprintln(w, "ok")
				} else {
					fmt.Fprintln(w, "integrity check failed:")
					for _, p := range res.Problems {
						fmt.Fprintln(w, "  "+p)
					}
				}
				if err == nil && !res.OK {
					return silent(ExitError)
				}
				return err
			})
		},
	})
	return c
}

// lastPass describes a probe's last periodic pass: "last pass 2m ago: 253
// swept, 14 replied (26 s)".
func (a *app) lastPass(collector string, p scheduler.PassSummary) string {
	verb := "probed"
	if collector == platform.CollectorARP {
		verb = "swept"
	}
	s := fmt.Sprintf("last pass %s: %d %s, %d replied", a.ago(p.At), p.Probed, verb, p.Replied)
	if p.Blocked > 0 {
		s += fmt.Sprintf(", %d blocked", p.Blocked)
	}
	took := fmt.Sprintf("%.0f s", p.Seconds)
	if p.Seconds >= 120 {
		took = fmt.Sprintf("%.0f min", p.Seconds/60)
	}
	s += " (" + took
	if !p.Complete {
		s += ", cut short"
	}
	return s + ")"
}
