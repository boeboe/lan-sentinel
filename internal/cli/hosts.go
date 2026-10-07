package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"lan-sentinel/internal/store"
)

func (a *app) hostsCmd() *cobra.Command {
	c := &cobra.Command{Use: "hosts", Short: "Query the host inventory and its history"}
	c.AddCommand(a.hostsListCmd(), a.hostsShowCmd(), a.hostsFindCmd(), a.hostsHistoryCmd(), a.hostsEvidenceCmd(),
		a.hostsSetCmd(), a.hostsUnsetCmd())
	return c
}

// queryFlags are the explicit query kinds that override auto-detection.
type queryFlags struct{ ip, mac, hostname, id string }

func (q *queryFlags) add(c *cobra.Command) {
	f := c.Flags()
	f.StringVar(&q.ip, "ip", "", "query an IP address")
	f.StringVar(&q.mac, "mac", "", "query a MAC address")
	f.StringVar(&q.hostname, "hostname", "", "query a hostname (even one that looks like an address)")
	f.StringVar(&q.id, "id", "", "query a host ID")
}

// resolve returns the query from the argument or exactly one kind flag.
func (q queryFlags) resolve(args []string) (string, store.QueryKind, error) {
	var text string
	var kind store.QueryKind
	n := 0
	for _, f := range []struct {
		v string
		k store.QueryKind
	}{{q.ip, store.KindIP}, {q.mac, store.KindMAC}, {q.hostname, store.KindName}, {q.id, store.KindHost}} {
		if f.v != "" {
			text, kind = f.v, f.k
			n++
		}
	}
	if len(args) == 1 {
		text = args[0]
		n++
	}
	if n != 1 {
		return "", "", failf(ExitUsage, "give one query: an argument (host ID, MAC, IP or hostname) or one of --ip, --mac, --hostname, --id")
	}
	return text, kind, nil
}

func (a *app) hostsListCmd() *cobra.Command {
	var iface, vendor, device, description, seen string
	var active, stale bool
	var port int
	c := &cobra.Command{
		Use:   "list",
		Short: "Inventory: MAC, IP, hostname, vendor, device type, interface, presence, last seen, description",
		Long: "List hosts. --active shows live hosts (ACTIVE or RECENT), --stale the others\n" +
			"(STALE or MISSING); --port hosts with that port OPEN; --device hosts whose\n" +
			"device type (the most confident identification) contains the text;\n" +
			"--description hosts whose description contains it.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			tf := &timeFlags{a: a}
			f := store.HostFilter{Interface: iface, Live: active, NotLive: stale, Vendor: vendor, Device: device, Description: description, Port: port, SeenSince: tf.ago("seen-within", seen)}
			if tf.err != nil {
				return tf.err
			}
			return a.run(cmd, false, func(ctx context.Context, b backend) error {
				hosts, err := b.Hosts(ctx, f)
				if err != nil {
					return err
				}
				return a.hostsTable(hosts)
			})
		},
	}
	fl := c.Flags()
	fl.StringVar(&iface, "interface", "", "only this interface")
	fl.BoolVar(&active, "active", false, "only live hosts (ACTIVE or RECENT)")
	fl.BoolVar(&stale, "stale", false, "only hosts that are not live (STALE or MISSING)")
	fl.StringVar(&vendor, "vendor", "", "vendor or manufacturer contains this text")
	fl.StringVar(&device, "device", "", "device type contains this text (e.g. printer, plc)")
	fl.StringVar(&description, "description", "", "the description contains this text")
	fl.IntVar(&port, "port", 0, "an OPEN service on this port")
	fl.StringVar(&seen, "seen-within", "", "last seen within this duration (24h, 7d) or since this time")
	return c
}

func vendorOf(h store.HostSummary) string {
	if h.Manufacturer != "" {
		return h.Manufacturer
	}
	return h.Vendor
}

func (a *app) hostsTable(hosts []store.HostSummary) error {
	w := a.output()
	switch a.g.output {
	case "json":
		return writeJSON(w, hosts)
	case "jsonl":
		return writeJSONL(w, hosts)
	}
	header := []string{"MAC", "IP", "HOSTNAME", "VENDOR", "DEVICE", "IFACE", "STATE", "LAST SEEN", "DESCRIPTION"}
	rows := make([][]string, 0, len(hosts))
	for _, h := range hosts {
		if a.g.output == "csv" {
			rows = append(rows, []string{h.MAC, strings.Join(h.IPs, " "), h.PreferredName, vendorOf(h), h.DeviceType, h.Interface, h.Presence,
				h.LastSeen.UTC().Format(time.RFC3339), h.Description})
			continue
		}
		ip := "-"
		if len(h.IPs) > 0 {
			ip = h.IPs[0]
			if len(h.IPs) > 1 {
				ip += fmt.Sprintf(" (+%d)", len(h.IPs)-1)
			}
		}
		rows = append(rows, []string{h.MAC, ip, dash(h.PreferredName), dash(vendorOf(h)), dash(h.DeviceType), h.Interface, h.Presence, a.ago(h.LastSeen),
			h.Description})
	}
	if a.g.output == "csv" {
		return writeCSV(w, header, rows)
	}
	return writeTable(w, header, rows)
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func (a *app) hostsShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <host-id>",
		Short: "Full record of one host, with every address and name over time",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := onlyFormats(a.g.output, "table", "json"); err != nil {
				return err
			}
			return a.run(cmd, false, func(ctx context.Context, b backend) error {
				h, err := b.Host(ctx, args[0])
				if err != nil {
					return err
				}
				if a.g.output == "json" {
					return writeJSON(a.output(), h)
				}
				a.hostRecord(a.output(), h, nil)
				return nil
			})
		},
	}
}

// hostRecord prints a host as in docs/CLI.md §5; at marks the bindings
// unconfirmed at that time.
func (a *app) hostRecord(w io.Writer, h store.Host, at *time.Time) {
	mac := h.MAC
	if v := vendorOf(h.HostSummary); v != "" {
		mac += "  " + v
	}
	if h.LocallyAdministered {
		mac += "  (locally administered)"
	}
	fmt.Fprintf(w, "Host ID:     %s\nInterface:   %s\nMAC:         %s\nState:       %s\n", h.HostID, h.Interface, mac, h.Presence)
	if h.PreferredName != "" {
		fmt.Fprintf(w, "Name:        %s\n", h.PreferredName)
	}
	if h.DeviceType != "" {
		fmt.Fprintf(w, "Device:      %s\n", h.DeviceType)
	}
	if h.Description != "" {
		fmt.Fprintf(w, "Description: %s\n", h.Description)
	}
	fmt.Fprintf(w, "First seen:  %s\nLast seen:   %s\n", a.stamp(h.FirstSeen), a.stamp(h.LastSeen))
	if len(h.Addresses) > 0 {
		fmt.Fprintln(w, "\nAddresses:")
		for _, b := range h.Addresses {
			fmt.Fprintf(w, "  %s\n", a.bindingLine(b, at))
		}
	}
	if len(h.Names) > 0 {
		fmt.Fprintln(w, "\nNames:")
		for _, n := range h.Names {
			line := fmt.Sprintf("  %-16s %-8s confirmed %s", n.Name, n.Type, a.ago(n.LastSeen))
			if n.Stale {
				line += " (stale)"
			}
			if n.EndedAt != nil {
				line += "  replaced " + a.stamp(*n.EndedAt)
			}
			fmt.Fprintln(w, line)
		}
	}
	if len(h.Services) > 0 {
		fmt.Fprintln(w, "\nServices:")
		for _, s := range h.Services {
			fmt.Fprintf(w, "  %-8s %-11s %s\n", s.Proto+"/"+strconv.Itoa(s.Port), s.State, a.ago(s.LastResultAt))
		}
	}
	// The current claims, most confident first; hosts evidence has them all.
	var current []store.Identification
	for _, i := range h.Identifications {
		if i.Current {
			current = append(current, i)
		}
	}
	sort.SliceStable(current, func(x, y int) bool {
		if current[x].Field != current[y].Field {
			return current[x].Field < current[y].Field
		}
		return current[x].Confidence > current[y].Confidence
	})
	if len(current) > 0 {
		fmt.Fprintln(w, "\nIdentification:")
		for _, i := range current {
			fmt.Fprintf(w, "  %s=%s  %s  confidence %.2f\n", i.Field, i.Value, i.Source, i.Confidence)
		}
	}
}

// bindingLine renders "IP  first → end|open  sources: …  CONFLICT".
func (a *app) bindingLine(b store.Binding, at *time.Time) string {
	end := "open"
	if b.EndedAt != nil {
		end = a.stamp(*b.EndedAt)
	}
	line := fmt.Sprintf("%-16s %s → %s", b.IP, a.stamp(b.FirstSeen), end)
	if len(b.Sources) > 0 {
		var src []string
		for _, s := range b.Sources {
			src = append(src, s.Source)
		}
		line += "   sources: " + strings.Join(src, ", ")
	}
	if b.Conflict {
		line += "   CONFLICT"
	}
	if at != nil && at.After(b.LastSeen) {
		line += fmt.Sprintf("   (unconfirmed since %s)", a.stamp(b.LastSeen))
	}
	return line
}

func (a *app) hostsFindCmd() *cobra.Command {
	var q queryFlags
	var iface, atFlag string
	c := &cobra.Command{
		Use:   "find <query>",
		Short: "Current or point-in-time holder(s) with addresses, names and services",
		Long: "Find hosts by host ID, MAC, IP or hostname (detected in that order). With --at,\n" +
			"answer for that time: the holder of an IP with its binding and what replaced it,\n" +
			"every holder of a duplicate IP, or the bindings before and after when nobody\n" +
			"held it. Exit 1 when nothing matches.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := onlyFormats(a.g.output, "table", "json"); err != nil {
				return err
			}
			text, kind, err := q.resolve(args)
			if err != nil {
				return err
			}
			tf := &timeFlags{a: a}
			fq := store.FindQuery{Query: text, Kind: kind, Interface: iface}
			if t := tf.at("at", atFlag); !t.IsZero() {
				fq.At = &t
			}
			if tf.err != nil {
				return tf.err
			}
			return a.run(cmd, false, func(ctx context.Context, b backend) error {
				res, err := b.Find(ctx, fq)
				if err != nil {
					return err
				}
				if a.g.output == "json" {
					err = writeJSON(a.output(), res)
				} else {
					a.findResult(a.output(), res)
				}
				if err == nil && len(res.Hosts) == 0 {
					return silent(ExitDegraded)
				}
				return err
			})
		},
	}
	q.add(c)
	c.Flags().StringVar(&iface, "interface", "", "only this interface")
	c.Flags().StringVar(&atFlag, "at", "", "answer for this time (YYYY-MM-DD[ HH:MM[:SS]] local, or RFC 3339)")
	return c
}

func (a *app) findResult(w io.Writer, res store.FindResult) {
	if len(res.Hosts) == 0 {
		when := "now"
		if res.At != nil {
			when = "at " + a.stamp(*res.At)
		}
		fmt.Fprintf(w, "No holder of %s %s.\n", res.Query, when)
		for _, p := range res.Previous {
			fmt.Fprintf(w, "Previous:    %s held by %s on %s until %s\n", p.Binding.IP, p.MAC, p.Interface, a.stamp(*p.Binding.EndedAt))
		}
		for _, n := range res.Next {
			fmt.Fprintf(w, "Next:        %s held by %s on %s from %s\n", n.Binding.IP, n.MAC, n.Interface, a.stamp(n.Binding.FirstSeen))
		}
		return
	}
	for i, h := range res.Hosts {
		if i > 0 {
			fmt.Fprintln(w)
		}
		if h.Binding == nil || res.At == nil {
			a.hostRecord(w, h.Host, res.At)
			continue
		}
		// An IP at a point in time: the holder and its binding.
		mac := h.MAC
		if v := vendorOf(h.HostSummary); v != "" {
			mac += "  " + v
		}
		fmt.Fprintf(w, "Host ID:     %s\nInterface:   %s\nMAC:         %s\n", h.HostID, h.Interface, mac)
		if h.PreferredName != "" {
			fmt.Fprintf(w, "Name:        %s\n", h.PreferredName)
		}
		if h.Description != "" {
			fmt.Fprintf(w, "Description: %s\n", h.Description)
		}
		b := *h.Binding
		b.Conflict = h.Conflict // in conflict at the time asked about
		fmt.Fprintf(w, "Binding:     %s\n", a.bindingLine(b, res.At))
		if h.ReplacedBy != nil {
			fmt.Fprintf(w, "Replaced by: %s → %s from %s\n", h.ReplacedBy.Binding.IP, h.ReplacedBy.MAC, a.stamp(h.ReplacedBy.Binding.FirstSeen))
		}
		if h.MovedTo != nil {
			fmt.Fprintf(w, "Moved to:    %s at %s\n", h.MovedTo.Binding.IP, a.stamp(h.MovedTo.Binding.FirstSeen))
		}
		if h.ConflictEvent != nil {
			e := h.ConflictEvent
			fmt.Fprintf(w, "Conflict:    %s %s %s between %s and %s\n", a.stamp(e.TS), e.Type, e.New, e.MAC, e.RelatedMAC)
		}
	}
}

func (a *app) hostsHistoryCmd() *cobra.Command {
	var q queryFlags
	var iface, since, until string
	c := &cobra.Command{
		Use:   "history <query>",
		Short: "Event timeline for a host, MAC, IP or name",
		Long: "For a host ID or MAC, every event of the host; for an IP, every event whose\n" +
			"old value, new value or evidence IP is that IP, across all its holders; for a\n" +
			"name, every event of the hosts that ever had it.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			text, kind, err := q.resolve(args)
			if err != nil {
				return err
			}
			tf := &timeFlags{a: a}
			hq := store.HistoryQuery{Query: text, Kind: kind, Interface: iface, Since: tf.ago("since", since), Until: tf.at("until", until)}
			if tf.err != nil {
				return tf.err
			}
			return a.run(cmd, false, func(ctx context.Context, b backend) error {
				evs, err := b.History(ctx, hq)
				if err != nil {
					return err
				}
				return a.eventsTable(evs)
			})
		},
	}
	q.add(c)
	fl := c.Flags()
	fl.StringVar(&iface, "interface", "", "only this interface")
	fl.StringVar(&since, "since", "", "from this time or duration ago (24h, 7d)")
	fl.StringVar(&until, "until", "", "up to this time")
	return c
}

// eventValue is the readable change of an event.
func eventValue(e store.Event) string {
	switch {
	case e.New != "" && e.New == e.MAC: // HOST_DISCOVERED: show the address
		return dash(e.EvidenceIP())
	case e.Old != "" && e.New != "":
		return e.Old + " -> " + e.New
	case e.New != "":
		return e.New
	}
	return dash(e.Old)
}

func (a *app) eventsTable(evs []store.Event) error {
	w := a.output()
	switch a.g.output {
	case "json":
		return writeJSON(w, evs)
	case "jsonl":
		return writeJSONL(w, evs)
	}
	header := []string{"TIME", "TYPE", "IFACE", "MAC", "VALUE", "RELATED", "CAUSE"}
	rows := make([][]string, 0, len(evs))
	marked := map[string]bool{}
	for _, e := range evs {
		row := []string{"", e.Type, dash(e.Interface), dash(e.MAC), eventValue(e), dash(e.RelatedMAC), e.Cause}
		if a.g.output == "csv" {
			row[0] = e.TS.UTC().Format(time.RFC3339Nano)
			row = append(row, e.ClockSync)
		} else {
			mark := clockMarks[e.ClockSync]
			row[0] = a.stamp(e.TS) + mark
			marked[mark] = marked[mark] || mark != ""
		}
		rows = append(rows, row)
	}
	if a.g.output == "csv" {
		return writeCSV(w, append(header, "CLOCK_SYNC"), rows)
	}
	if err := writeTable(w, header, rows); err != nil {
		return err
	}
	// Events written before the clock was synchronised (NFR-REL-2).
	if marked["*"] {
		fmt.Fprintln(w, "* written before the system clock was synchronised: the time may be off")
	}
	if marked["?"] {
		fmt.Fprintln(w, "? written while the clock's synchronisation was unknown")
	}
	return nil
}

// clockMarks flag event times by the clock's state when they were written.
var clockMarks = map[string]string{"unsynced": "*", "unknown": "?"}

func (a *app) hostsEvidenceCmd() *cobra.Command {
	var q queryFlags
	var iface, since string
	c := &cobra.Command{
		Use:   "evidence <query>",
		Short: "Why we believe what we believe about a host",
		Long: "For every host that ever matched the query: per address, name, service and\n" +
			"identification the sources that confirmed it with first and last seen, the\n" +
			"observation counts per source within roll-up retention, and the host's events\n" +
			"with their evidence snapshots.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := onlyFormats(a.g.output, "table", "json", "jsonl"); err != nil {
				return err
			}
			text, kind, err := q.resolve(args)
			if err != nil {
				return err
			}
			tf := &timeFlags{a: a}
			from := tf.ago("since", since)
			if tf.err != nil {
				return tf.err
			}
			return a.run(cmd, false, func(ctx context.Context, b backend) error {
				all, err := b.EvidenceFor(ctx, store.HostFilter{Query: text, QueryKind: kind, Interface: iface}, from)
				if err != nil {
					return err
				}
				switch a.g.output {
				case "json":
					err = writeJSON(a.output(), nonNilSlice(all))
				case "jsonl":
					err = writeJSONL(a.output(), all)
				default:
					a.evidenceTable(a.output(), all)
				}
				if err == nil && len(all) == 0 {
					return silent(ExitDegraded)
				}
				return err
			})
		},
	}
	q.add(c)
	c.Flags().StringVar(&iface, "interface", "", "only this interface")
	c.Flags().StringVar(&since, "since", "", "events and counts from this time or duration ago")
	return c
}

func nonNilSlice[T any](v []T) []T {
	if v == nil {
		return []T{}
	}
	return v
}

func (a *app) evidenceTable(w io.Writer, all []store.Evidence) {
	for i, ev := range all {
		if i > 0 {
			fmt.Fprintln(w, strings.Repeat("-", 72))
		}
		h := ev.Host
		fmt.Fprintf(w, "Host %s  %s  on %s\n", h.HostID, h.MAC, h.Interface)
		if len(h.Addresses) > 0 {
			fmt.Fprintln(w, "\nAddresses:")
			for _, b := range h.Addresses {
				fmt.Fprintf(w, "  %s\n", a.bindingLine(store.Binding{IP: b.IP, FirstSeen: b.FirstSeen, LastSeen: b.LastSeen, EndedAt: b.EndedAt, Conflict: b.Conflict}, nil))
				for _, s := range b.Sources {
					fmt.Fprintf(w, "      %-16s first %s  last %s\n", s.Source, a.stamp(s.FirstSeen), a.stamp(s.LastSeen))
				}
			}
		}
		if len(h.Names) > 0 {
			fmt.Fprintln(w, "\nNames:")
			for _, n := range h.Names {
				fmt.Fprintf(w, "  %-16s %-8s %-14s first %s  last %s\n", n.Name, n.Type, n.Source, a.stamp(n.FirstSeen), a.stamp(n.LastSeen))
			}
		}
		if len(h.Services) > 0 {
			fmt.Fprintln(w, "\nServices:")
			for _, s := range h.Services {
				fmt.Fprintf(w, "  %-8s %-11s first %s  last result %s\n", s.Proto+"/"+strconv.Itoa(s.Port), s.State, a.stamp(s.FirstSeen), a.stamp(s.LastResultAt))
			}
		}
		if len(h.Identifications) > 0 {
			fmt.Fprintln(w, "\nIdentification:")
			for _, id := range h.Identifications {
				mark := " "
				if id.Current {
					mark = "*"
				}
				fmt.Fprintf(w, " %s%s=%s  %s  confidence %.2f  %s\n", mark, id.Field, id.Value, id.Source, id.Confidence, compact(id.Evidence))
			}
			fmt.Fprintln(w, "  (* current: the value each source holds now)")
		}
		if len(ev.Counts) > 0 {
			fmt.Fprintln(w, "\nObservations (raw and roll-ups):")
			for _, c := range ev.Counts {
				fmt.Fprintf(w, "  %-16s %-16s %6d  first %s  last %s\n", c.Source, dash(c.IP), c.Count, a.stamp(c.FirstSeen), a.stamp(c.LastSeen))
			}
		}
		if len(ev.Events) > 0 {
			fmt.Fprintln(w, "\nEvents:")
			for _, e := range ev.Events {
				fmt.Fprintf(w, "  %s  %-22s %s  (%s)\n      evidence %s\n", a.stamp(e.TS), e.Type, eventValue(e), e.Cause, compact(e.Evidence))
			}
		}
	}
}

// compact renders JSON on one line.
func compact(raw json.RawMessage) string {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return string(raw)
	}
	b, _ := json.Marshal(v)
	return string(b)
}
