package cli

import (
	"context"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"lan-sentinel/internal/api"
	"lan-sentinel/internal/events"
	"lan-sentinel/internal/store"
)

func (a *app) observationsCmd() *cobra.Command {
	c := &cobra.Command{Use: "observations", Short: "Raw evidence and its hourly roll-ups"}
	var f store.ObservationFilter
	var since, until string
	var rollups bool
	list := &cobra.Command{
		Use:     "list",
		Short:   "Raw observations within retention; hourly roll-ups with --rollups",
		Example: "  sudo lan-sentinel observations list --since 1h",
		Long: "List the latest observations (default 1000) in time order. Observations older\n" +
			"than raw retention exist only as hourly roll-ups (--rollups): one row per host,\n" +
			"source, MAC, IP and hour, with a count.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			tf := &timeFlags{a: a}
			f.Since, f.Until = tf.ago("since", since), tf.at("until", until)
			if tf.err != nil {
				return tf.err
			}
			return a.run(cmd, false, func(ctx context.Context, b backend) error {
				if rollups {
					rs, err := b.Rollups(ctx, f)
					if err != nil {
						return err
					}
					return a.rollupsTable(rs)
				}
				obs, err := b.Observations(ctx, f)
				if err != nil {
					return err
				}
				return a.observationsTable(obs)
			})
		},
	}
	fl := list.Flags()
	fl.StringVar(&f.HostID, "host", "", "only this host ID")
	fl.StringVar(&f.Interface, "interface", "", "only this interface")
	fl.StringVar(&f.MAC, "mac", "", "only this MAC")
	fl.StringVar(&f.IP, "ip", "", "only this IP")
	fl.StringVar(&f.Source, "source", "", "only this source (e.g. passive_arp)")
	fl.BoolVar(&f.Unbound, "unbound", false, "only observations that matched no host")
	fl.StringVar(&since, "since", "", "from this time or duration ago (24h, 7d)")
	fl.StringVar(&until, "until", "", "up to this time")
	fl.IntVar(&f.Limit, "limit", store.DefaultObservationLimit, "at most this many rows (the latest)")
	fl.BoolVar(&rollups, "rollups", false, "hourly roll-ups instead of raw observations")
	c.AddCommand(list)
	return c
}

func (a *app) listOut(header []string, rows [][]string, v any, jsonl func() error) error {
	w := a.output()
	switch a.g.output {
	case "json":
		return writeJSON(w, v)
	case "jsonl":
		return jsonl()
	case "csv":
		return writeCSV(w, header, rows)
	}
	return writeTable(w, header, rows)
}

func (a *app) ts(t time.Time) string {
	if a.g.output == "csv" {
		return t.UTC().Format(time.RFC3339Nano)
	}
	return a.stamp(t)
}

func (a *app) observationsTable(obs []store.Observation) error {
	header := []string{"TIME", "IFACE", "SOURCE", "MAC", "IP", "HOSTNAME", "SERVICE", "HOST"}
	rows := make([][]string, 0, len(obs))
	for _, o := range obs {
		svc := ""
		if len(o.Service) > 0 {
			svc = compact(o.Service)
		}
		rows = append(rows, []string{a.ts(o.TS), o.Interface, o.Source, dash(o.MAC), dash(o.IP), dash(o.Hostname), dash(svc), dash(o.HostID)})
	}
	return a.listOut(header, rows, obs, func() error { return writeJSONL(a.output(), obs) })
}

func (a *app) rollupsTable(rs []store.Rollup) error {
	header := []string{"HOUR", "IFACE", "SOURCE", "MAC", "IP", "COUNT", "HOST"}
	rows := make([][]string, 0, len(rs))
	for _, r := range rs {
		rows = append(rows, []string{a.ts(r.Hour), r.Interface, r.Source, dash(r.MAC), dash(r.IP), strconv.FormatInt(r.Count, 10), dash(r.HostID)})
	}
	return a.listOut(header, rows, rs, func() error { return writeJSONL(a.output(), rs) })
}

// eventNames are the CLI names of every event type, sorted, for errors:
// operators have no docs on the box.
func eventNames() []string {
	var names []string
	for _, s := range events.All() {
		names = append(names, s.CLIName)
	}
	slices.Sort(names)
	return names
}

// eventTypes resolves --type values (CLI or spec names) to spec names.
func eventTypes(names []string) ([]string, error) {
	var out []string
	for _, v := range names {
		for _, n := range strings.Split(v, ",") {
			t, ok := api.EventType(n)
			if !ok {
				return nil, failf(ExitUsage, "--type: unknown event type %q; one of: %s", n, strings.Join(eventNames(), ", "))
			}
			out = append(out, string(t))
		}
	}
	return out, nil
}

func (a *app) eventsCmd() *cobra.Command {
	c := &cobra.Command{Use: "events", Short: "State transitions with their evidence"}
	var f store.EventFilter
	var since, until string
	var types []string
	list := &cobra.Command{
		Use:     "list",
		Short:   "All events on this box",
		Example: "  sudo lan-sentinel events list --type ip-changed --since 24h",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			tf := &timeFlags{a: a}
			f.Since, f.Until = tf.ago("since", since), tf.at("until", until)
			if tf.err != nil {
				return tf.err
			}
			var err error
			if f.Types, err = eventTypes(types); err != nil {
				return err
			}
			return a.run(cmd, false, func(ctx context.Context, b backend) error {
				evs, err := b.Events(ctx, f)
				if err != nil {
					return err
				}
				return a.eventsTable(evs)
			})
		},
	}
	fl := list.Flags()
	fl.StringVar(&since, "since", "", "from this time or duration ago (24h, 7d)")
	fl.StringVar(&until, "until", "", "up to this time")
	fl.StringSliceVar(&types, "type", nil, "event types by CLI name, e.g. ip-changed, duplicate-ip (repeatable)")
	fl.StringVar(&f.Interface, "interface", "", "only this interface")
	fl.StringVar(&f.MAC, "mac", "", "events of hosts with this MAC")
	fl.StringVar(&f.IP, "ip", "", "events about this IP")
	fl.IntVar(&f.Limit, "limit", 1000, "at most this many events (the latest)")
	c.AddCommand(list)
	return c
}

func (a *app) servicesCmd() *cobra.Command {
	c := &cobra.Command{Use: "services", Short: "Probe results"}
	var f store.ServiceFilter
	list := &cobra.Command{
		Use:     "list",
		Short:   "Probe results per host and port",
		Example: "  sudo lan-sentinel services list --interface eth0",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return a.run(cmd, false, func(ctx context.Context, b backend) error {
				svc, err := b.Services(ctx, f)
				if err != nil {
					return err
				}
				header := []string{"IP", "MAC", "IFACE", "PORT", "STATE", "LAST CHECK"}
				rows := make([][]string, 0, len(svc))
				for _, s := range svc {
					last := a.ago(s.LastResultAt)
					if a.g.output == "csv" {
						last = s.LastResultAt.UTC().Format(time.RFC3339)
					}
					rows = append(rows, []string{dash(strings.Join(s.IPs, " ")), s.MAC, s.Interface, strconv.Itoa(s.Port) + "/" + s.Proto, s.State, last})
				}
				return a.listOut(header, rows, svc, func() error { return writeJSONL(a.output(), svc) })
			})
		},
	}
	fl := list.Flags()
	fl.IntVar(&f.Port, "port", 0, "only this port")
	fl.StringVar(&f.State, "state", "", "only this state (OPEN, REFUSED, TIMEOUT, UNREACHABLE, UNKNOWN)")
	fl.StringVar(&f.Interface, "interface", "", "only this interface")
	c.AddCommand(list)
	return c
}

func (a *app) dhcpCmd() *cobra.Command {
	c := &cobra.Command{Use: "dhcp", Short: "DHCP servers seen on the interfaces"}
	var f store.DHCPServerFilter
	servers := &cobra.Command{
		Use:     "servers",
		Short:   "DHCP servers: identity, relay, sender, allowlist verdict and what they advertise",
		Example: "  sudo lan-sentinel dhcp servers",
		Long: "Lists every DHCP server identity (option 54) seen in a reply, per interface, relay\n" +
			"and sender MAC (the server's, or the relay's). STATUS is the allowlist verdict at the\n" +
			"last reply: allowed, unexpected, or unchecked when the interface has no allowlist\n" +
			"(interfaces[].dhcp.servers). The allowlist matches the advertised identifier and\n" +
			"does not authenticate a server. On a switched port many replies are unicast to\n" +
			"the client and never seen, so an empty list does not prove there is no server.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			switch strings.ToLower(f.Status) {
			case "", "allowed", "unexpected", "unchecked":
			default:
				return failf(ExitUsage, "--status: want allowed, unexpected or unchecked, got %q", f.Status)
			}
			return a.run(cmd, false, func(ctx context.Context, b backend) error {
				servers, err := b.DHCPServers(ctx, f)
				if err != nil {
					return err
				}
				header := []string{"SERVER ID", "RELAY", "MAC", "IP", "IFACE", "STATUS", "ROUTER", "DNS", "MASK", "LAST SEEN"}
				rows := make([][]string, 0, len(servers))
				for _, s := range servers {
					id := s.ServerID
					if id == "" {
						id = "unknown"
					}
					last := a.ago(s.LastSeen)
					if a.g.output == "csv" {
						last = s.LastSeen.UTC().Format(time.RFC3339)
					}
					rows = append(rows, []string{id, dash(s.Relay), s.MAC, dash(s.IP), s.Interface, s.Status,
						dash(s.Config["router"]), dash(s.Config["dns"]), dash(s.Config["subnet_mask"]), last})
				}
				return a.listOut(header, rows, servers, func() error { return writeJSONL(a.output(), servers) })
			})
		},
	}
	fl := servers.Flags()
	fl.StringVar(&f.Interface, "interface", "", "only this interface")
	fl.StringVar(&f.Status, "status", "", "only this verdict (allowed, unexpected, unchecked)")
	c.AddCommand(servers)
	return c
}

func (a *app) interfacesCmd() *cobra.Command {
	c := &cobra.Command{Use: "interfaces", Short: "Monitored interfaces"}
	c.AddCommand(&cobra.Command{
		Use:     "list",
		Short:   "State, MAC, current prefixes, passive/active per interface",
		Example: "  sudo lan-sentinel interfaces list",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return a.run(cmd, false, func(ctx context.Context, b backend) error {
				ifs, err := b.Interfaces(ctx)
				if err != nil {
					return err
				}
				header := []string{"NAME", "STATE", "MAC", "PREFIXES", "PASSIVE", "ACTIVE", "HOSTS"}
				rows := make([][]string, 0, len(ifs))
				for _, i := range ifs {
					passive := onOff(i.Passive)
					if i.Replay {
						passive = "replay"
					}
					rows = append(rows, []string{i.Name, i.State, dash(i.MAC), dash(strings.Join(i.Prefixes, " ")), passive, onOff(i.Active), strconv.Itoa(i.Hosts)})
				}
				return a.listOut(header, rows, ifs, func() error { return writeJSONL(a.output(), ifs) })
			})
		},
	})
	return c
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}
