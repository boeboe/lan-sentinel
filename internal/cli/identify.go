package cli

import (
	"fmt"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"lan-sentinel/internal/config"
	"lan-sentinel/internal/store"
)

func (a *app) identifyCmd() *cobra.Command {
	c := &cobra.Command{Use: "identify", Short: "Force an identification probe on a host"}
	c.AddCommand(a.identifyRunCmd())
	return c
}

func (a *app) identifyRunCmd() *cobra.Command {
	var q queryFlags
	var iface, probeName string
	c := &cobra.Command{
		Use:   "run <host> --probe NAME",
		Short: "Send one identification probe (bypasses only the once-per-MAC latch)",
		Long: "Sends one identification probe to a host the daemon has already tried, or\n" +
			"has not reached yet (ADR 0011). The host is given as for hosts set. --probe is\n" +
			"one of modbus, http, tls, snmp, ssh-banner, telnet, ftp. The kill switch,\n" +
			"budget, excludes, configured networks and the fresh unambiguous-binding rule\n" +
			"still apply. Needs the daemon.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := onlyFormats(a.g.output, "table", "json"); err != nil {
				return err
			}
			if a.g.offline {
				return failf(ExitUsage, "%s needs the running daemon; it does not work with --offline", cmd.CommandPath())
			}
			if !slices.Contains(config.IdentifyProbeNames, probeName) {
				return failf(ExitUsage, "--probe must be one of %v, got %q", config.IdentifyProbeNames, probeName)
			}
			query, kind, err := q.resolve(args)
			if err != nil {
				return err
			}
			cl := a.client()
			res, err := cl.Find(cmd.Context(), store.FindQuery{Query: query, Kind: kind, Interface: iface})
			if err != nil {
				return a.failed(err)
			}
			switch len(res.Hosts) {
			case 0:
				return failf(ExitDegraded, "no current host matches %s", query)
			case 1:
			default:
				var b strings.Builder
				fmt.Fprintf(&b, "%s matches %d hosts; name one with --interface or its host ID:", query, len(res.Hosts))
				for _, h := range res.Hosts {
					fmt.Fprintf(&b, "\n  %s  %s  %s", h.HostID, h.Interface, h.MAC)
				}
				return failf(ExitUsage, "%s", b.String())
			}
			att, err := cl.IdentifyRun(cmd.Context(), res.Hosts[0].HostID, probeName)
			if err != nil {
				return a.failed(err)
			}
			if a.g.output == "json" {
				return writeJSON(a.output(), att)
			}
			fmt.Fprintf(a.output(), "identify %s on %s: %s\n", att.Probe, res.Hosts[0].MAC, att.Result)
			return nil
		},
	}
	q.add(c)
	c.Flags().StringVar(&iface, "interface", "", "the host's interface, when the query matches hosts on several")
	c.Flags().StringVar(&probeName, "probe", "", "identification probe to send (required)")
	_ = c.MarkFlagRequired("probe")
	return c
}
