package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"lan-sentinel/internal/store"
)

// hostsSetCmd sets metadata on a host: for now its description
// (docs/DATA_MODEL.md §5.8).
func (a *app) hostsSetCmd() *cobra.Command {
	var q queryFlags
	var iface, description string
	c := &cobra.Command{
		Use:   "set <host> --description TEXT",
		Short: "Set metadata on a host: its description",
		Long: "Sets a host's description, free text for context such as \"Solar panel rooftop\"\n" +
			"or \"Mobile phone Bart\": one line of at most 200 characters. The host is a host ID,\n" +
			"MAC, IP or hostname that matches exactly one current host; add --interface or\n" +
			"use the host ID when it matches several. Each change is recorded as\n" +
			"HOST_DESCRIBED with the calling user. Needs the daemon.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !cmd.Flags().Changed("description") {
				return failf(ExitUsage, "nothing to set: give --description")
			}
			if strings.TrimSpace(description) == "" {
				return failf(ExitUsage, "--description is empty: remove a description with hosts unset --description")
			}
			return a.describeHost(cmd, q, args, iface, description)
		},
	}
	q.add(c)
	c.Flags().StringVar(&iface, "interface", "", "the host's interface, when the query matches hosts on several")
	c.Flags().StringVar(&description, "description", "", "the description")
	return c
}

// hostsUnsetCmd removes metadata from a host.
func (a *app) hostsUnsetCmd() *cobra.Command {
	var q queryFlags
	var iface string
	var description bool
	c := &cobra.Command{
		Use:   "unset <host> --description",
		Short: "Remove metadata from a host: its description",
		Long: "Removes a host's description, recorded as HOST_DESCRIBED with the calling user.\n" +
			"The host is given as for hosts set. Needs the daemon.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !description {
				return failf(ExitUsage, "nothing to unset: give --description")
			}
			return a.describeHost(cmd, q, args, iface, "")
		},
	}
	q.add(c)
	c.Flags().StringVar(&iface, "interface", "", "the host's interface, when the query matches hosts on several")
	c.Flags().BoolVar(&description, "description", false, "remove the description")
	return c
}

// describeHost resolves the query to exactly one current host and sets its
// description through the daemon ("" removes it).
func (a *app) describeHost(cmd *cobra.Command, q queryFlags, args []string, iface, text string) error {
	if err := onlyFormats(a.g.output, "table", "json"); err != nil {
		return err
	}
	if a.g.offline {
		return failf(ExitUsage, "%s needs the running daemon; it does not work with --offline", cmd.CommandPath())
	}
	text, err := store.CleanDescription(text)
	if err != nil {
		return failf(ExitUsage, "--description: %v", err)
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
	h, err := cl.SetDescription(cmd.Context(), res.Hosts[0].HostID, text)
	if err != nil {
		return a.failed(err)
	}
	if a.g.output == "json" {
		return writeJSON(a.output(), h)
	}
	if text == "" {
		fmt.Fprintf(a.output(), "Description of %s on %s removed.\n", h.MAC, h.Interface)
	} else {
		fmt.Fprintf(a.output(), "Description of %s on %s: %s\n", h.MAC, h.Interface, h.Description)
	}
	return nil
}
