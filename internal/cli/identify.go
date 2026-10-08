package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"lan-sentinel/internal/api"
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
	var iface, probeSpec, sni string
	c := &cobra.Command{
		Use:   "run <host> --probe NAME",
		Short: "Send identification probes (bypasses only the once-per-MAC latch)",
		Long: "Sends one or more identification probes to a host the daemon has already tried,\n" +
			"or has not reached yet. The host is given as for hosts set. --probe is all (the\n" +
			"probes enabled on the host's interface), one name, or a comma-separated list:\n" +
			"modbus, http, tls, snmp, ssh-banner, telnet, ftp. --sni NAME is valid when tls\n" +
			"is in the list. The kill switch, budget, excludes, configured networks and the\n" +
			"fresh unambiguous-binding rule still apply. Needs the daemon.",
		Example: "  sudo lan-sentinel identify run --probe http,tls --ip 192.168.0.128\n" +
			"  sudo lan-sentinel identify run --probe all --ip 192.168.0.128",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := onlyFormats(a.g.output, "table", "json"); err != nil {
				return err
			}
			if a.g.offline {
				return failf(ExitUsage, "%s needs the running daemon; it does not work with --offline", cmd.CommandPath())
			}
			names, all, err := parseIdentifyProbes(probeSpec)
			if err != nil {
				return err
			}
			if sni != "" {
				if !all && !slices.Contains(names, "tls") {
					return failf(ExitUsage, "--sni applies only to --probe tls")
				}
				n, ok := config.SNIName(sni)
				if !ok {
					return failf(ExitUsage, "--sni must be a DNS name (has a dot, not an IP), got %q", sni)
				}
				sni = n
			}
			query, kind, err := q.resolve(args)
			if err != nil {
				return err
			}
			cl := a.client()
			host, err := oneCurrent(cmd.Context(), cl, query, kind, iface)
			if err != nil {
				return a.failed(err)
			}
			if all {
				if names, err = enabledProbes(cmd, cl, host.Interface); err != nil {
					return a.failed(err)
				}
				if len(names) == 0 {
					return failf(ExitError, "no identification probe is enabled on %s (interfaces[].active.identify)", host.Interface)
				}
				if sni != "" && !slices.Contains(names, "tls") {
					return failf(ExitUsage, "--sni applies only to --probe tls, which is not enabled on %s", host.Interface)
				}
			}
			var lines []identifyResult
			// report writes the JSON array; with -o table each line was
			// printed as it happened. It also runs before a failure, so the
			// attempts already made are never lost.
			report := func() error {
				if a.g.output != "json" || len(lines) == 0 {
					return nil
				}
				return writeJSON(a.output(), lines)
			}
			sent := 0
			for _, name := range names {
				jobSNI := ""
				if name == "tls" {
					jobSNI = sni
				}
				att, err := cl.IdentifyRun(cmd.Context(), host.HostID, name, jobSNI)
				switch {
				case errors.Is(err, api.ErrIdentifyRefused):
					lines = append(lines, identifyResult{IdentifyAttempt: store.IdentifyAttempt{Probe: name}, Error: err.Error()})
					if a.g.output != "json" {
						fmt.Fprintf(a.output(), "identify %s on %s: not sent (%s)\n", name, host.MAC, err)
					}
					continue
				case err != nil:
					if rerr := report(); rerr != nil {
						return rerr
					}
					return a.failed(err)
				}
				sent++
				lines = append(lines, identifyResult{IdentifyAttempt: att})
				if a.g.output != "json" {
					fmt.Fprintf(a.output(), "identify %s on %s: %s\n", att.Probe, host.MAC, att.Result)
				}
			}
			if err := report(); err != nil {
				return err
			}
			if sent == 0 {
				return failf(ExitError, "no identification probe was sent")
			}
			return nil
		},
	}
	q.add(c)
	c.Flags().StringVar(&iface, "interface", "", "the host's interface, when the query matches hosts on several")
	c.Flags().StringVar(&probeSpec, "probe", "", "all, one name, or a comma-separated list (required)")
	c.Flags().StringVar(&sni, "sni", "", "TLS Server Name; only when tls is in --probe")
	_ = c.MarkFlagRequired("probe")
	return c
}

// identifyResult is one probe of identify run: the attempt, or why it was
// not sent.
type identifyResult struct {
	store.IdentifyAttempt
	Error string `json:"error,omitempty"`
}

// parseIdentifyProbes reads --probe: all (expanded once the host's
// interface is known), one name, or a comma list.
func parseIdentifyProbes(spec string) (names []string, all bool, err error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, false, failf(ExitUsage, "--probe is required")
	}
	if spec == "all" {
		return nil, true, nil
	}
	seen := map[string]bool{}
	for _, p := range strings.Split(spec, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			return nil, false, failf(ExitUsage, "--probe has an empty name")
		}
		if p == "all" {
			return nil, false, failf(ExitUsage, "--probe all cannot be mixed with other names")
		}
		if !slices.Contains(config.IdentifyProbeNames, p) {
			return nil, false, failf(ExitUsage, "--probe must be all, or one or more of %v, got %q", config.IdentifyProbeNames, p)
		}
		if seen[p] {
			continue
		}
		seen[p] = true
		names = append(names, p)
	}
	return names, false, nil
}

// enabledProbes is what --probe all means: the probes the daemon's running
// configuration enables on iface, in catalogue order, so names an operator
// has not enabled there are not tried (and not listed as not sent).
func enabledProbes(cmd *cobra.Command, cl *api.Client, iface string) ([]string, error) {
	raw, err := cl.Config(cmd.Context())
	if err != nil {
		return nil, err
	}
	var cfg struct {
		Interfaces []struct {
			Name   string `json:"name"`
			Active struct {
				Identify []struct {
					Name string `json:"name"`
				} `json:"identify"`
			} `json:"active"`
		} `json:"interfaces"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("daemon configuration: %w", err)
	}
	on := map[string]bool{}
	for _, ic := range cfg.Interfaces {
		if ic.Name == iface {
			for _, e := range ic.Active.Identify {
				on[e.Name] = true
			}
		}
	}
	var names []string
	for _, n := range config.IdentifyProbeNames {
		if on[n] {
			names = append(names, n)
		}
	}
	return names, nil
}
