package cli

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"
	"go.yaml.in/yaml/v3"

	"lan-sentinel/internal/api"
	"lan-sentinel/internal/config"
)

func (a *app) configCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "config",
		Short: "Show, validate or reload the configuration",
	}
	c.AddCommand(a.configValidateCmd(), a.configShowCmd(), a.configReloadCmd())
	return c
}

// load loads the config; a validation error is printed in full and turned
// into exit 2, but the loaded value is still returned when available.
func (a *app) load() (*config.Loaded, error) {
	l, err := config.Load(a.loadOptions())
	if err == nil {
		return l, nil
	}
	var ve *config.ValidationError
	if errors.As(err, &ve) {
		fmt.Fprintln(a.env.Stderr, ve.Error())
		return l, silent(ExitError)
	}
	return nil, fail(ExitError, err)
}

func (a *app) configValidateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "validate",
		Short: "Validate a config before rollout",
		Long: "Validate the configuration file, environment and flags. Prints the interfaces,\n" +
			"active scan networks, enabled probes, budgets and the estimated maximum probe\n" +
			"rate. Exit 0 if valid, 2 with per-key errors otherwise.",
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			if err := onlyFormats(a.g.output, "table", "json"); err != nil {
				return err
			}
			l, err := a.load()
			if err != nil {
				return err
			}
			s := config.Summarize(l.Config)
			if a.g.output == "json" {
				return writeJSON(a.out(), struct {
					Valid bool   `json:"valid"`
					Path  string `json:"path"`
					config.Summary
				}{true, l.Path, s})
			}
			if !a.g.quiet {
				printSummary(a.out(), l, s)
			}
			return nil
		},
	}
}

func printSummary(w io.Writer, l *config.Loaded, s config.Summary) {
	c := l.Config
	fmt.Fprintf(w, "Configuration %s is valid.\n\nInterfaces:\n", l.Path)
	rows := make([][]string, 0, len(s.Interfaces))
	for _, is := range s.Interfaces {
		passive := "passive off"
		switch {
		case is.Mode == "replay":
			passive = "replay " + is.ReplayFile
		case is.Passive && is.Promiscuous:
			passive = "passive (promiscuous)"
		case is.Passive:
			passive = "passive"
		}
		active := "active off"
		if is.Active {
			active = "active on  networks " + strings.Join(is.Networks, ", ")
			if len(is.Exclude) > 0 {
				active += "  exclude " + strings.Join(is.Exclude, ", ")
			}
			active += fmt.Sprintf("  sweep %d addresses (%s)", is.SweepTargets, sweepTime(is.SweepSeconds))
		}
		rows = append(rows, []string{"  " + is.Name, passive, active})
	}
	_ = writeTable(w, []string{"  NAME", "PASSIVE", "ACTIVE"}, rows)

	probes := "none"
	if len(s.Probes) > 0 {
		probes = strings.Join(s.Probes, "; ")
	}
	b := c.Active.Budgets
	fmt.Fprintf(w, "\nProbes:   %s\n", probes)
	fmt.Fprintf(w, "Budgets:  global %g pps; arp %g pps; icmp %g pps; ndp %g pps; udp %g pps; tcp %g connects/s (≤%d per interface, ≤%d per host)\n",
		c.Active.MaxPacketsPerSecond, b.ARP.PacketsPerSecond, b.ICMP.PacketsPerSecond, b.NDP.PacketsPerSecond,
		b.UDP.PacketsPerSecond, b.TCP.ConnectsPerSecond, b.TCP.MaxConcurrentPerInterface, b.TCP.MaxConcurrentPerHost)
	if c.Active.MaxSweepTargets > config.DefaultMaxSweepTargets {
		fmt.Fprintf(w, "Expert override: active.max_sweep_targets %d (default %d); preview operator sweeps with scan plan\n",
			c.Active.MaxSweepTargets, config.DefaultMaxSweepTargets)
	}
	if s.MaxPacketsPerSecond == 0 {
		fmt.Fprintln(w, "Estimated maximum probe rate: 0 pps (active discovery is disabled on every interface)")
	} else {
		fmt.Fprintf(w, "Estimated maximum probe rate: %g pps\n", s.MaxPacketsPerSecond)
	}
}

// sweepTime prints how long a full sweep takes.
func sweepTime(seconds float64) string {
	switch {
	case seconds < 120:
		return fmt.Sprintf("~%.0f s", seconds)
	case seconds < 2*3600:
		return fmt.Sprintf("~%.0f min", seconds/60)
	}
	return fmt.Sprintf("~%.1f h", seconds/3600)
}

func (a *app) configShowCmd() *cobra.Command {
	var sources bool
	c := &cobra.Command{
		Use:   "show",
		Short: "Show the effective configuration after merging defaults, file, env and flags",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			l, loadErr := a.load()
			if l == nil {
				return loadErr
			}
			var err error
			if sources {
				err = a.showSources(l)
			} else {
				err = a.showConfig(l)
			}
			if err != nil {
				return err
			}
			return loadErr // still exit 2 if the config is invalid
		},
	}
	c.Flags().BoolVar(&sources, "sources", false, "print every key with where its value came from")
	return c
}

func (a *app) showConfig(l *config.Loaded) error {
	if err := onlyFormats(a.g.output, "table", "json"); err != nil {
		return err
	}
	if a.g.output == "json" {
		return writeJSON(a.out(), l.Config)
	}
	enc := yaml.NewEncoder(a.out())
	enc.SetIndent(2)
	if err := enc.Encode(l.Config); err != nil {
		return fail(ExitError, fmt.Errorf("encode config: %w", err))
	}
	return enc.Close()
}

func (a *app) showSources(l *config.Loaded) error {
	settings, err := l.Settings()
	if err != nil {
		return fail(ExitError, err)
	}
	switch a.g.output {
	case "json":
		return writeJSON(a.out(), settings)
	case "jsonl":
		return writeJSONL(a.out(), settings)
	}
	rows := make([][]string, len(settings))
	for i, s := range settings {
		rows[i] = []string{s.Key, s.Value, s.Source}
	}
	if a.g.output == "csv" {
		return writeCSV(a.out(), []string{"key", "value", "source"}, rows)
	}
	return writeTable(a.out(), []string{"KEY", "VALUE", "SOURCE"}, rows)
}

func (a *app) configReloadCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "reload",
		Short: "Make the running daemon re-read its configuration file",
		Long: "Makes the daemon re-read the configuration file it was started with (--config\n" +
			"does not change which), as systemctl reload does, and prints what took effect.\n" +
			"Probes, each interface's active settings, intervals, thresholds and the log\n" +
			"level apply at once. Changes to the set of interfaces, passive capture,\n" +
			"storage, the API, metrics or the log format need a restart: they are listed\n" +
			"and keep their running values. A file that does not validate changes nothing\n" +
			"(exit 2 with the errors); check it first with config validate.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := onlyFormats(a.g.output, "table", "json"); err != nil {
				return err
			}
			if a.g.offline {
				return failf(ExitUsage, "%s needs the running daemon; it does not work with --offline", cmd.CommandPath())
			}
			res, err := a.client().ReloadConfig(cmd.Context())
			if err != nil {
				return a.failed(err)
			}
			if a.g.output == "json" {
				return writeJSON(a.output(), res)
			}
			printReload(a.output(), res)
			return nil
		},
	}
}

func printReload(w io.Writer, res api.ReloadResult) {
	fmt.Fprintf(w, "Configuration %s reloaded.\n", res.Path)
	if len(res.Applied)+len(res.NotApplied) == 0 {
		fmt.Fprintln(w, "No changes.")
		return
	}
	changes := func(cs []config.Change) [][]string {
		rows := make([][]string, len(cs))
		for i, c := range cs {
			rows[i] = []string{"  " + c.Key, c.Old, c.New}
		}
		return rows
	}
	if len(res.Applied) > 0 {
		fmt.Fprintln(w, "\nApplied:")
		_ = writeTable(w, []string{"  KEY", "OLD", "NEW"}, changes(res.Applied))
	}
	if len(res.NotApplied) > 0 {
		fmt.Fprintln(w, "\nNot applied, needs a restart (sudo systemctl restart lan-sentinel):")
		_ = writeTable(w, []string{"  KEY", "RUNNING", "FILE"}, changes(res.NotApplied))
	}
}
