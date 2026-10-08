// Package cli implements the lan-sentinel command line (docs/CLI.md).
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"lan-sentinel/internal/config"
)

// Exit codes (docs/CLI.md §4).
const (
	ExitOK          = 0
	ExitDegraded    = 1
	ExitError       = 2
	ExitUnreachable = 3
	ExitUsage       = 64
)

// exitError carries an exit code. RunE functions always return one, so any
// other error reaching Execute came from cobra's argument parsing and is a
// usage error.
type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string { return e.err.Error() }
func (e *exitError) Unwrap() error { return e.err }

func fail(code int, err error) error { return &exitError{code: code, err: err} }

func failf(code int, format string, args ...any) error {
	return &exitError{code: code, err: fmt.Errorf(format, args...)}
}

// silent is an exit code whose message has already been printed.
type silent int

func (s silent) Error() string { return fmt.Sprintf("exit %d", int(s)) }

// Env is the process environment the CLI runs in.
type Env struct {
	Args    []string
	Stdout  io.Writer
	Stderr  io.Writer
	Environ []string
	// StderrIsTerminal selects text logging for `daemon run` when the log
	// format is not configured.
	StderrIsTerminal bool
	// Now and Location default to the system clock and time zone; tests
	// fix them.
	Now      func() time.Time
	Location *time.Location
}

func (e Env) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

func (e Env) loc() *time.Location {
	if e.Location != nil {
		return e.Location
	}
	return time.Local
}

// OSEnv returns the real process environment.
func OSEnv() Env {
	return Env{
		Args: os.Args[1:], Stdout: os.Stdout, Stderr: os.Stderr, Environ: os.Environ(),
		StderrIsTerminal: term.IsTerminal(int(os.Stderr.Fd())),
	}
}

type globals struct {
	config   string
	db       string
	socket   string
	output   string
	noColor  bool
	logLevel string
	timeout  time.Duration
	offline  bool
	quiet    bool
}

var outputFormats = []string{"table", "json", "jsonl", "csv"}

type app struct {
	env    Env
	g      globals
	root   *cobra.Command
	socket string // the socket the client connected to
}

// Execute runs the CLI and returns the process exit code.
func Execute(ctx context.Context, env Env) int {
	a := &app{env: env}
	a.root = a.newRoot()
	a.root.SetArgs(env.Args)
	a.root.SetOut(env.Stdout)
	a.root.SetErr(env.Stderr)
	err := a.root.ExecuteContext(ctx)
	if err == nil {
		return ExitOK
	}
	var s silent
	if errors.As(err, &s) {
		return int(s)
	}
	var ee *exitError
	if errors.As(err, &ee) {
		fmt.Fprintln(env.Stderr, "lan-sentinel:", ee.err)
		return ee.code
	}
	fmt.Fprintln(env.Stderr, "lan-sentinel:", err)
	fmt.Fprintln(env.Stderr, "Run 'lan-sentinel --help' for usage.")
	return ExitUsage
}

func (a *app) newRoot() *cobra.Command {
	root := &cobra.Command{
		Use:           "lan-sentinel",
		Short:         "Persistent, interface-aware host inventory for OT networks",
		Long:          "LAN Sentinel keeps a historical inventory of the hosts on local networks.\nThe same binary is the daemon, the CLI client, the database inspector and the scanner.",
		Example:       "  sudo lan-sentinel hosts list --active\n  sudo lan-sentinel hosts show 192.168.0.99",
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(*cobra.Command, []string) error {
			if !slices.Contains(outputFormats, a.g.output) {
				return fmt.Errorf("invalid --output %q: use one of %v", a.g.output, outputFormats)
			}
			return nil
		},
	}
	f := root.PersistentFlags()
	f.StringVar(&a.g.config, "config", "", "config file (default $"+config.EnvConfigPath+" or "+config.DefaultConfigPath+")")
	f.StringVar(&a.g.db, "db", "", "database path (default from config)")
	f.StringVar(&a.g.socket, "socket", "", "API socket (default from config)")
	f.StringVarP(&a.g.output, "output", "o", "table", "output format: table, json, jsonl or csv")
	f.BoolVar(&a.g.noColor, "no-color", false, "disable colour")
	f.StringVar(&a.g.logLevel, "log-level", "", "log level: trace, debug, info, warn or error")
	f.DurationVar(&a.g.timeout, "timeout", 10*time.Second, "client timeout")
	f.BoolVar(&a.g.offline, "offline", false, "read the database directly, read-only")
	f.BoolVar(&a.g.quiet, "quiet", false, "minimal output; rely on the exit code")

	root.AddCommand(a.versionCmd(), a.configCmd(), a.daemonCmd(), a.hostsCmd(), a.observationsCmd(), a.eventsCmd(),
		a.servicesCmd(), a.dhcpCmd(), a.interfacesCmd(), a.watchCmd(), a.dbCmd(), a.activeCmd(), a.scanCmd(), a.identifyCmd())
	return root
}

// loadOptions builds config load options from the global flags. Flags that
// were not given leave the config untouched.
func (a *app) loadOptions() config.LoadOptions {
	o := config.LoadOptions{Path: a.g.config, Environ: a.env.Environ}
	pf := a.root.PersistentFlags()
	for _, m := range []struct{ flag, key string }{
		{"db", "storage.path"}, {"socket", "api.socket"}, {"log-level", "logging.level"},
	} {
		if pf.Changed(m.flag) {
			v, _ := pf.GetString(m.flag)
			o.Flags = append(o.Flags, config.Override{Key: m.key, Value: v, Origin: "--" + m.flag})
		}
	}
	return o
}

func (a *app) out() io.Writer { return a.env.Stdout }
