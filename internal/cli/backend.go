package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"

	"lan-sentinel/internal/api"
	"lan-sentinel/internal/config"
	"lan-sentinel/internal/store"
)

// backend is where read commands get their data: the daemon's API (online,
// the default) or the database opened read-only (--offline). Both answer
// with the same store types from the same queries.
type backend interface {
	Interfaces(ctx context.Context) ([]store.InterfaceInfo, error)
	Hosts(ctx context.Context, f store.HostFilter) ([]store.HostSummary, error)
	Host(ctx context.Context, id string) (store.Host, error)
	Find(ctx context.Context, q store.FindQuery) (store.FindResult, error)
	History(ctx context.Context, q store.HistoryQuery) ([]store.Event, error)
	EvidenceFor(ctx context.Context, f store.HostFilter, since time.Time) ([]store.Evidence, error)
	Observations(ctx context.Context, f store.ObservationFilter) ([]store.Observation, error)
	Rollups(ctx context.Context, f store.ObservationFilter) ([]store.Rollup, error)
	Events(ctx context.Context, f store.EventFilter) ([]store.Event, error)
	Services(ctx context.Context, f store.ServiceFilter) ([]store.ServiceRow, error)
	DHCPServers(ctx context.Context, f store.DHCPServerFilter) ([]store.DHCPServer, error)
	DBInfo(ctx context.Context) (store.DBInfo, error)
	DBCheck(ctx context.Context) (store.CheckResult, error)
	Close() error
}

type online struct{ *api.Client }

func (online) Close() error { return nil }

// offline reads the database directly (docs/CLI.md §1).
type offline struct {
	*store.Reader
	cfg *config.Config
}

func (o offline) Interfaces(ctx context.Context) ([]store.InterfaceInfo, error) {
	ifs, err := o.Reader.Interfaces(ctx)
	if err != nil {
		return nil, err
	}
	return api.WithConfig(ifs, o.cfg), nil
}

func (o offline) DBCheck(ctx context.Context) (store.CheckResult, error) { return o.Check(ctx) }

// settings loads the configuration for client commands. A config file that
// cannot be read is not fatal when the flags say where to connect: the
// compiled defaults stand in.
func (a *app) settings(need string) (*config.Config, error) {
	l, err := config.Load(a.loadOptions())
	if err == nil {
		return l.Config, nil
	}
	var ve *config.ValidationError
	if errors.As(err, &ve) {
		return nil, fail(ExitError, err)
	}
	if a.root.PersistentFlags().Changed(need) {
		cfg := config.Defaults()
		cfg.Storage.Path, cfg.API.Socket = a.g.db, a.g.socket
		return cfg, nil
	}
	return nil, failf(ExitError, "%v (pass --%s to skip the config file)", err, need)
}

// connect returns the backend for a read command: the API, or with
// --offline the database. needDaemon commands refuse --offline (exit 64).
func (a *app) connect(cmd *cobra.Command, needDaemon bool) (backend, error) {
	if a.g.offline {
		if needDaemon {
			return nil, failf(ExitUsage, "%s needs the running daemon; it does not work with --offline", cmd.CommandPath())
		}
		cfg, err := a.settings("db")
		if err != nil {
			return nil, err
		}
		r, err := store.OpenReadOnly(cfg.Storage.Path, store.ReadOptions{NameExpiry: cfg.Identity.NameExpiry.D(), Now: a.env.now})
		if err != nil {
			return nil, fail(ExitError, err)
		}
		if r.Immutable {
			fmt.Fprintf(a.env.Stderr, "notice: %s has no WAL (daemon not running); reading it as it is. If the daemon starts meanwhile, re-run.\n",
				cfg.Storage.Path)
		}
		return offline{Reader: r, cfg: cfg}, nil
	}
	return online{a.client()}, nil
}

// client returns the API client for the configured socket.
func (a *app) client() *api.Client {
	socket := a.g.socket
	if socket == "" {
		socket = config.DefaultSocketPath
		if cfg, err := a.settings("socket"); err == nil {
			socket = cfg.API.Socket
		}
	}
	a.socket = socket
	return api.NewClient(socket, a.g.timeout)
}

// failed maps a backend error to an exit code (docs/CLI.md §4).
func (a *app) failed(err error) error {
	var ee *exitError
	switch {
	case err == nil:
		return nil
	case errors.As(err, &ee):
		return err
	case errors.Is(err, os.ErrPermission):
		return failf(ExitError, "%v (run with sudo)", err)
	case errors.Is(err, api.ErrUnreachable):
		return failf(ExitUnreachable, "%v (is lan-sentinel running? --offline reads the database directly)", err)
	case errors.Is(err, store.ErrBadQuery):
		return fail(ExitUsage, err)
	}
	return fail(ExitError, err)
}

// output returns where results go: nowhere with --quiet.
func (a *app) output() io.Writer {
	if a.g.quiet {
		return io.Discard
	}
	return a.env.Stdout
}

// run executes fn against a backend and maps its errors.
func (a *app) run(cmd *cobra.Command, needDaemon bool, fn func(ctx context.Context, b backend) error) error {
	b, err := a.connect(cmd, needDaemon)
	if err != nil {
		return err
	}
	defer b.Close() //nolint:errcheck // read-only; nothing to lose
	return a.failed(fn(cmd.Context(), b))
}
