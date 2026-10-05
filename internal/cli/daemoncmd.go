package cli

import (
	"errors"

	"github.com/spf13/cobra"

	"lan-sentinel/internal/config"
	"lan-sentinel/internal/daemon"
)

func (a *app) daemonCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "daemon",
		Short: "Run the service",
	}
	c.AddCommand(a.daemonRunCmd())
	return c
}

func (a *app) daemonRunCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "run",
		Short: "Run the service in the foreground (systemd owns the process)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			err := daemon.Run(cmd.Context(), daemon.Options{
				Load:             a.loadOptions(),
				Stderr:           a.env.Stderr,
				StderrIsTerminal: a.env.StderrIsTerminal,
			})
			var ve *config.ValidationError
			switch {
			case errors.As(err, &ve):
				a.env.Stderr.Write([]byte(ve.Error() + "\n")) //nolint:errcheck // best effort
				return silent(ExitError)
			case err != nil:
				return fail(ExitError, err)
			}
			return nil
		},
	}
}
