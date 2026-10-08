package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"lan-sentinel/internal/buildinfo"
)

func (a *app) versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "version",
		Short:   "Print version, commit, commit date, Go version and platform",
		Example: "  lan-sentinel version",
		Args:    cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			bi := buildinfo.Get()
			if err := onlyFormats(a.g.output, "table", "json"); err != nil {
				return err
			}
			if a.g.output == "json" {
				return writeJSON(a.out(), bi)
			}
			if a.g.quiet {
				fmt.Fprintln(a.out(), bi.Version)
				return nil
			}
			fmt.Fprintf(a.out(), "lan-sentinel %s\n  commit:    %s\n  committed: %s\n  go:        %s\n  platform:  %s\n",
				bi.Version, bi.Commit, bi.Date, bi.GoVersion, bi.Platform)
			return nil
		},
	}
}
