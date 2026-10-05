// Command lan-sentinel is the LAN Sentinel daemon, CLI client, database
// inspector and on-demand scanner in one binary.
package main

import (
	"context"
	"os"

	"lan-sentinel/internal/cli"
)

func main() {
	os.Exit(cli.Execute(context.Background(), cli.OSEnv()))
}
