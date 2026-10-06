// Command gen writes the synthetic pcap fixtures into test/fixtures
// (`make fixtures`).
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"lan-sentinel/test/fixtures"
)

func main() {
	dir := flag.String("dir", "test/fixtures", "output directory")
	flag.Parse()
	files, err := fixtures.Files()
	if err != nil {
		fmt.Fprintln(os.Stderr, "gen:", err)
		os.Exit(1)
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(*dir, name), data, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "gen:", err)
			os.Exit(1)
		}
		fmt.Printf("wrote %s (%d bytes)\n", filepath.Join(*dir, name), len(data))
	}
}
