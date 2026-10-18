package cli

import (
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// Every command and every flag is in docs/CLI.md, so the frozen v1
// contract and the binary cannot drift apart unnoticed (AGENTS.md §12).
func TestCLIDocumented(t *testing.T) {
	b, err := os.ReadFile("../../docs/CLI.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(b)
	a := &app{env: Env{}}
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		for _, sub := range c.Commands() {
			if sub.Hidden || sub.Name() == "help" || sub.Name() == "completion" {
				continue
			}
			path := strings.TrimPrefix(sub.CommandPath(), "lan-sentinel ")
			if !strings.Contains(doc, "`"+path) {
				t.Errorf("command %q is not in docs/CLI.md", path)
			}
			sub.LocalFlags().VisitAll(func(f *pflag.Flag) {
				if f.Hidden || f.Name == "help" {
					return
				}
				if !strings.Contains(doc, "--"+f.Name) {
					t.Errorf("flag --%s of %q is not in docs/CLI.md", f.Name, path)
				}
			})
			walk(sub)
		}
	}
	root := a.newRoot()
	root.PersistentFlags().VisitAll(func(f *pflag.Flag) {
		if !strings.Contains(doc, "--"+f.Name) {
			t.Errorf("global flag --%s is not in docs/CLI.md", f.Name)
		}
	})
	walk(root)
}
