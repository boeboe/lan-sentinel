package cli

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return fmt.Errorf("encode json: %w", err)
	}
	return nil
}

func writeJSONL[T any](w io.Writer, rows []T) error {
	enc := json.NewEncoder(w)
	for _, r := range rows {
		if err := enc.Encode(r); err != nil {
			return fmt.Errorf("encode json: %w", err)
		}
	}
	return nil
}

// writeCSV writes rows as CSV. Hostnames and other text come from the
// network, so a cell a spreadsheet would run as a formula (starting with =,
// +, -, @, tab or carriage return) is prefixed with a quote; the table
// placeholder "-" becomes an empty cell.
func writeCSV(w io.Writer, header []string, rows [][]string) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(header); err != nil {
		return fmt.Errorf("write csv: %w", err)
	}
	for _, r := range rows {
		safe := make([]string, len(r))
		for i, c := range r {
			safe[i] = csvCell(c)
		}
		if err := cw.Write(safe); err != nil {
			return fmt.Errorf("write csv: %w", err)
		}
	}
	cw.Flush()
	if err := cw.Error(); err != nil {
		return fmt.Errorf("write csv: %w", err)
	}
	return nil
}

func csvCell(c string) string {
	if c == "-" {
		return ""
	}
	if c != "" && strings.ContainsRune("=+-@\t\r", rune(c[0])) {
		return "'" + c
	}
	return c
}

func writeTable(w io.Writer, header []string, rows [][]string) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, strings.Join(header, "\t"))
	for _, r := range rows {
		fmt.Fprintln(tw, strings.Join(r, "\t"))
	}
	if err := tw.Flush(); err != nil {
		return fmt.Errorf("write table: %w", err)
	}
	return nil
}

// onlyFormats rejects output formats a command does not support.
func onlyFormats(got string, allowed ...string) error {
	for _, a := range allowed {
		if got == a {
			return nil
		}
	}
	return failf(ExitUsage, "--output %s is not supported by this command (use %s)", got, strings.Join(allowed, " or "))
}
