package gate

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

// RenderJSON writes the report as stable, indented JSON.
func RenderJSON(w io.Writer, r Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(r)
}

// RenderTable writes a human-readable per-severity summary and the top
// findings, most-severe-first.
func RenderTable(w io.Writer, r Report) error {
	var b strings.Builder
	if r.Repository != "" || r.ImageID != "" {
		fmt.Fprintf(&b, "Image: %s", r.Repository)
		if r.ImageID != "" {
			fmt.Fprintf(&b, " @ %s", r.ImageID)
		}
		b.WriteByte('\n')
	}

	tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SEVERITY\tCOUNT")
	for _, s := range Order() {
		fmt.Fprintf(tw, "%s\t%d\n", s, r.Counts[s.String()])
	}
	fmt.Fprintf(tw, "TOTAL\t%d\n", r.Total)
	if err := tw.Flush(); err != nil {
		return err
	}

	if len(r.Top) > 0 {
		b.WriteString("\nTop findings:\n")
		tt := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tt, "  SEVERITY\tCVE\tPACKAGE")
		for _, f := range r.Top {
			pkg := f.Package
			if f.Version != "" {
				pkg = pkg + " " + f.Version
			}
			if pkg == "" {
				pkg = "-"
			}
			fmt.Fprintf(tt, "  %s\t%s\t%s\n", f.Severity, f.Name, pkg)
		}
		if err := tt.Flush(); err != nil {
			return err
		}
	}

	fmt.Fprintf(&b, "\nGate: fail-on=%s -> ", r.FailOn)
	if r.Gated {
		b.WriteString("FAILED\n")
	} else {
		b.WriteString("passed\n")
	}

	_, err := io.WriteString(w, b.String())
	return err
}
