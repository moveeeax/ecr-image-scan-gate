// Package gate contains the pure severity-gating logic for ECR image scan
// findings. It has no AWS dependency: callers hand it a slice of findings and
// it computes per-severity counts, selects the top findings, and decides
// whether the configured threshold has been crossed.
package gate

import (
	"fmt"
	"sort"
	"strings"
)

// Severity is an ECR finding severity, ordered from least to most severe.
type Severity int

const (
	Undefined Severity = iota
	Informational
	Low
	Medium
	High
	Critical
)

// order lists severities from most to least severe for reporting.
var order = []Severity{Critical, High, Medium, Low, Informational, Undefined}

var names = map[Severity]string{
	Undefined:     "UNDEFINED",
	Informational: "INFORMATIONAL",
	Low:           "LOW",
	Medium:        "MEDIUM",
	High:          "HIGH",
	Critical:      "CRITICAL",
}

// String returns the canonical uppercase ECR severity name.
func (s Severity) String() string {
	if n, ok := names[s]; ok {
		return n
	}
	return "UNDEFINED"
}

// MarshalJSON emits the severity as its uppercase name rather than the
// underlying ordinal, so JSON output is self-describing.
func (s Severity) MarshalJSON() ([]byte, error) {
	return []byte(`"` + s.String() + `"`), nil
}

// UnmarshalJSON accepts either the uppercase name or the ordinal.
func (s *Severity) UnmarshalJSON(b []byte) error {
	str := strings.Trim(string(b), `"`)
	*s = ParseSeverity(str)
	return nil
}

// ParseSeverity maps an ECR severity string (case-insensitive) to a Severity.
// Unknown or empty strings map to Undefined, matching how ECR reports
// findings that were never assigned a severity.
func ParseSeverity(s string) Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return Critical
	case "HIGH":
		return High
	case "MEDIUM":
		return Medium
	case "LOW":
		return Low
	case "INFORMATIONAL":
		return Informational
	default:
		return Undefined
	}
}

// ParseThreshold parses a --fail-on value. Unlike ParseSeverity it rejects
// unknown values so a typo in CI config fails loudly instead of silently
// gating on UNDEFINED (which would fail on every finding).
func ParseThreshold(s string) (Severity, error) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return Critical, nil
	case "HIGH":
		return High, nil
	case "MEDIUM":
		return Medium, nil
	case "LOW":
		return Low, nil
	case "INFORMATIONAL":
		return Informational, nil
	case "UNDEFINED":
		return Undefined, nil
	default:
		return Undefined, fmt.Errorf("unknown severity %q (want one of critical, high, medium, low, informational, undefined)", s)
	}
}

// Finding is a single vulnerability finding, normalized from the ECR API or an
// offline describe-image-scan-findings JSON dump.
type Finding struct {
	Name        string   `json:"name"`
	Severity    Severity `json:"severity"`
	Package     string   `json:"package,omitempty"`
	Version     string   `json:"version,omitempty"`
	URI         string   `json:"uri,omitempty"`
	Description string   `json:"description,omitempty"`
}

// Report is the full result of classifying a set of findings against a gate.
type Report struct {
	Repository string         `json:"repository,omitempty"`
	ImageID    string         `json:"imageId,omitempty"`
	FailOn     string         `json:"failOn"`
	Counts     map[string]int `json:"counts"`
	Total      int            `json:"total"`
	Top        []Finding      `json:"top"`
	Gated      bool           `json:"gated"`
	Allowlist  []string       `json:"allowlist,omitempty"`
	Suppressed map[string]int `json:"suppressed,omitempty"`
}

// Options configure a classification run.
type Options struct {
	FailOn     Severity
	TopN       int
	Allowlist  []string // CVE ids that are accepted and never gate the build
	Repository string
	ImageID    string
}

// Classify aggregates findings by severity, applies the CVE allowlist, picks
// the top-N most severe findings, and decides whether the gate is tripped.
//
// It is a pure function: given the same findings and options it always returns
// the same report, with no I/O. That is what makes the gate unit-testable
// offline against JSON fixtures.
func Classify(findings []Finding, opts Options) Report {
	allow := make(map[string]bool, len(opts.Allowlist))
	for _, id := range opts.Allowlist {
		allow[strings.ToUpper(strings.TrimSpace(id))] = true
	}

	counts := map[string]int{}
	for _, s := range order {
		counts[s.String()] = 0
	}

	suppressed := map[string]int{}
	var gating []Finding
	for _, f := range findings {
		if allow[strings.ToUpper(strings.TrimSpace(f.Name))] {
			suppressed[f.Severity.String()]++
			continue
		}
		counts[f.Severity.String()]++
		gating = append(gating, f)
	}

	total := 0
	for _, s := range order {
		total += counts[s.String()]
	}

	// Sort by severity desc, then name asc for a stable, deterministic Top list.
	sort.SliceStable(gating, func(i, j int) bool {
		if gating[i].Severity != gating[j].Severity {
			return gating[i].Severity > gating[j].Severity
		}
		return gating[i].Name < gating[j].Name
	})

	topN := opts.TopN
	if topN <= 0 {
		topN = 10
	}
	top := gating
	if len(top) > topN {
		top = top[:topN]
	}

	gated := false
	for _, f := range gating {
		if f.Severity >= opts.FailOn {
			gated = true
			break
		}
	}

	rep := Report{
		Repository: opts.Repository,
		ImageID:    opts.ImageID,
		FailOn:     opts.FailOn.String(),
		Counts:     counts,
		Total:      total,
		Top:        append([]Finding(nil), top...),
		Gated:      gated,
	}
	if len(opts.Allowlist) > 0 {
		rep.Allowlist = opts.Allowlist
	}
	if len(suppressed) > 0 {
		rep.Suppressed = suppressed
	}
	return rep
}

// Order returns the severities most-severe-first, for stable reporting.
func Order() []Severity { return append([]Severity(nil), order...) }
