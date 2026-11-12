package gate

import (
	"bytes"
	"strings"
	"testing"
)

func f(name string, sev Severity) Finding { return Finding{Name: name, Severity: sev} }

func TestParseSeverity(t *testing.T) {
	cases := map[string]Severity{
		"CRITICAL": Critical, "critical": Critical,
		"High": High, "medium": Medium, "LOW": Low,
		"informational": Informational, "": Undefined, "nonsense": Undefined,
	}
	for in, want := range cases {
		if got := ParseSeverity(in); got != want {
			t.Errorf("ParseSeverity(%q)=%v want %v", in, got, want)
		}
	}
}

func TestParseThresholdRejectsUnknown(t *testing.T) {
	if _, err := ParseThreshold("high"); err != nil {
		t.Fatalf("high should parse: %v", err)
	}
	if _, err := ParseThreshold("bogus"); err == nil {
		t.Fatal("bogus threshold should error")
	}
}

// TestGateThresholds is the acceptance table from the spec:
// a set with a CRITICAL fails --fail-on high and --fail-on critical;
// a set whose worst is MEDIUM passes both; --fail-on low fails on any finding.
func TestGateThresholds(t *testing.T) {
	withCritical := []Finding{f("CVE-1", Medium), f("CVE-2", Critical)}
	worstMedium := []Finding{f("CVE-3", Low), f("CVE-4", Medium)}

	tests := []struct {
		name      string
		findings  []Finding
		failOn    Severity
		wantGated bool
	}{
		{"critical set fails on high", withCritical, High, true},
		{"critical set fails on critical", withCritical, Critical, true},
		{"medium set passes on high", worstMedium, High, false},
		{"medium set passes on critical", worstMedium, Critical, false},
		{"medium set fails on low", worstMedium, Low, true},
		{"critical set fails on low", withCritical, Low, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := Classify(tt.findings, Options{FailOn: tt.failOn})
			if r.Gated != tt.wantGated {
				t.Errorf("Gated=%v want %v", r.Gated, tt.wantGated)
			}
		})
	}
}

func TestCountsAndTotal(t *testing.T) {
	findings := []Finding{
		f("a", Critical), f("b", High), f("c", High),
		f("d", Medium), f("e", Low), f("g", Undefined),
	}
	r := Classify(findings, Options{FailOn: High})
	if r.Total != 6 {
		t.Fatalf("Total=%d want 6", r.Total)
	}
	want := map[string]int{"CRITICAL": 1, "HIGH": 2, "MEDIUM": 1, "LOW": 1, "INFORMATIONAL": 0, "UNDEFINED": 1}
	for k, v := range want {
		if r.Counts[k] != v {
			t.Errorf("count[%s]=%d want %d", k, r.Counts[k], v)
		}
	}
}

func TestTopSortedStable(t *testing.T) {
	findings := []Finding{
		f("CVE-9", High), f("CVE-1", Critical), f("CVE-5", High), f("CVE-2", Critical),
	}
	r := Classify(findings, Options{FailOn: Critical, TopN: 3})
	if len(r.Top) != 3 {
		t.Fatalf("Top len=%d want 3", len(r.Top))
	}
	// Critical first, ties broken by name ascending.
	wantOrder := []string{"CVE-1", "CVE-2", "CVE-5"}
	for i, w := range wantOrder {
		if r.Top[i].Name != w {
			t.Errorf("Top[%d]=%s want %s", i, r.Top[i].Name, w)
		}
	}
}

func TestAllowlistSuppresses(t *testing.T) {
	findings := []Finding{f("CVE-2024-0001", Critical), f("CVE-2024-0002", High)}
	r := Classify(findings, Options{FailOn: High, Allowlist: []string{"cve-2024-0001"}})
	// The suppressed CRITICAL must not appear in counts; the remaining HIGH
	// finding still gates at fail-on high.
	if !r.Gated {
		t.Error("remaining HIGH finding should still trip fail-on high")
	}
	if r.Counts["CRITICAL"] != 0 {
		t.Errorf("suppressed CRITICAL leaked into counts: %d", r.Counts["CRITICAL"])
	}
	if r.Counts["HIGH"] != 1 {
		t.Errorf("HIGH count=%d want 1", r.Counts["HIGH"])
	}
	if r.Suppressed["CRITICAL"] != 1 {
		t.Errorf("Suppressed[CRITICAL]=%d want 1", r.Suppressed["CRITICAL"])
	}
}

func TestAllowlistCanClearGate(t *testing.T) {
	findings := []Finding{f("CVE-X", Critical)}
	r := Classify(findings, Options{FailOn: Critical, Allowlist: []string{"CVE-X"}})
	if r.Gated {
		t.Error("only finding is allowlisted; gate must pass")
	}
	if r.Total != 0 {
		t.Errorf("Total=%d want 0 after suppression", r.Total)
	}
}

func TestParseDump(t *testing.T) {
	dump := `{
	  "repositoryName": "my-service",
	  "imageId": {"imageTag": "abc123"},
	  "imageScanStatus": {"status": "COMPLETE"},
	  "imageScanFindings": {
	    "findings": [
	      {"name": "CVE-2024-1111", "severity": "CRITICAL", "uri": "http://x",
	       "attributes": [{"key":"package_name","value":"openssl"},{"key":"package_version","value":"1.1.1"}]},
	      {"name": "CVE-2024-2222", "severity": "medium", "attributes": []}
	    ]
	  }
	}`
	d, err := ParseDump(strings.NewReader(dump))
	if err != nil {
		t.Fatal(err)
	}
	if d.Repository != "my-service" || d.ImageID != "abc123" {
		t.Errorf("repo=%q img=%q", d.Repository, d.ImageID)
	}
	if d.Status != "COMPLETE" || len(d.Enhanced) != 0 {
		t.Errorf("status=%q enhanced=%d", d.Status, len(d.Enhanced))
	}
	findings := d.Basic
	if len(findings) != 2 {
		t.Fatalf("len=%d want 2", len(findings))
	}
	if findings[0].Severity != Critical || findings[0].Package != "openssl" || findings[0].Version != "1.1.1" {
		t.Errorf("bad first finding: %+v", findings[0])
	}
	if findings[1].Severity != Medium {
		t.Errorf("second severity=%v want MEDIUM", findings[1].Severity)
	}
}

func TestRenderJSONStable(t *testing.T) {
	r := Classify([]Finding{f("CVE-1", Critical)}, Options{FailOn: High, Repository: "r", ImageID: "t"})
	var b bytes.Buffer
	if err := RenderJSON(&b, r); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if !strings.Contains(out, `"gated": true`) || !strings.Contains(out, `"CRITICAL": 1`) {
		t.Errorf("unexpected json: %s", out)
	}
}

func TestRenderTable(t *testing.T) {
	r := Classify([]Finding{f("CVE-1", Critical), f("CVE-2", Low)}, Options{FailOn: High, TopN: 5})
	var b bytes.Buffer
	if err := RenderTable(&b, r); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"CRITICAL", "TOTAL", "Top findings", "FAILED"} {
		if !strings.Contains(out, want) {
			t.Errorf("table missing %q:\n%s", want, out)
		}
	}
}
