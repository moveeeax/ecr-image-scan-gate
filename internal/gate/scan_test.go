package gate

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

const enhancedDump = `{
  "repositoryName": "my-service",
  "imageId": {"imageDigest": "sha256:abc"},
  "imageScanStatus": {"status": "ACTIVE", "description": "Continuous scan is selected for image."},
  "imageScanFindings": {
    "enhancedFindings": [
      {
        "title": "CVE-2023-0464 - openssl",
        "severity": "HIGH",
        "status": "ACTIVE",
        "fixAvailable": "YES",
        "score": 7.5,
        "packageVulnerabilityDetails": {
          "vulnerabilityId": "CVE-2023-0464",
          "sourceUrl": "https://nvd.nist.gov/vuln/detail/CVE-2023-0464",
          "vulnerablePackages": [
            {"name": "openssl", "version": "3.0.7"},
            {"name": "libssl3", "version": "3.0.7"}
          ]
        }
      },
      {
        "title": "untriaged finding",
        "severity": "UNTRIAGED",
        "status": "ACTIVE",
        "packageVulnerabilityDetails": {"vulnerablePackages": []}
      }
    ]
  }
}`

func TestParseDumpEnhanced(t *testing.T) {
	d, err := ParseDump(strings.NewReader(enhancedDump))
	if err != nil {
		t.Fatal(err)
	}
	if d.ImageID != "sha256:abc" || d.Status != "ACTIVE" {
		t.Errorf("img=%q status=%q", d.ImageID, d.Status)
	}
	if len(d.Basic) != 0 || len(d.Enhanced) != 2 {
		t.Fatalf("basic=%d enhanced=%d want 0/2", len(d.Basic), len(d.Enhanced))
	}
	got := d.Enhanced[0]
	want := Finding{
		Name: "CVE-2023-0464", Severity: High, Package: "openssl", Version: "3.0.7",
		URI: "https://nvd.nist.gov/vuln/detail/CVE-2023-0464", FixAvailable: "YES", Score: 7.5, Status: "ACTIVE",
	}
	if got != want {
		t.Errorf("enhanced[0]=%+v\nwant        %+v", got, want)
	}
	// No vulnerability id: named by title. UNTRIAGED is not an ECR severity.
	if d.Enhanced[1].Name != "untriaged finding" || d.Enhanced[1].Severity != Undefined {
		t.Errorf("enhanced[1]=%+v", d.Enhanced[1])
	}
}

func TestParseDumpFailsClosedOnStatus(t *testing.T) {
	tests := []struct {
		name, status string
	}{
		{"in progress", `"imageScanStatus": {"status": "IN_PROGRESS"},`},
		{"failed", `"imageScanStatus": {"status": "FAILED", "description": "boom"},`},
		{"unsupported", `"imageScanStatus": {"status": "UNSUPPORTED_IMAGE"},`},
		{"missing", ``},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dump := `{"repositoryName":"r",` + tt.status + `"imageScanFindings":{"findings":[]}}`
			_, err := ParseDump(strings.NewReader(dump))
			var se *ScanStatusError
			if !errors.As(err, &se) {
				t.Fatalf("err=%v, want *ScanStatusError", err)
			}
		})
	}
}

func TestScanStatusErrorMessage(t *testing.T) {
	msg := CheckStatus("in_progress", "").Error()
	if !strings.Contains(msg, "IN_PROGRESS") || !strings.Contains(msg, "--wait") {
		t.Errorf("pending message should name status and --wait: %q", msg)
	}
	msg = CheckStatus("FAILED", "Unable to scan").Error()
	if !strings.Contains(msg, "FAILED") || !strings.Contains(msg, "Unable to scan") || strings.Contains(msg, "--wait") {
		t.Errorf("failed message: %q", msg)
	}
	if CheckStatus("COMPLETE", "") != nil || CheckStatus("active", "") != nil {
		t.Error("COMPLETE and ACTIVE are ready")
	}
}

func TestParseScanType(t *testing.T) {
	for in, want := range map[string]ScanType{"auto": ScanTypeAuto, "BASIC": ScanTypeBasic, " enhanced ": ScanTypeEnhanced} {
		got, err := ParseScanType(in)
		if err != nil || got != want {
			t.Errorf("ParseScanType(%q)=%q,%v want %q", in, got, err, want)
		}
	}
	if _, err := ParseScanType("inspector"); err == nil {
		t.Error("unknown scan type should error")
	}
}

func TestSelectFindings(t *testing.T) {
	basic := []Finding{f("CVE-B", Low)}
	enhanced := []Finding{f("CVE-E", High)}

	tests := []struct {
		name            string
		t               ScanType
		basic, enhanced []Finding
		wantName        string // first finding, "" for none
		wantType        string
		wantErr         bool
	}{
		{"auto prefers enhanced", ScanTypeAuto, basic, enhanced, "CVE-E", "ENHANCED", false},
		{"auto falls back to basic", ScanTypeAuto, basic, nil, "CVE-B", "BASIC", false},
		{"auto with nothing", ScanTypeAuto, nil, nil, "", "", false},
		{"basic", ScanTypeBasic, basic, nil, "CVE-B", "BASIC", false},
		{"basic empty clean", ScanTypeBasic, nil, nil, "", "BASIC", false},
		{"basic on enhanced registry", ScanTypeBasic, nil, enhanced, "", "", true},
		{"enhanced", ScanTypeEnhanced, nil, enhanced, "CVE-E", "ENHANCED", false},
		{"enhanced on basic registry", ScanTypeEnhanced, basic, nil, "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, typ, err := SelectFindings(tt.t, tt.basic, tt.enhanced)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tt.wantErr)
			}
			if typ != tt.wantType {
				t.Errorf("type=%q want %q", typ, tt.wantType)
			}
			name := ""
			if len(got) > 0 {
				name = got[0].Name
			}
			if name != tt.wantName {
				t.Errorf("first=%q want %q", name, tt.wantName)
			}
		})
	}
}

func TestClassifyInspectorStatus(t *testing.T) {
	findings := []Finding{
		{Name: "CVE-A", Severity: Critical, Status: "CLOSED"},
		{Name: "CVE-B", Severity: Critical, Status: "SUPPRESSED"},
		{Name: "CVE-C", Severity: Medium, Status: "ACTIVE"},
	}
	r := Classify(findings, Options{FailOn: High})
	if r.Gated {
		t.Error("closed and suppressed CRITICALs must not trip the gate")
	}
	if r.Total != 1 || r.Counts["MEDIUM"] != 1 || r.Counts["CRITICAL"] != 0 {
		t.Errorf("total=%d counts=%v", r.Total, r.Counts)
	}
	if r.Suppressed["CRITICAL"] != 1 {
		t.Errorf("suppressed=%v want CRITICAL:1", r.Suppressed)
	}
}

func TestRenderScanTypeAndFix(t *testing.T) {
	d, err := ParseDump(strings.NewReader(enhancedDump))
	if err != nil {
		t.Fatal(err)
	}
	fs, typ, err := SelectFindings(ScanTypeAuto, d.Basic, d.Enhanced)
	if err != nil {
		t.Fatal(err)
	}
	r := Classify(fs, Options{FailOn: High, ScanType: typ, ScanStatus: d.Status})

	var tb bytes.Buffer
	if err := RenderTable(&tb, r); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Scan: ENHANCED (ACTIVE)", "FIX", "openssl 3.0.7", "YES"} {
		if !strings.Contains(tb.String(), want) {
			t.Errorf("table missing %q:\n%s", want, tb.String())
		}
	}

	var jb bytes.Buffer
	if err := RenderJSON(&jb, r); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"scanType": "ENHANCED"`, `"scanStatus": "ACTIVE"`, `"fixAvailable": "YES"`, `"score": 7.5`} {
		if !strings.Contains(jb.String(), want) {
			t.Errorf("json missing %q:\n%s", want, jb.String())
		}
	}
}

func TestRenderTableBasicHasNoFixColumn(t *testing.T) {
	r := Classify([]Finding{f("CVE-1", High)}, Options{FailOn: High, ScanType: "BASIC", ScanStatus: "COMPLETE"})
	var b bytes.Buffer
	if err := RenderTable(&b, r); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "Scan: BASIC (COMPLETE)") || strings.Contains(b.String(), "FIX") {
		t.Errorf("unexpected table:\n%s", b.String())
	}
}
