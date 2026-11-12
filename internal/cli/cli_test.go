package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/moveeeax/ecr-image-scan-gate/internal/gate"
)

func TestScanJSONPassing(t *testing.T) {
	// A dump whose worst finding is MEDIUM: --fail-on critical passes and the
	// command returns without hitting the os.Exit gate.
	dump := `{"repositoryName":"r","imageId":{"imageTag":"t"},"imageScanStatus":{"status":"COMPLETE"},"imageScanFindings":{"findings":[
	  {"name":"CVE-1","severity":"MEDIUM"},{"name":"CVE-2","severity":"LOW"}]}}`
	path := writeTemp(t, dump)

	cmd := NewRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"scan", "--input", path, "--fail-on", "critical", "--output", "json"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	s := out.String()
	if !strings.Contains(s, `"gated": false`) {
		t.Errorf("expected passing gate, got: %s", s)
	}
	if !strings.Contains(s, `"MEDIUM": 1`) {
		t.Errorf("expected MEDIUM count, got: %s", s)
	}
}

func TestScanTablePassing(t *testing.T) {
	dump := `{"repositoryName":"r","imageId":{"imageTag":"t"},"imageScanStatus":{"status":"COMPLETE"},"imageScanFindings":{"findings":[
	  {"name":"CVE-1","severity":"LOW"}]}}`
	path := writeTemp(t, dump)

	cmd := NewRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"scan", "--input", path, "--fail-on", "high", "--output", "table"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	s := out.String()
	for _, want := range []string{"SEVERITY", "TOTAL", "passed"} {
		if !strings.Contains(s, want) {
			t.Errorf("table missing %q:\n%s", want, s)
		}
	}
}

func TestScanRejectsBadThreshold(t *testing.T) {
	cmd := NewRootCmd()
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"scan", "--input", "../../examples/findings.json", "--fail-on", "bogus"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error on bad --fail-on")
	}
}

func TestScanRequiresSource(t *testing.T) {
	cmd := NewRootCmd()
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"scan"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error when no input/repo given")
	}
}

func TestScanEnhancedDumpJSON(t *testing.T) {
	// Enhanced registries leave imageScanFindings.findings empty; the gate
	// must read enhancedFindings instead.
	dump := `{"repositoryName":"r","imageId":{"imageTag":"t"},"imageScanStatus":{"status":"ACTIVE"},
	  "imageScanFindings":{"enhancedFindings":[
	    {"severity":"CRITICAL","status":"ACTIVE","packageVulnerabilityDetails":{"vulnerabilityId":"CVE-9"}}]}}`
	path := writeTemp(t, dump)

	cmd := NewRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	// The CRITICAL is allowlisted so the command returns instead of calling
	// os.Exit(1); it must still show up as suppressed, which proves the
	// enhanced list was read.
	cmd.SetArgs([]string{"scan", "--input", path, "--allow", "CVE-9", "--output", "json"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	var rep gate.Report
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatalf("decode %s: %v", out.String(), err)
	}
	if rep.ScanType != "ENHANCED" || rep.ScanStatus != "ACTIVE" {
		t.Errorf("scanType=%q scanStatus=%q", rep.ScanType, rep.ScanStatus)
	}
	if rep.Suppressed["CRITICAL"] != 1 || rep.Gated {
		t.Errorf("suppressed=%v gated=%v", rep.Suppressed, rep.Gated)
	}
}

func TestScanRejects(t *testing.T) {
	inProgress := writeTemp(t, `{"repositoryName":"r","imageScanStatus":{"status":"IN_PROGRESS"},"imageScanFindings":{"findings":[]}}`)
	noStatus := writeTemp(t, `{"repositoryName":"r","imageScanFindings":{"findings":[]}}`)
	enhancedOnly := writeTemp(t, `{"repositoryName":"r","imageScanStatus":{"status":"ACTIVE"},
	  "imageScanFindings":{"enhancedFindings":[{"severity":"LOW","packageVulnerabilityDetails":{"vulnerabilityId":"CVE-1"}}]}}`)

	tests := []struct {
		name string
		args []string
		want string
	}{
		{"scan in progress", []string{"--input", inProgress}, "IN_PROGRESS"},
		{"dump without status", []string{"--input", noStatus}, "status is missing"},
		{"basic on enhanced dump", []string{"--input", enhancedOnly, "--scan-type", "basic"}, "only enhanced findings"},
		{"bad scan type", []string{"--input", enhancedOnly, "--scan-type", "inspector"}, "unknown scan type"},
		{"wait with input", []string{"--input", enhancedOnly, "--wait", "1m"}, "live mode only"},
		{"start-scan without wait", []string{"--repo", "r", "--tag", "t", "--start-scan"}, "requires --wait"},
		{"negative wait", []string{"--repo", "r", "--tag", "t", "--wait", "-1s"}, "negative"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := NewRootCmd()
			cmd.SetOut(new(bytes.Buffer))
			cmd.SetErr(new(bytes.Buffer))
			cmd.SetArgs(append([]string{"scan"}, tt.args...))
			err := cmd.Execute()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err=%v, want it to contain %q", err, tt.want)
			}
		})
	}
}

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	path := t.TempDir() + "/f.json"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}
