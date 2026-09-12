package cli

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestScanJSONPassing(t *testing.T) {
	// A dump whose worst finding is MEDIUM: --fail-on critical passes and the
	// command returns without hitting the os.Exit gate.
	dump := `{"repositoryName":"r","imageId":{"imageTag":"t"},"imageScanFindings":{"findings":[
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
	dump := `{"repositoryName":"r","imageId":{"imageTag":"t"},"imageScanFindings":{"findings":[
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

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	path := t.TempDir() + "/f.json"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}
