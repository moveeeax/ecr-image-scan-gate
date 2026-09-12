// Package cli wires the cobra command tree for ecr-image-scan-gate.
package cli

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/moveeeax/ecr-image-scan-gate/internal/awsecr"
	"github.com/moveeeax/ecr-image-scan-gate/internal/gate"
)

// version is overridden at build time via -ldflags.
var version = "dev"

// NewRootCmd builds the root command.
func NewRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "ecr-image-scan-gate",
		Short:         "Gate CI on Amazon ECR image scan findings",
		SilenceUsage:  true,
		SilenceErrors: false,
		Version:       version,
	}
	root.AddCommand(newScanCmd())
	return root
}

type scanFlags struct {
	repo      string
	tag       string
	digest    string
	region    string
	input     string
	output    string
	failOn    string
	topN      int
	allowlist []string
}

func newScanCmd() *cobra.Command {
	var fl scanFlags
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Summarize ECR scan findings and gate on severity",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runScan(cmd.Context(), cmd, fl)
		},
	}
	f := cmd.Flags()
	f.StringVar(&fl.repo, "repo", "", "ECR repository name (live mode)")
	f.StringVar(&fl.tag, "tag", "", "image tag (live mode)")
	f.StringVar(&fl.digest, "digest", "", "image digest, e.g. sha256:... (live mode)")
	f.StringVar(&fl.region, "region", "", "AWS region (defaults to ambient config)")
	f.StringVar(&fl.input, "input", "", "read a describe-image-scan-findings JSON dump instead of calling AWS")
	f.StringVarP(&fl.output, "output", "o", "table", "output format: table|json")
	f.StringVar(&fl.failOn, "fail-on", "high", "gate severity: critical|high|medium|low|informational|undefined")
	f.IntVar(&fl.topN, "top", 10, "number of top findings to list")
	f.StringSliceVar(&fl.allowlist, "allow", nil, "CVE ids to allowlist (repeatable or comma-separated)")
	return cmd
}

func runScan(ctx context.Context, cmd *cobra.Command, fl scanFlags) error {
	failOn, err := gate.ParseThreshold(fl.failOn)
	if err != nil {
		return err
	}
	if fl.output != "table" && fl.output != "json" {
		return fmt.Errorf("unknown output %q (want table or json)", fl.output)
	}

	var (
		findings []gate.Finding
		repo     = fl.repo
		imageID  = fl.tag
	)
	if imageID == "" {
		imageID = fl.digest
	}

	switch {
	case fl.input != "":
		fs, r, img, perr := readDump(fl.input)
		if perr != nil {
			return perr
		}
		findings = fs
		if repo == "" {
			repo = r
		}
		if imageID == "" {
			imageID = img
		}
	case fl.repo != "" && (fl.tag != "" || fl.digest != ""):
		client, cerr := awsecr.New(ctx, fl.region)
		if cerr != nil {
			return cerr
		}
		fs, ref, ferr := client.Fetch(ctx, fl.repo, fl.tag, fl.digest)
		if ferr != nil {
			return ferr
		}
		findings = fs
		if imageID == "" {
			imageID = ref
		}
	default:
		return fmt.Errorf("provide --input <dump.json>, or --repo with --tag/--digest for live mode")
	}

	rep := gate.Classify(findings, gate.Options{
		FailOn:     failOn,
		TopN:       fl.topN,
		Allowlist:  splitAll(fl.allowlist),
		Repository: repo,
		ImageID:    imageID,
	})

	w := cmd.OutOrStdout()
	if fl.output == "json" {
		if err := gate.RenderJSON(w, rep); err != nil {
			return err
		}
	} else {
		if err := gate.RenderTable(w, rep); err != nil {
			return err
		}
	}

	if rep.Gated {
		// Distinct exit code so CI can tell a tripped gate (1) from a
		// usage/runtime error (2).
		os.Exit(1)
	}
	return nil
}

func readDump(path string) ([]gate.Finding, string, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, "", "", err
	}
	defer f.Close()
	return gate.ParseDump(f)
}

// splitAll normalizes an allowlist that may arrive as comma-joined values.
func splitAll(in []string) []string {
	var out []string
	for _, v := range in {
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
	}
	return out
}
