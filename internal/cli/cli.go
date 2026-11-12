// Package cli wires the cobra command tree for ecr-image-scan-gate.
package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

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
	scanType  string
	wait      time.Duration
	startScan bool
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
	f.StringVar(&fl.scanType, "scan-type", "auto", "findings list to gate on: auto|basic|enhanced (auto: enhanced if non-empty, else basic)")
	f.DurationVar(&fl.wait, "wait", 0, "poll up to this long until the scan is COMPLETE/ACTIVE and the finding count is stable, e.g. 10m (live mode)")
	f.BoolVar(&fl.startScan, "start-scan", false, "call ecr:StartImageScan when the image has no scan yet; requires --wait (live mode)")
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
	scanType, err := gate.ParseScanType(fl.scanType)
	if err != nil {
		return err
	}
	if fl.wait < 0 {
		return fmt.Errorf("--wait must not be negative")
	}
	if fl.input != "" && (fl.wait > 0 || fl.startScan) {
		return fmt.Errorf("--wait and --start-scan work in live mode only, not with --input")
	}
	if fl.startScan && fl.wait == 0 {
		return fmt.Errorf("--start-scan requires --wait, a new scan is never finished on the first read")
	}

	var (
		basic, enhanced []gate.Finding
		status          string
		repo            = fl.repo
		imageID         = fl.tag
	)
	if imageID == "" {
		imageID = fl.digest
	}

	switch {
	case fl.input != "":
		d, perr := readDump(fl.input)
		if perr != nil {
			return perr
		}
		basic, enhanced, status = d.Basic, d.Enhanced, d.Status
		if repo == "" {
			repo = d.Repository
		}
		if imageID == "" {
			imageID = d.ImageID
		}
	case fl.repo != "" && (fl.tag != "" || fl.digest != ""):
		client, cerr := awsecr.New(ctx, fl.region)
		if cerr != nil {
			return cerr
		}
		var res awsecr.Result
		if fl.wait > 0 {
			res, err = client.Wait(ctx, fl.repo, fl.tag, fl.digest, awsecr.WaitOptions{
				Timeout:   fl.wait,
				StartScan: fl.startScan,
			})
		} else {
			res, err = client.Fetch(ctx, fl.repo, fl.tag, fl.digest)
		}
		if err != nil {
			return err
		}
		// Fail closed: an unfinished, failed or unsupported scan has empty or
		// partial findings, so it must not pass the gate.
		if err := gate.CheckStatus(res.Status, res.StatusDescription); err != nil {
			return err
		}
		basic, enhanced, status = res.Basic, res.Enhanced, res.Status
		if imageID == "" {
			imageID = res.Ref
		}
	default:
		return fmt.Errorf("provide --input <dump.json>, or --repo with --tag/--digest for live mode")
	}

	findings, resolvedType, err := gate.SelectFindings(scanType, basic, enhanced)
	if err != nil {
		return err
	}

	rep := gate.Classify(findings, gate.Options{
		FailOn:     failOn,
		TopN:       fl.topN,
		Allowlist:  splitAll(fl.allowlist),
		Repository: repo,
		ImageID:    imageID,
		ScanType:   resolvedType,
		ScanStatus: status,
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

func readDump(path string) (gate.Dump, error) {
	f, err := os.Open(path)
	if err != nil {
		return gate.Dump{}, err
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
