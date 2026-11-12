// Package awsecr fetches image scan findings live from Amazon ECR and
// normalizes them into gate.Finding values. It is deliberately thin: all the
// classification logic lives in package gate, which stays AWS-free and
// unit-testable.
package awsecr

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"

	"github.com/moveeeax/ecr-image-scan-gate/internal/gate"
)

// API is the subset of the ECR client this package uses. Defining it as an
// interface lets tests inject a fake without touching AWS.
type API interface {
	DescribeImageScanFindings(ctx context.Context, in *ecr.DescribeImageScanFindingsInput, optFns ...func(*ecr.Options)) (*ecr.DescribeImageScanFindingsOutput, error)
	StartImageScan(ctx context.Context, in *ecr.StartImageScanInput, optFns ...func(*ecr.Options)) (*ecr.StartImageScanOutput, error)
}

// Client wraps an ECR API and turns paginated findings into gate.Findings.
type Client struct {
	api API
	// sleep waits between polls; tests replace it to avoid real delays.
	sleep func(ctx context.Context, d time.Duration) error
}

// New builds a Client from the default AWS config chain (env, shared config,
// IAM role). region may be empty to use the ambient default.
func New(ctx context.Context, region string) (*Client, error) {
	var opts []func(*awsconfig.LoadOptions) error
	if region != "" {
		opts = append(opts, awsconfig.WithRegion(region))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}
	return NewWithAPI(ecr.NewFromConfig(cfg)), nil
}

// NewWithAPI wraps a caller-supplied API (used in tests).
func NewWithAPI(api API) *Client {
	return &Client{api: api, sleep: sleepCtx}
}

// Result is one complete (all pages) read of an image's scan findings.
type Result struct {
	Ref               string // the tag or digest the caller asked for
	Status            string // imageScanStatus.status
	StatusDescription string
	Basic             []gate.Finding // imageScanFindings.findings
	Enhanced          []gate.Finding // imageScanFindings.enhancedFindings
}

// Fetch pulls all scan findings for repo at the given tag or digest, following
// pagination, and returns them normalized together with the scan status.
// Exactly one of tag/digest should be set; if both are empty the call will
// fail server-side. Fetch does not judge the status; callers use
// gate.CheckStatus.
func (c *Client) Fetch(ctx context.Context, repo, tag, digest string) (Result, error) {
	imageID := ecrtypes.ImageIdentifier{}
	res := Result{}
	if tag != "" {
		imageID.ImageTag = aws.String(tag)
		res.Ref = tag
	}
	if digest != "" {
		imageID.ImageDigest = aws.String(digest)
		if res.Ref == "" {
			res.Ref = digest
		}
	}

	var next *string
	for {
		out, err := c.api.DescribeImageScanFindings(ctx, &ecr.DescribeImageScanFindingsInput{
			RepositoryName: aws.String(repo),
			ImageId:        &imageID,
			NextToken:      next,
			MaxResults:     aws.Int32(1000),
		})
		if err != nil {
			return res, fmt.Errorf("describe image scan findings: %w", err)
		}
		if out.ImageScanStatus != nil {
			res.Status = string(out.ImageScanStatus.Status)
			res.StatusDescription = aws.ToString(out.ImageScanStatus.Description)
		}
		if out.ImageScanFindings != nil {
			for _, rf := range out.ImageScanFindings.Findings {
				res.Basic = append(res.Basic, normalize(rf))
			}
			for _, ef := range out.ImageScanFindings.EnhancedFindings {
				res.Enhanced = append(res.Enhanced, normalizeEnhanced(ef))
			}
		}
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		next = out.NextToken
	}
	return res, nil
}

// WaitOptions configure Wait.
type WaitOptions struct {
	// Timeout bounds the whole wait, including the stability re-polls.
	Timeout time.Duration
	// StartScan calls ecr:StartImageScan when no scan exists for the image.
	StartScan bool
	// Interval is the first delay between polls (default 5s). Each poll
	// multiplies it by 1.5 up to MaxInterval (default 30s).
	Interval    time.Duration
	MaxInterval time.Duration
}

// Wait polls the scan until its status is COMPLETE or ACTIVE, then keeps
// polling until the number of findings is the same on two consecutive polls,
// because Amazon Inspector publishes enhanced findings gradually after the
// status turns ACTIVE.
//
// It returns the last Result as soon as the status is terminal and not ready
// (FAILED, UNSUPPORTED_IMAGE, ...), leaving the verdict to gate.CheckStatus.
// It returns an error when no scan exists (unless StartScan is set) and when
// the timeout passes first; the timeout error names the last status seen.
func (c *Client) Wait(ctx context.Context, repo, tag, digest string, opts WaitOptions) (Result, error) {
	interval := opts.Interval
	if interval <= 0 {
		interval = 5 * time.Second
	}
	maxInterval := opts.MaxInterval
	if maxInterval <= 0 {
		maxInterval = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	started := false
	lastCount := -1 // findings count of the previous ready poll
	var last Result
	for {
		res, err := c.Fetch(ctx, repo, tag, digest)
		var notFound *ecrtypes.ScanNotFoundException
		switch {
		case errors.As(err, &notFound) && opts.StartScan && !started:
			if serr := c.startScan(ctx, repo, tag, digest); serr != nil {
				return res, serr
			}
			started = true
			res.Status = gate.StatusPending
		case errors.As(err, &notFound) && started:
			// The scan was just requested and is not visible yet.
			res.Status = gate.StatusPending
		case err != nil:
			if ctx.Err() != nil {
				return last, timeoutError(opts.Timeout, last)
			}
			return res, err
		}
		last = res

		switch {
		case gate.IsReadyStatus(res.Status):
			count := len(res.Basic) + len(res.Enhanced)
			if count == lastCount {
				return res, nil
			}
			lastCount = count
		case gate.IsPendingStatus(res.Status):
			lastCount = -1
		default:
			// Terminal and not ready: nothing to wait for.
			return res, nil
		}

		if err := c.sleep(ctx, interval); err != nil {
			return last, timeoutError(opts.Timeout, last)
		}
		interval = min(interval*3/2, maxInterval)
	}
}

func (c *Client) startScan(ctx context.Context, repo, tag, digest string) error {
	imageID := &ecrtypes.ImageIdentifier{}
	if tag != "" {
		imageID.ImageTag = aws.String(tag)
	}
	if digest != "" {
		imageID.ImageDigest = aws.String(digest)
	}
	_, err := c.api.StartImageScan(ctx, &ecr.StartImageScanInput{
		RepositoryName: aws.String(repo),
		ImageId:        imageID,
	})
	if err != nil {
		return fmt.Errorf("start image scan: %w", err)
	}
	return nil
}

func timeoutError(timeout time.Duration, last Result) error {
	status := last.Status
	if status == "" {
		status = "unknown"
	}
	msg := fmt.Sprintf("timed out after %s waiting for the scan: last status %s", timeout, status)
	if last.StatusDescription != "" {
		msg += ": " + last.StatusDescription
	}
	if gate.IsReadyStatus(last.Status) {
		msg += " (finding count still changing)"
	}
	return errors.New(msg)
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func normalize(rf ecrtypes.ImageScanFinding) gate.Finding {
	f := gate.Finding{
		Severity: gate.ParseSeverity(string(rf.Severity)),
	}
	if rf.Name != nil {
		f.Name = *rf.Name
	}
	if rf.Uri != nil {
		f.URI = *rf.Uri
	}
	if rf.Description != nil {
		f.Description = *rf.Description
	}
	for _, a := range rf.Attributes {
		if a.Key == nil || a.Value == nil {
			continue
		}
		switch *a.Key {
		case "package_name":
			f.Package = *a.Value
		case "package_version":
			f.Version = *a.Value
		}
	}
	return f
}

func normalizeEnhanced(ef ecrtypes.EnhancedImageScanFinding) gate.Finding {
	e := gate.EnhancedFields{
		Title:        aws.ToString(ef.Title),
		Severity:     aws.ToString(ef.Severity),
		Status:       aws.ToString(ef.Status),
		FixAvailable: aws.ToString(ef.FixAvailable),
		Score:        ef.Score,
		Description:  aws.ToString(ef.Description),
	}
	if pv := ef.PackageVulnerabilityDetails; pv != nil {
		e.VulnerabilityID = aws.ToString(pv.VulnerabilityId)
		e.SourceURL = aws.ToString(pv.SourceUrl)
		for _, p := range pv.VulnerablePackages {
			e.PackageNames = append(e.PackageNames, aws.ToString(p.Name))
			e.PackageVersions = append(e.PackageVersions, aws.ToString(p.Version))
		}
	}
	return gate.NewEnhancedFinding(e)
}
