// Package awsecr fetches image scan findings live from Amazon ECR and
// normalizes them into gate.Finding values. It is deliberately thin: all the
// classification logic lives in package gate, which stays AWS-free and
// unit-testable.
package awsecr

import (
	"context"
	"fmt"

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
}

// Client wraps an ECR API and turns paginated findings into gate.Findings.
type Client struct {
	api API
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
	return &Client{api: ecr.NewFromConfig(cfg)}, nil
}

// NewWithAPI wraps a caller-supplied API (used in tests).
func NewWithAPI(api API) *Client { return &Client{api: api} }

// Fetch pulls all scan findings for repo at the given tag or digest, following
// pagination, and returns them normalized. Exactly one of tag/digest should be
// set; if both are empty the call will fail server-side.
func (c *Client) Fetch(ctx context.Context, repo, tag, digest string) ([]gate.Finding, string, error) {
	imageID := ecrtypes.ImageIdentifier{}
	ref := ""
	if tag != "" {
		imageID.ImageTag = aws.String(tag)
		ref = tag
	}
	if digest != "" {
		imageID.ImageDigest = aws.String(digest)
		if ref == "" {
			ref = digest
		}
	}

	var findings []gate.Finding
	var next *string
	for {
		out, err := c.api.DescribeImageScanFindings(ctx, &ecr.DescribeImageScanFindingsInput{
			RepositoryName: aws.String(repo),
			ImageId:        &imageID,
			NextToken:      next,
			MaxResults:     aws.Int32(1000),
		})
		if err != nil {
			return nil, ref, fmt.Errorf("describe image scan findings: %w", err)
		}
		if out.ImageScanFindings != nil {
			for _, rf := range out.ImageScanFindings.Findings {
				findings = append(findings, normalize(rf))
			}
		}
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		next = out.NextToken
	}
	return findings, ref, nil
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
