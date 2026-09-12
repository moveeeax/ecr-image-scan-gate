package awsecr

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"

	"github.com/moveeeax/ecr-image-scan-gate/internal/gate"
)

type fakeAPI struct {
	pages []*ecr.DescribeImageScanFindingsOutput
	calls int
}

func (f *fakeAPI) DescribeImageScanFindings(ctx context.Context, in *ecr.DescribeImageScanFindingsInput, _ ...func(*ecr.Options)) (*ecr.DescribeImageScanFindingsOutput, error) {
	out := f.pages[f.calls]
	f.calls++
	return out, nil
}

func TestFetchPaginatesAndNormalizes(t *testing.T) {
	fake := &fakeAPI{pages: []*ecr.DescribeImageScanFindingsOutput{
		{
			ImageScanFindings: &ecrtypes.ImageScanFindings{
				Findings: []ecrtypes.ImageScanFinding{
					{
						Name:     aws.String("CVE-2024-1"),
						Severity: ecrtypes.FindingSeverityCritical,
						Attributes: []ecrtypes.Attribute{
							{Key: aws.String("package_name"), Value: aws.String("openssl")},
							{Key: aws.String("package_version"), Value: aws.String("1.1.1")},
						},
					},
				},
			},
			NextToken: aws.String("page2"),
		},
		{
			ImageScanFindings: &ecrtypes.ImageScanFindings{
				Findings: []ecrtypes.ImageScanFinding{
					{Name: aws.String("CVE-2024-2"), Severity: ecrtypes.FindingSeverityMedium},
				},
			},
		},
	}}

	c := NewWithAPI(fake)
	findings, ref, err := c.Fetch(context.Background(), "repo", "tagged", "")
	if err != nil {
		t.Fatal(err)
	}
	if fake.calls != 2 {
		t.Errorf("expected 2 paginated calls, got %d", fake.calls)
	}
	if ref != "tagged" {
		t.Errorf("ref=%q want tagged", ref)
	}
	if len(findings) != 2 {
		t.Fatalf("len=%d want 2", len(findings))
	}
	if findings[0].Severity != gate.Critical || findings[0].Package != "openssl" || findings[0].Version != "1.1.1" {
		t.Errorf("bad normalize: %+v", findings[0])
	}
	if findings[1].Severity != gate.Medium {
		t.Errorf("second severity=%v", findings[1].Severity)
	}
}
