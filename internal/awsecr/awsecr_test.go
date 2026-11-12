package awsecr

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"

	"github.com/moveeeax/ecr-image-scan-gate/internal/gate"
)

// fakeAPI returns pages in order. A nil page with a non-nil entry in errs
// returns that error instead. The last page repeats once the list is used up.
type fakeAPI struct {
	pages      []*ecr.DescribeImageScanFindingsOutput
	errs       []error
	calls      int
	startCalls int
	startErr   error
}

func (f *fakeAPI) DescribeImageScanFindings(ctx context.Context, in *ecr.DescribeImageScanFindingsInput, _ ...func(*ecr.Options)) (*ecr.DescribeImageScanFindingsOutput, error) {
	i := min(f.calls, len(f.pages)-1)
	f.calls++
	if i < len(f.errs) && f.errs[i] != nil {
		return nil, f.errs[i]
	}
	return f.pages[i], nil
}

func (f *fakeAPI) StartImageScan(ctx context.Context, in *ecr.StartImageScanInput, _ ...func(*ecr.Options)) (*ecr.StartImageScanOutput, error) {
	f.startCalls++
	return &ecr.StartImageScanOutput{}, f.startErr
}

func status(s ecrtypes.ScanStatus) *ecrtypes.ImageScanStatus {
	return &ecrtypes.ImageScanStatus{Status: s}
}

func basicPage(st ecrtypes.ScanStatus, names ...string) *ecr.DescribeImageScanFindingsOutput {
	out := &ecr.DescribeImageScanFindingsOutput{
		ImageScanStatus:   status(st),
		ImageScanFindings: &ecrtypes.ImageScanFindings{},
	}
	for _, n := range names {
		out.ImageScanFindings.Findings = append(out.ImageScanFindings.Findings,
			ecrtypes.ImageScanFinding{Name: aws.String(n), Severity: ecrtypes.FindingSeverityHigh})
	}
	return out
}

func enhancedPage(st ecrtypes.ScanStatus, n int) *ecr.DescribeImageScanFindingsOutput {
	out := &ecr.DescribeImageScanFindingsOutput{
		ImageScanStatus:   status(st),
		ImageScanFindings: &ecrtypes.ImageScanFindings{},
	}
	for range n {
		out.ImageScanFindings.EnhancedFindings = append(out.ImageScanFindings.EnhancedFindings,
			ecrtypes.EnhancedImageScanFinding{Severity: aws.String("HIGH"), Status: aws.String("ACTIVE")})
	}
	return out
}

// newTestClient returns a client whose sleep records delays instead of
// sleeping, but still honors context cancellation.
func newTestClient(api API, slept *[]time.Duration) *Client {
	c := NewWithAPI(api)
	c.sleep = func(ctx context.Context, d time.Duration) error {
		*slept = append(*slept, d)
		return ctx.Err()
	}
	return c
}

func TestFetchPaginatesAndNormalizes(t *testing.T) {
	fake := &fakeAPI{pages: []*ecr.DescribeImageScanFindingsOutput{
		{
			ImageScanStatus: status(ecrtypes.ScanStatusComplete),
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
			ImageScanStatus: status(ecrtypes.ScanStatusComplete),
			ImageScanFindings: &ecrtypes.ImageScanFindings{
				Findings: []ecrtypes.ImageScanFinding{
					{Name: aws.String("CVE-2024-2"), Severity: ecrtypes.FindingSeverityMedium},
				},
			},
		},
	}}

	c := NewWithAPI(fake)
	res, err := c.Fetch(context.Background(), "repo", "tagged", "")
	if err != nil {
		t.Fatal(err)
	}
	if fake.calls != 2 {
		t.Errorf("expected 2 paginated calls, got %d", fake.calls)
	}
	if res.Ref != "tagged" || res.Status != "COMPLETE" {
		t.Errorf("ref=%q status=%q", res.Ref, res.Status)
	}
	findings := res.Basic
	if len(findings) != 2 || len(res.Enhanced) != 0 {
		t.Fatalf("basic=%d enhanced=%d want 2/0", len(findings), len(res.Enhanced))
	}
	if findings[0].Severity != gate.Critical || findings[0].Package != "openssl" || findings[0].Version != "1.1.1" {
		t.Errorf("bad normalize: %+v", findings[0])
	}
	if findings[1].Severity != gate.Medium {
		t.Errorf("second severity=%v", findings[1].Severity)
	}
}

func TestFetchNormalizesEnhanced(t *testing.T) {
	fake := &fakeAPI{pages: []*ecr.DescribeImageScanFindingsOutput{{
		ImageScanStatus: &ecrtypes.ImageScanStatus{Status: ecrtypes.ScanStatusActive, Description: aws.String("Continuous scan")},
		ImageScanFindings: &ecrtypes.ImageScanFindings{
			EnhancedFindings: []ecrtypes.EnhancedImageScanFinding{{
				Title:        aws.String("CVE-2023-0464 - openssl"),
				Severity:     aws.String("CRITICAL"),
				Status:       aws.String("ACTIVE"),
				FixAvailable: aws.String("PARTIAL"),
				Score:        9.8,
				PackageVulnerabilityDetails: &ecrtypes.PackageVulnerabilityDetails{
					VulnerabilityId: aws.String("CVE-2023-0464"),
					SourceUrl:       aws.String("https://nvd.nist.gov/vuln/detail/CVE-2023-0464"),
					VulnerablePackages: []ecrtypes.VulnerablePackage{
						{Name: aws.String("openssl"), Version: aws.String("3.0.7")},
					},
				},
			}},
		},
	}}}

	res, err := NewWithAPI(fake).Fetch(context.Background(), "repo", "", "sha256:abc")
	if err != nil {
		t.Fatal(err)
	}
	if res.Ref != "sha256:abc" || res.Status != "ACTIVE" || res.StatusDescription != "Continuous scan" {
		t.Errorf("ref=%q status=%q desc=%q", res.Ref, res.Status, res.StatusDescription)
	}
	if len(res.Enhanced) != 1 {
		t.Fatalf("enhanced=%d want 1", len(res.Enhanced))
	}
	want := gate.Finding{
		Name: "CVE-2023-0464", Severity: gate.Critical, Package: "openssl", Version: "3.0.7",
		URI: "https://nvd.nist.gov/vuln/detail/CVE-2023-0464", FixAvailable: "PARTIAL", Score: 9.8, Status: "ACTIVE",
	}
	if res.Enhanced[0] != want {
		t.Errorf("got  %+v\nwant %+v", res.Enhanced[0], want)
	}
}

func TestWaitPollsUntilCompleteAndStable(t *testing.T) {
	fake := &fakeAPI{pages: []*ecr.DescribeImageScanFindingsOutput{
		basicPage(ecrtypes.ScanStatusInProgress),
		basicPage(ecrtypes.ScanStatusInProgress),
		basicPage(ecrtypes.ScanStatusComplete, "CVE-1"),
		basicPage(ecrtypes.ScanStatusComplete, "CVE-1"),
	}}
	var slept []time.Duration
	c := newTestClient(fake, &slept)

	res, err := c.Wait(context.Background(), "repo", "t", "", WaitOptions{
		Timeout: time.Minute, Interval: 2 * time.Second, MaxInterval: 3 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "COMPLETE" || len(res.Basic) != 1 {
		t.Errorf("status=%q basic=%d", res.Status, len(res.Basic))
	}
	if fake.calls != 4 {
		t.Errorf("calls=%d want 4 (2 in progress, 2 stable)", fake.calls)
	}
	// Backoff grows by 1.5x and is capped at MaxInterval.
	want := []time.Duration{2 * time.Second, 3 * time.Second, 3 * time.Second}
	if len(slept) != len(want) {
		t.Fatalf("slept=%v want %v", slept, want)
	}
	for i := range want {
		if slept[i] != want[i] {
			t.Errorf("slept=%v want %v", slept, want)
			break
		}
	}
}

func TestWaitRepollsWhileEnhancedFindingsTrickleIn(t *testing.T) {
	fake := &fakeAPI{pages: []*ecr.DescribeImageScanFindingsOutput{
		enhancedPage(ecrtypes.ScanStatusActive, 0),
		enhancedPage(ecrtypes.ScanStatusActive, 3),
		enhancedPage(ecrtypes.ScanStatusActive, 5),
		enhancedPage(ecrtypes.ScanStatusActive, 5),
	}}
	var slept []time.Duration
	res, err := newTestClient(fake, &slept).Wait(context.Background(), "repo", "t", "", WaitOptions{Timeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Enhanced) != 5 || fake.calls != 4 {
		t.Errorf("enhanced=%d calls=%d want 5/4", len(res.Enhanced), fake.calls)
	}
}

func TestWaitReturnsTerminalStatus(t *testing.T) {
	failed := basicPage(ecrtypes.ScanStatusFailed)
	failed.ImageScanStatus.Description = aws.String("UnsupportedImageError")
	fake := &fakeAPI{pages: []*ecr.DescribeImageScanFindingsOutput{basicPage(ecrtypes.ScanStatusInProgress), failed}}
	var slept []time.Duration
	res, err := newTestClient(fake, &slept).Wait(context.Background(), "repo", "t", "", WaitOptions{Timeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if fake.calls != 2 {
		t.Errorf("calls=%d want 2, FAILED must stop the wait", fake.calls)
	}
	var se *gate.ScanStatusError
	if !errors.As(gate.CheckStatus(res.Status, res.StatusDescription), &se) || se.Status != "FAILED" {
		t.Errorf("CheckStatus on %q should fail", res.Status)
	}
}

func TestWaitStartsScanWhenNoneExists(t *testing.T) {
	notFound := &ecrtypes.ScanNotFoundException{Message: aws.String("no scan")}
	fake := &fakeAPI{
		pages: []*ecr.DescribeImageScanFindingsOutput{nil, nil, basicPage(ecrtypes.ScanStatusInProgress), basicPage(ecrtypes.ScanStatusComplete)},
		errs:  []error{notFound, notFound},
	}
	var slept []time.Duration
	res, err := newTestClient(fake, &slept).Wait(context.Background(), "repo", "t", "", WaitOptions{Timeout: time.Minute, StartScan: true})
	if err != nil {
		t.Fatal(err)
	}
	if fake.startCalls != 1 {
		t.Errorf("StartImageScan calls=%d want 1", fake.startCalls)
	}
	if res.Status != "COMPLETE" {
		t.Errorf("status=%q want COMPLETE", res.Status)
	}
}

func TestWaitWithoutStartScanFailsOnMissingScan(t *testing.T) {
	fake := &fakeAPI{
		pages: []*ecr.DescribeImageScanFindingsOutput{nil},
		errs:  []error{&ecrtypes.ScanNotFoundException{Message: aws.String("no scan")}},
	}
	var slept []time.Duration
	_, err := newTestClient(fake, &slept).Wait(context.Background(), "repo", "t", "", WaitOptions{Timeout: time.Minute})
	var nf *ecrtypes.ScanNotFoundException
	if !errors.As(err, &nf) {
		t.Fatalf("err=%v, want ScanNotFoundException", err)
	}
	if fake.startCalls != 0 {
		t.Error("StartImageScan must not be called without StartScan")
	}
}

func TestWaitStartScanError(t *testing.T) {
	fake := &fakeAPI{
		pages:    []*ecr.DescribeImageScanFindingsOutput{nil},
		errs:     []error{&ecrtypes.ScanNotFoundException{}},
		startErr: &ecrtypes.LimitExceededException{Message: aws.String("one scan per 24h")},
	}
	var slept []time.Duration
	_, err := newTestClient(fake, &slept).Wait(context.Background(), "repo", "t", "", WaitOptions{Timeout: time.Minute, StartScan: true})
	if err == nil || !strings.Contains(err.Error(), "start image scan") {
		t.Fatalf("err=%v, want start image scan error", err)
	}
}

func TestWaitTimesOut(t *testing.T) {
	fake := &fakeAPI{pages: []*ecr.DescribeImageScanFindingsOutput{basicPage(ecrtypes.ScanStatusInProgress)}}
	c := NewWithAPI(fake) // real sleep, short timeout
	_, err := c.Wait(context.Background(), "repo", "t", "", WaitOptions{
		Timeout: 50 * time.Millisecond, Interval: 5 * time.Millisecond, MaxInterval: 10 * time.Millisecond,
	})
	if err == nil {
		t.Fatal("expected timeout error")
	}
	for _, want := range []string{"timed out after 50ms", "IN_PROGRESS"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err, want)
		}
	}
	if fake.calls < 2 {
		t.Errorf("calls=%d, expected several polls before timing out", fake.calls)
	}
}
