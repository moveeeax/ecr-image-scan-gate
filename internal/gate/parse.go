package gate

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// rawScanDump mirrors the shape of `aws ecr describe-image-scan-findings`
// output closely enough to parse the fields the gate needs.
type rawScanDump struct {
	RepositoryName string `json:"repositoryName"`
	ImageID        struct {
		ImageTag    string `json:"imageTag"`
		ImageDigest string `json:"imageDigest"`
	} `json:"imageId"`
	ImageScanStatus struct {
		Status      string `json:"status"`
		Description string `json:"description"`
	} `json:"imageScanStatus"`
	ImageScanFindings struct {
		Findings         []rawFinding         `json:"findings"`
		EnhancedFindings []rawEnhancedFinding `json:"enhancedFindings"`
	} `json:"imageScanFindings"`
}

type rawFinding struct {
	Name       string `json:"name"`
	Severity   string `json:"severity"`
	URI        string `json:"uri"`
	Attributes []struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	} `json:"attributes"`
}

// rawEnhancedFinding is an Amazon Inspector finding as returned in
// imageScanFindings.enhancedFindings.
type rawEnhancedFinding struct {
	Title                       string  `json:"title"`
	Description                 string  `json:"description"`
	Severity                    string  `json:"severity"`
	Status                      string  `json:"status"`
	FixAvailable                string  `json:"fixAvailable"`
	Score                       float64 `json:"score"`
	PackageVulnerabilityDetails struct {
		VulnerabilityID    string `json:"vulnerabilityId"`
		SourceURL          string `json:"sourceUrl"`
		VulnerablePackages []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"vulnerablePackages"`
	} `json:"packageVulnerabilityDetails"`
}

// Dump is a parsed describe-image-scan-findings response. Basic and Enhanced
// hold the two findings lists; SelectFindings picks the one to gate on.
type Dump struct {
	Repository        string
	ImageID           string
	Status            string
	StatusDescription string
	Basic             []Finding
	Enhanced          []Finding
}

// ParseDump reads a describe-image-scan-findings JSON dump and returns the
// normalized findings plus the repository and image id it references, so the
// classifier core can run entirely offline with no AWS calls.
//
// It fails closed on the scan status: a dump whose imageScanStatus.status is
// missing or anything other than COMPLETE/ACTIVE returns a *ScanStatusError,
// because its findings are empty or partial.
func ParseDump(r io.Reader) (Dump, error) {
	var raw rawScanDump
	dec := json.NewDecoder(r)
	if err := dec.Decode(&raw); err != nil {
		return Dump{}, fmt.Errorf("parse scan dump: %w", err)
	}

	d := Dump{
		Repository:        raw.RepositoryName,
		ImageID:           raw.ImageID.ImageTag,
		Status:            strings.ToUpper(strings.TrimSpace(raw.ImageScanStatus.Status)),
		StatusDescription: raw.ImageScanStatus.Description,
	}
	if d.ImageID == "" {
		d.ImageID = raw.ImageID.ImageDigest
	}
	if err := CheckStatus(d.Status, d.StatusDescription); err != nil {
		return d, err
	}

	for _, rf := range raw.ImageScanFindings.Findings {
		f := Finding{
			Name:     rf.Name,
			Severity: ParseSeverity(rf.Severity),
			URI:      rf.URI,
		}
		for _, a := range rf.Attributes {
			switch a.Key {
			case "package_name":
				f.Package = a.Value
			case "package_version":
				f.Version = a.Value
			}
		}
		d.Basic = append(d.Basic, f)
	}

	for _, re := range raw.ImageScanFindings.EnhancedFindings {
		pv := re.PackageVulnerabilityDetails
		var names, versions []string
		for _, p := range pv.VulnerablePackages {
			names = append(names, p.Name)
			versions = append(versions, p.Version)
		}
		d.Enhanced = append(d.Enhanced, NewEnhancedFinding(EnhancedFields{
			VulnerabilityID: pv.VulnerabilityID,
			Title:           re.Title,
			Severity:        re.Severity,
			Status:          re.Status,
			FixAvailable:    re.FixAvailable,
			Score:           re.Score,
			SourceURL:       pv.SourceURL,
			Description:     re.Description,
			PackageNames:    names,
			PackageVersions: versions,
		}))
	}
	return d, nil
}

// EnhancedFields are the parts of an Amazon Inspector finding the gate uses.
// Both the live path (SDK types) and the dump path (JSON) fill this struct so
// the two normalize identically.
type EnhancedFields struct {
	VulnerabilityID string
	Title           string
	Severity        string
	Status          string
	FixAvailable    string
	Score           float64
	SourceURL       string
	Description     string
	PackageNames    []string // vulnerablePackages[].name
	PackageVersions []string // vulnerablePackages[].version, same order
}

// NewEnhancedFinding normalizes an Amazon Inspector finding into a Finding.
// The finding is named by its vulnerability id (the CVE), falling back to the
// title. Inspector severities outside the ECR set (UNTRIAGED) map to
// UNDEFINED. When several packages are affected, the first one is reported as
// Package/Version.
func NewEnhancedFinding(e EnhancedFields) Finding {
	f := Finding{
		Name:         e.VulnerabilityID,
		Severity:     ParseSeverity(e.Severity),
		URI:          e.SourceURL,
		Description:  e.Description,
		FixAvailable: strings.ToUpper(e.FixAvailable),
		Score:        e.Score,
		Status:       strings.ToUpper(e.Status),
	}
	if f.Name == "" {
		f.Name = e.Title
	}
	if len(e.PackageNames) > 0 {
		f.Package = e.PackageNames[0]
		if len(e.PackageVersions) > 0 {
			f.Version = e.PackageVersions[0]
		}
	}
	return f
}
