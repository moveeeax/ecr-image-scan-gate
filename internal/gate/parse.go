package gate

import (
	"encoding/json"
	"fmt"
	"io"
)

// rawScanDump mirrors the shape of `aws ecr describe-image-scan-findings`
// output closely enough to parse the fields the gate needs.
type rawScanDump struct {
	RepositoryName string `json:"repositoryName"`
	ImageID        struct {
		ImageTag    string `json:"imageTag"`
		ImageDigest string `json:"imageDigest"`
	} `json:"imageId"`
	ImageScanFindings struct {
		Findings []rawFinding `json:"findings"`
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

// ParseDump reads a describe-image-scan-findings JSON dump and returns the
// normalized findings plus the repository and image id it references, so the
// classifier core can run entirely offline with no AWS calls.
func ParseDump(r io.Reader) (findings []Finding, repo, imageID string, err error) {
	var dump rawScanDump
	dec := json.NewDecoder(r)
	if err := dec.Decode(&dump); err != nil {
		return nil, "", "", fmt.Errorf("parse scan dump: %w", err)
	}

	repo = dump.RepositoryName
	imageID = dump.ImageID.ImageTag
	if imageID == "" {
		imageID = dump.ImageID.ImageDigest
	}

	for _, rf := range dump.ImageScanFindings.Findings {
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
			case "CVSS3_SCORE", "CVSS2_SCORE":
				// carried in description for context, non-fatal
			}
		}
		findings = append(findings, f)
	}
	return findings, repo, imageID, nil
}
