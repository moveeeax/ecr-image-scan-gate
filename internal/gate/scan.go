package gate

import (
	"fmt"
	"strings"
)

// ScanType selects which findings list of a describe-image-scan-findings
// response the gate reads.
type ScanType string

const (
	// ScanTypeAuto uses the enhanced list when it is non-empty, otherwise the
	// basic list.
	ScanTypeAuto ScanType = "auto"
	// ScanTypeBasic reads imageScanFindings.findings (ECR basic scanning).
	ScanTypeBasic ScanType = "basic"
	// ScanTypeEnhanced reads imageScanFindings.enhancedFindings (Amazon
	// Inspector).
	ScanTypeEnhanced ScanType = "enhanced"
)

// ParseScanType parses a --scan-type value.
func ParseScanType(s string) (ScanType, error) {
	switch t := ScanType(strings.ToLower(strings.TrimSpace(s))); t {
	case ScanTypeAuto, ScanTypeBasic, ScanTypeEnhanced:
		return t, nil
	default:
		return "", fmt.Errorf("unknown scan type %q (want auto, basic or enhanced)", s)
	}
}

// SelectFindings picks the findings list for the requested scan type and
// returns it with the resolved type name (BASIC or ENHANCED) for the report.
//
// In auto mode the enhanced list wins when it is non-empty; when both lists
// are empty the resolved type is empty because the response does not say
// which scanner produced it. An explicit type whose list is empty while the
// other list has findings is an error: gating on the empty list would pass an
// image that has findings.
func SelectFindings(t ScanType, basic, enhanced []Finding) ([]Finding, string, error) {
	switch t {
	case ScanTypeAuto, "":
		switch {
		case len(enhanced) > 0:
			return enhanced, "ENHANCED", nil
		case len(basic) > 0:
			return basic, "BASIC", nil
		default:
			return nil, "", nil
		}
	case ScanTypeBasic:
		if len(basic) == 0 && len(enhanced) > 0 {
			return nil, "", fmt.Errorf("--scan-type basic, but the scan returned only enhanced findings (%d); use --scan-type enhanced or auto", len(enhanced))
		}
		return basic, "BASIC", nil
	case ScanTypeEnhanced:
		if len(enhanced) == 0 && len(basic) > 0 {
			return nil, "", fmt.Errorf("--scan-type enhanced, but the scan returned only basic findings (%d); use --scan-type basic or auto", len(basic))
		}
		return enhanced, "ENHANCED", nil
	default:
		return nil, "", fmt.Errorf("unknown scan type %q", t)
	}
}

// Scan status values from ECR's ScanStatus enum that the gate treats
// specially. COMPLETE is the terminal state of a basic scan, ACTIVE the state
// of an enhanced (continuous) scan that has results.
const (
	StatusComplete   = "COMPLETE"
	StatusActive     = "ACTIVE"
	StatusInProgress = "IN_PROGRESS"
	StatusPending    = "PENDING"
)

// ScanStatusError reports a scan that is not in a state the gate can trust:
// still running, failed, unsupported, or missing. Findings from such a scan
// are empty or partial, so the gate refuses to pass on them.
type ScanStatusError struct {
	Status      string
	Description string
}

func (e *ScanStatusError) Error() string {
	if e.Status == "" {
		return "scan status is missing; refusing to gate on findings of an unknown scan state"
	}
	msg := fmt.Sprintf("scan status is %s, not COMPLETE/ACTIVE", e.Status)
	if e.Description != "" {
		msg += ": " + e.Description
	}
	if IsPendingStatus(e.Status) {
		msg += " (use --wait to poll until the scan finishes)"
	}
	return msg
}

// IsReadyStatus reports whether findings of a scan in this status can be
// gated on.
func IsReadyStatus(status string) bool {
	s := strings.ToUpper(strings.TrimSpace(status))
	return s == StatusComplete || s == StatusActive
}

// IsPendingStatus reports whether a scan in this status may still reach a
// ready state, so a waiting caller should poll again.
func IsPendingStatus(status string) bool {
	s := strings.ToUpper(strings.TrimSpace(status))
	return s == StatusInProgress || s == StatusPending
}

// CheckStatus returns a *ScanStatusError unless status is COMPLETE or ACTIVE.
func CheckStatus(status, description string) error {
	if IsReadyStatus(status) {
		return nil
	}
	return &ScanStatusError{Status: strings.ToUpper(strings.TrimSpace(status)), Description: description}
}
