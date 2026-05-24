package osv

import (
	"strings"

	"github.com/johanviberg/guardian/internal/model"
)

// severityForVuln maps an OSV vuln detail to a guardian severity.
//
// Preference order:
//  1. database_specific.severity (CRITICAL/HIGH/MODERATE|MEDIUM/LOW), when present.
//  2. a CVSS_V3 vector parsed to a base score and banded.
//  3. model.SeverityInfo when neither is available or parseable.
func severityForVuln(v *vulnDetail) model.Severity {
	if v == nil {
		return model.SeverityInfo
	}
	if s, ok := severityFromLabel(v.DatabaseSpecific.Severity); ok {
		return s
	}
	if vec, ok := cvssV3Vector(v); ok {
		if score, err := cvssV3BaseScore(vec); err == nil {
			return bandScore(score)
		}
	}
	return model.SeverityInfo
}

// severityFromLabel maps an OSV database_specific.severity label to a guardian
// severity. The second return is false when the label is empty or unknown.
func severityFromLabel(label string) (model.Severity, bool) {
	switch strings.ToUpper(strings.TrimSpace(label)) {
	case "CRITICAL":
		return model.SeverityCritical, true
	case "HIGH":
		return model.SeverityHigh, true
	case "MODERATE", "MEDIUM":
		return model.SeverityMedium, true
	case "LOW":
		return model.SeverityLow, true
	}
	return "", false
}

// cvssV3Vector returns the first CVSS_V3 vector string from the vuln's severity
// entries, if any.
func cvssV3Vector(v *vulnDetail) (string, bool) {
	for _, s := range v.Severity {
		if strings.EqualFold(s.Type, "CVSS_V3") && s.Score != "" {
			return s.Score, true
		}
	}
	return "", false
}

// bandScore maps a CVSS v3 base score to a guardian severity band.
func bandScore(score float64) model.Severity {
	switch {
	case score >= 9.0:
		return model.SeverityCritical
	case score >= 7.0:
		return model.SeverityHigh
	case score >= 4.0:
		return model.SeverityMedium
	case score > 0:
		return model.SeverityLow
	default:
		return model.SeverityInfo
	}
}
