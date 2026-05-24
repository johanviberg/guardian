package osv

import (
	"math"
	"testing"

	"github.com/johanviberg/guardian/internal/model"
)

func TestCVSSV3BaseScore(t *testing.T) {
	tests := []struct {
		name   string
		vector string
		want   float64
	}{
		// Known CVSS v3.1 reference vectors and their published base scores.
		{"critical-9.8", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
		{"high-7.5", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5},
		{"medium-6.1-scope-changed", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1},
		{"medium-4.3", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N", 4.3},
		{"low-3.1", "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1},
		{"none-0.0", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0},
		{"no-version-prefix", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
		{"v3.0-critical", "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
		{"changed-scope-critical-10.0", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := cvssV3BaseScore(tc.vector)
			if err != nil {
				t.Fatalf("cvssV3BaseScore(%q): %v", tc.vector, err)
			}
			if math.Abs(got-tc.want) > 0.001 {
				t.Errorf("cvssV3BaseScore(%q) = %.2f, want %.2f", tc.vector, got, tc.want)
			}
		})
	}
}

func TestCVSSV3BaseScoreErrors(t *testing.T) {
	bad := []string{
		"",
		"not-a-vector",
		"CVSS:2.0/AV:N", // unsupported version
		"CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // bad AV value
		"CVSS:3.1/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",      // missing AV
	}
	for _, v := range bad {
		if _, err := cvssV3BaseScore(v); err == nil {
			t.Errorf("cvssV3BaseScore(%q) = nil error, want error", v)
		}
	}
}

func TestBandScore(t *testing.T) {
	tests := []struct {
		score float64
		want  model.Severity
	}{
		{10.0, model.SeverityCritical},
		{9.0, model.SeverityCritical},
		{8.9, model.SeverityHigh},
		{7.0, model.SeverityHigh},
		{6.9, model.SeverityMedium},
		{4.0, model.SeverityMedium},
		{3.9, model.SeverityLow},
		{0.1, model.SeverityLow},
		{0.0, model.SeverityInfo},
	}
	for _, tc := range tests {
		if got := bandScore(tc.score); got != tc.want {
			t.Errorf("bandScore(%.1f) = %q, want %q", tc.score, got, tc.want)
		}
	}
}

func TestSeverityForVuln(t *testing.T) {
	// database_specific.severity takes precedence over CVSS.
	v := &vulnDetail{
		DatabaseSpecific: databaseSpecific{Severity: "HIGH"},
		Severity:         []severityEntry{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"}},
	}
	if got := severityForVuln(v); got != model.SeverityHigh {
		t.Errorf("label precedence: got %q, want high", got)
	}

	// Fall back to CVSS when no label.
	v = &vulnDetail{
		Severity: []severityEntry{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
	}
	if got := severityForVuln(v); got != model.SeverityCritical {
		t.Errorf("cvss fallback: got %q, want critical", got)
	}

	// Neither available -> info.
	if got := severityForVuln(&vulnDetail{}); got != model.SeverityInfo {
		t.Errorf("no data: got %q, want info", got)
	}

	// MODERATE maps to medium.
	v = &vulnDetail{DatabaseSpecific: databaseSpecific{Severity: "MODERATE"}}
	if got := severityForVuln(v); got != model.SeverityMedium {
		t.Errorf("MODERATE: got %q, want medium", got)
	}
}
