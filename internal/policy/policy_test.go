package policy

import (
	"testing"

	"github.com/johanviberg/guardian/internal/model"
)

func TestClassify(t *testing.T) {
	tests := []struct {
		name string
		in   model.Finding
		want model.Class
	}{
		{
			name: "exact catalog match at critical is confirmed-malicious",
			in:   model.Finding{CatalogID: "MAL-2026-104", Severity: model.SeverityCritical},
			want: model.ClassConfirmedMalicious,
		},
		{
			name: "catalog match at high is vulnerable",
			in:   model.Finding{CatalogID: "GHSA-1", Severity: model.SeverityHigh},
			want: model.ClassVulnerable,
		},
		{
			name: "catalog match at medium is vulnerable",
			in:   model.Finding{CatalogID: "GHSA-2", Severity: model.SeverityMedium},
			want: model.ClassVulnerable,
		},
		{
			name: "catalog match at low is vulnerable",
			in:   model.Finding{CatalogID: "GHSA-3", Severity: model.SeverityLow},
			want: model.ClassVulnerable,
		},
		{
			name: "catalog match at info is vulnerable",
			in:   model.Finding{CatalogID: "GHSA-4", Severity: model.SeverityInfo},
			want: model.ClassVulnerable,
		},
		{
			name: "no catalog id at critical is informational",
			in:   model.Finding{CatalogID: "", Severity: model.SeverityCritical},
			want: model.ClassInformational,
		},
		{
			name: "no catalog id at low is informational",
			in:   model.Finding{CatalogID: "", Severity: model.SeverityLow},
			want: model.ClassInformational,
		},
		{
			name: "no catalog id no severity is informational",
			in:   model.Finding{},
			want: model.ClassInformational,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Classify(tt.in); got != tt.want {
				t.Errorf("Classify() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestClassifyAll(t *testing.T) {
	t.Run("nil input yields nil", func(t *testing.T) {
		if got := ClassifyAll(nil); got != nil {
			t.Errorf("ClassifyAll(nil) = %v, want nil", got)
		}
	})

	t.Run("sets class without mutating input", func(t *testing.T) {
		in := []model.Finding{
			{CatalogID: "MAL-1", Severity: model.SeverityCritical},
			{CatalogID: "VULN-1", Severity: model.SeverityHigh},
			{CatalogID: "", Severity: model.SeverityLow},
		}
		got := ClassifyAll(in)
		want := []model.Class{
			model.ClassConfirmedMalicious,
			model.ClassVulnerable,
			model.ClassInformational,
		}
		for i := range got {
			if got[i].Class != want[i] {
				t.Errorf("got[%d].Class = %q, want %q", i, got[i].Class, want[i])
			}
		}
		// Input must remain unmutated.
		for i := range in {
			if in[i].Class != "" {
				t.Errorf("input mutated at %d: Class = %q", i, in[i].Class)
			}
		}
	})
}

func TestSuppressionRuleMatches(t *testing.T) {
	f := model.Finding{Ecosystem: "npm", Name: "left-pad", Version: "1.0.0"}
	tests := []struct {
		name string
		rule SuppressionRule
		want bool
	}{
		{"exact all three", SuppressionRule{"npm", "left-pad", "1.0.0"}, true},
		{"wrong version exact", SuppressionRule{"npm", "left-pad", "2.0.0"}, false},
		{"wrong name", SuppressionRule{"npm", "right-pad", "1.0.0"}, false},
		{"wrong ecosystem", SuppressionRule{"pypi", "left-pad", "1.0.0"}, false},
		{"version star wildcard", SuppressionRule{"npm", "left-pad", "*"}, true},
		{"version empty wildcard", SuppressionRule{"npm", "left-pad", ""}, true},
		{"empty name wildcard", SuppressionRule{"npm", "", "1.0.0"}, true},
		{"empty ecosystem wildcard", SuppressionRule{"", "left-pad", "1.0.0"}, true},
		{"all wildcard", SuppressionRule{"", "", ""}, true},
		{"all wildcard with star version", SuppressionRule{"", "", "*"}, true},
		{"name wildcard but wrong version", SuppressionRule{"npm", "", "9.9.9"}, false},
		{"case sensitive name", SuppressionRule{"npm", "Left-Pad", "1.0.0"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.rule.Matches(f); got != tt.want {
				t.Errorf("Matches() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestApplySuppressions(t *testing.T) {
	mk := func() []model.Finding {
		return []model.Finding{
			{Ecosystem: "npm", Name: "left-pad", Version: "1.0.0"},
			{Ecosystem: "npm", Name: "right-pad", Version: "2.0.0"},
			{Ecosystem: "pypi", Name: "requests", Version: "3.0.0", Suppressed: true},
		}
	}

	t.Run("nil findings yields nil", func(t *testing.T) {
		if got := ApplySuppressions(nil, SuppressorFromRules(nil)); got != nil {
			t.Errorf("got %v, want nil", got)
		}
	})

	t.Run("nil suppressor leaves Suppressed untouched", func(t *testing.T) {
		got := ApplySuppressions(mk(), nil)
		want := []bool{false, false, true}
		for i := range got {
			if got[i].Suppressed != want[i] {
				t.Errorf("got[%d].Suppressed = %v, want %v", i, got[i].Suppressed, want[i])
			}
		}
	})

	t.Run("rule matches one and does not mutate input", func(t *testing.T) {
		in := mk()
		rules := []SuppressionRule{{Ecosystem: "npm", Name: "left-pad", Version: "*"}}
		got := ApplySuppressions(in, SuppressorFromRules(rules))
		want := []bool{true, false, true}
		for i := range got {
			if got[i].Suppressed != want[i] {
				t.Errorf("got[%d].Suppressed = %v, want %v", i, got[i].Suppressed, want[i])
			}
		}
		if in[0].Suppressed {
			t.Errorf("input mutated: in[0].Suppressed = true")
		}
	})

	t.Run("already-suppressed stays suppressed", func(t *testing.T) {
		in := mk()
		// A suppressor that matches nothing.
		got := ApplySuppressions(in, SuppressorFromRules([]SuppressionRule{{Name: "nonexistent"}}))
		if !got[2].Suppressed {
			t.Errorf("pre-suppressed finding lost suppression")
		}
	})

	t.Run("custom Suppressor func", func(t *testing.T) {
		s := Suppressor(func(f model.Finding) bool { return f.Ecosystem == "npm" })
		got := ApplySuppressions(mk(), s)
		want := []bool{true, true, true}
		for i := range got {
			if got[i].Suppressed != want[i] {
				t.Errorf("got[%d].Suppressed = %v, want %v", i, got[i].Suppressed, want[i])
			}
		}
	})
}

func TestExitCode(t *testing.T) {
	mal := model.Finding{CatalogID: "MAL-1", Severity: model.SeverityCritical, Class: model.ClassConfirmedMalicious}
	vuln := model.Finding{CatalogID: "V-1", Severity: model.SeverityHigh, Class: model.ClassVulnerable}
	info := model.Finding{Class: model.ClassInformational}

	supp := func(f model.Finding) model.Finding { f.Suppressed = true; return f }

	tests := []struct {
		name string
		in   []model.Finding
		want int
	}{
		{"no findings is 0", nil, 0},
		{"empty slice is 0", []model.Finding{}, 0},
		{"only informational escalates to 1", []model.Finding{info}, 1},
		{"vulnerable is 1", []model.Finding{vuln}, 1},
		{"malicious is 2", []model.Finding{mal}, 2},
		{"malicious wins over vulnerable", []model.Finding{vuln, mal, info}, 2},
		{"suppressed malicious does not escalate", []model.Finding{supp(mal)}, 0},
		{"suppressed malicious with live vuln yields 1", []model.Finding{supp(mal), vuln}, 1},
		{"all suppressed is 0", []model.Finding{supp(mal), supp(vuln)}, 0},
		{
			name: "empty class falls back to on-the-fly classify",
			in:   []model.Finding{{CatalogID: "MAL-2", Severity: model.SeverityCritical}},
			want: 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ExitCode(tt.in); got != tt.want {
				t.Errorf("ExitCode() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestSummarize(t *testing.T) {
	findings := []model.Finding{
		{CatalogID: "MAL-1", Severity: model.SeverityCritical, Class: model.ClassConfirmedMalicious},
		{CatalogID: "V-1", Severity: model.SeverityHigh, Class: model.ClassVulnerable},
		{CatalogID: "V-2", Severity: model.SeverityHigh, Class: model.ClassVulnerable},
		{Class: model.ClassInformational, Severity: model.SeverityInfo},
		{CatalogID: "MAL-9", Severity: model.SeverityCritical, Class: model.ClassConfirmedMalicious, Suppressed: true},
	}
	s := Summarize(findings)

	if s.Total != 4 {
		t.Errorf("Total = %d, want 4", s.Total)
	}
	if s.Suppressed != 1 {
		t.Errorf("Suppressed = %d, want 1", s.Suppressed)
	}
	if s.ByClass[model.ClassConfirmedMalicious] != 1 {
		t.Errorf("ByClass[malicious] = %d, want 1 (suppressed excluded)", s.ByClass[model.ClassConfirmedMalicious])
	}
	if s.ByClass[model.ClassVulnerable] != 2 {
		t.Errorf("ByClass[vulnerable] = %d, want 2", s.ByClass[model.ClassVulnerable])
	}
	if s.ByClass[model.ClassInformational] != 1 {
		t.Errorf("ByClass[informational] = %d, want 1", s.ByClass[model.ClassInformational])
	}
	if s.BySeverity[model.SeverityHigh] != 2 {
		t.Errorf("BySeverity[high] = %d, want 2", s.BySeverity[model.SeverityHigh])
	}
	if s.BySeverity[model.SeverityCritical] != 1 {
		t.Errorf("BySeverity[critical] = %d, want 1 (suppressed excluded)", s.BySeverity[model.SeverityCritical])
	}
}

func TestSummarizeEmptyMapsNonNil(t *testing.T) {
	s := Summarize(nil)
	if s.ByClass == nil || s.BySeverity == nil {
		t.Fatal("Summarize(nil) returned nil maps")
	}
	if s.Total != 0 || s.Suppressed != 0 {
		t.Errorf("Summarize(nil) = %+v, want zero counts", s)
	}
}

func TestSummarizeFallbackClassify(t *testing.T) {
	// Finding with empty Class should be classified on the fly.
	findings := []model.Finding{{CatalogID: "MAL-1", Severity: model.SeverityCritical}}
	s := Summarize(findings)
	if s.ByClass[model.ClassConfirmedMalicious] != 1 {
		t.Errorf("fallback classify failed: ByClass = %v", s.ByClass)
	}
}
