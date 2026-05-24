// Package policy contains guardian's pure classification and gating logic:
// turning raw scanner findings into policy-classified findings, applying
// suppressions, computing CI/cron exit codes, and summarizing results for
// reporting.
//
// This package is deliberately dependency-free apart from internal/model. It
// imports no datastore, scanner, or config package so that it stays trivially
// testable and reusable. Suppression sources (e.g. internal/store) are injected
// via the Suppressor function type rather than imported.
package policy

import "github.com/johanviberg/guardian/internal/model"

// Classify returns the policy Class for a single finding.
//
// Rules (mirroring docs/plans "Diff & policy"):
//   - confirmed-malicious: an exact catalog match at SeverityCritical. An exact
//     catalog match is signalled by a non-empty CatalogID.
//   - vulnerable: a catalog match (non-empty CatalogID) below critical severity.
//   - informational: anything else (no catalog match / inventory-only signal).
//
// Classify never inspects or mutates Suppressed; suppression is an orthogonal
// concern applied by ApplySuppressions.
func Classify(f model.Finding) model.Class {
	// Enrichment (OSV) findings describe known vulnerabilities, not malicious
	// publishes: they are ClassVulnerable regardless of severity, and never
	// confirmed-malicious. A concrete OSV/CVE id is always present.
	if f.Source == model.SourceOSV || f.EvidenceType == "osv" {
		return model.ClassVulnerable
	}
	if f.CatalogID == "" {
		return model.ClassInformational
	}
	if f.Severity == model.SeverityCritical {
		return model.ClassConfirmedMalicious
	}
	return model.ClassVulnerable
}

// ClassifyAll returns a copy of findings with Class populated by Classify.
//
// The input slice is not mutated; a new slice with element copies is returned so
// callers can rely on value semantics. A nil input yields a nil result.
func ClassifyAll(findings []model.Finding) []model.Finding {
	if findings == nil {
		return nil
	}
	out := make([]model.Finding, len(findings))
	for i, f := range findings {
		f.Class = Classify(f)
		out[i] = f
	}
	return out
}

// Suppressor reports whether a finding is covered by an active suppression.
//
// Callers (e.g. the CLI wiring internal/store) are responsible for time-based
// expiry: an expired suppression must simply not be reported as matching here.
// This keeps policy free of clock and storage dependencies. A nil Suppressor is
// treated as "nothing is suppressed".
type Suppressor func(model.Finding) bool

// SuppressionRule is a simple declarative suppression usable without a custom
// Suppressor. It matches on ecosystem, name, and version. Expiry is the caller's
// responsibility: do not include expired rules when building a Suppressor from
// them.
//
// Matching rules (v1, intentionally minimal):
//   - Ecosystem: exact, case-sensitive match. Empty Ecosystem matches any
//     ecosystem (wildcard).
//   - Name: exact, case-sensitive match. Empty Name matches any name (wildcard).
//   - Version: exact, case-sensitive match, OR the literal "*" which matches any
//     version. Empty Version also matches any version (wildcard), so "" and "*"
//     are equivalent for Version.
//
// All three dimensions are ANDed: a rule matches a finding only if every
// non-wildcard field is equal.
type SuppressionRule struct {
	Ecosystem string
	Name      string
	Version   string
}

// Matches reports whether the rule covers the given finding per the rules
// documented on SuppressionRule.
func (r SuppressionRule) Matches(f model.Finding) bool {
	if r.Ecosystem != "" && r.Ecosystem != f.Ecosystem {
		return false
	}
	if r.Name != "" && r.Name != f.Name {
		return false
	}
	if r.Version != "" && r.Version != "*" && r.Version != f.Version {
		return false
	}
	return true
}

// SuppressorFromRules builds a Suppressor that matches if ANY of the supplied
// rules matches. Pass only currently-active (non-expired) rules. With no rules,
// the returned Suppressor reports false for every finding.
func SuppressorFromRules(rules []SuppressionRule) Suppressor {
	return func(f model.Finding) bool {
		for _, r := range rules {
			if r.Matches(f) {
				return true
			}
		}
		return false
	}
}

// ApplySuppressions returns a copy of findings with Suppressed set to true for
// any finding the Suppressor matches. Findings already marked Suppressed stay
// suppressed (suppression is monotonic within a single application). A nil
// Suppressor leaves Suppressed untouched. The input slice is not mutated; a nil
// input yields a nil result.
func ApplySuppressions(findings []model.Finding, s Suppressor) []model.Finding {
	if findings == nil {
		return nil
	}
	out := make([]model.Finding, len(findings))
	for i, f := range findings {
		if !f.Suppressed && s != nil && s(f) {
			f.Suppressed = true
		}
		out[i] = f
	}
	return out
}

// ExitCode computes the process exit code from a set of findings, for use by CI
// and cron gating. Precedence (highest wins):
//
//	2 - at least one non-suppressed confirmed-malicious finding.
//	1 - at least one non-suppressed finding, none confirmed-malicious.
//	0 - no non-suppressed findings (clean, or everything suppressed).
//
// Suppressed findings never escalate the exit code. Classification is read from
// Finding.Class, so callers should run ClassifyAll first; as a safety net a
// finding with an empty Class is classified on the fly.
func ExitCode(findings []model.Finding) int {
	return ExitCodeWithGate(findings, Gate{})
}

// Gate configures how enrichment (non-catalog) findings affect the exit code.
//
// The zero value never gates on enrichment: OSV findings stay informational and
// do not escalate the process exit code. Set EnrichFailOn to a severity to make
// enrichment findings at or above that severity escalate to exit code 1.
type Gate struct {
	// EnrichFailOn is the minimum severity at which an enrichment finding
	// (Source=="osv") escalates the exit code to 1. The zero value ("") never
	// escalates on enrichment.
	EnrichFailOn model.Severity
}

// isEnrichment reports whether a finding came from enrichment rather than the
// catalog. An empty Source is treated as catalog.
func isEnrichment(f model.Finding) bool {
	return f.Source == model.SourceOSV || f.EvidenceType == "osv"
}

// severityRank orders severities from least to most urgent for threshold
// comparison: info(0) < low(1) < medium(2) < high(3) < critical(4). An
// unrecognized severity ranks below info (-1) so it never meets a threshold.
func severityRank(s model.Severity) int {
	switch s {
	case model.SeverityInfo:
		return 0
	case model.SeverityLow:
		return 1
	case model.SeverityMedium:
		return 2
	case model.SeverityHigh:
		return 3
	case model.SeverityCritical:
		return 4
	}
	return -1
}

// ExitCodeWithGate computes the process exit code, applying gate g to enrichment
// findings. Precedence (highest wins):
//
//	2 - at least one non-suppressed confirmed-malicious CATALOG finding.
//	1 - at least one non-suppressed CATALOG finding (none confirmed-malicious),
//	    OR at least one non-suppressed ENRICHMENT finding whose severity is >=
//	    g.EnrichFailOn (only when g.EnrichFailOn is set).
//	0 - otherwise.
//
// Enrichment findings are informational by default: with a zero Gate they never
// escalate the exit code. Suppressed findings never escalate. Classification is
// read from Finding.Class, falling back to Classify for an empty Class.
func ExitCodeWithGate(findings []model.Finding, g Gate) int {
	code := 0
	for _, f := range findings {
		if f.Suppressed {
			continue
		}
		if isEnrichment(f) {
			// Informational by default; only escalates when a threshold is set
			// and met.
			if g.EnrichFailOn != "" && severityRank(f.Severity) >= severityRank(g.EnrichFailOn) {
				code = 1
			}
			continue
		}
		class := f.Class
		if class == "" {
			class = Classify(f)
		}
		if class == model.ClassConfirmedMalicious {
			return 2
		}
		code = 1
	}
	return code
}

// Summary is a reporting roll-up of a set of findings. Actionable counts
// (ByClass, BySeverity, Total) exclude suppressed findings; Suppressed is
// reported separately.
type Summary struct {
	// Total is the number of non-suppressed (actionable) findings.
	Total int
	// Suppressed is the number of suppressed findings, excluded from all other
	// counts.
	Suppressed int
	// ByClass counts non-suppressed findings per policy Class.
	ByClass map[model.Class]int
	// BySeverity counts non-suppressed findings per Severity.
	BySeverity map[model.Severity]int
}

// Summarize rolls findings up into a Summary. Classification is read from
// Finding.Class, falling back to Classify for findings with an empty Class. The
// returned maps are always non-nil (possibly empty).
func Summarize(findings []model.Finding) Summary {
	s := Summary{
		ByClass:    make(map[model.Class]int),
		BySeverity: make(map[model.Severity]int),
	}
	for _, f := range findings {
		if f.Suppressed {
			s.Suppressed++
			continue
		}
		class := f.Class
		if class == "" {
			class = Classify(f)
		}
		s.Total++
		s.ByClass[class]++
		s.BySeverity[f.Severity]++
	}
	return s
}
