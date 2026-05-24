// Package diff compares two guardian scan runs and reports what changed:
// findings that are New, Resolved, or Persisting relative to a prior run.
//
// Findings are keyed by model.FindingKey via Finding.Key(), i.e. the tuple
// (catalog_id, ecosystem, name, version, source_file). The package is pure: it
// holds no clock, storage, or config dependency and only imports internal/model.
package diff

import (
	"fmt"
	"sort"

	"github.com/rmxventures/guardian/internal/model"
)

// Result is the set-difference of a current run against a previous run.
//
//   - New: present in curr, absent from prev.
//   - Resolved: present in prev, absent from curr.
//   - Persisting: present in both (the curr copy is retained).
//
// Each slice is sorted deterministically by FindingKey so output is stable
// across runs regardless of scanner ordering.
type Result struct {
	New        []model.Finding
	Resolved   []model.Finding
	Persisting []model.Finding
}

// Compare set-differences curr against prev, keyed by Finding.Key().
//
// prev may be nil (first run): every finding in curr is New. curr may also be
// nil: every finding in prev is Resolved. When the same key appears more than
// once within a single run, the first occurrence wins and later duplicates are
// dropped, keeping the comparison a true set difference.
func Compare(prev, curr *model.ScanRun) Result {
	prevByKey := indexByKey(findingsOf(prev))
	currByKey := indexByKey(findingsOf(curr))

	var res Result
	for key, f := range currByKey {
		if _, ok := prevByKey[key]; ok {
			res.Persisting = append(res.Persisting, f)
		} else {
			res.New = append(res.New, f)
		}
	}
	for key, f := range prevByKey {
		if _, ok := currByKey[key]; !ok {
			res.Resolved = append(res.Resolved, f)
		}
	}

	sortFindings(res.New)
	sortFindings(res.Resolved)
	sortFindings(res.Persisting)
	return res
}

func findingsOf(run *model.ScanRun) []model.Finding {
	if run == nil {
		return nil
	}
	return run.Findings
}

// indexByKey maps each finding by its key, first occurrence winning.
func indexByKey(findings []model.Finding) map[model.FindingKey]model.Finding {
	m := make(map[model.FindingKey]model.Finding, len(findings))
	for _, f := range findings {
		k := f.Key()
		if _, exists := m[k]; !exists {
			m[k] = f
		}
	}
	return m
}

// sortFindings orders findings deterministically by their key fields.
func sortFindings(fs []model.Finding) {
	sort.Slice(fs, func(i, j int) bool {
		return lessKey(fs[i].Key(), fs[j].Key())
	})
}

func lessKey(a, b model.FindingKey) bool {
	if a.CatalogID != b.CatalogID {
		return a.CatalogID < b.CatalogID
	}
	if a.Ecosystem != b.Ecosystem {
		return a.Ecosystem < b.Ecosystem
	}
	if a.Name != b.Name {
		return a.Name < b.Name
	}
	if a.Version != b.Version {
		return a.Version < b.Version
	}
	return a.SourceFile < b.SourceFile
}

// CountNewBySeverity counts the New findings per severity, ignoring suppressed
// ones (suppressed findings are not actionable changes). The returned map is
// always non-nil.
func (r Result) CountNewBySeverity() map[model.Severity]int {
	out := make(map[model.Severity]int)
	for _, f := range r.New {
		if f.Suppressed {
			continue
		}
		out[f.Severity]++
	}
	return out
}

// CountNewByClass counts the New findings per class, ignoring suppressed ones.
// Classification is read from Finding.Class. The returned map is always non-nil.
func (r Result) CountNewByClass() map[model.Class]int {
	out := make(map[model.Class]int)
	for _, f := range r.New {
		if f.Suppressed {
			continue
		}
		out[f.Class]++
	}
	return out
}

// Empty reports whether nothing changed: no New and no Resolved findings.
// Persisting findings do not count as a change.
func (r Result) Empty() bool {
	return len(r.New) == 0 && len(r.Resolved) == 0
}

// Summarize renders a short human-readable summary of the changes since a prior
// run, e.g. "3 new criticals, 1 new finding, 2 resolved since run #7". since is
// a label for the prior run (caller-formatted, e.g. "run #7" or "yesterday");
// when empty, the "since ..." suffix is omitted. Returns "no changes since ..."
// when nothing changed.
func (r Result) Summarize(since string) string {
	suffix := ""
	if since != "" {
		suffix = " since " + since
	}
	if r.Empty() {
		return "no changes" + suffix
	}

	var parts []string
	if n := r.CountNewByClass()[model.ClassConfirmedMalicious]; n > 0 {
		parts = append(parts, fmt.Sprintf("%d new critical%s", n, plural(n)))
	}
	if n := newActionable(r); n > 0 {
		parts = append(parts, fmt.Sprintf("%d new finding%s", n, plural(n)))
	}
	if n := len(r.Resolved); n > 0 {
		parts = append(parts, fmt.Sprintf("%d resolved", n))
	}

	if len(parts) == 0 {
		// Only suppressed New findings and no Resolved: report quietly.
		return "no actionable changes" + suffix
	}
	return join(parts) + suffix
}

// newActionable counts non-suppressed New findings that are not
// confirmed-malicious (those are reported separately as "criticals").
func newActionable(r Result) int {
	n := 0
	for _, f := range r.New {
		if f.Suppressed || f.Class == model.ClassConfirmedMalicious {
			continue
		}
		n++
	}
	return n
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func join(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += ", "
		}
		out += p
	}
	return out
}
