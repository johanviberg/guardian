package diff

import (
	"reflect"
	"testing"

	"github.com/rmxventures/guardian/internal/model"
)

func f(catalog, eco, name, ver, src string) model.Finding {
	return model.Finding{
		CatalogID:  catalog,
		Ecosystem:  eco,
		Name:       name,
		Version:    ver,
		SourceFile: src,
	}
}

func run(fs ...model.Finding) *model.ScanRun {
	return &model.ScanRun{Findings: fs}
}

func keys(fs []model.Finding) []model.FindingKey {
	out := make([]model.FindingKey, len(fs))
	for i, x := range fs {
		out[i] = x.Key()
	}
	return out
}

func TestCompare(t *testing.T) {
	a := f("MAL-1", "npm", "a", "1.0.0", "package.json")
	b := f("MAL-2", "npm", "b", "2.0.0", "package.json")
	c := f("MAL-3", "pypi", "c", "3.0.0", "requirements.txt")

	tests := []struct {
		name                       string
		prev, curr                 *model.ScanRun
		wantNew, wantRes, wantPers []model.Finding
	}{
		{
			name:    "nil prev makes everything new",
			prev:    nil,
			curr:    run(a, b),
			wantNew: []model.Finding{a, b},
		},
		{
			name:    "nil curr resolves everything",
			prev:    run(a, b),
			curr:    nil,
			wantRes: []model.Finding{a, b},
		},
		{
			name: "both nil yields empty result",
			prev: nil,
			curr: nil,
		},
		{
			name:     "add resolve persist mix",
			prev:     run(a, b),
			curr:     run(b, c),
			wantNew:  []model.Finding{c},
			wantRes:  []model.Finding{a},
			wantPers: []model.Finding{b},
		},
		{
			name:     "identical runs all persist",
			prev:     run(a, b, c),
			curr:     run(a, b, c),
			wantPers: []model.Finding{a, b, c},
		},
		{
			name: "empty runs yield empty result",
			prev: run(),
			curr: run(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Compare(tt.prev, tt.curr)
			if !reflect.DeepEqual(keys(got.New), keys(tt.wantNew)) {
				t.Errorf("New = %v, want %v", keys(got.New), keys(tt.wantNew))
			}
			if !reflect.DeepEqual(keys(got.Resolved), keys(tt.wantRes)) {
				t.Errorf("Resolved = %v, want %v", keys(got.Resolved), keys(tt.wantRes))
			}
			if !reflect.DeepEqual(keys(got.Persisting), keys(tt.wantPers)) {
				t.Errorf("Persisting = %v, want %v", keys(got.Persisting), keys(tt.wantPers))
			}
		})
	}
}

// TestCompareKeyFields ensures every component of FindingKey participates in
// identity: a difference in any single field makes a finding distinct.
func TestCompareKeyFields(t *testing.T) {
	base := f("MAL-1", "npm", "a", "1.0.0", "package.json")
	variants := []model.Finding{
		f("MAL-2", "npm", "a", "1.0.0", "package.json"),       // catalog id
		f("MAL-1", "pypi", "a", "1.0.0", "package.json"),      // ecosystem
		f("MAL-1", "npm", "b", "1.0.0", "package.json"),       // name
		f("MAL-1", "npm", "a", "2.0.0", "package.json"),       // version
		f("MAL-1", "npm", "a", "1.0.0", "other/package.json"), // source file
	}
	for i, v := range variants {
		got := Compare(run(base), run(v))
		if len(got.Persisting) != 0 {
			t.Errorf("variant %d unexpectedly persisted (key field not distinguishing)", i)
		}
		if len(got.New) != 1 || len(got.Resolved) != 1 {
			t.Errorf("variant %d: New=%d Resolved=%d, want 1/1", i, len(got.New), len(got.Resolved))
		}
	}
}

func TestCompareOrderingStable(t *testing.T) {
	// Insertion order in curr is intentionally scrambled; output must be sorted.
	c := f("MAL-3", "pypi", "c", "3.0.0", "r.txt")
	a := f("MAL-1", "npm", "a", "1.0.0", "p.json")
	b := f("MAL-2", "npm", "b", "2.0.0", "p.json")

	got := Compare(nil, run(c, a, b))
	want := []model.FindingKey{a.Key(), b.Key(), c.Key()} // sorted by catalog id
	if !reflect.DeepEqual(keys(got.New), want) {
		t.Errorf("New order = %v, want %v", keys(got.New), want)
	}
}

func TestCompareDuplicateKeysFirstWins(t *testing.T) {
	a1 := f("MAL-1", "npm", "a", "1.0.0", "p.json")
	a2 := a1
	a2.Confidence = 0.5 // same key, different payload

	got := Compare(nil, run(a1, a2))
	if len(got.New) != 1 {
		t.Fatalf("New = %d, want 1 (dedup by key)", len(got.New))
	}
	if got.New[0].Confidence != 0 {
		t.Errorf("expected first occurrence (Confidence 0), got %v", got.New[0].Confidence)
	}
}

func TestResultCounts(t *testing.T) {
	mal := model.Finding{CatalogID: "MAL-1", Severity: model.SeverityCritical, Class: model.ClassConfirmedMalicious, Name: "x"}
	vuln := model.Finding{CatalogID: "V-1", Severity: model.SeverityHigh, Class: model.ClassVulnerable, Name: "y"}
	suppMal := mal
	suppMal.Name = "z"
	suppMal.Suppressed = true

	r := Result{New: []model.Finding{mal, vuln, suppMal}}

	bySev := r.CountNewBySeverity()
	if bySev[model.SeverityCritical] != 1 {
		t.Errorf("CountNewBySeverity[critical] = %d, want 1 (suppressed excluded)", bySev[model.SeverityCritical])
	}
	if bySev[model.SeverityHigh] != 1 {
		t.Errorf("CountNewBySeverity[high] = %d, want 1", bySev[model.SeverityHigh])
	}

	byClass := r.CountNewByClass()
	if byClass[model.ClassConfirmedMalicious] != 1 {
		t.Errorf("CountNewByClass[malicious] = %d, want 1", byClass[model.ClassConfirmedMalicious])
	}
	if byClass[model.ClassVulnerable] != 1 {
		t.Errorf("CountNewByClass[vulnerable] = %d, want 1", byClass[model.ClassVulnerable])
	}
}

func TestResultEmpty(t *testing.T) {
	if !(Result{}).Empty() {
		t.Error("zero Result should be Empty")
	}
	if !(Result{Persisting: []model.Finding{{}}}).Empty() {
		t.Error("only-persisting Result should be Empty")
	}
	if (Result{New: []model.Finding{{}}}).Empty() {
		t.Error("Result with New should not be Empty")
	}
	if (Result{Resolved: []model.Finding{{}}}).Empty() {
		t.Error("Result with Resolved should not be Empty")
	}
}

func TestSummarize(t *testing.T) {
	mal := model.Finding{CatalogID: "MAL-1", Severity: model.SeverityCritical, Class: model.ClassConfirmedMalicious}
	mal2 := model.Finding{CatalogID: "MAL-2", Severity: model.SeverityCritical, Class: model.ClassConfirmedMalicious, Name: "n2"}
	vuln := model.Finding{CatalogID: "V-1", Severity: model.SeverityHigh, Class: model.ClassVulnerable}
	suppMal := model.Finding{CatalogID: "MAL-3", Class: model.ClassConfirmedMalicious, Suppressed: true, Name: "s"}

	tests := []struct {
		name  string
		r     Result
		since string
		want  string
	}{
		{"empty with since", Result{}, "run #7", "no changes since run #7"},
		{"empty no since", Result{}, "", "no changes"},
		{
			name:  "criticals and resolved",
			r:     Result{New: []model.Finding{mal, mal2, vuln}, Resolved: []model.Finding{vuln}},
			since: "run #7",
			want:  "2 new criticals, 1 new finding, 1 resolved since run #7",
		},
		{
			name:  "single critical singular",
			r:     Result{New: []model.Finding{mal}},
			since: "yesterday",
			want:  "1 new critical since yesterday",
		},
		{
			name:  "only resolved",
			r:     Result{Resolved: []model.Finding{vuln, mal}},
			since: "",
			want:  "2 resolved",
		},
		{
			name:  "only suppressed new findings",
			r:     Result{New: []model.Finding{suppMal}},
			since: "run #1",
			want:  "no actionable changes since run #1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.r.Summarize(tt.since); got != tt.want {
				t.Errorf("Summarize() = %q, want %q", got, tt.want)
			}
		})
	}
}
