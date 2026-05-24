package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/johanviberg/guardian/internal/model"
)

func TestParseNDJSON(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		wantComponents []model.Component
		wantFindings   []model.Finding
		wantSkipped    int
	}{
		{
			name:  "empty input",
			input: "",
		},
		{
			name:  "blank lines ignored, not counted as skipped",
			input: "\n   \n\t\n",
		},
		{
			name:  "single package record",
			input: `{"record_type":"package","ecosystem":"npm","package_name":"left-pad","version":"1.3.0","source_file":"/p/lock.json","confidence":"high"}`,
			wantComponents: []model.Component{{
				Ecosystem: "npm", Name: "left-pad", Version: "1.3.0",
				SourceFile: "/p/lock.json", Confidence: 1.0,
			}},
		},
		{
			name:  "single finding record, class left empty",
			input: `{"record_type":"finding","catalog_id":"MAL-1","severity":"critical","ecosystem":"npm","package_name":"evil","version":"6.6.6","source_file":"/p/lock.json","confidence":"high","evidence":"exact name+version match (version=6.6.6)"}`,
			wantFindings: []model.Finding{{
				CatalogID: "MAL-1", Severity: model.SeverityCritical, Ecosystem: "npm",
				Name: "evil", Version: "6.6.6", SourceFile: "/p/lock.json",
				EvidenceType: "exact name+version match (version=6.6.6)", Confidence: 1.0,
				Class: "", Source: model.SourceCatalog,
			}},
		},
		{
			name: "malformed line skipped and counted",
			input: "garbage not json\n" +
				`{"record_type":"package","ecosystem":"go","package_name":"x","version":"1","source_file":"/go.sum","confidence":"low"}`,
			wantComponents: []model.Component{{
				Ecosystem: "go", Name: "x", Version: "1", SourceFile: "/go.sum", Confidence: 0.25,
			}},
			wantSkipped: 1,
		},
		{
			name: "scan_summary and diagnostic ignored, not skipped",
			input: `{"record_type":"scan_summary","status":"complete"}` + "\n" +
				`{"record_type":"diagnostic","level":"info","message":"hi"}`,
		},
		{
			name:  "unknown confidence maps to zero",
			input: `{"record_type":"package","ecosystem":"npm","package_name":"p","version":"1","source_file":"/x","confidence":"bogus"}`,
			wantComponents: []model.Component{{
				Ecosystem: "npm", Name: "p", Version: "1", SourceFile: "/x", Confidence: 0,
			}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			comps, finds, skipped := parseNDJSON([]byte(tt.input))
			if skipped != tt.wantSkipped {
				t.Errorf("skipped = %d, want %d", skipped, tt.wantSkipped)
			}
			if !equalComponents(comps, tt.wantComponents) {
				t.Errorf("components = %+v, want %+v", comps, tt.wantComponents)
			}
			if !equalFindings(finds, tt.wantFindings) {
				t.Errorf("findings = %+v, want %+v", finds, tt.wantFindings)
			}
		})
	}
}

// TestParseNDJSONGoldenFile parses the canned multi-record fixture (both
// record types plus a malformed line plus a scan_summary) and asserts the
// fully-parsed shape.
func TestParseNDJSONGoldenFile(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "sample.ndjson"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	comps, finds, skipped := parseNDJSON(data)

	if skipped != 1 {
		t.Errorf("skipped = %d, want 1 (the malformed line)", skipped)
	}

	wantComps := []model.Component{
		{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0", SourceFile: "/proj/package-lock.json", Confidence: 1.0},
		{Ecosystem: "pypi", Name: "requests", Version: "2.31.0", SourceFile: "/proj/.venv/lib/requests-2.31.0.dist-info/METADATA", Confidence: 0.5},
	}
	if !equalComponents(comps, wantComps) {
		t.Errorf("components = %+v, want %+v", comps, wantComps)
	}

	wantFinds := []model.Finding{
		{
			CatalogID: "MAL-2026-104", Severity: model.SeverityCritical, Ecosystem: "npm",
			Name: "evil-dep", Version: "6.6.6", SourceFile: "/proj/package-lock.json",
			EvidenceType: "exact name+version match (version=6.6.6)", Confidence: 1.0, Class: "",
			Source: model.SourceCatalog,
		},
	}
	if !equalFindings(finds, wantFinds) {
		t.Errorf("findings = %+v, want %+v", finds, wantFinds)
	}
	// Class must be empty: policy assigns it, not the scanner.
	for _, f := range finds {
		if f.Class != "" {
			t.Errorf("finding %s has Class=%q, want empty", f.CatalogID, f.Class)
		}
	}
}

func TestConfidenceToFloat(t *testing.T) {
	cases := map[string]float64{"high": 1.0, "medium": 0.5, "low": 0.25, "": 0, "weird": 0}
	for in, want := range cases {
		if got := confidenceToFloat(in); got != want {
			t.Errorf("confidenceToFloat(%q) = %v, want %v", in, got, want)
		}
	}
}

func equalComponents(a, b []model.Component) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func equalFindings(a, b []model.Finding) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestVendoredScannerSelfTest exercises the real vendored engine end-to-end.
// It needs a writable temp directory but no network; skip if temp dir is
// unavailable for any reason.
func TestVendoredScannerSelfTest(t *testing.T) {
	if _, err := os.MkdirTemp("", "guardian-selftest-probe-*"); err != nil {
		t.Skipf("temp dir unavailable, skipping selftest: %v", err)
	}
	s := NewVendoredScanner()
	if err := s.SelfTest(context.Background()); err != nil {
		t.Fatalf("SelfTest failed: %v", err)
	}
}

// TestVendoredScannerScanEmpty runs a real project-profile scan against an
// empty temp directory: it should succeed and return no components/findings.
func TestVendoredScannerScanEmpty(t *testing.T) {
	dir := t.TempDir()
	s := NewVendoredScanner()
	res, err := s.Scan(context.Background(), Options{
		Profile: model.ProfileProject,
		Roots:   []string{dir},
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if res.Profile != model.ProfileProject {
		t.Errorf("Profile = %q, want project", res.Profile)
	}
	if res.ScannerVersion == "" {
		t.Error("ScannerVersion is empty")
	}
	if len(res.Components) != 0 || len(res.Findings) != 0 {
		t.Errorf("expected empty scan, got %d components / %d findings", len(res.Components), len(res.Findings))
	}
	if res.FinishedAt.Before(res.StartedAt) {
		t.Error("FinishedAt is before StartedAt")
	}
}
