package catalog

import (
	"strings"
	"testing"
)

func TestMergeCatalogs_Empty(t *testing.T) {
	merged, warns := MergeCatalogs()
	if len(merged.Entries) != 0 {
		t.Fatalf("want 0 entries, got %d", len(merged.Entries))
	}
	if len(warns) != 0 {
		t.Fatalf("want 0 warnings, got %v", warns)
	}
}

func TestMergeCatalogs_NilSkipped(t *testing.T) {
	a := &Catalog{SchemaVersion: "0.1.0", Entries: []Entry{
		{ID: "A", Ecosystem: "npm", Package: "pkg-a", Versions: []string{"1.0"}},
	}}
	merged, _ := MergeCatalogs(nil, a, nil)
	if len(merged.Entries) != 1 {
		t.Fatalf("want 1 entry, got %d", len(merged.Entries))
	}
}

func TestMergeCatalogs_SingleSource(t *testing.T) {
	a := &Catalog{
		SchemaVersion: "0.1.0",
		Entries: []Entry{
			{ID: "A1", Ecosystem: "npm", Package: "pkg-a", Versions: []string{"1.0", "2.0"}, Severity: "high"},
		},
	}
	merged, warns := MergeCatalogs(a)
	if len(warns) != 0 {
		t.Fatalf("unexpected warnings: %v", warns)
	}
	if len(merged.Entries) != 1 {
		t.Fatalf("want 1 entry, got %d", len(merged.Entries))
	}
	e := merged.Entries[0]
	if e.ID != "A1" || len(e.Versions) != 2 {
		t.Fatalf("unexpected entry: %+v", e)
	}
}

func TestMergeCatalogs_UnionVersions(t *testing.T) {
	a := &Catalog{SchemaVersion: "0.1.0", Entries: []Entry{
		{ID: "PKG", Ecosystem: "npm", Package: "evil", Versions: []string{"1.0", "2.0"}, Severity: "high"},
	}}
	b := &Catalog{SchemaVersion: "0.1.0", Entries: []Entry{
		{ID: "PKG", Ecosystem: "npm", Package: "evil", Versions: []string{"2.0", "3.0"}, Severity: "medium"},
	}}
	merged, warns := MergeCatalogs(a, b)
	if len(warns) != 0 {
		t.Fatalf("unexpected warnings: %v", warns)
	}
	if len(merged.Entries) != 1 {
		t.Fatalf("want 1 merged entry, got %d", len(merged.Entries))
	}
	e := merged.Entries[0]
	// versions: 1.0, 2.0 from a; 3.0 new from b (2.0 deduped)
	if len(e.Versions) != 3 {
		t.Fatalf("want 3 versions after union, got %v", e.Versions)
	}
	if e.Versions[0] != "1.0" || e.Versions[1] != "2.0" || e.Versions[2] != "3.0" {
		t.Fatalf("versions in wrong order: %v", e.Versions)
	}
	// severity: high wins over medium
	if e.Severity != "high" {
		t.Fatalf("severity = %q, want %q", e.Severity, "high")
	}
}

func TestMergeCatalogs_HighestSeverity(t *testing.T) {
	cases := []struct {
		a, b, want string
	}{
		{"critical", "high", "critical"},
		{"medium", "critical", "critical"},
		{"low", "info", "low"},
		{"info", "info", "info"},
		{"high", "medium", "high"},
		{"", "critical", "critical"},
		{"critical", "", "critical"},
		{"unknown-free-form", "info", "info"},   // known severity wins
		{"info", "unknown-free-form", "info"},   // known severity wins
		{"unknown-a", "unknown-b", "unknown-a"}, // both unknown: first wins
	}
	for _, tc := range cases {
		got := highestSeverity(tc.a, tc.b)
		if got != tc.want {
			t.Errorf("highestSeverity(%q, %q) = %q, want %q", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestMergeCatalogs_EcosystemMismatchWarning(t *testing.T) {
	a := &Catalog{SchemaVersion: "0.1.0", Entries: []Entry{
		{ID: "X", Ecosystem: "npm", Package: "pkg", Versions: []string{"1.0"}},
	}}
	b := &Catalog{SchemaVersion: "0.1.0", Entries: []Entry{
		// Same ID, different ecosystem
		{ID: "X", Ecosystem: "pypi", Package: "pkg", Versions: []string{"2.0"}},
	}}
	merged, warns := MergeCatalogs(a, b)
	if len(warns) == 0 {
		t.Fatal("want a warning for ecosystem mismatch, got none")
	}
	found := false
	for _, w := range warns {
		if strings.Contains(w, "ecosystem/package mismatch") && strings.Contains(w, "X") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected ecosystem/package mismatch warning, got: %v", warns)
	}
	// First values kept.
	if merged.Entries[0].Ecosystem != "npm" {
		t.Fatalf("ecosystem = %q, want %q (first wins)", merged.Entries[0].Ecosystem, "npm")
	}
	// Versions still unioned.
	if len(merged.Entries[0].Versions) != 2 {
		t.Fatalf("versions = %v, want 2", merged.Entries[0].Versions)
	}
}

func TestMergeCatalogs_SchemaVersionMismatchWarning(t *testing.T) {
	a := &Catalog{SchemaVersion: "0.1.0", Entries: []Entry{
		{ID: "A", Ecosystem: "npm", Package: "pa", Versions: []string{"1"}},
	}}
	b := &Catalog{SchemaVersion: "0.2.0", Entries: []Entry{
		{ID: "B", Ecosystem: "npm", Package: "pb", Versions: []string{"2"}},
	}}
	merged, warns := MergeCatalogs(a, b)
	found := false
	for _, w := range warns {
		if strings.Contains(w, "schema_version") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected schema_version warning, got: %v", warns)
	}
	// First schema version wins.
	if merged.SchemaVersion != "0.1.0" {
		t.Fatalf("schema_version = %q, want %q", merged.SchemaVersion, "0.1.0")
	}
	// Both entries are present.
	if len(merged.Entries) != 2 {
		t.Fatalf("want 2 entries, got %d", len(merged.Entries))
	}
}

func TestMergeCatalogs_StableInsertionOrder(t *testing.T) {
	a := &Catalog{SchemaVersion: "0.1.0", Entries: []Entry{
		{ID: "Z", Ecosystem: "npm", Package: "z", Versions: []string{"1"}},
		{ID: "A", Ecosystem: "npm", Package: "a", Versions: []string{"1"}},
	}}
	b := &Catalog{SchemaVersion: "0.1.0", Entries: []Entry{
		{ID: "M", Ecosystem: "npm", Package: "m", Versions: []string{"1"}},
	}}
	merged, _ := MergeCatalogs(a, b)
	if len(merged.Entries) != 3 {
		t.Fatalf("want 3 entries, got %d", len(merged.Entries))
	}
	// Order: Z (first from a), A (second from a), M (from b)
	ids := make([]string, len(merged.Entries))
	for i, e := range merged.Entries {
		ids[i] = e.ID
	}
	if ids[0] != "Z" || ids[1] != "A" || ids[2] != "M" {
		t.Fatalf("wrong insertion order: %v", ids)
	}
}

func TestMergeCatalogs_ThreeSources(t *testing.T) {
	a := &Catalog{SchemaVersion: "0.1.0", Entries: []Entry{
		{ID: "SHARED", Ecosystem: "npm", Package: "p", Versions: []string{"1.0"}, Severity: "info"},
		{ID: "FROM-A", Ecosystem: "go", Package: "g", Versions: []string{"v1"}},
	}}
	b := &Catalog{SchemaVersion: "0.1.0", Entries: []Entry{
		{ID: "SHARED", Ecosystem: "npm", Package: "p", Versions: []string{"2.0"}, Severity: "high"},
		{ID: "FROM-B", Ecosystem: "pypi", Package: "py", Versions: []string{"3.0"}},
	}}
	c := &Catalog{SchemaVersion: "0.1.0", Entries: []Entry{
		{ID: "SHARED", Ecosystem: "npm", Package: "p", Versions: []string{"3.0"}, Severity: "critical"},
		{ID: "FROM-C", Ecosystem: "npm", Package: "c", Versions: []string{"4.0"}},
	}}

	merged, warns := MergeCatalogs(a, b, c)
	if len(warns) != 0 {
		t.Fatalf("unexpected warnings: %v", warns)
	}
	// 1 SHARED + FROM-A + FROM-B + FROM-C = 4 entries
	if len(merged.Entries) != 4 {
		t.Fatalf("want 4 entries, got %d", len(merged.Entries))
	}
	shared := merged.Entries[0]
	if shared.ID != "SHARED" {
		t.Fatalf("first entry should be SHARED, got %q", shared.ID)
	}
	// Versions: 1.0 (a), 2.0 (b), 3.0 (c)
	if len(shared.Versions) != 3 {
		t.Fatalf("SHARED versions = %v, want 3", shared.Versions)
	}
	// Severity: critical (highest)
	if shared.Severity != "critical" {
		t.Fatalf("SHARED severity = %q, want critical", shared.Severity)
	}
}

func TestUnionVersions(t *testing.T) {
	cases := []struct {
		a, b []string
		want []string
	}{
		{[]string{"1", "2"}, []string{"2", "3"}, []string{"1", "2", "3"}},
		{[]string{"1"}, []string{"1"}, []string{"1"}},
		{nil, []string{"1"}, []string{"1"}},
		{[]string{"1"}, nil, []string{"1"}},
		{nil, nil, []string{}},
	}
	for _, tc := range cases {
		got := unionVersions(tc.a, tc.b)
		if len(got) != len(tc.want) {
			t.Errorf("unionVersions(%v, %v) = %v, want %v", tc.a, tc.b, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("unionVersions(%v, %v)[%d] = %q, want %q", tc.a, tc.b, i, got[i], tc.want[i])
			}
		}
	}
}
