package catalog

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// minimalEntry builds a valid Entry for test use.
func minimalEntry() Entry {
	return Entry{
		ID:        "MAL-2026-104",
		Ecosystem: "npm",
		Package:   "evil",
		Versions:  []string{"1.0.0"},
		Severity:  "critical",
	}
}

// validCatalog builds a structurally valid Catalog.
func validCatalog() *Catalog {
	return &Catalog{
		SchemaVersion: "0.1.0",
		Entries:       []Entry{minimalEntry()},
	}
}

// ---- Parse ----

func TestParseStringSchemaVersion(t *testing.T) {
	// schema_version MUST be a string; integer should cause a parse error
	// because json.Unmarshal into a string field rejects a JSON number.
	intSV := `{"schema_version": 1, "entries": []}`
	_, err := Parse([]byte(intSV))
	if err == nil {
		t.Fatal("Parse with integer schema_version = nil error, want error (engine rejects int)")
	}
}

func TestParseStringSchemaVersionRoundTrip(t *testing.T) {
	const raw = `{"schema_version":"0.1.0","entries":[]}`
	c, err := Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.SchemaVersion != "0.1.0" {
		t.Fatalf("SchemaVersion = %q, want \"0.1.0\"", c.SchemaVersion)
	}
}

func TestParseToleratesUnknownTopLevelKeys(t *testing.T) {
	// Real catalog files carry _comment and _indicators at the top level.
	const raw = `{
		"schema_version": "0.1.0",
		"_comment": "this is ignored",
		"_indicators": {"foo": "bar"},
		"entries": [
			{"id":"X","ecosystem":"npm","package":"p","versions":["1.0"],"severity":"critical","source":"https://example.com"}
		]
	}`
	c, err := Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse with unknown keys: %v", err)
	}
	if len(c.Entries) != 1 {
		t.Fatalf("entry count = %d, want 1", len(c.Entries))
	}
}

func TestParseToleratesUnknownEntryKeys(t *testing.T) {
	// Per-entry unknown fields like "source" and "indicators" must not error.
	const raw = `{
		"schema_version": "0.1.0",
		"entries": [
			{"id":"Y","ecosystem":"go","package":"github.com/evil/pkg","versions":["v1.0.0"],
			 "severity":"high","source":"https://socket.dev/blog/evil","indicators":{"sha256":"abc"}}
		]
	}`
	c, err := Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse with unknown entry fields: %v", err)
	}
	if c.Entries[0].Package != "github.com/evil/pkg" {
		t.Fatalf("entry package = %q", c.Entries[0].Package)
	}
}

func TestParseAcceptsEmptyInput(t *testing.T) {
	for _, input := range []string{"", "  ", "\n\t"} {
		c, err := Parse([]byte(input))
		if err != nil {
			t.Fatalf("Parse(%q) = %v, want nil error", input, err)
		}
		if c.SchemaVersion != SchemaVersion {
			t.Fatalf("empty parse: SchemaVersion = %q", c.SchemaVersion)
		}
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	if _, err := Parse([]byte("not json")); err == nil {
		t.Fatal("Parse(garbage) = nil error, want error")
	}
}

// ---- Validate ----

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Catalog)
		wantErr string
	}{
		// Valid cases.
		{"valid", func(*Catalog) {}, ""},
		{"empty entries ok", func(c *Catalog) { c.Entries = nil }, ""},
		// schema_version is a string now.
		{"empty schema_version", func(c *Catalog) { c.SchemaVersion = "" }, "schema_version"},
		{"whitespace schema_version", func(c *Catalog) { c.SchemaVersion = "  " }, "schema_version"},
		// Required entry fields.
		{"missing id", func(c *Catalog) { c.Entries[0].ID = "" }, "missing id"},
		{"missing ecosystem", func(c *Catalog) { c.Entries[0].Ecosystem = "" }, "missing ecosystem"},
		{"missing package", func(c *Catalog) { c.Entries[0].Package = "" }, "missing package"},
		{"no versions", func(c *Catalog) { c.Entries[0].Versions = nil }, "no versions"},
		// Severity is free-form: unknown values must NOT cause an error.
		{"unknown severity ok", func(c *Catalog) { c.Entries[0].Severity = "spicy" }, ""},
		{"empty severity ok", func(c *Catalog) { c.Entries[0].Severity = "" }, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := validCatalog()
			tt.mutate(c)
			err := c.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

// ---- LoadFile ----

func TestLoadFileRealCatalogShape(t *testing.T) {
	// Write a catalog that mimics the exact shape of a real vendored file
	// (string schema_version, _comment, per-entry source).
	const content = `{
		"schema_version": "0.1.0",
		"_comment": "test advisory",
		"entries": [
			{
				"id":        "socket-2026-05-19-go-shopsprint-decimal",
				"name":      "github.com/shopsprint/decimal v1.3.3 (typosquat DNS backdoor)",
				"ecosystem": "go",
				"package":   "github.com/shopsprint/decimal",
				"versions":  ["v1.3.3"],
				"severity":  "critical",
				"source":    "https://socket.dev/blog/example"
			}
		]
	}`
	dir := t.TempDir()
	path := filepath.Join(dir, "test.json")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if c.Entries[0].Severity != "critical" {
		t.Fatalf("severity = %q", c.Entries[0].Severity)
	}
}

// ---- LoadDir ----

func writeJSON(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLoadDirMergesAlphabetically(t *testing.T) {
	dir := t.TempDir()
	writeJSON(t, dir, "b.json", `{"schema_version":"0.1.0","entries":[
		{"id":"B","ecosystem":"npm","package":"b-pkg","versions":["1.0"]}
	]}`)
	writeJSON(t, dir, "a.json", `{"schema_version":"0.1.0","entries":[
		{"id":"A","ecosystem":"npm","package":"a-pkg","versions":["1.0"]}
	]}`)
	writeJSON(t, dir, "README.md", `not json`)       // should be skipped
	os.MkdirAll(filepath.Join(dir, "subdir"), 0o755) // should be skipped

	c, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if len(c.Entries) != 2 {
		t.Fatalf("entry count = %d, want 2", len(c.Entries))
	}
	// Alphabetical order: a.json first.
	if c.Entries[0].ID != "A" || c.Entries[1].ID != "B" {
		t.Fatalf("entries = %v/%v, want A then B", c.Entries[0].ID, c.Entries[1].ID)
	}
}

func TestLoadDirEmptyDirReturnsEmptyCatalog(t *testing.T) {
	dir := t.TempDir()
	c, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir empty dir: %v", err)
	}
	if len(c.Entries) != 0 {
		t.Fatalf("entry count = %d, want 0", len(c.Entries))
	}
}

func TestLoadDirConflictingSchemaVersionErrors(t *testing.T) {
	dir := t.TempDir()
	writeJSON(t, dir, "a.json", `{"schema_version":"0.1.0","entries":[
		{"id":"A","ecosystem":"npm","package":"a","versions":["1"]}
	]}`)
	writeJSON(t, dir, "b.json", `{"schema_version":"0.2.0","entries":[
		{"id":"B","ecosystem":"npm","package":"b","versions":["1"]}
	]}`)
	_, err := LoadDir(dir)
	if err == nil {
		t.Fatal("LoadDir with conflicting schema_versions = nil error, want error")
	}
	if !strings.Contains(err.Error(), "conflicts") {
		t.Fatalf("error = %v, want \"conflicts\"", err)
	}
}

func TestLoadDirToleratesUnknownKeysInFiles(t *testing.T) {
	dir := t.TempDir()
	writeJSON(t, dir, "a.json", `{
		"schema_version":"0.1.0",
		"_comment":"ignored",
		"_indicators":{"key":"val"},
		"entries":[{"id":"A","ecosystem":"npm","package":"a","versions":["1"],"source":"https://x.com"}]
	}`)
	c, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir with unknown keys: %v", err)
	}
	if len(c.Entries) != 1 {
		t.Fatalf("entry count = %d, want 1", len(c.Entries))
	}
}

func TestLoadDirVendoredThreatIntel(t *testing.T) {
	// Smoke-test against the real vendored catalogs to catch any schema
	// drift between this package and the actual upstream files.
	vendoredDir := "../../internal/bumblebee/threat_intel"
	if _, err := os.Stat(vendoredDir); os.IsNotExist(err) {
		t.Skip("vendored threat_intel directory not found, skipping real-catalog smoke test")
	}
	c, err := LoadDir(vendoredDir)
	if err != nil {
		t.Fatalf("LoadDir(vendored): %v", err)
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate(vendored): %v", err)
	}
	if len(c.Entries) == 0 {
		t.Fatal("vendored catalog has zero entries, expected > 0")
	}
	t.Logf("vendored catalog: schema_version=%q entries=%d", c.SchemaVersion, len(c.Entries))
}

// ---- SHA256Hex ----

func TestSHA256HexIsDeterministic(t *testing.T) {
	c := validCatalog()
	h1, err := c.SHA256Hex()
	if err != nil {
		t.Fatal(err)
	}
	h2, err := c.SHA256Hex()
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Fatalf("SHA256Hex not deterministic: %q vs %q", h1, h2)
	}
	if len(h1) != 64 {
		t.Fatalf("SHA256Hex len = %d, want 64", len(h1))
	}
}

// ---- JSON round-trip (schema_version stays string) ----

func TestCatalogJSONRoundTrip(t *testing.T) {
	c := &Catalog{
		SchemaVersion: "0.1.0",
		Entries: []Entry{
			{ID: "X", Ecosystem: "npm", Package: "pkg", Versions: []string{"1.0"}, Severity: "high"},
		},
	}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var back Catalog
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.SchemaVersion != "0.1.0" {
		t.Fatalf("round-trip SchemaVersion = %q, want \"0.1.0\"", back.SchemaVersion)
	}
}
