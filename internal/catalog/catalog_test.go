package catalog

import (
	"strings"
	"testing"

	"github.com/rmxventures/guardian/internal/model"
)

func validCatalog() *Catalog {
	return &Catalog{
		SchemaVersion: 1,
		Entries: []Entry{
			{ID: "MAL-2026-104", Ecosystem: "npm", Package: "evil", Versions: []string{"1.0.0"}, Severity: model.SeverityCritical},
		},
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Catalog)
		wantErr string
	}{
		{"valid", func(*Catalog) {}, ""},
		{"nil schema", func(c *Catalog) { c.SchemaVersion = 0 }, "schema_version"},
		{"no entries", func(c *Catalog) { c.Entries = nil }, "no entries"},
		{"missing id", func(c *Catalog) { c.Entries[0].ID = "" }, "missing id"},
		{"missing ecosystem", func(c *Catalog) { c.Entries[0].Ecosystem = "" }, "missing ecosystem"},
		{"missing package", func(c *Catalog) { c.Entries[0].Package = "" }, "missing package"},
		{"no versions", func(c *Catalog) { c.Entries[0].Versions = nil }, "no versions"},
		{"bad severity", func(c *Catalog) { c.Entries[0].Severity = "spicy" }, "unknown severity"},
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

func TestParseRejectsGarbage(t *testing.T) {
	if _, err := Parse([]byte("not json")); err == nil {
		t.Fatal("Parse(garbage) = nil error, want error")
	}
}
