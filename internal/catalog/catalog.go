// Package catalog fetches, caches, versions, and validates Bumblebee exposure
// catalogs.
//
// A catalog is a JSON document of the shape:
//
//	{
//	  "schema_version": 1,
//	  "entries": [
//	    {"id": "MAL-2026-104", "ecosystem": "npm", "package": "evil",
//	     "versions": ["1.0.0"], "severity": "critical"}
//	  ]
//	}
//
// guardian's catalog management layer (this package) is responsible for keeping
// a local cached copy fresh, recording provenance metadata (version, fetch time,
// sha256 checksum, entry count, source URL), and reporting freshness to
// `guardian status` / `guardian doctor`. Detection itself (exact
// (ecosystem, name, version) matching) is performed downstream by the scanner.
package catalog

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/rmxventures/guardian/internal/model"
)

// Catalog models the on-disk / over-the-wire exposure catalog JSON.
type Catalog struct {
	SchemaVersion int     `json:"schema_version"`
	Version       string  `json:"version,omitempty"` // optional catalog-supplied version
	Entries       []Entry `json:"entries"`
}

// Entry is a single exposure advisory in the catalog.
type Entry struct {
	ID        string         `json:"id"`
	Ecosystem string         `json:"ecosystem"`
	Package   string         `json:"package"`
	Versions  []string       `json:"versions"`
	Severity  model.Severity `json:"severity"`
}

// validSeverities is the set of severity values guardian accepts in a catalog.
// It mirrors internal/model's Severity constants.
var validSeverities = map[model.Severity]bool{
	model.SeverityCritical: true,
	model.SeverityHigh:     true,
	model.SeverityMedium:   true,
	model.SeverityLow:      true,
	model.SeverityInfo:     true,
}

// LoadFile reads and parses a catalog JSON file. It does not validate the
// catalog's contents; call Validate for that.
func LoadFile(path string) (*Catalog, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("catalog: read %s: %w", path, err)
	}
	return Parse(b)
}

// Parse decodes a catalog from raw JSON bytes. Unknown fields are tolerated so
// that newer upstream catalog schemas remain forward-compatible; structural
// soundness is enforced separately by Validate.
func Parse(b []byte) (*Catalog, error) {
	var c Catalog
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("catalog: parse: %w", err)
	}
	return &c, nil
}

// Validate checks that the catalog is structurally sound: it has at least one
// entry, and every entry carries the required fields with a known severity.
func (c *Catalog) Validate() error {
	if c == nil {
		return errors.New("catalog: nil catalog")
	}
	if c.SchemaVersion <= 0 {
		return fmt.Errorf("catalog: invalid schema_version %d", c.SchemaVersion)
	}
	if len(c.Entries) == 0 {
		return errors.New("catalog: no entries")
	}
	for i, e := range c.Entries {
		if e.ID == "" {
			return fmt.Errorf("catalog: entry %d: missing id", i)
		}
		if e.Ecosystem == "" {
			return fmt.Errorf("catalog: entry %d (%s): missing ecosystem", i, e.ID)
		}
		if e.Package == "" {
			return fmt.Errorf("catalog: entry %d (%s): missing package", i, e.ID)
		}
		if len(e.Versions) == 0 {
			return fmt.Errorf("catalog: entry %d (%s): no versions", i, e.ID)
		}
		if !validSeverities[e.Severity] {
			return fmt.Errorf("catalog: entry %d (%s): unknown severity %q", i, e.ID, e.Severity)
		}
	}
	return nil
}
