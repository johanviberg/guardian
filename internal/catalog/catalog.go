// Package catalog fetches, caches, versions, and validates Bumblebee exposure
// catalogs.
//
// # Real catalog schema (from vendored internal/bumblebee/threat_intel/)
//
// Each per-advisory catalog file is a JSON object with the shape below.
// Unknown top-level keys (e.g. "_comment", "_indicators") and unknown
// per-entry keys (e.g. "source", "indicators") are tolerated for forward
// compatibility.
//
//	{
//	  "schema_version": "0.1.0",          // STRING — required; engine rejects integer
//	  "_comment": "...",                   // optional, ignored
//	  "_indicators": {...},                // optional, ignored
//	  "entries": [
//	    {
//	      "id":        "...",              // required
//	      "name":      "...",              // optional free-form label
//	      "ecosystem": "npm",             // required
//	      "package":   "evil",            // required
//	      "versions":  ["1.0.0"],         // required, non-empty
//	      "severity":  "critical",        // optional, FREE-FORM (not an enum)
//	      "source":    "...",             // optional, ignored
//	      ...                             // any unknown keys ignored
//	    }
//	  ]
//	}
//
// The upstream threat_intel/ directory is a set of per-advisory JSON files;
// there is no single combined catalog.json. LoadDir merges them. The engine
// (internal/bumblebee/internal/exposure) accepts either a single file or a
// directory as its --exposure-catalog argument; Ensure caches a merged single
// file so either the file or directory path works as input to the engine.
package catalog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// SchemaVersion is the only schema_version value that the bundled engine
// (internal/bumblebee) currently accepts. Our Validate enforces this so
// problems surface before the scanner is invoked.
const SchemaVersion = "0.1.0"

// Catalog models a parsed exposure catalog. It may be loaded from a single
// per-advisory JSON file or merged from a directory of such files via LoadDir.
type Catalog struct {
	// SchemaVersion is a STRING in the real format ("0.1.0"). The engine
	// REJECTS integer values, so this field must remain string.
	SchemaVersion string  `json:"schema_version"`
	Version       string  `json:"version,omitempty"` // optional catalog-supplied version tag
	Entries       []Entry `json:"entries"`
}

// Entry is a single exposure advisory in the catalog.
//
// Severity is a FREE-FORM string label (e.g. "critical", "high", "info")
// echoed onto findings. The engine does not interpret it for matching; guardian
// maps it downstream in internal/policy. Unknown values are accepted — do not
// restrict to any enum.
//
// Name is an optional human-readable label (not used for matching).
type Entry struct {
	ID        string   `json:"id"`
	Name      string   `json:"name,omitempty"` // optional human label, not used for matching
	Ecosystem string   `json:"ecosystem"`
	Package   string   `json:"package"`
	Versions  []string `json:"versions"`
	Severity  string   `json:"severity,omitempty"` // free-form; NOT restricted to an enum
}

// rawCatalog is used to decode JSON while discarding unknown top-level keys
// (e.g. "_comment", "_indicators") that appear in real catalog files.
type rawCatalog struct {
	SchemaVersion string  `json:"schema_version"`
	Version       string  `json:"version"`
	Entries       []Entry `json:"entries"`
}

// LoadFile reads and parses a single catalog JSON file from path. Unknown
// top-level keys are silently ignored.
func LoadFile(path string) (*Catalog, error) {
	// #nosec G304 -- path is a user-supplied catalog location; reading it for a
	// read-only JSON decode of catalog data is the documented function of this API.
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("catalog: read %s: %w", path, err)
	}
	c, err := Parse(b)
	if err != nil {
		return nil, fmt.Errorf("catalog: %s: %w", path, err)
	}
	return c, nil
}

// Parse decodes a catalog from raw JSON bytes. Unknown fields at any level are
// tolerated so that upstream additions (e.g. "_comment", "_indicators",
// per-entry "source" / "indicators") do not cause parse errors.
//
// An empty or whitespace-only input is accepted as a zero-entry catalog (for
// placeholder files staged before content is published).
func Parse(b []byte) (*Catalog, error) {
	if strings.TrimSpace(string(b)) == "" {
		return &Catalog{SchemaVersion: SchemaVersion}, nil
	}
	var raw rawCatalog
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("catalog: parse: %w", err)
	}
	return &Catalog{
		SchemaVersion: raw.SchemaVersion,
		Version:       raw.Version,
		Entries:       raw.Entries,
	}, nil
}

// LoadDir loads and merges all *.json catalog files found directly inside dir
// (alphabetical order, mirroring the engine's loadDir semantics). Non-.json
// files, subdirectories, and symlinks that resolve to directories are skipped.
//
// Merge rules (same as the engine):
//   - schema_version must be identical across all files that declare it.
//   - Entries are concatenated in file-alphabetical order.
//   - An empty directory (or one with no .json files) returns an empty Catalog
//     rather than an error — this matches the engine's placeholder convention.
func LoadDir(dir string) (*Catalog, error) {
	des, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("catalog: read dir %s: %w", dir, err)
	}

	var names []string
	for _, de := range des {
		if de.IsDir() {
			continue
		}
		if !strings.HasSuffix(strings.ToLower(de.Name()), ".json") {
			continue
		}
		// Skip symlinks that resolve to directories.
		if de.Type()&os.ModeSymlink != 0 {
			if target, serr := os.Stat(filepath.Join(dir, de.Name())); serr == nil && target.IsDir() {
				continue
			}
		}
		names = append(names, de.Name())
	}
	sort.Strings(names)

	var combined []Entry
	var schemaVersion string
	var firstSource string

	for _, name := range names {
		path := filepath.Join(dir, name)
		c, err := LoadFile(path)
		if err != nil {
			return nil, err // LoadFile already wraps with path context
		}
		switch {
		case schemaVersion == "":
			schemaVersion = c.SchemaVersion
			firstSource = path
		case c.SchemaVersion != "" && c.SchemaVersion != schemaVersion:
			return nil, fmt.Errorf("catalog: %s declares schema_version %q which conflicts with %q (from %s)",
				path, c.SchemaVersion, schemaVersion, firstSource)
		}
		combined = append(combined, c.Entries...)
	}

	if schemaVersion == "" {
		schemaVersion = SchemaVersion // sensible default for an empty/placeholder dir
	}
	return &Catalog{SchemaVersion: schemaVersion, Entries: combined}, nil
}

// Validate checks that the catalog is structurally sound:
//   - schema_version is a non-empty string (the engine requires this)
//   - every entry has the required fields: id, ecosystem, package, and at
//     least one version
//   - severity, when present, is accepted as-is (free-form label)
//
// An empty entries slice is allowed; placeholder catalogs are valid. Callers
// that require at least one entry (e.g. after a remote fetch) should check
// len(c.Entries) separately.
func (c *Catalog) Validate() error {
	if c == nil {
		return errors.New("catalog: nil catalog")
	}
	if strings.TrimSpace(c.SchemaVersion) == "" {
		return errors.New("catalog: schema_version is required and must be a non-empty string (real catalogs use \"0.1.0\")")
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
		// Severity is free-form; no enum restriction applied here.
	}
	return nil
}

// SHA256Hex returns the hex-encoded SHA-256 of the catalog's canonical JSON
// representation, used for provenance and change-detection in the metadata
// sidecar. The JSON is marshalled from the in-memory Catalog (not the raw
// on-wire bytes) so the checksum is stable across re-fetches of semantically
// identical catalogs regardless of whitespace.
func (c *Catalog) SHA256Hex() (string, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
