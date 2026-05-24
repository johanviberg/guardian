package catalog

import (
	"fmt"
	"sort"
	"strings"
)

// severityRank maps a severity label to its numeric rank for conflict
// resolution. Higher rank = more severe.
//
// The five canonical severities rank in descending order. Free-form / unknown
// values rank below "info" (rank 0). This is intentionally lenient: a catalog
// entry with an unrecognised severity is never silently discarded — it just
// loses severity-comparison ties to any named severity.
func severityRank(s string) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	}
	return 0 // unknown / free-form
}

// highestSeverity returns whichever of a and b has the higher rank. When equal,
// a (the first occurrence) wins.
func highestSeverity(a, b string) string {
	if severityRank(b) > severityRank(a) {
		return b
	}
	return a
}

// unionVersions returns a deduplicated list of versions from both slices,
// preserving the stable order: all versions from a first (in their original
// order), then any additional versions from b not already present.
func unionVersions(a, b []string) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, v := range a {
		if _, ok := seen[v]; !ok {
			seen[v] = struct{}{}
			out = append(out, v)
		}
	}
	for _, v := range b {
		if _, ok := seen[v]; !ok {
			seen[v] = struct{}{}
			out = append(out, v)
		}
	}
	return out
}

// MergeCatalogs merges an arbitrary number of catalogs by union, using the
// following conflict-resolution rules when two entries share the same advisory
// id:
//
//   - Versions are unioned (deduped, stable order: first catalog's versions
//     first, then any additional from subsequent catalogs).
//   - Severity is the highest-ranked of the two (critical > high > medium > low
//     > info > unknown free-form). When ranks are equal, the first occurrence
//     wins.
//   - Name, Ecosystem, and Package are taken from the first occurrence.
//   - If ecosystem or package differs across sources for the same id, the first
//     values are kept and a human-readable warning string is appended to the
//     returned warnings slice.
//   - schema_version of the merged catalog is the first non-empty value seen
//     across all catalogs. If sources disagree a warning is emitted but the
//     merge proceeds.
//
// A nil or zero-entry catalog in the variadic list is silently skipped. The
// returned Catalog is a new value (none of the inputs are mutated). The
// warnings slice may be nil if no anomalies were detected.
func MergeCatalogs(cats ...*Catalog) (*Catalog, []string) {
	var (
		schemaVersion string
		schemaSource  int // index of catalog that set schemaVersion
		warnings      []string
	)

	// byID tracks the merged entry for each advisory id, in insertion order.
	type entry struct {
		e      Entry
		srcIdx int // first catalog index that contributed this id
	}
	idOrder := make([]string, 0)
	byID := make(map[string]*entry)

	for catIdx, cat := range cats {
		if cat == nil || len(cat.Entries) == 0 {
			continue
		}

		// Reconcile schema_version.
		if cat.SchemaVersion != "" {
			if schemaVersion == "" {
				schemaVersion = cat.SchemaVersion
				schemaSource = catIdx
			} else if cat.SchemaVersion != schemaVersion {
				warnings = append(warnings, fmt.Sprintf(
					"catalog source %d declares schema_version %q but source %d set %q; proceeding with %q",
					catIdx, cat.SchemaVersion, schemaSource, schemaVersion, schemaVersion,
				))
			}
		}

		for _, e := range cat.Entries {
			if e.ID == "" {
				continue // skip malformed entries
			}
			existing, found := byID[e.ID]
			if !found {
				cp := e
				byID[e.ID] = &entry{e: cp, srcIdx: catIdx}
				idOrder = append(idOrder, e.ID)
				continue
			}

			// Ecosystem/Package mismatch: data inconsistency — warn, keep first.
			if e.Ecosystem != existing.e.Ecosystem || e.Package != existing.e.Package {
				warnings = append(warnings, fmt.Sprintf(
					"advisory %q: ecosystem/package mismatch between source %d (%s/%s) and source %d (%s/%s); keeping first",
					e.ID, existing.srcIdx, existing.e.Ecosystem, existing.e.Package,
					catIdx, e.Ecosystem, e.Package,
				))
			}

			// Merge versions.
			existing.e.Versions = unionVersions(existing.e.Versions, e.Versions)
			// Merge severity: take the highest-ranked.
			existing.e.Severity = highestSeverity(existing.e.Severity, e.Severity)
		}
	}

	if schemaVersion == "" {
		schemaVersion = SchemaVersion
	}

	// Reconstruct entries in stable insertion order.
	merged := make([]Entry, 0, len(idOrder))
	for _, id := range idOrder {
		merged = append(merged, byID[id].e)
	}

	// Sort warnings for deterministic output.
	sort.Strings(warnings)

	return &Catalog{SchemaVersion: schemaVersion, Entries: merged}, warnings
}
