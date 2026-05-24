// Package model defines the core domain types exchanged between guardian's
// packages: scan records produced by the scanner, classified findings, and
// persisted scan runs. These types are the stable contract that every other
// internal package builds against.
package model

import "time"

// Severity is the catalog-assigned severity of an exposure finding.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Class is guardian's policy classification of a finding (see internal/policy).
type Class string

const (
	// ClassConfirmedMalicious is an exact catalog match at critical severity.
	ClassConfirmedMalicious Class = "confirmed-malicious"
	// ClassVulnerable is a catalog match below critical severity.
	ClassVulnerable Class = "vulnerable"
	// ClassInformational is an inventory-only signal, not a catalog match.
	ClassInformational Class = "informational"
)

// Profile mirrors Bumblebee's scan profiles.
type Profile string

const (
	ProfileBaseline Profile = "baseline"
	ProfileProject  Profile = "project"
	ProfileDeep     Profile = "deep"
)

// Component is an inventory entry: one package/extension/tool found on the
// machine. Corresponds to a Bumblebee "package record".
type Component struct {
	Ecosystem  string  `json:"ecosystem"`   // npm, pypi, go, rubygems, composer, vscode, ...
	Name       string  `json:"name"`        // package/extension name
	Version    string  `json:"version"`     // resolved version
	SourceFile string  `json:"source_file"` // lockfile/manifest it was found in
	Confidence float64 `json:"confidence"`  // scanner confidence 0..1
}

// Finding is an exposure match: a Component that matched a catalog entry.
// Corresponds to a Bumblebee "finding record", augmented with guardian's Class.
type Finding struct {
	CatalogID    string   `json:"catalog_id"`    // advisory/catalog entry id, e.g. MAL-2026-104
	Severity     Severity `json:"severity"`      // catalog-assigned severity
	Class        Class    `json:"class"`         // guardian policy classification
	Ecosystem    string   `json:"ecosystem"`     //
	Name         string   `json:"name"`          //
	Version      string   `json:"version"`       //
	SourceFile   string   `json:"source_file"`   // where the matched component lives
	EvidenceType string   `json:"evidence_type"` // e.g. "exact-version-match"
	Confidence   float64  `json:"confidence"`    //
	Suppressed   bool     `json:"suppressed"`    // matched an active suppression
}

// Key uniquely identifies a finding for diffing across runs.
func (f Finding) Key() FindingKey {
	return FindingKey{
		CatalogID:  f.CatalogID,
		Ecosystem:  f.Ecosystem,
		Name:       f.Name,
		Version:    f.Version,
		SourceFile: f.SourceFile,
	}
}

// FindingKey is the comparable identity of a finding used by internal/diff.
type FindingKey struct {
	CatalogID  string
	Ecosystem  string
	Name       string
	Version    string
	SourceFile string
}

// ScanResult is the parsed, typed output of a single scanner invocation,
// before policy classification or persistence.
type ScanResult struct {
	Profile        Profile     `json:"profile"`
	Roots          []string    `json:"roots"`
	CatalogVersion string      `json:"catalog_version"`
	ScannerVersion string      `json:"scanner_version"`
	Host           string      `json:"host"`
	StartedAt      time.Time   `json:"started_at"`
	FinishedAt     time.Time   `json:"finished_at"`
	Components     []Component `json:"components"`
	Findings       []Finding   `json:"findings"`
}

// ScanRun is a persisted scan, as stored in and loaded from the datastore.
type ScanRun struct {
	ID         int64     `json:"id"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	Profile    Profile   `json:"profile"`
	Roots      []string  `json:"roots"`
	CatalogVer string    `json:"catalog_version"`
	Host       string    `json:"host"`
	ScannerVer string    `json:"scanner_version"`
	ExitCode   int       `json:"exit_code"`
	Components []Component
	Findings   []Finding
}
