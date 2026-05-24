package scanner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"time"

	"github.com/johanviberg/guardian/internal/bumblebee/engine"
	"github.com/johanviberg/guardian/internal/model"
)

// VendoredScanner drives the in-tree Bumblebee fork via the
// internal/bumblebee/engine shim and parses its NDJSON into typed
// model records. It is the production Scanner implementation.
type VendoredScanner struct{}

// NewVendoredScanner returns a Scanner backed by the vendored Bumblebee engine.
func NewVendoredScanner() *VendoredScanner { return &VendoredScanner{} }

var _ Scanner = (*VendoredScanner)(nil)

// Version reports the underlying Bumblebee engine version.
func (s *VendoredScanner) Version() string { return engine.Version() }

// SelfTest runs the engine's embedded end-to-end validation.
func (s *VendoredScanner) SelfTest(ctx context.Context) error {
	return engine.SelfTest(ctx)
}

// Scan runs one scan via the vendored engine and returns parsed, typed
// results. Malformed NDJSON lines are skipped (and counted) rather than
// failing the whole scan; the skip count is surfaced via the returned
// result only indirectly (callers that need it can re-parse), but a scan
// never crashes on a bad line.
func (s *VendoredScanner) Scan(ctx context.Context, opts Options) (*model.ScanResult, error) {
	started := time.Now().UTC()

	ndjson, err := engine.Scan(ctx, string(opts.Profile), opts.Roots, opts.CatalogPath, opts.FindingsOnly)
	if err != nil {
		return nil, err
	}

	components, findings, _ := parseNDJSON(ndjson)

	host, _ := os.Hostname()
	finished := time.Now().UTC()

	return &model.ScanResult{
		Profile:        opts.Profile,
		Roots:          opts.Roots,
		ScannerVersion: engine.Version(),
		Host:           host,
		StartedAt:      started,
		FinishedAt:     finished,
		Components:     components,
		Findings:       findings,
	}, nil
}

// Bumblebee NDJSON record_type discriminators. Mirrors the constants in the
// vendored internal/model package (which we cannot import across the internal
// boundary).
const (
	recordTypePackage = "package"
	recordTypeFinding = "finding"
)

// ndjsonRecord is the subset of Bumblebee's NDJSON schema guardian consumes.
// Bumblebee emits two record types of interest — "package" and "finding" —
// plus "scan_summary" and "diagnostic" terminators/aside which we ignore.
type ndjsonRecord struct {
	RecordType string `json:"record_type"`

	// shared identity fields
	Ecosystem  string `json:"ecosystem"`
	Version    string `json:"version"`
	SourceFile string `json:"source_file"`
	Confidence string `json:"confidence"`

	// package-record name
	PackageName string `json:"package_name"`

	// finding-record fields
	CatalogID   string `json:"catalog_id"`
	Severity    string `json:"severity"`
	FindingType string `json:"finding_type"`
	Evidence    string `json:"evidence"`
}

// parseNDJSON splits Bumblebee NDJSON output into typed components and
// findings. The third return value is the count of malformed lines skipped.
// Blank lines and non-package/finding record types are ignored silently;
// only lines that fail to parse as JSON or have an unrecognized shape count
// as skipped.
func parseNDJSON(data []byte) (components []model.Component, findings []model.Finding, skipped int) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	// Records can be large (long dependency paths); raise the line cap well
	// above bufio's 64 KiB default.
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)

	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var rec ndjsonRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			skipped++
			continue
		}
		switch rec.RecordType {
		case recordTypePackage:
			components = append(components, model.Component{
				Ecosystem:  rec.Ecosystem,
				Name:       rec.PackageName,
				Version:    rec.Version,
				SourceFile: rec.SourceFile,
				Confidence: confidenceToFloat(rec.Confidence),
			})
		case recordTypeFinding:
			findings = append(findings, model.Finding{
				CatalogID:    rec.CatalogID,
				Severity:     model.Severity(rec.Severity),
				Ecosystem:    rec.Ecosystem,
				Name:         rec.PackageName,
				Version:      rec.Version,
				SourceFile:   rec.SourceFile,
				EvidenceType: rec.Evidence,
				Confidence:   confidenceToFloat(rec.Confidence),
				Source:       model.SourceCatalog,
				// Class is intentionally left empty: internal/policy sets it.
			})
		default:
			// scan_summary, diagnostic, or anything else: ignore.
			// A record with a recognized JSON shape but no record_type we
			// consume is not a parse error.
		}
	}
	return components, findings, skipped
}

// confidenceToFloat maps Bumblebee's categorical confidence string
// ("high"/"medium"/"low") to the float64 score guardian's model uses. An
// unknown or empty value maps to 0.
func confidenceToFloat(c string) float64 {
	switch c {
	case "high":
		return 1.0
	case "medium":
		return 0.5
	case "low":
		return 0.25
	default:
		return 0
	}
}
