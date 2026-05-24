// Package engine is guardian's sanctioned, EXPORTED entry point into the
// vendored Bumblebee scanner.
//
// Why this package exists: Go forbids importing a package rooted at
// .../internal/... from code outside that internal root's parent. The
// vendored scanner lives under internal/bumblebee/internal/..., so guardian's
// adapter at internal/scanner CANNOT import it directly. This package is
// rooted UNDER internal/bumblebee/, so it MAY import the vendored internals,
// and it re-exposes a small, stable, programmatic API that internal/scanner
// can call.
//
// The Scan function replicates the wiring that the vendored
// cmd/bumblebee/main.go performs in runScan, but writes NDJSON to an
// in-memory buffer instead of stdout. No subprocess is spawned.
package engine

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"github.com/johanviberg/guardian/internal/bumblebee/internal/endpoint"
	"github.com/johanviberg/guardian/internal/bumblebee/internal/exposure"
	"github.com/johanviberg/guardian/internal/bumblebee/internal/model"
	"github.com/johanviberg/guardian/internal/bumblebee/internal/output"
	"github.com/johanviberg/guardian/internal/bumblebee/internal/scanner"
)

// version mirrors the vendored cmd/bumblebee fallback (its VERSION file).
// Kept in sync by hack/sync-upstream.sh's review step. The build-info path
// below supersedes it whenever module/build metadata is available.
const fallbackVersion = "0.1.1"

// Version reports the underlying Bumblebee engine version. It mirrors the
// resolution logic in the vendored cmd/bumblebee/version.go: prefer the
// module version recorded in build info, falling back to the compiled-in
// default that tracks the upstream VERSION file.
func Version() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return fallbackVersion
	}
	v := strings.TrimSpace(bi.Main.Version)
	if v == "" || v == "(devel)" {
		return fallbackVersion
	}
	return v
}

// Scan runs one in-process Bumblebee scan and returns the raw NDJSON the
// scanner would have written to stdout. Records are package and finding
// records plus a terminating scan_summary; diagnostics are discarded (they
// are an out-of-band stderr stream upstream and not part of the record set
// guardian parses).
//
// profile is one of "baseline", "project", "deep". roots are the resolved
// filesystem roots to walk; for deep at least one is required. catalogPath,
// when non-empty, points at an exposure catalog JSON file (or a directory of
// them) and drives finding emission. findingsOnly suppresses package records
// while still emitting findings.
//
// Roots are taken as-is: guardian's scanner package owns profile-aware root
// resolution (the equivalent of cmd/bumblebee/roots.go), so the engine does
// not re-derive defaults here. Passing no roots yields an empty scan rather
// than an error, except for deep where it is reported.
func Scan(ctx context.Context, profile string, roots []string, catalogPath string, findingsOnly bool) ([]byte, error) {
	prof, err := normalizeProfile(profile)
	if err != nil {
		return nil, err
	}
	if findingsOnly && catalogPath == "" {
		return nil, fmt.Errorf("findingsOnly requires a catalog path")
	}
	if prof == model.ProfileDeep && len(roots) == 0 {
		return nil, fmt.Errorf("profile=deep requires at least one root")
	}

	var catalog *exposure.Catalog
	if catalogPath != "" {
		// 0 == unbounded per the vendored --max-catalog-size default semantics;
		// we use the upstream CLI default (64 MiB) to stay behavior-compatible.
		catalog, err = exposure.Load(catalogPath, 64*1024*1024)
		if err != nil {
			return nil, fmt.Errorf("load exposure catalog: %w", err)
		}
	}

	scanRoots := make([]scanner.Root, 0, len(roots))
	for _, r := range roots {
		scanRoots = append(scanRoots, scanner.Root{Path: r, Kind: rootKindFor(prof)})
	}

	var buf bytes.Buffer
	runID := newRunID()
	emitter := output.New(&buf, io.Discard, runID)

	scanStart := time.Now().UTC()
	base := model.Record{
		RecordType:     model.RecordTypePackage,
		SchemaVersion:  model.SchemaVersion,
		ScannerName:    model.ScannerName,
		ScannerVersion: Version(),
		RunID:          runID,
		ScanTime:       scanStart.Format(time.RFC3339Nano),
		Endpoint:       endpoint.Current(""),
		Profile:        prof,
	}

	cfg := scanner.Config{
		Profile:      prof,
		Roots:        scanRoots,
		MaxFileSize:  5 * 1024 * 1024,
		Concurrency:  4,
		Catalog:      catalog,
		FindingsOnly: findingsOnly,
		BaseRecord:   base,
		Emitter:      emitter,
	}

	res, runErr := scanner.Run(ctx, cfg)
	if runErr != nil && res.RecordsEmitted == 0 && res.FindingsEmitted == 0 {
		// Hard failure with nothing produced: surface it.
		return buf.Bytes(), fmt.Errorf("bumblebee scan: %w", runErr)
	}

	// Emit a terminating scan_summary so downstream parsers see a complete
	// stream, matching the CLI's default --emit-summary=true behavior.
	status := model.ScanStatusComplete
	errMsg := ""
	if runErr != nil {
		status = model.ScanStatusPartial
		errMsg = runErr.Error()
	}
	summaryRoots := make([]model.SummaryRoot, 0, len(scanRoots))
	for _, r := range scanRoots {
		summaryRoots = append(summaryRoots, model.SummaryRoot{Path: r.Path, Kind: r.Kind})
	}
	_ = emitter.EmitSummary(model.ScanSummary{
		SchemaVersion:            model.SchemaVersion,
		ScannerName:              model.ScannerName,
		ScannerVersion:           Version(),
		RunID:                    runID,
		ScanTime:                 scanStart.Format(time.RFC3339Nano),
		EndTime:                  time.Now().UTC().Format(time.RFC3339Nano),
		Endpoint:                 base.Endpoint,
		Profile:                  prof,
		Status:                   status,
		Roots:                    summaryRoots,
		PackageRecordsEmitted:    res.RecordsEmitted,
		PackageRecordsSuppressed: res.PackageRecordsSuppressed,
		FindingsEmitted:          res.FindingsEmitted,
		Duplicates:               res.Duplicates,
		DiagnosticsCount:         res.Diagnostics,
		FilesConsidered:          res.FilesConsidered,
		TimedOut:                 res.TimedOut,
		DurationMS:               res.Duration.Milliseconds(),
		Error:                    errMsg,
	})

	return buf.Bytes(), nil
}

// rootKindFor returns a reasonable default RootKind tag for a profile. The
// kind is informational on the record; guardian does not key on it.
func rootKindFor(profile string) string {
	switch profile {
	case model.ProfileProject:
		return model.RootKindProject
	case model.ProfileDeep:
		return model.RootKindDeepHome
	default:
		return model.RootKindUserPackage
	}
}

func normalizeProfile(profile string) (string, error) {
	switch strings.TrimSpace(profile) {
	case "", model.ProfileBaseline:
		return model.ProfileBaseline, nil
	case model.ProfileProject:
		return model.ProfileProject, nil
	case model.ProfileDeep:
		return model.ProfileDeep, nil
	default:
		return "", fmt.Errorf("unknown profile %q (want: baseline, project, deep)", profile)
	}
}

func newRunID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// SelfTest runs an embedded, deterministic end-to-end check of the vendored
// scanner: it materializes a tiny npm fixture plus a matching exposure
// catalog in a temp directory, scans it in-process, and asserts the scan
// produces exactly one finding. It makes no network calls and reads nothing
// outside its own temp dir.
//
// This mirrors the intent of the vendored cmd/bumblebee selftest subcommand
// (smoke-test that detection still works) without depending on package main's
// embedded fixtures, which are not importable across the internal boundary.
func SelfTest(ctx context.Context) error {
	dir, err := os.MkdirTemp("", "guardian-bumblebee-selftest-*")
	if err != nil {
		return fmt.Errorf("selftest: mktemp: %w", err)
	}
	defer os.RemoveAll(dir)

	const (
		evilName = "guardian-selftest-evil"
		evilVer  = "6.6.6"
	)

	// An npm package-lock.json (v3 / lockfileVersion 3 shape) naming a single
	// dependency the catalog flags. The npm scanner reads "packages" entries.
	lock := `{
  "name": "guardian-selftest",
  "version": "0.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {"name": "guardian-selftest", "version": "0.0.0"},
    "node_modules/` + evilName + `": {"version": "` + evilVer + `"}
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lock), 0o644); err != nil {
		return fmt.Errorf("selftest: write fixture: %w", err)
	}

	catalog := `{
  "schema_version": "0.1.0",
  "entries": [
    {
      "id": "GUARDIAN-SELFTEST-0001",
      "name": "guardian selftest sentinel",
      "severity": "critical",
      "ecosystem": "npm",
      "package": "` + evilName + `",
      "versions": ["` + evilVer + `"]
    }
  ]
}`
	catalogPath := filepath.Join(dir, "catalog.json")
	if err := os.WriteFile(catalogPath, []byte(catalog), 0o644); err != nil {
		return fmt.Errorf("selftest: write catalog: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	ndjson, err := Scan(ctx, model.ProfileProject, []string{dir}, catalogPath, false)
	if err != nil {
		return fmt.Errorf("selftest: scan: %w", err)
	}

	findings := 0
	for _, line := range bytes.Split(ndjson, []byte("\n")) {
		if bytes.Contains(line, []byte(`"record_type":"finding"`)) {
			findings++
		}
	}
	if findings < 1 {
		return fmt.Errorf("selftest: expected at least 1 finding, got %d (output: %s)", findings, ndjson)
	}
	return nil
}
