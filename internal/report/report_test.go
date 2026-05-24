package report

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rmxventures/guardian/internal/model"
)

var update = flag.Bool("update", false, "update golden files")

// fixedTime makes envelope/render output deterministic.
func fixedTime(t *testing.T) {
	t.Helper()
	old := now
	now = func() time.Time { return time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC) }
	t.Cleanup(func() { now = old })
}

func sampleFindings() []model.Finding {
	return []model.Finding{
		{
			CatalogID: "MAL-2026-104", Severity: model.SeverityCritical,
			Class: model.ClassConfirmedMalicious, Ecosystem: "npm",
			Name: "evil-pkg", Version: "1.2.3", SourceFile: "/proj/package-lock.json",
			EvidenceType: "exact-version-match", Confidence: 1.0,
		},
		{
			CatalogID: "CVE-2026-2222", Severity: model.SeverityHigh,
			Class: model.ClassVulnerable, Ecosystem: "pypi",
			Name: "requests", Version: "2.0.0", SourceFile: "/proj/requirements.txt",
			EvidenceType: "exact-version-match", Confidence: 0.9,
		},
		{
			CatalogID: "INFO-001", Severity: model.SeverityInfo,
			Class: model.ClassInformational, Ecosystem: "vscode",
			Name: "some.extension", Version: "0.1.0", SourceFile: "~/.vscode/extensions",
			Confidence: 0.5, Suppressed: true,
		},
	}
}

func goldenPath(name string) string { return filepath.Join("testdata", name) }

func checkGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := goldenPath(name)
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s (run with -update): %v", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("golden %s mismatch\n--- got ---\n%s\n--- want ---\n%s", name, got, want)
	}
}

func TestWriteJSON_EnvelopeShape(t *testing.T) {
	fixedTime(t)
	var buf bytes.Buffer
	data := ScanView{
		Profile: model.ProfileBaseline, Host: "laptop",
		CatalogVersion: "2026.05.20", ScannedAt: time.Date(2026, 5, 24, 11, 0, 0, 0, time.UTC),
		ComponentCount: 42, Findings: sampleFindings(),
		Counts: CountFindings(sampleFindings()), ExitCode: 2,
	}
	if err := WriteJSON(&buf, "scan", data); err != nil {
		t.Fatal(err)
	}

	// Assert required envelope keys and values structurally.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("envelope not valid JSON: %v", err)
	}
	for _, key := range []string{"schema_version", "command", "generated_at", "data"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("envelope missing key %q", key)
		}
	}
	var env Envelope
	if err := json.Unmarshal(buf.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if env.SchemaVersion != SchemaVersion {
		t.Errorf("schema_version = %d want %d", env.SchemaVersion, SchemaVersion)
	}
	if env.Command != "scan" {
		t.Errorf("command = %q", env.Command)
	}
	if env.GeneratedAt.IsZero() {
		t.Error("generated_at is zero")
	}

	checkGolden(t, "envelope_scan.json", buf.Bytes())
}

func TestRenderScan_Golden(t *testing.T) {
	var buf bytes.Buffer
	v := ScanView{
		Profile: model.ProfileBaseline, Host: "laptop",
		CatalogVersion: "2026.05.20",
		ScannedAt:      time.Date(2026, 5, 24, 11, 0, 0, 0, time.UTC),
		ComponentCount: 42, Findings: sampleFindings(),
		Counts: CountFindings(sampleFindings()), ExitCode: 2,
	}
	if err := (Renderer{}).RenderScan(&buf, v); err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "render_scan.txt", buf.Bytes())
}

func TestRenderStatus_Golden(t *testing.T) {
	var buf bytes.Buffer
	v := StatusView{
		Host: "laptop", CatalogVersion: "2026.05.20", CatalogFresh: true,
		LastScanAt: time.Date(2026, 5, 24, 11, 0, 0, 0, time.UTC),
		Findings:   sampleFindings(), Counts: CountFindings(sampleFindings()),
	}
	if err := (Renderer{}).RenderStatus(&buf, v); err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "render_status.txt", buf.Bytes())
}

func TestRenderStatus_Clean(t *testing.T) {
	var buf bytes.Buffer
	v := StatusView{Host: "laptop", CatalogVersion: "2026.05.20", CatalogFresh: false}
	if err := (Renderer{}).RenderStatus(&buf, v); err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "render_status_clean.txt", buf.Bytes())
}

func TestRenderDiff_Golden(t *testing.T) {
	f := sampleFindings()
	var buf bytes.Buffer
	v := DiffView{
		New:        []model.Finding{f[0]},
		Resolved:   []model.Finding{f[1]},
		Persisting: []model.Finding{f[2]},
	}
	if err := (Renderer{}).RenderDiff(&buf, v); err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "render_diff.txt", buf.Bytes())
}

func TestCountFindings(t *testing.T) {
	c := CountFindings(sampleFindings())
	if c.Critical != 1 || c.High != 1 || c.Info != 1 {
		t.Errorf("counts = %+v", c)
	}
	if c.Total() != 3 {
		t.Errorf("total = %d", c.Total())
	}
}

func TestColorEnabled(t *testing.T) {
	r := Renderer{EnableColor: true}
	tag := r.severityTag(model.SeverityCritical)
	if !bytes.Contains([]byte(tag), []byte("\x1b[")) {
		t.Errorf("expected ANSI escape in %q", tag)
	}
	plain := Renderer{}.severityTag(model.SeverityCritical)
	if bytes.Contains([]byte(plain), []byte("\x1b[")) {
		t.Errorf("default should be colorless: %q", plain)
	}
}
