package osv

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/johanviberg/guardian/internal/enrich"
	"github.com/johanviberg/guardian/internal/model"
)

// osvTestServer serves a fixed querybatch + vuln-detail dataset and counts hits.
type osvTestServer struct {
	*httptest.Server
	batchHits  int64
	detailHits int64
	// detailFor maps an OSV id to its detail JSON.
	detailFor map[string]vulnDetail
	// batchResultFor maps "ecosystem|name|version" to the vuln ids OSV returns.
	batchResultFor map[string][]string
}

func newOSVTestServer(t *testing.T) *osvTestServer {
	t.Helper()
	s := &osvTestServer{
		detailFor:      map[string]vulnDetail{},
		batchResultFor: map[string][]string{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&s.batchHits, 1)
		var req batchRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		resp := batchResponse{Results: make([]batchResult, len(req.Queries))}
		for i, q := range req.Queries {
			key := q.Package.Ecosystem + "|" + q.Package.Name + "|" + q.Version
			for _, id := range s.batchResultFor[key] {
				resp.Results[i].Vulns = append(resp.Results[i].Vulns, batchVuln{ID: id})
			}
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/v1/vulns/", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&s.detailHits, 1)
		id := r.URL.Path[len("/v1/vulns/"):]
		d, ok := s.detailFor[id]
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(d)
	})
	s.Server = httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

func (s *osvTestServer) newEnricher(t *testing.T, cacheDir string, ttl time.Duration) *Enricher {
	t.Helper()
	e := New(cacheDir, ttl, &http.Client{Timeout: 5 * time.Second})
	e.SetBaseURL(s.URL)
	return e
}

func TestEnrichMappingAndFindings(t *testing.T) {
	s := newOSVTestServer(t)
	s.batchResultFor["npm|lodash|4.17.15"] = []string{"GHSA-xxxx-lodash"}
	s.detailFor["GHSA-xxxx-lodash"] = vulnDetail{
		ID:               "GHSA-xxxx-lodash",
		Aliases:          []string{"CVE-2021-23337"},
		Summary:          "Command injection in lodash",
		DatabaseSpecific: databaseSpecific{Severity: "HIGH"},
	}

	comps := []model.Component{
		{Ecosystem: "npm", Name: "lodash", Version: "4.17.15", SourceFile: "package-lock.json", Confidence: 1.0},
		// Unsupported ecosystem: must be skipped.
		{Ecosystem: "vscode", Name: "some.ext", Version: "1.2.3"},
		// No concrete version: must be skipped.
		{Ecosystem: "npm", Name: "noversion", Version: ""},
		// Supported but no vulns reported.
		{Ecosystem: "pypi", Name: "requests", Version: "2.31.0"},
	}

	findings, err := s.newEnricher(t, t.TempDir(), time.Hour).Enrich(context.Background(), comps)
	if err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.CatalogID != "CVE-2021-23337" {
		t.Errorf("CatalogID = %q, want CVE alias", f.CatalogID)
	}
	if f.Source != model.SourceOSV || f.EvidenceType != "osv" {
		t.Errorf("source/evidence = %q/%q", f.Source, f.EvidenceType)
	}
	if f.Class != model.ClassVulnerable {
		t.Errorf("Class = %q, want vulnerable", f.Class)
	}
	if f.Severity != model.SeverityHigh {
		t.Errorf("Severity = %q, want high", f.Severity)
	}
	if f.Name != "lodash" || f.Version != "4.17.15" || f.Ecosystem != "npm" {
		t.Errorf("component fields mismatch: %+v", f)
	}
	if f.Summary != "Command injection in lodash" {
		t.Errorf("Summary = %q", f.Summary)
	}
}

func TestEnrichCacheHitMiss(t *testing.T) {
	s := newOSVTestServer(t)
	s.batchResultFor["npm|lodash|4.17.15"] = []string{"GHSA-xxxx-lodash"}
	s.detailFor["GHSA-xxxx-lodash"] = vulnDetail{
		ID:               "GHSA-xxxx-lodash",
		DatabaseSpecific: databaseSpecific{Severity: "HIGH"},
	}
	cacheDir := t.TempDir()
	comps := []model.Component{{Ecosystem: "npm", Name: "lodash", Version: "4.17.15"}}

	// First run: detail is fetched once (miss).
	if _, err := s.newEnricher(t, cacheDir, time.Hour).Enrich(context.Background(), comps); err != nil {
		t.Fatalf("first Enrich: %v", err)
	}
	if got := atomic.LoadInt64(&s.detailHits); got != 1 {
		t.Fatalf("detail hits after first run = %d, want 1", got)
	}

	// Second run with the same cache dir: detail is served from cache (no new
	// detail fetch). The batch query still runs.
	if _, err := s.newEnricher(t, cacheDir, time.Hour).Enrich(context.Background(), comps); err != nil {
		t.Fatalf("second Enrich: %v", err)
	}
	if got := atomic.LoadInt64(&s.detailHits); got != 1 {
		t.Errorf("detail hits after cached run = %d, want still 1 (cache hit)", got)
	}
}

func TestEnrichOfflineSoftFail(t *testing.T) {
	// Point the enricher at a closed server to force a connection failure.
	s := newOSVTestServer(t)
	url := s.URL
	s.Close()

	e := New(t.TempDir(), time.Hour, &http.Client{Timeout: 200 * time.Millisecond})
	e.SetBaseURL(url)

	comps := []model.Component{{Ecosystem: "npm", Name: "lodash", Version: "4.17.15"}}
	findings, err := e.Enrich(context.Background(), comps)
	if err == nil {
		t.Fatal("expected a soft error when offline")
	}
	var soft *enrich.SoftError
	if !errors.As(err, &soft) {
		t.Fatalf("error %v is not *enrich.SoftError", err)
	}
	if soft.Source != "osv" {
		t.Errorf("SoftError.Source = %q, want osv", soft.Source)
	}
	// Offline must yield no findings but must NOT have cached a "no vulns" result.
	if len(findings) != 0 {
		t.Errorf("offline findings = %d, want 0", len(findings))
	}
}

func TestEnrichNoSupportedComponents(t *testing.T) {
	s := newOSVTestServer(t)
	comps := []model.Component{{Ecosystem: "vscode", Name: "ext", Version: "1.0.0"}}
	findings, err := s.newEnricher(t, t.TempDir(), time.Hour).Enrich(context.Background(), comps)
	if err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0", len(findings))
	}
	// No batch query should have been issued.
	if got := atomic.LoadInt64(&s.batchHits); got != 0 {
		t.Errorf("batch hits = %d, want 0 (nothing to query)", got)
	}
}

func TestPreferredID(t *testing.T) {
	if got := preferredID("GHSA-x", []string{"GHSA-y", "CVE-2021-1"}); got != "CVE-2021-1" {
		t.Errorf("preferredID = %q, want CVE alias", got)
	}
	if got := preferredID("GHSA-x", []string{"GHSA-y"}); got != "" {
		t.Errorf("preferredID without CVE = %q, want empty", got)
	}
}
