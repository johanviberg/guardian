// Package osv implements an enrich.Enricher backed by the public OSV.dev
// vulnerability database (https://osv.dev). It batches supported components
// against the querybatch endpoint, fetches per-vuln details (with a local
// on-disk cache), and maps each (component, vuln) pair into a model.Finding.
//
// Enrichment is best-effort and offline-tolerant: any network failure is wrapped
// in an *enrich.SoftError and returned alongside whatever findings were gathered
// so the caller can warn and proceed. Only standard-library HTTP/JSON is used;
// no API key is required (a descriptive User-Agent is sent).
package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/johanviberg/guardian/internal/enrich"
	"github.com/johanviberg/guardian/internal/model"
)

const (
	// defaultBaseURL is the OSV REST API root.
	defaultBaseURL = "https://api.osv.dev"
	// batchLimit is the maximum number of queries per querybatch request.
	batchLimit = 1000
	// detailWorkers bounds concurrent vuln-detail fetches.
	detailWorkers = 8
	// userAgent identifies guardian to the OSV API.
	userAgent = "guardian-osv-enricher (+https://github.com/johanviberg/guardian)"
)

// ecosystemMap maps guardian ecosystem identifiers to OSV ecosystem names.
// Ecosystems absent from this map (vscode, cursor, windsurf, browserext, mcp,
// editorext, …) have no OSV coverage and are skipped.
var ecosystemMap = map[string]string{
	"npm":      "npm",
	"pypi":     "PyPI",
	"go":       "Go",
	"rubygems": "RubyGems",
	"composer": "Packagist",
}

// Enricher queries OSV.dev for known vulnerabilities affecting scanned components.
type Enricher struct {
	baseURL string
	client  *http.Client
	cache   *cache
}

// New constructs an OSV Enricher. cacheDir is where per-vuln detail JSON is
// cached (empty disables caching); ttl is the cache freshness window; client is
// the HTTP client (its Timeout serves as the per-request timeout). A nil client
// falls back to http.DefaultClient.
func New(cacheDir string, ttl time.Duration, client *http.Client) *Enricher {
	if client == nil {
		client = http.DefaultClient
	}
	return &Enricher{
		baseURL: defaultBaseURL,
		client:  client,
		cache:   newCache(cacheDir, ttl),
	}
}

// SetBaseURL overrides the OSV API root. It exists for tests that point the
// enricher at an httptest server; production code uses the default.
func (e *Enricher) SetBaseURL(u string) { e.baseURL = u }

// Name implements enrich.Enricher.
func (e *Enricher) Name() string { return "osv" }

// Enrich implements enrich.Enricher. It returns findings for every supported
// component that OSV reports a vulnerability for. On a network failure it
// returns the findings gathered so far together with an *enrich.SoftError.
func (e *Enricher) Enrich(ctx context.Context, comps []model.Component) ([]model.Finding, error) {
	queries, queryComps := e.buildQueries(comps)
	if len(queries) == 0 {
		return nil, nil
	}

	// Step 1: batch-query OSV for vuln ids per component.
	idsPerComp, err := e.queryBatchAll(ctx, queries)
	if err != nil {
		return nil, &enrich.SoftError{Source: e.Name(), Err: err}
	}

	// Collect the unique set of vuln ids to fetch details for.
	uniqueIDs := uniqueVulnIDs(idsPerComp)

	// Step 2: fetch details for each unique id (cache + bounded concurrency).
	details, detailErr := e.fetchDetails(ctx, uniqueIDs)

	// Step 3: build findings by pairing each component with its vuln details.
	findings := e.buildFindings(queryComps, idsPerComp, details)

	if detailErr != nil {
		return findings, &enrich.SoftError{Source: e.Name(), Err: detailErr}
	}
	return findings, nil
}

// buildQueries maps supported, versioned components to OSV batch queries. It
// returns the queries and the parallel slice of components they came from
// (aligned by index).
func (e *Enricher) buildQueries(comps []model.Component) ([]batchQuery, []model.Component) {
	var queries []batchQuery
	var queryComps []model.Component
	for _, c := range comps {
		osvEco, ok := ecosystemMap[c.Ecosystem]
		if !ok || c.Version == "" || c.Name == "" {
			continue // unsupported ecosystem or no concrete version: skip.
		}
		queries = append(queries, batchQuery{
			Package: batchPackage{Ecosystem: osvEco, Name: c.Name},
			Version: c.Version,
		})
		queryComps = append(queryComps, c)
	}
	return queries, queryComps
}

// queryBatchAll runs querybatch in chunks of batchLimit and returns, per input
// query index, the list of vuln ids OSV reported.
func (e *Enricher) queryBatchAll(ctx context.Context, queries []batchQuery) ([][]string, error) {
	out := make([][]string, len(queries))
	for start := 0; start < len(queries); start += batchLimit {
		end := start + batchLimit
		if end > len(queries) {
			end = len(queries)
		}
		chunk := queries[start:end]
		results, err := e.queryBatch(ctx, chunk)
		if err != nil {
			return nil, err
		}
		for i, r := range results {
			if start+i >= len(out) {
				break
			}
			ids := make([]string, 0, len(r.Vulns))
			for _, v := range r.Vulns {
				if v.ID != "" {
					ids = append(ids, v.ID)
				}
			}
			out[start+i] = ids
		}
	}
	return out, nil
}

func (e *Enricher) queryBatch(ctx context.Context, queries []batchQuery) ([]batchResult, error) {
	reqBody, err := json.Marshal(batchRequest{Queries: queries})
	if err != nil {
		return nil, fmt.Errorf("osv: marshal querybatch: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.baseURL+"/v1/querybatch", bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)

	resp, err := e.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("osv: querybatch: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv: querybatch: status %d", resp.StatusCode)
	}
	var br batchResponse
	if err := json.NewDecoder(resp.Body).Decode(&br); err != nil {
		return nil, fmt.Errorf("osv: decode querybatch: %w", err)
	}
	return br.Results, nil
}

// fetchDetails fetches details for each id, using the cache first and a bounded
// worker pool for the network fetches. It returns a map id->detail (only
// successful fetches are present) and, if any network fetch failed, a non-nil
// error (the first encountered) so the caller can soft-fail.
func (e *Enricher) fetchDetails(ctx context.Context, ids []string) (map[string]*vulnDetail, error) {
	out := make(map[string]*vulnDetail, len(ids))
	var toFetch []string

	for _, id := range ids {
		if d, ok := e.cache.get(id); ok {
			out[id] = d
			continue
		}
		toFetch = append(toFetch, id)
	}
	if len(toFetch) == 0 {
		return out, nil
	}

	var (
		mu       sync.Mutex
		firstErr error
		wg       sync.WaitGroup
	)
	jobs := make(chan string)

	workers := detailWorkers
	if workers > len(toFetch) {
		workers = len(toFetch)
	}
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range jobs {
				d, err := e.fetchDetail(ctx, id)
				mu.Lock()
				if err != nil {
					if firstErr == nil {
						firstErr = err
					}
				} else if d != nil {
					out[id] = d
					e.cache.put(id, d)
				}
				mu.Unlock()
			}
		}()
	}

feed:
	for _, id := range toFetch {
		select {
		case <-ctx.Done():
			mu.Lock()
			if firstErr == nil {
				firstErr = ctx.Err()
			}
			mu.Unlock()
			break feed
		case jobs <- id:
		}
	}
	close(jobs)
	wg.Wait()
	return out, firstErr
}

func (e *Enricher) fetchDetail(ctx context.Context, id string) (*vulnDetail, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.baseURL+"/v1/vulns/"+id, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := e.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("osv: vulns/%s: %w", id, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		// Limit body read defensively.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("osv: vulns/%s: status %d", id, resp.StatusCode)
	}
	var d vulnDetail
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return nil, fmt.Errorf("osv: decode vulns/%s: %w", id, err)
	}
	return &d, nil
}

// buildFindings pairs each component with the details of the vulns OSV reported
// for it, producing one finding per (component, vuln). Findings are returned in
// a deterministic order (by component index, then catalog id).
func (e *Enricher) buildFindings(comps []model.Component, idsPerComp [][]string, details map[string]*vulnDetail) []model.Finding {
	var findings []model.Finding
	for i, c := range comps {
		if i >= len(idsPerComp) {
			break
		}
		seen := map[string]bool{}
		ids := append([]string(nil), idsPerComp[i]...)
		sort.Strings(ids)
		for _, id := range ids {
			if seen[id] {
				continue
			}
			seen[id] = true
			d := details[id] // may be nil if the detail fetch failed.
			findings = append(findings, findingFor(c, id, d))
		}
	}
	return findings
}

// findingFor maps a single (component, vuln) into a model.Finding. The
// CatalogID prefers a CVE alias when present, else the OSV/GHSA id.
func findingFor(c model.Component, osvID string, d *vulnDetail) model.Finding {
	catalogID := osvID
	summary := ""
	severity := model.SeverityInfo
	if d != nil {
		if cve := preferredID(osvID, d.Aliases); cve != "" {
			catalogID = cve
		}
		summary = d.Summary
		if summary == "" {
			summary = d.Details
		}
		severity = severityForVuln(d)
	}
	return model.Finding{
		CatalogID:    catalogID,
		Severity:     severity,
		Class:        model.ClassVulnerable,
		Ecosystem:    c.Ecosystem,
		Name:         c.Name,
		Version:      c.Version,
		SourceFile:   c.SourceFile,
		EvidenceType: "osv",
		Confidence:   c.Confidence,
		Source:       model.SourceOSV,
		Summary:      summary,
	}
}

// preferredID returns a CVE alias if one is present, else "".
func preferredID(_ string, aliases []string) string {
	for _, a := range aliases {
		if len(a) >= 4 && a[:4] == "CVE-" {
			return a
		}
	}
	return ""
}

// uniqueVulnIDs flattens the per-component id lists into a sorted unique set.
func uniqueVulnIDs(idsPerComp [][]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, ids := range idsPerComp {
		for _, id := range ids {
			if id != "" && !seen[id] {
				seen[id] = true
				out = append(out, id)
			}
		}
	}
	sort.Strings(out)
	return out
}
