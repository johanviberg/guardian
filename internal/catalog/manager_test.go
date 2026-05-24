package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// ---- Catalog fixtures ----

// goodCatalogJSON is a valid single-file catalog (string schema_version,
// optional "version" field, free-form severity, tolerated extra "source" key).
const goodCatalogJSON = `{
  "schema_version": "0.1.0",
  "version": "2026.05.24",
  "entries": [
    {"id": "MAL-2026-104", "ecosystem": "npm", "package": "evil",
     "versions": ["1.0.0"], "severity": "critical", "source": "https://example.com"},
    {"id": "GHSA-xxxx", "ecosystem": "pypi", "package": "risky",
     "versions": ["2.0.0", "2.1.0"], "severity": "high"}
  ]
}`

// malformedCatalogJSON has a missing ecosystem — Validate should reject it.
const malformedCatalogJSON = `{
  "schema_version": "0.1.0",
  "entries": [
    {"id": "BAD", "package": "evil", "versions": ["1.0.0"], "severity": "critical"}
  ]
}`

// perAdvisory{A,B,C}JSON are three minimal per-advisory catalogs used in
// directory-listing tests.
const perAdvisoryAJSON = `{
  "schema_version": "0.1.0",
  "_comment": "advisory A",
  "entries": [
    {"id":"ADV-A-1","ecosystem":"npm","package":"pkg-a","versions":["1.0.0"],"severity":"critical"}
  ]
}`

const perAdvisoryBJSON = `{
  "schema_version": "0.1.0",
  "_comment": "advisory B",
  "entries": [
    {"id":"ADV-B-1","ecosystem":"pypi","package":"pkg-b","versions":["2.0.0"],"severity":"high"},
    {"id":"ADV-B-2","ecosystem":"pypi","package":"pkg-b-extra","versions":["3.0.0"],"severity":"medium"}
  ]
}`

const perAdvisoryCJSON = `{
  "schema_version": "0.1.0",
  "entries": [
    {"id":"ADV-C-1","ecosystem":"go","package":"github.com/evil/c","versions":["v1.2.3"],"severity":"info"}
  ]
}`

// ---- Server helpers ----

// singleFileServer serves body at every path and counts hits.
func singleFileServer(t *testing.T, body string) (*httptest.Server, *int64) {
	t.Helper()
	var hits int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// dirListingServer builds a TLS httptest server that:
//   - serves a GitHub Contents API JSON listing at /listing (counting listHits)
//   - serves per-file bodies at /files/<name> (counting fileHits per name)
//
// catalogBodies is a map[filename]body; download_urls in the listing point at
// /files/<filename> on the same server.
func dirListingServer(t *testing.T, catalogBodies map[string]string) (srv *httptest.Server, listHits *int64, fileHits *int64) {
	t.Helper()
	var lhits, fhits int64

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/listing":
			atomic.AddInt64(&lhits, 1)
			// Build a GitHub Contents API-style listing.
			// Assign the server URL inside the handler so we have access to it.
			// We use a placeholder that is replaced after the server starts — but
			// since we need the URL before the server is started we use a
			// self-referential trick via the Host header.
			scheme := "https"
			host := r.Host
			var ghFiles []ghFile
			for name := range catalogBodies {
				ghFiles = append(ghFiles, ghFile{
					Name:        name,
					Type:        "file",
					DownloadURL: fmt.Sprintf("%s://%s/files/%s", scheme, host, name),
				})
			}
			// Also include a non-JSON file and a directory entry to verify filtering.
			ghFiles = append(ghFiles,
				ghFile{Name: "README.md", Type: "file", DownloadURL: fmt.Sprintf("%s://%s/files/README.md", scheme, host)},
				ghFile{Name: "subdir", Type: "dir", DownloadURL: ""},
			)
			enc, _ := json.Marshal(ghFiles)
			_, _ = w.Write(enc)

		case len(r.URL.Path) > len("/files/") && r.URL.Path[:len("/files/")] == "/files/":
			name := r.URL.Path[len("/files/"):]
			body, ok := catalogBodies[name]
			if !ok {
				http.NotFound(w, r)
				return
			}
			atomic.AddInt64(&fhits, 1)
			_, _ = w.Write([]byte(body))

		default:
			http.NotFound(w, r)
		}
	})

	srv = httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)
	return srv, &lhits, &fhits
}

// statusServer returns a TLS server that always responds with the given status code.
func statusServer(t *testing.T, status int, extraHeaders map[string]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		for k, v := range extraHeaders {
			w.Header().Set(k, v)
		}
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// ---- Manager constructors ----

// newSingleFileManager builds a Manager whose SourceURL ends in ".json" so it
// uses single-file mode. The server must already be a TLS httptest.Server.
func newSingleFileManager(t *testing.T, srv *httptest.Server, cacheDir string, ttl time.Duration, clock func() time.Time, offline bool) *Manager {
	t.Helper()
	cfg := Config{
		CacheDir:   cacheDir,
		SourceURL:  srv.URL + "/catalog.json", // ".json" suffix → single-file mode
		TTL:        ttl,
		Offline:    offline,
		HTTPClient: srv.Client(),
		now:        clock,
	}
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return m
}

// newDirListingManager builds a Manager whose SourceURL points at the /listing
// path (no .json suffix → directory-listing mode).
func newDirListingManager(t *testing.T, srv *httptest.Server, cacheDir string, ttl time.Duration, clock func() time.Time, offline bool) *Manager {
	t.Helper()
	cfg := Config{
		CacheDir:   cacheDir,
		SourceURL:  srv.URL + "/listing",
		TTL:        ttl,
		Offline:    offline,
		HTTPClient: srv.Client(),
		now:        clock,
	}
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return m
}

// ---- isSingleFileURL ----

func TestIsSingleFileURL(t *testing.T) {
	cases := []struct {
		url  string
		want bool
	}{
		{"https://example.com/catalog.json", true},
		{"https://example.com/catalog.JSON", true},
		{"https://example.com/catalog.json?ref=main", true}, // path ends in .json; query string is ignored
		{"https://api.github.com/repos/x/y/contents/threat_intel?ref=main", false},
		{"https://raw.githubusercontent.com/x/y/main/threat_intel/evil.json", true},
		{"https://example.com/", false},
	}
	for _, tc := range cases {
		if got := isSingleFileURL(tc.url); got != tc.want {
			t.Errorf("isSingleFileURL(%q) = %v, want %v", tc.url, got, tc.want)
		}
	}
}

// ---- Single-file mode: existing behavior preserved ----

func TestEnsureFreshFetch(t *testing.T) {
	srv, hits := singleFileServer(t, goodCatalogJSON)
	dir := t.TempDir()
	m := newSingleFileManager(t, srv, dir, time.Hour, time.Now, false)

	path, version, err := m.Ensure(context.Background())
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if version != "2026.05.24" {
		t.Fatalf("version = %q, want catalog-supplied 2026.05.24", version)
	}
	if got := atomic.LoadInt64(hits); got != 1 {
		t.Fatalf("server hits = %d, want 1", got)
	}
	if path != filepath.Join(dir, catalogFileName) {
		t.Fatalf("path = %q, unexpected", path)
	}
	cat, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile cached: %v", err)
	}
	if err := cat.Validate(); err != nil {
		t.Fatalf("Validate cached: %v", err)
	}
}

func TestEnsureCacheHitWithinTTL(t *testing.T) {
	srv, hits := singleFileServer(t, goodCatalogJSON)
	dir := t.TempDir()
	m := newSingleFileManager(t, srv, dir, time.Hour, time.Now, false)

	if _, _, err := m.Ensure(context.Background()); err != nil {
		t.Fatalf("first Ensure: %v", err)
	}
	if _, _, err := m.Ensure(context.Background()); err != nil {
		t.Fatalf("second Ensure: %v", err)
	}
	if got := atomic.LoadInt64(hits); got != 1 {
		t.Fatalf("server hits = %d, want 1 (cache hit must not refetch)", got)
	}
}

func TestEnsureStaleRefetch(t *testing.T) {
	srv, hits := singleFileServer(t, goodCatalogJSON)
	dir := t.TempDir()

	base := time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC)
	now := base
	m := newSingleFileManager(t, srv, dir, time.Hour, func() time.Time { return now }, false)

	if _, _, err := m.Ensure(context.Background()); err != nil {
		t.Fatalf("first Ensure: %v", err)
	}
	now = base.Add(2 * time.Hour)
	if _, _, err := m.Ensure(context.Background()); err != nil {
		t.Fatalf("stale Ensure: %v", err)
	}
	if got := atomic.LoadInt64(hits); got != 2 {
		t.Fatalf("server hits = %d, want 2 (stale must refetch)", got)
	}
}

func TestEnsureChecksumRecorded(t *testing.T) {
	srv, _ := singleFileServer(t, goodCatalogJSON)
	dir := t.TempDir()
	m := newSingleFileManager(t, srv, dir, time.Hour, time.Now, false)

	if _, _, err := m.Ensure(context.Background()); err != nil {
		t.Fatalf("Ensure: %v", err)
	}

	mb, err := os.ReadFile(filepath.Join(dir, metaFileName))
	if err != nil {
		t.Fatalf("read meta: %v", err)
	}
	var meta Meta
	if err := json.Unmarshal(mb, &meta); err != nil {
		t.Fatalf("unmarshal meta: %v", err)
	}
	if len(meta.SHA256) != 64 {
		t.Fatalf("sha256 = %q, want 64 hex chars", meta.SHA256)
	}
	if meta.EntryCount != 2 {
		t.Fatalf("entry_count = %d, want 2", meta.EntryCount)
	}
	if meta.Version != "2026.05.24" {
		t.Fatalf("version = %q, want 2026.05.24", meta.Version)
	}
	if meta.FetchedAt.IsZero() {
		t.Fatal("fetched_at is zero")
	}
}

func TestEnsureOfflineWithCacheReturnsErrStale(t *testing.T) {
	srv, _ := singleFileServer(t, goodCatalogJSON)
	dir := t.TempDir()

	base := time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC)
	now := base
	clock := func() time.Time { return now }

	m := newSingleFileManager(t, srv, dir, time.Hour, clock, false)
	if _, _, err := m.Ensure(context.Background()); err != nil {
		t.Fatalf("prime Ensure: %v", err)
	}
	now = base.Add(2 * time.Hour)
	off := newSingleFileManager(t, srv, dir, time.Hour, clock, true)
	path, version, err := off.Ensure(context.Background())
	if !errors.Is(err, ErrStale) {
		t.Fatalf("Ensure err = %v, want wrapping ErrStale", err)
	}
	if path == "" || version != "2026.05.24" {
		t.Fatalf("path=%q version=%q, want cached path + version", path, version)
	}
}

func TestEnsureOfflineNoCacheNoFallbackHardError(t *testing.T) {
	srv, _ := singleFileServer(t, goodCatalogJSON)
	dir := t.TempDir()
	m := newSingleFileManager(t, srv, dir, time.Hour, time.Now, true)

	_, _, err := m.Ensure(context.Background())
	if !errors.Is(err, ErrNoCatalog) {
		t.Fatalf("Ensure err = %v, want wrapping ErrNoCatalog", err)
	}
	if errors.Is(err, ErrStale) {
		t.Fatalf("Ensure err = %v, must not be ErrStale when no cache", err)
	}
}

func TestEnsureOfflineNoCacheVendoredFallback(t *testing.T) {
	vendorDir := t.TempDir()
	const advisory = `{
		"schema_version": "0.1.0",
		"entries": [
			{"id":"V1","ecosystem":"npm","package":"vuln","versions":["1.0"],"severity":"high"}
		]
	}`
	if err := os.WriteFile(filepath.Join(vendorDir, "advisory.json"), []byte(advisory), 0o644); err != nil {
		t.Fatal(err)
	}

	srv, _ := singleFileServer(t, goodCatalogJSON)
	dir := t.TempDir()
	cfg := Config{
		CacheDir:          dir,
		SourceURL:         srv.URL + "/catalog.json",
		TTL:               time.Hour,
		Offline:           true,
		DefaultCatalogDir: vendorDir,
		HTTPClient:        srv.Client(),
		now:               time.Now,
	}
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	path, _, err := m.Ensure(context.Background())
	if !errors.Is(err, ErrStale) {
		t.Fatalf("Ensure err = %v, want ErrStale (vendored fallback)", err)
	}
	if path != vendorDir {
		t.Fatalf("path = %q, want vendored dir %q", path, vendorDir)
	}
}

func TestEnsureMalformedCatalogRejected(t *testing.T) {
	srv, _ := singleFileServer(t, malformedCatalogJSON)
	dir := t.TempDir()
	m := newSingleFileManager(t, srv, dir, time.Hour, time.Now, false)

	_, _, err := m.Ensure(context.Background())
	if err == nil {
		t.Fatal("Ensure with malformed catalog = nil error, want error")
	}
	if !errors.Is(err, ErrNoCatalog) {
		t.Fatalf("Ensure err = %v, want wrapping ErrNoCatalog", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, catalogFileName)); !os.IsNotExist(statErr) {
		t.Fatalf("catalog file should not exist after rejected fetch, stat=%v", statErr)
	}
}

// ---- Directory-listing mode ----

func TestEnsureDirListingFetchesAllFiles(t *testing.T) {
	bodies := map[string]string{
		"a-advisory.json": perAdvisoryAJSON,
		"b-advisory.json": perAdvisoryBJSON,
		"c-advisory.json": perAdvisoryCJSON,
	}
	srv, listHits, fileHits := dirListingServer(t, bodies)
	dir := t.TempDir()
	m := newDirListingManager(t, srv, dir, time.Hour, time.Now, false)

	path, version, err := m.Ensure(context.Background())
	if err != nil {
		t.Fatalf("Ensure (dir mode): %v", err)
	}

	// Listing endpoint hit exactly once.
	if got := atomic.LoadInt64(listHits); got != 1 {
		t.Fatalf("listing hits = %d, want 1", got)
	}
	// Each of the 3 JSON files was fetched exactly once.
	if got := atomic.LoadInt64(fileHits); got != 3 {
		t.Fatalf("file hits = %d, want 3 (one per advisory .json)", got)
	}

	// Cached file exists and is parseable.
	if path != filepath.Join(dir, catalogFileName) {
		t.Fatalf("path = %q, want catalog.json in cache dir", path)
	}
	cached, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile cached: %v", err)
	}
	if err := cached.Validate(); err != nil {
		t.Fatalf("Validate cached: %v", err)
	}

	// Entry count = 1 (A) + 2 (B) + 1 (C) = 4.
	if len(cached.Entries) != 4 {
		t.Fatalf("cached entry count = %d, want 4", len(cached.Entries))
	}

	// Metadata sidecar correct.
	mb, err := os.ReadFile(filepath.Join(dir, metaFileName))
	if err != nil {
		t.Fatalf("read meta: %v", err)
	}
	var meta Meta
	if err := json.Unmarshal(mb, &meta); err != nil {
		t.Fatalf("unmarshal meta: %v", err)
	}
	if meta.EntryCount != 4 {
		t.Fatalf("meta entry_count = %d, want 4", meta.EntryCount)
	}
	if len(meta.SHA256) != 64 {
		t.Fatalf("meta sha256 = %q, want 64 hex chars", meta.SHA256)
	}
	if meta.FetchedAt.IsZero() {
		t.Fatal("meta fetched_at is zero")
	}
	// Version was derived (no version field in any advisory fixture).
	if version == "" {
		t.Fatal("version is empty")
	}
	t.Logf("dir-mode version: %s", version)
}

func TestEnsureDirListingCacheHitNoRefetch(t *testing.T) {
	bodies := map[string]string{
		"a-advisory.json": perAdvisoryAJSON,
	}
	srv, listHits, _ := dirListingServer(t, bodies)
	dir := t.TempDir()
	m := newDirListingManager(t, srv, dir, time.Hour, time.Now, false)

	if _, _, err := m.Ensure(context.Background()); err != nil {
		t.Fatalf("first Ensure: %v", err)
	}
	if _, _, err := m.Ensure(context.Background()); err != nil {
		t.Fatalf("second Ensure: %v", err)
	}
	if got := atomic.LoadInt64(listHits); got != 1 {
		t.Fatalf("listing hits = %d, want 1 (cache hit must not refetch)", got)
	}
}

func TestEnsureDirListingStaleRefetch(t *testing.T) {
	bodies := map[string]string{
		"a-advisory.json": perAdvisoryAJSON,
	}
	srv, listHits, _ := dirListingServer(t, bodies)
	dir := t.TempDir()

	base := time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC)
	now := base
	m := newDirListingManager(t, srv, dir, time.Hour, func() time.Time { return now }, false)

	if _, _, err := m.Ensure(context.Background()); err != nil {
		t.Fatalf("first Ensure: %v", err)
	}
	now = base.Add(2 * time.Hour)
	if _, _, err := m.Ensure(context.Background()); err != nil {
		t.Fatalf("stale Ensure: %v", err)
	}
	if got := atomic.LoadInt64(listHits); got != 2 {
		t.Fatalf("listing hits = %d, want 2 (stale must refetch)", got)
	}
}

func TestEnsureDirListingNoJSONFiles(t *testing.T) {
	// Listing returns only non-JSON and dir entries — should result in ErrNoCatalog.
	bodies := map[string]string{} // empty: server listing has README.md + subdir only
	srv, _, _ := dirListingServer(t, bodies)
	dir := t.TempDir()
	m := newDirListingManager(t, srv, dir, time.Hour, time.Now, false)

	_, _, err := m.Ensure(context.Background())
	if !errors.Is(err, ErrNoCatalog) {
		t.Fatalf("Ensure err = %v, want wrapping ErrNoCatalog", err)
	}
}

func TestEnsureDirListingMalformedFileRejected(t *testing.T) {
	// One advisory file in the listing is malformed — the whole fetch should fail.
	bodies := map[string]string{
		"good.json": perAdvisoryAJSON,
		"bad.json":  malformedCatalogJSON, // missing ecosystem
	}
	srv, _, _ := dirListingServer(t, bodies)
	dir := t.TempDir()
	m := newDirListingManager(t, srv, dir, time.Hour, time.Now, false)

	_, _, err := m.Ensure(context.Background())
	if err == nil {
		t.Fatal("Ensure with malformed file in listing = nil error, want error")
	}
	if !errors.Is(err, ErrNoCatalog) {
		t.Fatalf("Ensure err = %v, want wrapping ErrNoCatalog", err)
	}
	// Nothing cached.
	if _, statErr := os.Stat(filepath.Join(dir, catalogFileName)); !os.IsNotExist(statErr) {
		t.Fatalf("catalog should not be cached after rejected fetch, stat=%v", statErr)
	}
}

func TestEnsureDirListingNonOKThenErrStaleWithCache(t *testing.T) {
	// Prime the cache in single-file mode, then switch to a dir-listing server
	// that returns 503, and confirm we get ErrStale with the old cached path.
	srvOK, _ := singleFileServer(t, goodCatalogJSON)
	dir := t.TempDir()

	base := time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC)
	now := base
	clock := func() time.Time { return now }

	// Prime cache.
	mOK := newSingleFileManager(t, srvOK, dir, time.Hour, clock, false)
	if _, _, err := mOK.Ensure(context.Background()); err != nil {
		t.Fatalf("prime Ensure: %v", err)
	}

	// Advance past TTL; point at a 503 server (dir-listing mode).
	now = base.Add(2 * time.Hour)
	srvBad := statusServer(t, http.StatusServiceUnavailable, nil)
	cfg := Config{
		CacheDir:   dir,
		SourceURL:  srvBad.URL + "/listing", // no .json → dir mode
		TTL:        time.Hour,
		HTTPClient: srvBad.Client(),
		now:        clock,
	}
	mBad, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	path, version, err := mBad.Ensure(context.Background())
	if !errors.Is(err, ErrStale) {
		t.Fatalf("Ensure err = %v, want ErrStale", err)
	}
	if path == "" || version != "2026.05.24" {
		t.Fatalf("path=%q version=%q, want cached values", path, version)
	}
}

func TestEnsureDirRateLimitSurfacesHelpfulError(t *testing.T) {
	// A 403 with X-RateLimit-Remaining: 0 should produce a clear error and,
	// with a cache present, ErrStale.
	srvOK, _ := singleFileServer(t, goodCatalogJSON)
	dir := t.TempDir()

	base := time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC)
	now := base
	clock := func() time.Time { return now }

	// Prime cache.
	mOK := newSingleFileManager(t, srvOK, dir, time.Hour, clock, false)
	if _, _, err := mOK.Ensure(context.Background()); err != nil {
		t.Fatalf("prime Ensure: %v", err)
	}

	// Advance past TTL; rate-limited 403.
	now = base.Add(2 * time.Hour)
	srvRL := statusServer(t, http.StatusForbidden, map[string]string{
		"X-RateLimit-Remaining": "0",
		"X-RateLimit-Reset":     "1748260800",
	})
	cfg := Config{
		CacheDir:   dir,
		SourceURL:  srvRL.URL + "/listing",
		TTL:        time.Hour,
		HTTPClient: srvRL.Client(),
		now:        clock,
	}
	mRL, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	_, _, err = mRL.Ensure(context.Background())
	if !errors.Is(err, ErrStale) {
		t.Fatalf("Ensure err = %v, want ErrStale (rate-limited, cache present)", err)
	}
	// Error message should mention rate limit.
	if err == nil || err.Error() == "" {
		t.Fatal("error message is empty")
	}
	t.Logf("rate-limit error: %v", err)
}

// ---- Freshness ----

func TestFreshness(t *testing.T) {
	srv, _ := singleFileServer(t, goodCatalogJSON)
	dir := t.TempDir()

	base := time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC)
	now := base
	clock := func() time.Time { return now }
	m := newSingleFileManager(t, srv, dir, time.Hour, clock, false)

	// No cache yet.
	if _, _, _, err := m.Freshness(context.Background()); !errors.Is(err, ErrNoCatalog) {
		t.Fatalf("Freshness without cache = %v, want ErrNoCatalog", err)
	}

	if _, _, err := m.Ensure(context.Background()); err != nil {
		t.Fatalf("Ensure: %v", err)
	}

	version, fetchedAt, stale, err := m.Freshness(context.Background())
	if err != nil {
		t.Fatalf("Freshness: %v", err)
	}
	if version != "2026.05.24" {
		t.Fatalf("version = %q", version)
	}
	if !fetchedAt.Equal(base) {
		t.Fatalf("fetchedAt = %v, want %v", fetchedAt, base)
	}
	if stale {
		t.Fatal("stale = true within TTL, want false")
	}

	now = base.Add(2 * time.Hour)
	_, _, stale, err = m.Freshness(context.Background())
	if err != nil {
		t.Fatalf("Freshness (stale): %v", err)
	}
	if !stale {
		t.Fatal("stale = false past TTL, want true")
	}
}

// ---- deriveVersion ----

func TestDeriveVersionUsesVersionField(t *testing.T) {
	c := &Catalog{SchemaVersion: "0.1.0", Version: "v2026.05.24"}
	got := deriveVersion(c, time.Now(), "aabbcc")
	if got != "v2026.05.24" {
		t.Fatalf("deriveVersion = %q, want %q", got, "v2026.05.24")
	}
}

func TestDeriveVersionFallback(t *testing.T) {
	c := &Catalog{SchemaVersion: "0.1.0"}
	got := deriveVersion(c, time.Date(2026, 5, 24, 0, 0, 0, 0, time.UTC), "abcdef0123456789")
	want := "20260524-abcdef012345"
	if got != want {
		t.Fatalf("deriveVersion = %q, want %q", got, want)
	}
}

// ---- NewManager defaults and validation ----

func TestNewManagerDefaults(t *testing.T) {
	m, err := NewManager(Config{CacheDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if m.cfg.SourceURL != DefaultSourceURL {
		t.Fatalf("SourceURL = %q, want DefaultSourceURL", m.cfg.SourceURL)
	}
	if m.cfg.TTL != DefaultTTL {
		t.Fatalf("TTL = %v, want DefaultTTL", m.cfg.TTL)
	}
}

func TestNewManagerRequiresCacheDir(t *testing.T) {
	if _, err := NewManager(Config{}); err == nil {
		t.Fatal("NewManager without CacheDir = nil error, want error")
	}
}
