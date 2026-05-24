package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// goodCatalogJSON is a valid single-file catalog with string schema_version,
// an optional "version" field, free-form severity, and an extra per-entry
// "source" key (tolerated).
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

// malformedCatalogJSON has a missing ecosystem on the only entry — Validate
// should reject it.
const malformedCatalogJSON = `{
  "schema_version": "0.1.0",
  "entries": [
    {"id": "BAD", "package": "evil", "versions": ["1.0.0"], "severity": "critical"}
  ]
}`

// catalogServer serves body and counts hits.
func catalogServer(t *testing.T, body string) (*httptest.Server, *int64) {
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

// newManager builds a Manager pointed at srv with a controllable clock.
func newManager(t *testing.T, srv *httptest.Server, cacheDir string, ttl time.Duration, clock func() time.Time, offline bool) *Manager {
	t.Helper()
	cfg := Config{
		CacheDir:   cacheDir,
		SourceURL:  srv.URL, // httptest TLS server URL starts with https://
		TTL:        ttl,
		Offline:    offline,
		HTTPClient: srv.Client(), // trusts the test-server's self-signed cert
		now:        clock,
	}
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return m
}

// ---- Ensure: fresh fetch ----

func TestEnsureFreshFetch(t *testing.T) {
	srv, hits := catalogServer(t, goodCatalogJSON)
	dir := t.TempDir()
	m := newManager(t, srv, dir, time.Hour, time.Now, false)

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
	// Cached file must be parseable and valid.
	cat, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile cached: %v", err)
	}
	if err := cat.Validate(); err != nil {
		t.Fatalf("Validate cached: %v", err)
	}
}

// ---- Ensure: cache hit within TTL — server must NOT be hit again ----

func TestEnsureCacheHitWithinTTL(t *testing.T) {
	srv, hits := catalogServer(t, goodCatalogJSON)
	dir := t.TempDir()
	m := newManager(t, srv, dir, time.Hour, time.Now, false)

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

// ---- Ensure: stale cache triggers refetch ----

func TestEnsureStaleRefetch(t *testing.T) {
	srv, hits := catalogServer(t, goodCatalogJSON)
	dir := t.TempDir()

	base := time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC)
	now := base
	m := newManager(t, srv, dir, time.Hour, func() time.Time { return now }, false)

	if _, _, err := m.Ensure(context.Background()); err != nil {
		t.Fatalf("first Ensure: %v", err)
	}
	// Advance past TTL.
	now = base.Add(2 * time.Hour)
	if _, _, err := m.Ensure(context.Background()); err != nil {
		t.Fatalf("stale Ensure: %v", err)
	}
	if got := atomic.LoadInt64(hits); got != 2 {
		t.Fatalf("server hits = %d, want 2 (stale must refetch)", got)
	}
}

// ---- Ensure: checksum + metadata recorded ----

func TestEnsureChecksumRecorded(t *testing.T) {
	srv, _ := catalogServer(t, goodCatalogJSON)
	dir := t.TempDir()
	m := newManager(t, srv, dir, time.Hour, time.Now, false)

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
	if meta.SourceURL != srv.URL {
		t.Fatalf("source_url = %q, want %q", meta.SourceURL, srv.URL)
	}
	if meta.Version != "2026.05.24" {
		t.Fatalf("version = %q, want 2026.05.24", meta.Version)
	}
	if meta.FetchedAt.IsZero() {
		t.Fatal("fetched_at is zero")
	}
}

// ---- Ensure: offline with stale cache → ErrStale, usable path ----

func TestEnsureOfflineWithCacheReturnsErrStale(t *testing.T) {
	srv, _ := catalogServer(t, goodCatalogJSON)
	dir := t.TempDir()

	base := time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC)
	now := base
	clock := func() time.Time { return now }

	// Prime the cache while online.
	m := newManager(t, srv, dir, time.Hour, clock, false)
	if _, _, err := m.Ensure(context.Background()); err != nil {
		t.Fatalf("prime Ensure: %v", err)
	}

	// Go offline past TTL.
	now = base.Add(2 * time.Hour)
	off := newManager(t, srv, dir, time.Hour, clock, true)
	path, version, err := off.Ensure(context.Background())
	if !errors.Is(err, ErrStale) {
		t.Fatalf("Ensure err = %v, want wrapping ErrStale", err)
	}
	if path == "" || version != "2026.05.24" {
		t.Fatalf("path=%q version=%q, want cached path + version", path, version)
	}
}

// ---- Ensure: offline with no cache and no vendored fallback → ErrNoCatalog ----

func TestEnsureOfflineNoCacheNoFallbackHardError(t *testing.T) {
	srv, _ := catalogServer(t, goodCatalogJSON)
	dir := t.TempDir()
	m := newManager(t, srv, dir, time.Hour, time.Now, true)

	_, _, err := m.Ensure(context.Background())
	if !errors.Is(err, ErrNoCatalog) {
		t.Fatalf("Ensure err = %v, want wrapping ErrNoCatalog", err)
	}
	if errors.Is(err, ErrStale) {
		t.Fatalf("Ensure err = %v, must not be ErrStale when no cache", err)
	}
}

// ---- Ensure: offline with no cache but vendored fallback → ErrStale + path ----

func TestEnsureOfflineNoCacheVendoredFallback(t *testing.T) {
	// Build a local vendored-catalog directory.
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

	srv, _ := catalogServer(t, goodCatalogJSON)
	dir := t.TempDir()
	cfg := Config{
		CacheDir:          dir,
		SourceURL:         srv.URL,
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
	// Path returned must be the vendored dir, not the cache dir.
	if path != vendorDir {
		t.Fatalf("path = %q, want vendored dir %q", path, vendorDir)
	}
}

// ---- Ensure: malformed remote catalog rejected, nothing cached ----

func TestEnsureMalformedCatalogRejected(t *testing.T) {
	srv, _ := catalogServer(t, malformedCatalogJSON)
	dir := t.TempDir()
	m := newManager(t, srv, dir, time.Hour, time.Now, false)

	_, _, err := m.Ensure(context.Background())
	if err == nil {
		t.Fatal("Ensure with malformed catalog = nil error, want error")
	}
	if !errors.Is(err, ErrNoCatalog) {
		t.Fatalf("Ensure err = %v, want wrapping ErrNoCatalog (no cache to fall back on)", err)
	}
	// Nothing should have been written to the cache.
	if _, statErr := os.Stat(filepath.Join(dir, catalogFileName)); !os.IsNotExist(statErr) {
		t.Fatalf("catalog file should not exist after rejected fetch, stat=%v", statErr)
	}
}

// ---- Freshness ----

func TestFreshness(t *testing.T) {
	srv, _ := catalogServer(t, goodCatalogJSON)
	dir := t.TempDir()

	base := time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC)
	now := base
	clock := func() time.Time { return now }
	m := newManager(t, srv, dir, time.Hour, clock, false)

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

	// Advance past TTL.
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
	c := &Catalog{SchemaVersion: "0.1.0"} // no Version field
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
