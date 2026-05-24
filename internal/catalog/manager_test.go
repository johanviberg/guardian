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

const goodCatalogJSON = `{
  "schema_version": 1,
  "version": "2026.05.24",
  "entries": [
    {"id": "MAL-2026-104", "ecosystem": "npm", "package": "evil", "versions": ["1.0.0"], "severity": "critical"},
    {"id": "GHSA-xxxx", "ecosystem": "pypi", "package": "risky", "versions": ["2.0.0", "2.1.0"], "severity": "high"}
  ]
}`

const malformedCatalogJSON = `{
  "schema_version": 1,
  "entries": [
    {"id": "BAD", "ecosystem": "npm", "package": "evil", "versions": ["1.0.0"], "severity": "spicy"}
  ]
}`

// catalogServer serves body and counts hits.
func catalogServer(t *testing.T, body string) (*httptest.Server, *int64) {
	t.Helper()
	var hits int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// newManagerForServer builds a Manager pointed at a TLS test server, trusting
// its cert and using a controllable clock.
func newManagerForServer(t *testing.T, srv *httptest.Server, cacheDir string, ttl time.Duration, clock func() time.Time, offline bool) *Manager {
	t.Helper()
	cfg := Config{
		CacheDir:   cacheDir,
		SourceURL:  srv.URL, // httptest TLS server URL is https://
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

func TestEnsureFreshFetch(t *testing.T) {
	srv, hits := catalogServer(t, goodCatalogJSON)
	dir := t.TempDir()
	m := newManagerForServer(t, srv, dir, time.Hour, time.Now, false)

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
	// Catalog file must be parseable + valid.
	cat, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if err := cat.Validate(); err != nil {
		t.Fatalf("cached catalog invalid: %v", err)
	}
}

func TestEnsureCacheHitWithinTTL(t *testing.T) {
	srv, hits := catalogServer(t, goodCatalogJSON)
	dir := t.TempDir()
	m := newManagerForServer(t, srv, dir, time.Hour, time.Now, false)

	if _, _, err := m.Ensure(context.Background()); err != nil {
		t.Fatalf("first Ensure: %v", err)
	}
	// Second call within TTL must not hit the server again.
	if _, _, err := m.Ensure(context.Background()); err != nil {
		t.Fatalf("second Ensure: %v", err)
	}
	if got := atomic.LoadInt64(hits); got != 1 {
		t.Fatalf("server hits = %d, want 1 (cache hit should not refetch)", got)
	}
}

func TestEnsureStaleRefetch(t *testing.T) {
	srv, hits := catalogServer(t, goodCatalogJSON)
	dir := t.TempDir()

	base := time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC)
	now := base
	clock := func() time.Time { return now }

	m := newManagerForServer(t, srv, dir, time.Hour, clock, false)
	if _, _, err := m.Ensure(context.Background()); err != nil {
		t.Fatalf("first Ensure: %v", err)
	}

	// Advance the clock past the TTL; next Ensure should refetch.
	now = base.Add(2 * time.Hour)
	if _, _, err := m.Ensure(context.Background()); err != nil {
		t.Fatalf("stale Ensure: %v", err)
	}
	if got := atomic.LoadInt64(hits); got != 2 {
		t.Fatalf("server hits = %d, want 2 (stale should refetch)", got)
	}
}

func TestEnsureChecksumRecorded(t *testing.T) {
	srv, _ := catalogServer(t, goodCatalogJSON)
	dir := t.TempDir()
	m := newManagerForServer(t, srv, dir, time.Hour, time.Now, false)

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

func TestEnsureOfflineWithCacheReturnsStale(t *testing.T) {
	srv, _ := catalogServer(t, goodCatalogJSON)
	dir := t.TempDir()

	base := time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC)
	now := base
	clock := func() time.Time { return now }

	// Prime the cache while online.
	m := newManagerForServer(t, srv, dir, time.Hour, clock, false)
	if _, _, err := m.Ensure(context.Background()); err != nil {
		t.Fatalf("prime Ensure: %v", err)
	}

	// Now go offline and advance past TTL so the cache is stale.
	now = base.Add(2 * time.Hour)
	off := newManagerForServer(t, srv, dir, time.Hour, clock, true)
	path, version, err := off.Ensure(context.Background())
	if !errors.Is(err, ErrStale) {
		t.Fatalf("Ensure err = %v, want wrapping ErrStale", err)
	}
	if path == "" || version != "2026.05.24" {
		t.Fatalf("path=%q version=%q, want cached path + version", path, version)
	}
}

func TestEnsureOfflineWithoutCacheHardError(t *testing.T) {
	srv, _ := catalogServer(t, goodCatalogJSON)
	dir := t.TempDir()
	m := newManagerForServer(t, srv, dir, time.Hour, time.Now, true)

	_, _, err := m.Ensure(context.Background())
	if !errors.Is(err, ErrNoCatalog) {
		t.Fatalf("Ensure err = %v, want wrapping ErrNoCatalog", err)
	}
	if errors.Is(err, ErrStale) {
		t.Fatalf("Ensure err = %v, should not be ErrStale with no cache", err)
	}
}

func TestEnsureMalformedCatalogRejected(t *testing.T) {
	srv, _ := catalogServer(t, malformedCatalogJSON)
	dir := t.TempDir()
	m := newManagerForServer(t, srv, dir, time.Hour, time.Now, false)

	_, _, err := m.Ensure(context.Background())
	if err == nil {
		t.Fatal("Ensure with malformed catalog = nil error, want validation error")
	}
	if !errors.Is(err, ErrNoCatalog) {
		t.Fatalf("Ensure err = %v, want wrapping ErrNoCatalog (no cache to fall back on)", err)
	}
	// Nothing should have been written to the cache.
	if _, statErr := os.Stat(filepath.Join(dir, catalogFileName)); !os.IsNotExist(statErr) {
		t.Fatalf("catalog file should not exist after rejected fetch, stat err = %v", statErr)
	}
}

func TestFreshness(t *testing.T) {
	srv, _ := catalogServer(t, goodCatalogJSON)
	dir := t.TempDir()

	base := time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC)
	now := base
	clock := func() time.Time { return now }
	m := newManagerForServer(t, srv, dir, time.Hour, clock, false)

	// No cache yet.
	if _, _, _, err := m.Freshness(context.Background()); !errors.Is(err, ErrNoCatalog) {
		t.Fatalf("Freshness without cache err = %v, want ErrNoCatalog", err)
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

func TestDeriveVersionFallback(t *testing.T) {
	cat := &Catalog{SchemaVersion: 1} // no Version field
	got := deriveVersion(cat, time.Date(2026, 5, 24, 0, 0, 0, 0, time.UTC), "abcdef0123456789")
	want := "20260524-abcdef012345"
	if got != want {
		t.Fatalf("deriveVersion = %q, want %q", got, want)
	}
}

func TestNewManagerDefaults(t *testing.T) {
	m, err := NewManager(Config{CacheDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if m.cfg.SourceURL != DefaultSourceURL {
		t.Fatalf("SourceURL = %q, want default", m.cfg.SourceURL)
	}
	if m.cfg.TTL != DefaultTTL {
		t.Fatalf("TTL = %v, want default", m.cfg.TTL)
	}
}

func TestNewManagerRequiresCacheDir(t *testing.T) {
	if _, err := NewManager(Config{}); err == nil {
		t.Fatal("NewManager without CacheDir = nil error, want error")
	}
}
