package catalog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DefaultSourceURL is the GitHub Contents API listing for the Bumblebee
// threat_intel directory.
//
// NOTE: The real upstream layout is a DIRECTORY of per-advisory .json files
// (e.g. mini-shai-hulud.json, gemstuffer.json) — there is no single
// catalog.json. Remote sync therefore must enumerate this listing, download
// each .json, validate, and merge. Full remote multi-file sync is marked TODO
// below; the URL is correct but the fetch path is intentionally limited to a
// single-file fetch today (see TODO in fetch()).
//
// Confirm: https://github.com/perplexityai/bumblebee/tree/main/threat_intel
const DefaultSourceURL = "https://api.github.com/repos/perplexityai/bumblebee/contents/threat_intel?ref=main"

// DefaultTTL is the freshness window before a cached catalog is considered
// stale and Ensure attempts a refetch.
const DefaultTTL = 24 * time.Hour

const (
	catalogFileName = "catalog.json"
	metaFileName    = "catalog.meta.json"
)

// ErrStale is wrapped into the error returned by Ensure when a fresh fetch
// could not be performed (offline / fetch failure) but a usable cached catalog
// exists. Callers can test for it with errors.Is and decide whether to proceed.
var ErrStale = errors.New("catalog: cached copy is stale")

// ErrNoCatalog is returned when no usable catalog is available at all:
// fetching failed or was skipped and neither a cache nor a vendored fallback
// exists.
var ErrNoCatalog = errors.New("catalog: no catalog available")

// Config configures a Manager.
type Config struct {
	// CacheDir is the directory holding the cached merged catalog and its
	// metadata sidecar. It is created on demand.
	CacheDir string

	// SourceURL is the HTTPS URL to fetch the catalog from. Defaults to
	// DefaultSourceURL when empty. Override for testing or custom catalogs.
	SourceURL string

	// TTL is the freshness window. Defaults to DefaultTTL when zero.
	TTL time.Duration

	// Offline, when true, skips all network fetches; Ensure relies on the
	// cached copy then the vendored fallback. NoFetch is an alias kept for
	// caller ergonomics (both flags take effect if either is set).
	Offline bool
	NoFetch bool

	// DefaultCatalogDir is the path to a directory of bundled/vendored
	// catalog files used as a last-resort fallback when no cache exists and
	// fetching is impossible (offline mode or network failure). It is NOT
	// fetched from — it is read directly from disk.
	//
	// Set this to the vendored threat_intel/ directory so guardian works
	// offline out-of-the-box:
	//
	//   DefaultCatalogDir: "internal/bumblebee/threat_intel"
	//
	// When empty, no vendored fallback is used.
	DefaultCatalogDir string

	// HTTPClient is used for fetches. Defaults to a client with a sane
	// timeout.
	HTTPClient *http.Client

	// now allows tests to control time; nil means time.Now.
	now func() time.Time
}

// Manager fetches, caches, versions, and validates exposure catalogs.
type Manager struct {
	cfg Config
}

// Meta is the provenance sidecar recorded alongside a cached catalog.
type Meta struct {
	Version    string    `json:"version"`
	FetchedAt  time.Time `json:"fetched_at"`
	SHA256     string    `json:"sha256"`
	EntryCount int       `json:"entry_count"`
	SourceURL  string    `json:"source_url"`
}

// NewManager builds a Manager, applying defaults to the supplied config.
func NewManager(cfg Config) (*Manager, error) {
	if cfg.CacheDir == "" {
		return nil, errors.New("catalog: CacheDir is required")
	}
	if cfg.SourceURL == "" {
		cfg.SourceURL = DefaultSourceURL
	}
	if cfg.TTL == 0 {
		cfg.TTL = DefaultTTL
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	if cfg.now == nil {
		cfg.now = time.Now
	}
	return &Manager{cfg: cfg}, nil
}

func (m *Manager) offline() bool { return m.cfg.Offline || m.cfg.NoFetch }

func (m *Manager) catalogPath() string { return filepath.Join(m.cfg.CacheDir, catalogFileName) }
func (m *Manager) metaPath() string    { return filepath.Join(m.cfg.CacheDir, metaFileName) }

// Ensure guarantees a usable catalog path and returns it together with the
// catalog's version string.
//
// Resolution order:
//  1. Cached catalog present + fresh (within TTL) → return immediately, no I/O.
//  2. Cached missing/stale + fetching permitted → fetch, validate, cache
//     atomically, return new path.
//  3. Fetch fails (network error) but cache exists → return cached path +
//     ErrStale; caller decides whether to proceed.
//  4. Offline/NoFetch + cache exists but stale → same as (3).
//  5. No cache + fetch impossible → try DefaultCatalogDir (vendored fallback)
//     and return its path + ErrStale.
//  6. No cache, no fetch, no vendored fallback → ErrNoCatalog.
//
// The returned path always points at a file the engine's exposure.Load() can
// read (a valid JSON catalog with schema_version + entries).
func (m *Manager) Ensure(ctx context.Context) (cachedPath string, version string, err error) {
	_, cachedMeta, haveCache := m.loadCache()

	// (1) Fresh cache hit.
	if haveCache && !m.isStale(cachedMeta) {
		return m.catalogPath(), cachedMeta.Version, nil
	}

	// (2) Attempt fetch.
	if !m.offline() {
		meta, fetchErr := m.fetch(ctx)
		if fetchErr == nil {
			return m.catalogPath(), meta.Version, nil
		}
		// Fetch failed.
		if haveCache {
			// (3) Stale cache usable.
			return m.catalogPath(), cachedMeta.Version,
				fmt.Errorf("%w: fetch failed (%v), using cached copy", ErrStale, fetchErr)
		}
		// No cache — try vendored fallback.
		if p, v, ferr := m.vendoredFallback(); ferr == nil {
			return p, v, fmt.Errorf("%w: fetch failed (%v), using vendored catalog", ErrStale, fetchErr)
		}
		return "", "", fmt.Errorf("%w: fetch failed: %v", ErrNoCatalog, fetchErr)
	}

	// Offline path.
	if haveCache {
		// (4) Stale cache, offline.
		msg := fmt.Sprintf("offline, last fetched %s", cachedMeta.FetchedAt.Format(time.RFC3339))
		if !m.isStale(cachedMeta) {
			// still fresh even though we're offline — no error needed
			return m.catalogPath(), cachedMeta.Version, nil
		}
		return m.catalogPath(), cachedMeta.Version,
			fmt.Errorf("%w: %s", ErrStale, msg)
	}

	// (5) No cache, offline — try vendored fallback.
	if p, v, ferr := m.vendoredFallback(); ferr == nil {
		return p, v, fmt.Errorf("%w: offline and no cached catalog, using vendored catalog", ErrStale)
	}

	// (6) No catalog available.
	return "", "", fmt.Errorf("%w: offline and no cached catalog", ErrNoCatalog)
}

// vendoredFallback loads the DefaultCatalogDir as a merged catalog and returns
// its directory path and a derived version. It does NOT copy to CacheDir — the
// caller should pass the returned path straight to the engine.
func (m *Manager) vendoredFallback() (path string, version string, err error) {
	if m.cfg.DefaultCatalogDir == "" {
		return "", "", errors.New("no DefaultCatalogDir configured")
	}
	c, err := LoadDir(m.cfg.DefaultCatalogDir)
	if err != nil {
		return "", "", err
	}
	if verr := c.Validate(); verr != nil {
		return "", "", verr
	}
	sum, _ := c.SHA256Hex()
	ver := deriveVersion(c, m.cfg.now(), sum)
	return m.cfg.DefaultCatalogDir, ver, nil
}

// Freshness reports the cached catalog's version, fetch time, and whether it
// is stale. It performs no network access and is intended for
// `guardian status` / `guardian doctor`.
func (m *Manager) Freshness(_ context.Context) (version string, fetchedAt time.Time, stale bool, err error) {
	_, meta, ok := m.loadCache()
	if !ok {
		return "", time.Time{}, true, fmt.Errorf("%w: no cached catalog", ErrNoCatalog)
	}
	return meta.Version, meta.FetchedAt, m.isStale(meta), nil
}

func (m *Manager) isStale(meta Meta) bool {
	if meta.FetchedAt.IsZero() {
		return true
	}
	return m.cfg.now().Sub(meta.FetchedAt) > m.cfg.TTL
}

// loadCache reads the cached catalog body and its metadata sidecar. ok is
// false unless both the catalog file and a parseable sidecar exist.
func (m *Manager) loadCache() (body []byte, meta Meta, ok bool) {
	body, err := os.ReadFile(m.catalogPath())
	if err != nil {
		return nil, Meta{}, false
	}
	mb, err := os.ReadFile(m.metaPath())
	if err != nil {
		return nil, Meta{}, false
	}
	if err := json.Unmarshal(mb, &meta); err != nil {
		return nil, Meta{}, false
	}
	return body, meta, true
}

// fetch downloads the catalog from SourceURL, validates it, checksums the raw
// bytes, and atomically writes both the catalog file and its metadata sidecar
// to CacheDir.
//
// TODO(remote-dir-sync): The upstream threat_intel/ is a directory of
// per-advisory .json files, not a single file. Full remote sync should:
//  1. GET DefaultSourceURL (GitHub Contents API) → JSON array of {name, download_url}.
//  2. Filter entries where name ends in ".json".
//  3. Download each file, validate, accumulate entries.
//  4. Write the merged catalog atomically to CacheDir/catalog.json.
//
// Until that is implemented, SourceURL must point at a single raw JSON catalog
// (e.g. a custom mirror or a direct raw.githubusercontent.com URL for one
// file). Using DefaultSourceURL as-is will return a GitHub API JSON array
// (not a catalog), which Parse will accept as an empty catalog — Ensure will
// return ErrNoCatalog (no entries) rather than silently caching garbage,
// because fetch() rejects catalogs with zero entries after a remote fetch.
// Override SourceURL in Config to point at a single raw file for now.
func (m *Manager) fetch(ctx context.Context) (Meta, error) {
	if !strings.HasPrefix(strings.ToLower(m.cfg.SourceURL), "https://") {
		return Meta{}, fmt.Errorf("source URL must be HTTPS: %q", m.cfg.SourceURL)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.cfg.SourceURL, nil)
	if err != nil {
		return Meta{}, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := m.cfg.HTTPClient.Do(req)
	if err != nil {
		return Meta{}, fmt.Errorf("http get: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Meta{}, fmt.Errorf("unexpected status %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return Meta{}, fmt.Errorf("read body: %w", err)
	}

	cat, err := Parse(body)
	if err != nil {
		return Meta{}, err
	}
	if err := cat.Validate(); err != nil {
		return Meta{}, err
	}
	// After a remote fetch we require at least one entry — an empty catalog
	// from a remote source almost certainly means we fetched the wrong URL
	// (e.g. the GitHub Contents API listing itself rather than a raw file).
	if len(cat.Entries) == 0 {
		return Meta{}, errors.New("catalog: remote response parsed as an empty catalog (zero entries); check SourceURL — it should point at a single raw catalog JSON, not a directory listing")
	}

	sum := sha256.Sum256(body)
	hexSum := hex.EncodeToString(sum[:])
	now := m.cfg.now()

	meta := Meta{
		Version:    deriveVersion(cat, now, hexSum),
		FetchedAt:  now,
		SHA256:     hexSum,
		EntryCount: len(cat.Entries),
		SourceURL:  m.cfg.SourceURL,
	}

	if err := os.MkdirAll(m.cfg.CacheDir, 0o750); err != nil {
		return Meta{}, fmt.Errorf("create cache dir: %w", err)
	}
	if err := writeFileAtomic(m.catalogPath(), body, 0o644); err != nil {
		return Meta{}, fmt.Errorf("write catalog: %w", err)
	}
	mb, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return Meta{}, fmt.Errorf("marshal meta: %w", err)
	}
	if err := writeFileAtomic(m.metaPath(), mb, 0o644); err != nil {
		return Meta{}, fmt.Errorf("write meta: %w", err)
	}
	return meta, nil
}

// deriveVersion prefers the catalog's own Version field; otherwise it derives
// a stable version string from the fetch date and the first 12 hex chars of
// the sha256 checksum.
func deriveVersion(cat *Catalog, fetchedAt time.Time, hexSum string) string {
	if cat.Version != "" {
		return cat.Version
	}
	prefix := hexSum
	if len(prefix) > 12 {
		prefix = prefix[:12]
	}
	return fmt.Sprintf("%s-%s", fetchedAt.UTC().Format("20060102"), prefix)
}

// writeFileAtomic writes data to path via a temp file + rename so readers
// never observe a partial write.
func writeFileAtomic(path string, data []byte, perm os.FileMode) (err error) {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-"+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err = tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
