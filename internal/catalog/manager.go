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

// DefaultSourceURL is the default catalog source: Bumblebee's threat_intel
// exposure catalog, fetched over HTTPS.
//
// NOTE: This points at the raw catalog JSON in the upstream
// perplexityai/bumblebee repository. The exact path under threat_intel/ should
// be CONFIRMED against the real upstream repo layout before release — adjust
// this const (or override via Config.SourceURL) if the upstream filename or
// directory differs.
const DefaultSourceURL = "https://raw.githubusercontent.com/perplexityai/bumblebee/main/threat_intel/catalog.json"

// DefaultTTL is the freshness window before a cached catalog is considered
// stale and Ensure attempts a refetch.
const DefaultTTL = 24 * time.Hour

const (
	catalogFileName = "catalog.json"
	metaFileName    = "catalog.meta.json"
)

// ErrStale is wrapped into the error returned by Ensure when a fresh fetch could
// not be performed (offline / fetch failure) but a usable cached catalog
// exists. Callers can test for it with errors.Is and decide whether to proceed
// with the stale catalog.
var ErrStale = errors.New("catalog: cached copy is stale")

// ErrNoCatalog is returned when no usable catalog is available at all: fetching
// failed or was skipped and no cached copy exists.
var ErrNoCatalog = errors.New("catalog: no catalog available")

// Config configures a Manager.
type Config struct {
	// CacheDir is the directory holding the cached catalog and its metadata
	// sidecar. It is created on demand.
	CacheDir string
	// SourceURL is the HTTPS URL to fetch the catalog from. Defaults to
	// DefaultSourceURL when empty.
	SourceURL string
	// TTL is the freshness window. Defaults to DefaultTTL when zero.
	TTL time.Duration
	// Offline, when true, skips all network fetches; Ensure relies entirely on
	// the cached copy. NoFetch is an alias kept for caller ergonomics.
	Offline bool
	NoFetch bool
	// HTTPClient is used for fetches. Defaults to a client with a sane timeout.
	HTTPClient *http.Client
	// now allows tests to control time; nil means time.Now.
	now func() time.Time
}

// Manager fetches, caches, versions, and validates exposure catalogs.
type Manager struct {
	cfg Config
}

// Meta is the provenance sidecar recorded next to a cached catalog.
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

// Ensure guarantees a usable cached catalog and returns its path and version.
//
// Behaviour:
//   - If the cached catalog is present and fresh (within TTL), it is returned
//     without any network access.
//   - If it is missing or stale and fetching is permitted, the source URL is
//     fetched over HTTPS, parsed, validated, checksummed, and written to the
//     cache atomically, with a metadata sidecar recorded.
//   - If a fetch is needed but fails (offline / network error) yet a cached copy
//     exists, the cached path and version are returned alongside an error that
//     wraps ErrStale, so the caller may choose to proceed.
//   - If no catalog can be obtained at all, an error wrapping ErrNoCatalog is
//     returned.
func (m *Manager) Ensure(ctx context.Context) (cachedPath string, version string, err error) {
	cached, cachedMeta, haveCache := m.loadCache()

	// Fresh cache hit: no network.
	if haveCache && !m.isStale(cachedMeta) {
		return m.catalogPath(), cachedMeta.Version, nil
	}

	// A fetch is wanted but disabled.
	if m.offline() {
		if haveCache {
			return m.catalogPath(), cachedMeta.Version, fmt.Errorf("%w: offline, last fetched %s", ErrStale, cachedMeta.FetchedAt.Format(time.RFC3339))
		}
		return "", "", fmt.Errorf("%w: offline and no cached catalog", ErrNoCatalog)
	}

	meta, fetchErr := m.fetch(ctx)
	if fetchErr != nil {
		if haveCache {
			return m.catalogPath(), cachedMeta.Version, fmt.Errorf("%w: fetch failed (%v), using cached copy", ErrStale, fetchErr)
		}
		return "", "", fmt.Errorf("%w: fetch failed: %v", ErrNoCatalog, fetchErr)
	}
	_ = cached // cached body no longer needed after a successful fetch
	return m.catalogPath(), meta.Version, nil
}

// Freshness reports the current cached catalog's version, fetch time, and
// whether it is stale relative to the TTL. It performs no network access and is
// intended for `guardian status` / `guardian doctor`.
func (m *Manager) Freshness(ctx context.Context) (version string, fetchedAt time.Time, stale bool, err error) {
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

// loadCache reads the cached catalog and its metadata. ok is false unless both
// the catalog and a parseable metadata sidecar exist.
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

// fetch downloads, validates, checksums, and atomically writes the catalog plus
// its metadata sidecar.
func (m *Manager) fetch(ctx context.Context) (Meta, error) {
	if !strings.HasPrefix(strings.ToLower(m.cfg.SourceURL), "https://") {
		return Meta{}, fmt.Errorf("source URL must be HTTPS: %q", m.cfg.SourceURL)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.cfg.SourceURL, nil)
	if err != nil {
		return Meta{}, fmt.Errorf("build request: %w", err)
	}
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

	if err := os.MkdirAll(m.cfg.CacheDir, 0o755); err != nil {
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

// deriveVersion prefers the catalog's own version field; otherwise it derives a
// stable version string from the fetch date and the sha256 prefix.
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

// writeFileAtomic writes data to path by writing to a temp file in the same
// directory and renaming it into place, so readers never observe a partial
// file.
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
		tmp.Close()
		return err
	}
	if err = tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
