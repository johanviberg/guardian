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
	"unicode"

	"github.com/johanviberg/guardian/internal/catalog/minisign"
)

// SourceSpec describes a single catalog source for FeedSet.
type SourceSpec struct {
	// Name is a human-readable identifier used for per-source caching and
	// warnings. It must be unique within a FeedSet.
	Name string
	// URL is the HTTPS URL for this source (same semantics as Config.SourceURL).
	URL string
	// Verify selects minisign verification: VerifyOff, VerifyWarn, VerifyRequire.
	Verify string
	// PublicKey is the trusted minisign public key for this source.
	PublicKey minisign.PublicKey
	// PublicKeySet indicates whether PublicKey holds a real key.
	PublicKeySet bool
}

// MultiConfig configures a FeedSet.
type MultiConfig struct {
	// CacheDir is the root directory for all cached data. Per-source caches land
	// under CacheDir/sources/<name>/; the merged catalog at CacheDir/catalog.json.
	CacheDir string

	// Sources is the list of remote feed sources. At least one is required.
	Sources []SourceSpec

	// DefaultCatalogDir is the embedded baseline catalog directory (builtin).
	// Loaded as an implicit, always-trusted, unsigned source merged after all
	// remote sources. Optional; skipped when empty.
	DefaultCatalogDir string

	// TTL is the freshness window for all sources. Defaults to DefaultTTL.
	TTL time.Duration

	// NoFetch skips all network fetches; relies on cached copies and the baseline.
	NoFetch bool

	// HTTPClient is used for all outbound requests. Nil = 30-second-timeout client.
	HTTPClient *http.Client

	// WarnWriter receives human-readable warnings. Nil discards them.
	WarnWriter io.Writer

	// now is injectable for deterministic tests.
	now func() time.Time
}

// FeedMeta is the provenance sidecar for the merged catalog produced by FeedSet.
type FeedMeta struct {
	Version    string           `json:"version"`
	FetchedAt  time.Time        `json:"fetched_at"`
	SHA256     string           `json:"sha256"` // combined hash over per-source sha256s
	EntryCount int              `json:"entry_count"`
	Sources    []FeedSourceMeta `json:"sources"`
	Warnings   []string         `json:"warnings,omitempty"`
}

// FeedSourceMeta is per-source provenance in the FeedMeta sidecar.
type FeedSourceMeta struct {
	Name      string    `json:"name"`
	URL       string    `json:"url"`
	Version   string    `json:"version"`
	FetchedAt time.Time `json:"fetched_at"`
	SHA256    string    `json:"sha256"`
	Stale     bool      `json:"stale,omitempty"`
	Skipped   bool      `json:"skipped,omitempty"`
}

// FeedSet fetches, caches, and merges catalogs from multiple sources plus the
// embedded baseline, producing a single merged catalog.json for the engine.
type FeedSet struct {
	cfg      MultiConfig
	managers []*Manager // one per source, in Sources order
}

// NewFeedSet builds a FeedSet, creating per-source Managers.
func NewFeedSet(cfg MultiConfig) (*FeedSet, error) {
	if cfg.CacheDir == "" {
		return nil, errors.New("catalog: FeedSet CacheDir is required")
	}
	if len(cfg.Sources) == 0 {
		return nil, errors.New("catalog: FeedSet requires at least one source")
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

	fs := &FeedSet{cfg: cfg}
	fs.managers = make([]*Manager, len(cfg.Sources))
	for i, src := range cfg.Sources {
		subDir := filepath.Join(cfg.CacheDir, "sources", sanitizeName(src.Name))
		mgr, err := NewManager(Config{
			CacheDir:     subDir,
			SourceURL:    src.URL,
			TTL:          cfg.TTL,
			NoFetch:      cfg.NoFetch,
			HTTPClient:   cfg.HTTPClient,
			Verify:       src.Verify,
			PublicKey:    src.PublicKey,
			PublicKeySet: src.PublicKeySet,
			WarnWriter:   cfg.WarnWriter,
			now:          cfg.now,
		})
		if err != nil {
			return nil, fmt.Errorf("catalog: source %q: %w", src.Name, err)
		}
		fs.managers[i] = mgr
	}
	return fs, nil
}

// sanitizeName converts a source name to a filesystem-safe directory component.
// Only alphanumerics, '-', and '_' are kept; all other characters become '_'.
// The result is lower-cased and never empty.
func sanitizeName(name string) string {
	if name == "" {
		return "_unnamed"
	}
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	if b.Len() == 0 {
		return "_unnamed"
	}
	return b.String()
}

// feedMetaPath returns the path for the merged FeedSet metadata sidecar.
func (fs *FeedSet) feedMetaPath() string {
	return filepath.Join(fs.cfg.CacheDir, "feed.meta.json")
}

// mergedCatalogPath returns the path where the merged catalog.json is written.
func (fs *FeedSet) mergedCatalogPath() string {
	return filepath.Join(fs.cfg.CacheDir, catalogFileName)
}

// warnf emits a warning to the configured WarnWriter.
func (fs *FeedSet) warnf(format string, args ...any) {
	if fs.cfg.WarnWriter == nil {
		return
	}
	fmt.Fprintf(fs.cfg.WarnWriter, "guardian: catalog: "+format+"\n", args...)
}

// Ensure resolves the merged catalog for all sources + baseline, writes it to
// CacheDir/catalog.json, and returns the merged path and combined version.
//
// Per-source behavior:
//   - If a source fetch fails AND a cached copy exists, that cached copy is
//     used with a warning (stale).
//   - If a source uses require mode and signature verification fails,
//     ErrSignature is propagated immediately (hard error).
//   - If a source fails with no cached copy, it is skipped with a warning (and
//     its entries are absent from the merge).
//
// The embedded baseline (DefaultCatalogDir) is always loaded if present; it
// is never fetched from and cannot fail the merge.
func (fs *FeedSet) Ensure(ctx context.Context) (mergedPath, version string, err error) {
	var (
		catalogs   []*Catalog
		sourceMeta []FeedSourceMeta
		mergeWarns []string
	)

	// Step 1: gather each source.
	for i, src := range fs.cfg.Sources {
		mgr := fs.managers[i]
		path, ver, srcErr := mgr.Ensure(ctx)

		sm := FeedSourceMeta{
			Name: src.Name,
			URL:  src.URL,
		}

		switch {
		case errors.Is(srcErr, ErrSignature):
			// Hard error: propagate without fallback.
			return "", "", srcErr

		case srcErr == nil:
			// Success (possibly fresh or stale-but-cached).
			cat, lerr := loadCatalogPath(path)
			if lerr != nil {
				fs.warnf("source %q: loaded but unreadable (%v); skipping", src.Name, lerr)
				sm.Skipped = true
			} else {
				// Pull version and hash from the per-source meta sidecar if available.
				_, pm, hasMeta := mgr.loadCache()
				if hasMeta {
					sm.Version = pm.Version
					sm.FetchedAt = pm.FetchedAt
					sm.SHA256 = pm.SHA256
				}
				sm.Version = ver
				catalogs = append(catalogs, cat)
			}

		case errors.Is(srcErr, ErrStale):
			// Stale cache is usable.
			cat, lerr := loadCatalogPath(path)
			if lerr != nil {
				fs.warnf("source %q: stale cache unreadable (%v); skipping", src.Name, lerr)
				sm.Skipped = true
			} else {
				fs.warnf("source %q: %v", src.Name, srcErr)
				_, pm, hasMeta := mgr.loadCache()
				if hasMeta {
					sm.FetchedAt = pm.FetchedAt
					sm.SHA256 = pm.SHA256
				}
				sm.Version = ver
				sm.Stale = true
				catalogs = append(catalogs, cat)
			}

		default:
			// Total fetch failure, no cached copy.
			fs.warnf("source %q: %v; skipping", src.Name, srcErr)
			sm.Skipped = true
		}

		sourceMeta = append(sourceMeta, sm)
	}

	// Step 2: always load the embedded baseline (implicit unsigned source).
	if fs.cfg.DefaultCatalogDir != "" {
		baseline, berr := LoadDir(fs.cfg.DefaultCatalogDir)
		if berr != nil {
			fs.warnf("embedded baseline: %v; skipping", berr)
		} else {
			catalogs = append(catalogs, baseline)
		}
	}

	if len(catalogs) == 0 {
		return "", "", fmt.Errorf("%w: all sources failed and no baseline available", ErrNoCatalog)
	}

	// Step 3: merge.
	merged, warns := MergeCatalogs(catalogs...)
	mergeWarns = append(mergeWarns, warns...)
	for _, w := range warns {
		fs.warnf("%s", w)
	}

	// Step 4: marshal the merged catalog and hash its content. The version is
	// derived from the merged content hash, so it is stable and meaningful in
	// every case — including offline / baseline-only, where no remote source
	// contributes a hash (otherwise the version would degrade to the sha256 of
	// an empty input).
	mergedBody, err := json.MarshalIndent(merged, "", "  ")
	if err != nil {
		return "", "", fmt.Errorf("marshal merged catalog: %w", err)
	}

	mergedSum := sha256.Sum256(mergedBody)
	mergedHex := hex.EncodeToString(mergedSum[:])

	prefix := mergedHex
	if len(prefix) > 12 {
		prefix = prefix[:12]
	}
	now := fs.cfg.now()
	ver := fmt.Sprintf("%s-%s", now.UTC().Format("20060102"), prefix)
	// If the merged catalog itself has a version tag, prefer it.
	if merged.Version != "" {
		ver = merged.Version
	}

	if err := os.MkdirAll(fs.cfg.CacheDir, 0o750); err != nil {
		return "", "", fmt.Errorf("create cache dir: %w", err)
	}
	if err := writeFileAtomic(fs.mergedCatalogPath(), mergedBody, 0o640); err != nil {
		return "", "", fmt.Errorf("write merged catalog: %w", err)
	}

	fm := FeedMeta{
		Version:    ver,
		FetchedAt:  now,
		SHA256:     mergedHex,
		EntryCount: len(merged.Entries),
		Sources:    sourceMeta,
		Warnings:   mergeWarns,
	}
	fmBody, err := json.MarshalIndent(fm, "", "  ")
	if err != nil {
		return "", "", fmt.Errorf("marshal feed meta: %w", err)
	}
	if err := writeFileAtomic(fs.feedMetaPath(), fmBody, 0o640); err != nil {
		return "", "", fmt.Errorf("write feed meta: %w", err)
	}

	return fs.mergedCatalogPath(), ver, nil
}

// Freshness reads the cached FeedMeta sidecar (no network) and reports the
// merged version, the oldest source fetch time (as the staleness signal), and
// whether any source is stale.
func (fs *FeedSet) Freshness(_ context.Context) (version string, fetchedAt time.Time, stale bool, err error) {
	fm, ok := fs.loadFeedMeta()
	if !ok {
		return "", time.Time{}, true, fmt.Errorf("%w: no merged catalog cached", ErrNoCatalog)
	}
	version = fm.Version
	// Use the oldest source fetch time as the staleness signal.
	for _, sm := range fm.Sources {
		if sm.Skipped {
			continue
		}
		if fetchedAt.IsZero() || sm.FetchedAt.Before(fetchedAt) {
			fetchedAt = sm.FetchedAt
		}
		if sm.Stale {
			stale = true
		}
	}
	if fetchedAt.IsZero() {
		fetchedAt = fm.FetchedAt
	}
	// Check TTL against the oldest source.
	if !stale && !fetchedAt.IsZero() {
		stale = fs.cfg.now().Sub(fetchedAt) > fs.cfg.TTL
	}
	return version, fetchedAt, stale, nil
}

// LoadFeedMeta reads the merged feed metadata sidecar for display in catalog
// list/show commands. ok is false when no sidecar exists.
func (fs *FeedSet) LoadFeedMeta() (FeedMeta, bool) { return fs.loadFeedMeta() }

func (fs *FeedSet) loadFeedMeta() (FeedMeta, bool) {
	// #nosec G304 -- path is derived from the user's configured cache dir;
	// reading it for a read-only JSON decode is the documented function.
	b, err := os.ReadFile(fs.feedMetaPath())
	if err != nil {
		return FeedMeta{}, false
	}
	var fm FeedMeta
	if err := json.Unmarshal(b, &fm); err != nil {
		return FeedMeta{}, false
	}
	return fm, true
}

// loadCatalogPath loads a catalog from path. If path is a directory it calls
// LoadDir; otherwise LoadFile.
func loadCatalogPath(path string) (*Catalog, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.IsDir() {
		return LoadDir(path)
	}
	return LoadFile(path)
}

// FeedSetFromConfig is a convenience constructor that builds a FeedSet from the
// config-level EffectiveSources, resolving each source's public key. It is
// intended for cmd/ to call instead of constructing the FeedSet manually.
//
// defaultCatalogDir is the materialized embedded baseline directory (may be "").
func FeedSetFromConfig(
	cacheDir string,
	sources []SourceSpecRaw,
	defaultCatalogDir string,
	ttl time.Duration,
	noFetch bool,
	httpClient *http.Client,
	warnWriter io.Writer,
) (*FeedSet, error) {
	specs := make([]SourceSpec, 0, len(sources))
	for _, s := range sources {
		spec := SourceSpec{
			Name:   s.Name,
			URL:    s.URL,
			Verify: s.Verify,
		}
		if s.PublicKey != "" {
			pk, set, err := ResolvePublicKey(s.PublicKey)
			if err != nil {
				return nil, fmt.Errorf("catalog: source %q: %w", s.Name, err)
			}
			spec.PublicKey = pk
			spec.PublicKeySet = set
		}
		specs = append(specs, spec)
	}
	return NewFeedSet(MultiConfig{
		CacheDir:          cacheDir,
		Sources:           specs,
		DefaultCatalogDir: defaultCatalogDir,
		TTL:               ttl,
		NoFetch:           noFetch,
		HTTPClient:        httpClient,
		WarnWriter:        warnWriter,
	})
}

// SourceSpecRaw is a config-level source spec before public key resolution.
// This decouples the config package from the minisign package.
type SourceSpecRaw struct {
	Name      string
	URL       string
	Verify    string
	PublicKey string // path or inline key text
}

// FeedSetFreshness reads the merged FeedMeta from the cache dir and reports
// version, oldest source fetch time, and staleness. This is a package-level
// helper for cmd/ that does not need a live FeedSet.
func FeedSetFreshness(cacheDir string, ttl time.Duration) (version string, fetchedAt time.Time, stale bool, err error) {
	// #nosec G304 -- cacheDir is the user-configured cache directory;
	// reading the metadata sidecar for a read-only JSON decode is intended.
	b, readErr := os.ReadFile(filepath.Join(cacheDir, "feed.meta.json"))
	if readErr != nil {
		// Fall back to the legacy single-source sidecar.
		// #nosec G304 -- same as above
		b, readErr = os.ReadFile(filepath.Join(cacheDir, "catalog.meta.json"))
		if readErr != nil {
			return "", time.Time{}, true, fmt.Errorf("%w: no cached catalog", ErrNoCatalog)
		}
		var meta Meta
		if jerr := json.Unmarshal(b, &meta); jerr != nil {
			return "", time.Time{}, true, fmt.Errorf("%w: unreadable catalog metadata", ErrNoCatalog)
		}
		stale = meta.FetchedAt.IsZero() || time.Since(meta.FetchedAt) > ttl
		return meta.Version, meta.FetchedAt, stale, nil
	}
	var fm FeedMeta
	if jerr := json.Unmarshal(b, &fm); jerr != nil {
		return "", time.Time{}, true, fmt.Errorf("%w: unreadable feed metadata", ErrNoCatalog)
	}
	oldest := fm.FetchedAt
	for _, sm := range fm.Sources {
		if sm.Skipped {
			continue
		}
		if oldest.IsZero() || sm.FetchedAt.Before(oldest) {
			oldest = sm.FetchedAt
		}
	}
	stale = oldest.IsZero() || time.Since(oldest) > ttl
	return fm.Version, oldest, stale, nil
}
