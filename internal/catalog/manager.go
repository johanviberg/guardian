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
	"sort"
	"strings"
	"time"

	"github.com/johanviberg/guardian/internal/catalog/minisign"
)

// DefaultSourceURL is the GitHub Contents API listing for the upstream
// Bumblebee threat_intel directory.
//
// The API returns a JSON array of file objects; guardian filters for entries
// with type "file" and a name ending in ".json", then fetches each
// download_url individually. See fetchDir for the full protocol.
//
// Verify the path against the live repo:
// https://github.com/perplexityai/bumblebee/tree/main/threat_intel
const DefaultSourceURL = "https://api.github.com/repos/perplexityai/bumblebee/contents/threat_intel?ref=main"

// userAgent is sent on every HTTP request. GitHub's API requires a non-empty
// User-Agent; we identify the client clearly.
const userAgent = "guardian/1 catalog-sync (github.com/johanviberg/guardian)"

// DefaultTTL is the freshness window before a cached catalog is considered
// stale and Ensure attempts a refetch.
const DefaultTTL = 24 * time.Hour

const (
	catalogFileName = "catalog.json"
	metaFileName    = "catalog.meta.json"
)

// ErrStale is returned (wrapped) by Ensure when a fresh fetch could not be
// performed but a usable cached or vendored catalog exists. Callers test with
// errors.Is and decide whether to proceed.
var ErrStale = errors.New("catalog: cached copy is stale")

// ErrNoCatalog is returned when no usable catalog is available at all.
var ErrNoCatalog = errors.New("catalog: no catalog available")

// ErrSignature is returned (wrapped) when signature verification is required
// (Verify == VerifyRequire) and a downloaded catalog file has a missing or
// invalid minisign signature. When this is returned, nothing is written to the
// cache — verification happens before caching.
var ErrSignature = errors.New("catalog: signature verification failed")

// Signature-verification modes, mirroring config.Verify*.
const (
	// VerifyOff disables signature verification (default).
	VerifyOff = "off"
	// VerifyWarn verifies when a signature is available and warns (but proceeds)
	// on a missing or invalid signature.
	VerifyWarn = "warn"
	// VerifyRequire requires a valid signature on every catalog file; any
	// missing or invalid signature aborts the update with ErrSignature.
	VerifyRequire = "require"
)

// minisigSuffix is the conventional detached-signature filename suffix.
const minisigSuffix = ".minisig"

// errNotFound is an internal sentinel: httpGet wraps it for an HTTP 404 so that
// signature fetches can distinguish a cleanly-absent sibling .minisig from a
// transport error.
var errNotFound = errors.New("not found")

// Config configures a Manager.
type Config struct {
	// CacheDir is the directory holding cached catalog files and the metadata
	// sidecar. It is created on demand with mode 0750.
	CacheDir string

	// SourceURL is the HTTPS URL to fetch catalogs from. Defaults to
	// DefaultSourceURL when empty.
	//
	// Mode is determined by the URL suffix:
	//   - ends in ".json" → single-file mode: GET the URL, expect one catalog.
	//   - anything else   → directory-listing mode: expect a GitHub Contents API
	//     JSON array; each file entry is downloaded individually and merged.
	SourceURL string

	// TTL is the freshness window. Defaults to DefaultTTL when zero.
	TTL time.Duration

	// Offline / NoFetch skip all network fetches (either flag is sufficient).
	// Ensure then relies on the cached copy then the vendored fallback.
	Offline bool
	NoFetch bool

	// DefaultCatalogDir is the path to a directory of vendored/bundled catalog
	// files used as a last-resort fallback when no cache exists and fetching is
	// impossible. It is read directly from disk — never fetched from.
	//
	// Point this at the vendored threat_intel/ directory so guardian works
	// fully offline out-of-the-box:
	//
	//	DefaultCatalogDir: "internal/bumblebee/threat_intel"
	DefaultCatalogDir string

	// HTTPClient is used for all outbound requests. Defaults to a client with
	// a 30-second timeout.
	HTTPClient *http.Client

	// Verify selects minisign signature verification of fetched catalog files:
	// VerifyOff (default/empty), VerifyWarn, or VerifyRequire. Verification only
	// runs when Verify != VerifyOff and PublicKey is set.
	Verify string

	// PublicKey is the trusted minisign public key. It is only consulted when
	// Verify != VerifyOff. The zero value is treated as "no key".
	PublicKey minisign.PublicKey

	// PublicKeySet indicates whether PublicKey carries a real key. Callers that
	// construct Config from configuration should set this when a key was parsed.
	PublicKeySet bool

	// WarnWriter receives human-readable warnings (e.g. missing/invalid
	// signatures in VerifyWarn mode). Nil discards warnings.
	WarnWriter io.Writer

	// now is injectable for deterministic tests. Nil means time.Now.
	now func() time.Time
}

// Manager fetches, caches, versions, and validates exposure catalogs.
type Manager struct {
	cfg Config
}

// Meta is the provenance sidecar written alongside every cached catalog.
type Meta struct {
	Version    string    `json:"version"`
	FetchedAt  time.Time `json:"fetched_at"`
	SHA256     string    `json:"sha256"`
	EntryCount int       `json:"entry_count"`
	SourceURL  string    `json:"source_url"`
}

// ghFile is one element in a GitHub Contents API listing response.
type ghFile struct {
	Name        string `json:"name"`
	Type        string `json:"type"` // "file" | "dir" | "symlink" | "submodule"
	DownloadURL string `json:"download_url"`
}

// NewManager builds a Manager, filling in defaults.
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
	if cfg.Verify == "" {
		cfg.Verify = VerifyOff
	}
	return &Manager{cfg: cfg}, nil
}

// ResolvePublicKey interprets a configured public-key string, which may be
// either an inline minisign public key (the base64 line, optionally with its
// `untrusted comment:` line) OR a path to a minisign public-key file.
//
// Detection: the string is first tried as an inline key; if that fails it is
// treated as a file path. An empty string returns the zero key with set=false
// and no error (verification disabled).
func ResolvePublicKey(s string) (pk minisign.PublicKey, set bool, err error) {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return minisign.PublicKey{}, false, nil
	}
	if k, perr := minisign.ParsePublicKey(trimmed); perr == nil {
		return k, true, nil
	}
	// Fall back to treating it as a path.
	k, ferr := minisign.LoadPublicKey(s)
	if ferr != nil {
		return minisign.PublicKey{}, false,
			fmt.Errorf("catalog: public_key %q is neither a valid inline minisign key nor a readable key file: %w", s, ferr)
	}
	return k, true, nil
}

func (m *Manager) offline() bool { return m.cfg.Offline || m.cfg.NoFetch }

// verifyEnabled reports whether signature verification should run: the mode is
// not "off" and a trusted public key is present.
func (m *Manager) verifyEnabled() bool {
	return m.cfg.Verify != VerifyOff && m.cfg.Verify != "" && m.cfg.PublicKeySet
}

// warnf emits a warning to the configured WarnWriter, if any.
func (m *Manager) warnf(format string, args ...any) {
	if m.cfg.WarnWriter == nil {
		return
	}
	fmt.Fprintf(m.cfg.WarnWriter, "guardian: catalog signature: "+format+"\n", args...)
}

// verifyBytes verifies message against a detached minisign signature fetched
// from sigURL. label is a human-readable name for messages.
//
// Behavior depends on m.cfg.Verify:
//   - VerifyRequire: a missing or invalid signature returns a wrapped
//     ErrSignature (caller must abort and not cache).
//   - VerifyWarn: a missing or invalid signature is logged and nil is returned
//     so the caller proceeds.
//
// It is only called when verifyEnabled() is true.
func (m *Manager) verifyBytes(ctx context.Context, label string, message []byte, sigURL string) error {
	sigBytes, sigOK, err := m.fetchSignature(ctx, sigURL)
	if err != nil {
		// Hard transport error fetching the signature (not a clean 404).
		return m.signatureFailure(label, fmt.Sprintf("fetching signature: %v", err))
	}
	if !sigOK {
		return m.signatureFailure(label, "no signature available")
	}

	sig, err := minisign.ParseSignature(sigBytes)
	if err != nil {
		return m.signatureFailure(label, fmt.Sprintf("malformed signature: %v", err))
	}
	if err := m.cfg.PublicKey.Verify(message, sig); err != nil {
		switch {
		case errors.Is(err, minisign.ErrWrongKey):
			return m.signatureFailure(label, "signature was made with a different key than the configured public key")
		default:
			return m.signatureFailure(label, fmt.Sprintf("invalid signature: %v", err))
		}
	}
	return nil
}

// signatureFailure applies the configured policy to a verification failure:
// require => wrapped ErrSignature; warn => log and return nil.
func (m *Manager) signatureFailure(label, reason string) error {
	if m.cfg.Verify == VerifyRequire {
		return fmt.Errorf("%w: %s: %s", ErrSignature, label, reason)
	}
	// VerifyWarn: warn and proceed.
	m.warnf("%s: %s (proceeding because verify mode is %q)", label, reason, m.cfg.Verify)
	return nil
}

// fetchSignature fetches a detached signature. It returns ok=false (with no
// error) when the signature is cleanly absent (HTTP 404), so callers can treat
// "missing" distinctly from a transport failure.
func (m *Manager) fetchSignature(ctx context.Context, sigURL string) (body []byte, ok bool, err error) {
	body, err = m.httpGet(ctx, sigURL)
	if err != nil {
		if errors.Is(err, errNotFound) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return body, true, nil
}

func (m *Manager) catalogPath() string { return filepath.Join(m.cfg.CacheDir, catalogFileName) }
func (m *Manager) metaPath() string    { return filepath.Join(m.cfg.CacheDir, metaFileName) }

// isSingleFileURL reports whether SourceURL refers to a single catalog file
// (ends in ".json") rather than a directory listing endpoint.
func isSingleFileURL(rawURL string) bool {
	// Strip any query string before checking the suffix.
	path := rawURL
	if i := strings.IndexByte(rawURL, '?'); i >= 0 {
		path = rawURL[:i]
	}
	return strings.HasSuffix(strings.ToLower(path), ".json")
}

// Ensure guarantees a usable catalog and returns its local path and version.
//
// Resolution order:
//  1. Cache present and fresh (within TTL) → return immediately; no I/O.
//  2. Cache missing/stale and fetching permitted → fetch+validate+cache; return.
//  3. Fetch fails, cache exists → return cached path + ErrStale.
//  4. Offline, cache exists but stale → return cached path + ErrStale.
//  5. No cache, fetch impossible → try DefaultCatalogDir; return its path + ErrStale.
//  6. Nothing usable → ErrNoCatalog.
func (m *Manager) Ensure(ctx context.Context) (cachedPath string, version string, err error) {
	_, cachedMeta, haveCache := m.loadCache()

	// (1) Fresh cache hit.
	if haveCache && !m.isStale(cachedMeta) {
		return m.catalogPath(), cachedMeta.Version, nil
	}

	// (2) Attempt remote fetch.
	if !m.offline() {
		meta, fetchErr := m.fetch(ctx)
		if fetchErr == nil {
			return m.catalogPath(), meta.Version, nil
		}
		// A signature failure in require mode is a hard, security-relevant error.
		// Do not silently fall back to a cached or vendored catalog — surface it.
		if errors.Is(fetchErr, ErrSignature) {
			return "", "", fetchErr
		}
		// Fetch failed — degrade gracefully.
		if haveCache {
			// (3) Stale cache.
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
		if !m.isStale(cachedMeta) {
			// Fresh cache even though offline — no error.
			return m.catalogPath(), cachedMeta.Version, nil
		}
		// (4) Stale cache, offline.
		return m.catalogPath(), cachedMeta.Version,
			fmt.Errorf("%w: offline, last fetched %s", ErrStale, cachedMeta.FetchedAt.Format(time.RFC3339))
	}

	// (5) No cache, offline — try vendored fallback.
	if p, v, ferr := m.vendoredFallback(); ferr == nil {
		return p, v, fmt.Errorf("%w: offline and no cached catalog, using vendored catalog", ErrStale)
	}

	// (6) Nothing usable.
	return "", "", fmt.Errorf("%w: offline and no cached catalog", ErrNoCatalog)
}

// vendoredFallback loads DefaultCatalogDir and returns its path and a derived
// version. It does not copy to CacheDir — the engine accepts a directory path.
func (m *Manager) vendoredFallback() (path, version string, err error) {
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

// Freshness reports the cached catalog's version, fetch time, and staleness.
// No network access is performed — intended for `guardian status` / `guardian doctor`.
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

// fetch dispatches to fetchSingle or fetchDir based on the SourceURL shape.
func (m *Manager) fetch(ctx context.Context) (Meta, error) {
	if !strings.HasPrefix(strings.ToLower(m.cfg.SourceURL), "https://") {
		return Meta{}, fmt.Errorf("source URL must be HTTPS: %q", m.cfg.SourceURL)
	}
	if isSingleFileURL(m.cfg.SourceURL) {
		return m.fetchSingle(ctx, m.cfg.SourceURL)
	}
	return m.fetchDir(ctx)
}

// httpGet performs a GET request with the guardian User-Agent and returns the
// raw body. Non-2xx responses are surfaced as descriptive errors; a 403 with
// X-RateLimit-Remaining: 0 is called out explicitly.
func (m *Manager) httpGet(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)

	resp, err := m.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http get %s: %w", url, err)
	}
	defer resp.Body.Close() // #nosec G307 -- read-only response body; close error is ignorable here

	if resp.StatusCode != http.StatusOK {
		// A 404 is wrapped with errNotFound so callers (signature fetches) can
		// treat a cleanly-absent resource distinctly from a transport error.
		if resp.StatusCode == http.StatusNotFound {
			return nil, fmt.Errorf("%w: %s", errNotFound, url)
		}
		// Surface a helpful message for the GitHub API rate-limit case (HTTP 403
		// or 429 with X-RateLimit-Remaining: 0).
		remaining := resp.Header.Get("X-RateLimit-Remaining")
		if (resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests) &&
			remaining == "0" {
			return nil, fmt.Errorf("GitHub API rate limit exceeded (%s); retry after %s or set GITHUB_TOKEN",
				resp.Status, resp.Header.Get("X-RateLimit-Reset"))
		}
		return nil, fmt.Errorf("unexpected status %s from %s", resp.Status, url)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body from %s: %w", url, err)
	}
	return body, nil
}

// fetchSingle downloads a single raw JSON catalog from rawURL, validates it,
// and atomically writes it plus the metadata sidecar to CacheDir.
func (m *Manager) fetchSingle(ctx context.Context, rawURL string) (Meta, error) {
	body, err := m.httpGet(ctx, rawURL)
	if err != nil {
		return Meta{}, err
	}

	// Verify the exact bytes that will be cached, before parsing/caching, so a
	// VerifyRequire failure aborts without writing anything.
	if m.verifyEnabled() {
		sigURL := rawURL + minisigSuffix
		if verr := m.verifyBytes(ctx, "catalog", body, sigURL); verr != nil {
			return Meta{}, verr
		}
	}

	cat, err := Parse(body)
	if err != nil {
		return Meta{}, err
	}
	if err := cat.Validate(); err != nil {
		return Meta{}, err
	}
	if len(cat.Entries) == 0 {
		return Meta{}, errors.New("catalog: remote catalog has zero entries (check SourceURL)")
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
	if err := m.writeCatalogAndMeta(body, meta); err != nil {
		return Meta{}, err
	}
	return meta, nil
}

// fetchDir fetches the GitHub Contents API listing at SourceURL, downloads
// each *.json file in the listing, validates them individually, merges their
// entries into a single catalog, and writes it atomically to CacheDir.
//
// The merged catalog's SHA256 is computed as:
//
//	sha256( sha256(file1_bytes) || sha256(file2_bytes) || ... )
//
// where files are sorted alphabetically by name — the same ordering as
// LoadDir — so the combined hash is stable and reproducible from the same
// set of remote files.
func (m *Manager) fetchDir(ctx context.Context) (Meta, error) {
	// Step 1: fetch the directory listing.
	listBody, err := m.httpGet(ctx, m.cfg.SourceURL)
	if err != nil {
		return Meta{}, fmt.Errorf("fetch listing: %w", err)
	}

	var files []ghFile
	if err := json.Unmarshal(listBody, &files); err != nil {
		return Meta{}, fmt.Errorf("parse listing: expected GitHub Contents API JSON array: %w", err)
	}

	// Step 2: filter to *.json files with a non-empty download_url. Build a
	// lookup of every file's download_url by name so we can locate sibling
	// "<name>.minisig" signatures from the same listing.
	sigURLByName := make(map[string]string, len(files))
	for _, f := range files {
		if f.Type == "file" && f.DownloadURL != "" {
			sigURLByName[f.Name] = f.DownloadURL
		}
	}
	var toFetch []ghFile
	for _, f := range files {
		if f.Type != "file" {
			continue
		}
		// Exclude detached-signature files themselves from the merge set.
		if strings.HasSuffix(strings.ToLower(f.Name), minisigSuffix) {
			continue
		}
		if !strings.HasSuffix(strings.ToLower(f.Name), ".json") {
			continue
		}
		if f.DownloadURL == "" {
			continue
		}
		toFetch = append(toFetch, f)
	}
	// Sort by name for deterministic hash ordering.
	sort.Slice(toFetch, func(i, j int) bool { return toFetch[i].Name < toFetch[j].Name })

	if len(toFetch) == 0 {
		return Meta{}, errors.New("catalog: directory listing contained no .json files (check SourceURL)")
	}

	// Step 3: download, parse, and validate each file; accumulate entries and
	// build the combined checksum.
	var allEntries []Entry
	var schemaVersion string
	var firstSource string
	combinedHasher := sha256.New()

	for _, f := range toFetch {
		raw, err := m.httpGet(ctx, f.DownloadURL)
		if err != nil {
			return Meta{}, fmt.Errorf("download %s: %w", f.Name, err)
		}

		// Verify the exact downloaded bytes before merging/caching. The signature
		// is the sibling "<name>.minisig" entry from the same listing.
		if m.verifyEnabled() {
			sigURL, present := sigURLByName[f.Name+minisigSuffix]
			if !present {
				// No sibling signature listed at all.
				if verr := m.signatureFailure(f.Name, "no sibling .minisig in listing"); verr != nil {
					return Meta{}, verr
				}
			} else if verr := m.verifyBytes(ctx, f.Name, raw, sigURL); verr != nil {
				return Meta{}, verr
			}
		}

		cat, err := Parse(raw)
		if err != nil {
			return Meta{}, fmt.Errorf("parse %s: %w", f.Name, err)
		}
		if err := cat.Validate(); err != nil {
			return Meta{}, fmt.Errorf("validate %s: %w", f.Name, err)
		}
		// Enforce consistent schema_version across files (same rule as LoadDir).
		switch {
		case schemaVersion == "":
			schemaVersion = cat.SchemaVersion
			firstSource = f.Name
		case cat.SchemaVersion != "" && cat.SchemaVersion != schemaVersion:
			return Meta{}, fmt.Errorf("catalog: %s declares schema_version %q which conflicts with %q (from %s)",
				f.Name, cat.SchemaVersion, schemaVersion, firstSource)
		}
		allEntries = append(allEntries, cat.Entries...)
		// Feed this file's sha256 into the combined hasher.
		fileSum := sha256.Sum256(raw)
		combinedHasher.Write(fileSum[:]) // #nosec G104 -- sha256.Write never returns an error
	}

	if len(allEntries) == 0 {
		return Meta{}, errors.New("catalog: remote files yielded zero entries after merge")
	}
	if schemaVersion == "" {
		schemaVersion = SchemaVersion
	}

	// Step 4: build the merged catalog and marshal it for the cache file.
	merged := &Catalog{SchemaVersion: schemaVersion, Entries: allEntries}
	mergedBody, err := json.MarshalIndent(merged, "", "  ")
	if err != nil {
		return Meta{}, fmt.Errorf("marshal merged catalog: %w", err)
	}

	hexSum := hex.EncodeToString(combinedHasher.Sum(nil))
	now := m.cfg.now()
	meta := Meta{
		Version:    deriveVersion(merged, now, hexSum),
		FetchedAt:  now,
		SHA256:     hexSum,
		EntryCount: len(allEntries),
		SourceURL:  m.cfg.SourceURL,
	}
	if err := m.writeCatalogAndMeta(mergedBody, meta); err != nil {
		return Meta{}, err
	}
	return meta, nil
}

// writeCatalogAndMeta atomically writes the merged catalog JSON and its
// metadata sidecar to CacheDir, creating the directory if necessary.
func (m *Manager) writeCatalogAndMeta(catalogBody []byte, meta Meta) error {
	if err := os.MkdirAll(m.cfg.CacheDir, 0o750); err != nil {
		return fmt.Errorf("create cache dir: %w", err)
	}
	if err := writeFileAtomic(m.catalogPath(), catalogBody, 0o640); err != nil {
		return fmt.Errorf("write catalog: %w", err)
	}
	mb, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal meta: %w", err)
	}
	if err := writeFileAtomic(m.metaPath(), mb, 0o640); err != nil {
		return fmt.Errorf("write meta: %w", err)
	}
	return nil
}

// deriveVersion prefers the catalog's own Version field; otherwise it derives
// a stable version string from the fetch date and the first 12 hex chars of
// the checksum (combined sha256 for directory mode, raw sha256 for single-file).
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
// directory then renaming it into place. Readers never observe a partial file.
func writeFileAtomic(path string, data []byte, perm os.FileMode) (err error) {
	dir := filepath.Dir(path)
	// #nosec G306 -- perm is provided by the caller (0o640 for catalog files)
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
