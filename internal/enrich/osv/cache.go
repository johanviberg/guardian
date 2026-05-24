package osv

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// cache is a simple on-disk JSON cache of OSV vuln details, one file per vuln id,
// with a freshness TTL. It is best-effort: read/write errors are treated as a
// miss so enrichment continues to function without a usable cache.
type cache struct {
	dir string
	ttl time.Duration
	now func() time.Time
}

// cacheEntry is the on-disk envelope: the cached detail plus the time it was
// fetched, used for TTL validation.
type cacheEntry struct {
	FetchedAt time.Time   `json:"fetched_at"`
	Detail    *vulnDetail `json:"detail"`
}

func newCache(dir string, ttl time.Duration) *cache {
	return &cache{dir: dir, ttl: ttl, now: time.Now}
}

// safeFileName turns an OSV id into a filesystem-safe cache filename. OSV/GHSA
// ids contain only [A-Za-z0-9-], but we sanitize defensively against path
// traversal and separators.
func safeFileName(id string) string {
	var b strings.Builder
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	name := b.String()
	if name == "" || name == "." || name == ".." {
		name = "_"
	}
	return name + ".json"
}

func (c *cache) path(id string) string {
	return filepath.Join(c.dir, safeFileName(id))
}

// get returns a cached, non-stale detail for id, or (nil, false) on a miss or
// stale/corrupt entry.
func (c *cache) get(id string) (*vulnDetail, bool) {
	if c == nil || c.dir == "" {
		return nil, false
	}
	// #nosec G304 -- the path is built from a sanitized OSV id under the
	// caller-controlled cache dir; safeFileName strips separators and traversal.
	data, err := os.ReadFile(c.path(id))
	if err != nil {
		return nil, false
	}
	var e cacheEntry
	if err := json.Unmarshal(data, &e); err != nil || e.Detail == nil {
		return nil, false
	}
	if c.ttl > 0 && c.now().Sub(e.FetchedAt) > c.ttl {
		return nil, false
	}
	return e.Detail, true
}

// put writes a detail to the cache. Errors are swallowed: a cache that cannot be
// written must not break enrichment.
func (c *cache) put(id string, d *vulnDetail) {
	if c == nil || c.dir == "" || d == nil {
		return
	}
	if err := os.MkdirAll(c.dir, 0o750); err != nil {
		return
	}
	e := cacheEntry{FetchedAt: c.now(), Detail: d}
	data, err := json.Marshal(e)
	if err != nil {
		return
	}
	tmp := c.path(id) + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, c.path(id))
}
