// Package builtin embeds a baseline copy of the Bumblebee exposure catalogs so
// guardian ships a usable catalog inside the binary and works offline on first
// run, with no source tree or network required.
//
// The embedded files are a snapshot of perplexityai/bumblebee's threat_intel/
// directory, refreshed by hack/sync-upstream.sh alongside the vendored engine.
// They are the offline default; the catalog manager still fetches fresher
// catalogs over the network when available.
package builtin

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

//go:embed catalogs/*.json
var catalogsFS embed.FS

// FS returns the embedded catalog file tree rooted at the catalogs directory.
func FS() (fs.FS, error) { return fs.Sub(catalogsFS, "catalogs") }

// digest is the combined sha256 of every embedded catalog file (name+content),
// used to name the materialized directory so it is replaced when the embedded
// snapshot changes and shared when it does not.
func digest() (string, error) {
	names, err := fs.Glob(catalogsFS, "catalogs/*.json")
	if err != nil {
		return "", err
	}
	sort.Strings(names)
	h := sha256.New()
	for _, n := range names {
		b, err := catalogsFS.ReadFile(n)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(h, "%s\x00%d\x00", filepath.Base(n), len(b))
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil))[:16], nil
}

// Materialize writes the embedded catalogs into a stable subdirectory under
// baseDir (e.g. the user cache dir) and returns that directory. It is
// idempotent: the directory is named by content digest, so repeated calls with
// an unchanged snapshot reuse the same path and skip rewriting.
func Materialize(baseDir string) (string, error) {
	dig, err := digest()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(baseDir, "builtin-catalog-"+dig)

	// A marker file signals a complete prior materialization.
	marker := filepath.Join(dir, ".complete")
	if _, err := os.Stat(marker); err == nil {
		return dir, nil
	}

	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", fmt.Errorf("create builtin catalog dir: %w", err)
	}
	names, err := fs.Glob(catalogsFS, "catalogs/*.json")
	if err != nil {
		return "", err
	}
	for _, n := range names {
		b, err := catalogsFS.ReadFile(n)
		if err != nil {
			return "", err
		}
		dst := filepath.Join(dir, filepath.Base(n))
		tmp := dst + ".tmp"
		if err := os.WriteFile(tmp, b, 0o600); err != nil {
			return "", fmt.Errorf("write builtin catalog %s: %w", n, err)
		}
		if err := os.Rename(tmp, dst); err != nil {
			return "", fmt.Errorf("finalize builtin catalog %s: %w", n, err)
		}
	}
	if err := os.WriteFile(marker, []byte(dig), 0o600); err != nil {
		return "", fmt.Errorf("write builtin catalog marker: %w", err)
	}
	return dir, nil
}
