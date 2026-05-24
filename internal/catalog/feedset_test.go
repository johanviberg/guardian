package catalog

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/johanviberg/guardian/internal/catalog/minisign"
	"golang.org/x/crypto/blake2b"
)

// ---- minisign helpers (duplicated from verify_test.go for package-level use) ----

type feedSigner struct {
	pub   ed25519.PublicKey
	priv  ed25519.PrivateKey
	keyID [8]byte
}

func newFeedSigner(t *testing.T) feedSigner {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return feedSigner{pub: pub, priv: priv, keyID: [8]byte{11, 22, 33, 44, 55, 66, 77, 88}}
}

func (s feedSigner) pubKeyText() string {
	raw := make([]byte, 0, 42)
	raw = append(raw, 'E', 'd')
	raw = append(raw, s.keyID[:]...)
	raw = append(raw, s.pub...)
	return "untrusted comment: feedset test key\n" + base64.StdEncoding.EncodeToString(raw) + "\n"
}

func (s feedSigner) parsedPubKey(t *testing.T) minisign.PublicKey {
	t.Helper()
	pk, err := minisign.ParsePublicKey(s.pubKeyText())
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	return pk
}

func (s feedSigner) sign(msg []byte) []byte {
	h := blake2b.Sum512(msg)
	sig := ed25519.Sign(s.priv, h[:])
	payload := make([]byte, 0, 74)
	payload = append(payload, 'E', 'D')
	payload = append(payload, s.keyID[:]...)
	payload = append(payload, sig...)
	tc := "feedset-test"
	globalMsg := append(append([]byte(nil), sig...), []byte(tc)...)
	globalSig := ed25519.Sign(s.priv, globalMsg)
	return []byte(fmt.Sprintf("untrusted comment: sig\n%s\ntrusted comment: %s\n%s\n",
		base64.StdEncoding.EncodeToString(payload), tc, base64.StdEncoding.EncodeToString(globalSig)))
}

// ---- server helpers ----

// multiSourceServer serves multiple named catalogs with optional .minisig siblings.
func multiSourceServer(t *testing.T, catalogs map[string]string, sigs map[string][]byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Path[1:] // strip leading "/"
		if body, ok := catalogs[name]; ok {
			_, _ = w.Write([]byte(body))
			return
		}
		if sig, ok := sigs[name]; ok {
			_, _ = w.Write(sig)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// buildFeedSet creates a FeedSet with N single-file sources pointing at srv.
func buildFeedSet(t *testing.T, srv *httptest.Server, cacheDir string, specs []SourceSpec, baselineDir string, warn *bytes.Buffer) *FeedSet {
	t.Helper()
	var ww interface{ Write([]byte) (int, error) }
	if warn != nil {
		ww = warn
	}
	cfg := MultiConfig{
		CacheDir:          cacheDir,
		Sources:           specs,
		DefaultCatalogDir: baselineDir,
		TTL:               time.Hour,
		HTTPClient:        srv.Client(),
		WarnWriter:        ww,
		now:               time.Now,
	}
	fs, err := NewFeedSet(cfg)
	if err != nil {
		t.Fatalf("NewFeedSet: %v", err)
	}
	return fs
}

// ---- tests ----

func TestFeedSet_TwoSourcesMerge(t *testing.T) {
	// Two overlapping sources: shared advisory merged by union.
	catA := `{"schema_version":"0.1.0","entries":[
		{"id":"SHARED","ecosystem":"npm","package":"evil","versions":["1.0"],"severity":"high"},
		{"id":"ONLY-A","ecosystem":"npm","package":"a-only","versions":["1.0"]}
	]}`
	catB := `{"schema_version":"0.1.0","entries":[
		{"id":"SHARED","ecosystem":"npm","package":"evil","versions":["2.0"],"severity":"critical"},
		{"id":"ONLY-B","ecosystem":"pypi","package":"b-only","versions":["2.0"]}
	]}`

	srv := multiSourceServer(t, map[string]string{"a.json": catA, "b.json": catB}, nil)
	dir := t.TempDir()

	specs := []SourceSpec{
		{Name: "src-a", URL: srv.URL + "/a.json", Verify: VerifyOff},
		{Name: "src-b", URL: srv.URL + "/b.json", Verify: VerifyOff},
	}
	var warn bytes.Buffer
	fs := buildFeedSet(t, srv, dir, specs, "", &warn)

	path, ver, err := fs.Ensure(context.Background())
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if path == "" || ver == "" {
		t.Fatalf("path=%q ver=%q", path, ver)
	}

	// Load merged catalog.
	merged, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	// SHARED + ONLY-A + ONLY-B = 3 entries
	if len(merged.Entries) != 3 {
		t.Fatalf("want 3 merged entries, got %d: %v", len(merged.Entries), merged.Entries)
	}

	// Find SHARED and check union.
	for _, e := range merged.Entries {
		if e.ID == "SHARED" {
			if len(e.Versions) != 2 {
				t.Fatalf("SHARED versions = %v, want [1.0 2.0]", e.Versions)
			}
			if e.Severity != "critical" {
				t.Fatalf("SHARED severity = %q, want critical", e.Severity)
			}
		}
	}

	// FeedMeta sidecar exists and has two sources.
	fm, ok := fs.LoadFeedMeta()
	if !ok {
		t.Fatal("FeedMeta not written")
	}
	if len(fm.Sources) != 2 {
		t.Fatalf("FeedMeta sources = %d, want 2", len(fm.Sources))
	}
}

func TestFeedSet_SignedSourceRequire(t *testing.T) {
	s := newFeedSigner(t)
	body := goodCatalogJSON
	sig := s.sign([]byte(body))

	srv := multiSourceServer(t,
		map[string]string{"cat.json": body},
		map[string][]byte{"cat.json.minisig": sig},
	)
	dir := t.TempDir()

	specs := []SourceSpec{{
		Name:         "signed-src",
		URL:          srv.URL + "/cat.json",
		Verify:       VerifyRequire,
		PublicKey:    s.parsedPubKey(t),
		PublicKeySet: true,
	}}
	fs := buildFeedSet(t, srv, dir, specs, "", nil)

	path, _, err := fs.Ensure(context.Background())
	if err != nil {
		t.Fatalf("Ensure with valid sig: %v", err)
	}
	merged, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if len(merged.Entries) == 0 {
		t.Fatal("expected entries from signed source")
	}
}

func TestFeedSet_SignedSourceRequireInvalid(t *testing.T) {
	s := newFeedSigner(t)
	body := goodCatalogJSON
	// Sign wrong content.
	sig := s.sign([]byte("tampered"))

	srv := multiSourceServer(t,
		map[string]string{"cat.json": body},
		map[string][]byte{"cat.json.minisig": sig},
	)
	dir := t.TempDir()

	specs := []SourceSpec{{
		Name:         "signed-req",
		URL:          srv.URL + "/cat.json",
		Verify:       VerifyRequire,
		PublicKey:    s.parsedPubKey(t),
		PublicKeySet: true,
	}}
	fs := buildFeedSet(t, srv, dir, specs, "", nil)

	_, _, err := fs.Ensure(context.Background())
	if !errors.Is(err, ErrSignature) {
		t.Fatalf("Ensure = %v, want ErrSignature", err)
	}
}

func TestFeedSet_SignedRequireUnsignedWarn(t *testing.T) {
	// Source 1: require + signed (verifies OK)
	// Source 2: off (unsigned, no sig check)
	s := newFeedSigner(t)
	catA := perAdvisoryAJSON
	catB := perAdvisoryBJSON
	sigA := s.sign([]byte(catA))

	srv := multiSourceServer(t,
		map[string]string{"a.json": catA, "b.json": catB},
		map[string][]byte{"a.json.minisig": sigA},
	)
	dir := t.TempDir()

	specs := []SourceSpec{
		{Name: "signed", URL: srv.URL + "/a.json", Verify: VerifyRequire, PublicKey: s.parsedPubKey(t), PublicKeySet: true},
		{Name: "unsigned", URL: srv.URL + "/b.json", Verify: VerifyOff},
	}
	var warn bytes.Buffer
	fs := buildFeedSet(t, srv, dir, specs, "", &warn)

	path, _, err := fs.Ensure(context.Background())
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	merged, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	// Entries from both sources present.
	if len(merged.Entries) < 2 {
		t.Fatalf("want at least 2 entries (one per source), got %d", len(merged.Entries))
	}
}

func TestFeedSet_OfflineSourceSkippedOthersMerge(t *testing.T) {
	// Source that fails fetch (no cached copy) is skipped; others merge fine.
	catA := perAdvisoryAJSON
	catC := perAdvisoryCJSON

	srv := multiSourceServer(t, map[string]string{"a.json": catA, "c.json": catC}, nil)
	dir := t.TempDir()

	specs := []SourceSpec{
		{Name: "ok-a", URL: srv.URL + "/a.json", Verify: VerifyOff},
		{Name: "dead", URL: srv.URL + "/404-not-here.json", Verify: VerifyOff},
		{Name: "ok-c", URL: srv.URL + "/c.json", Verify: VerifyOff},
	}
	var warn bytes.Buffer
	fs := buildFeedSet(t, srv, dir, specs, "", &warn)

	path, _, err := fs.Ensure(context.Background())
	if err != nil {
		t.Fatalf("Ensure should succeed (dead source skipped): %v", err)
	}
	if warn.Len() == 0 {
		t.Fatal("expected a warning about the dead source")
	}
	merged, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	// Both ok sources contribute entries.
	if len(merged.Entries) < 2 {
		t.Fatalf("want entries from at least 2 sources, got %d", len(merged.Entries))
	}
}

func TestFeedSet_WithBaseline(t *testing.T) {
	// Build a small baseline dir.
	baseDir := t.TempDir()
	baseline := `{"schema_version":"0.1.0","entries":[
		{"id":"BASELINE-ONLY","ecosystem":"npm","package":"base","versions":["0.1"]}
	]}`
	if err := os.WriteFile(filepath.Join(baseDir, "baseline.json"), []byte(baseline), 0o644); err != nil {
		t.Fatal(err)
	}

	catA := perAdvisoryAJSON
	srv := multiSourceServer(t, map[string]string{"a.json": catA}, nil)
	dir := t.TempDir()

	specs := []SourceSpec{{Name: "net", URL: srv.URL + "/a.json", Verify: VerifyOff}}
	var warn bytes.Buffer
	fs := buildFeedSet(t, srv, dir, specs, baseDir, &warn)

	path, _, err := fs.Ensure(context.Background())
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	merged, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}

	// Should have entries from both the network source and the baseline.
	hasNetwork := false
	hasBaseline := false
	for _, e := range merged.Entries {
		if e.ID == "ADV-A-1" {
			hasNetwork = true
		}
		if e.ID == "BASELINE-ONLY" {
			hasBaseline = true
		}
	}
	if !hasNetwork {
		t.Fatal("network source entry missing from merged catalog")
	}
	if !hasBaseline {
		t.Fatal("baseline entry missing from merged catalog")
	}
}

func TestFeedSet_BackCompatSingleSource(t *testing.T) {
	// A FeedSet with a single VerifyOff source should produce the same merged
	// catalog as the legacy single-source Manager (same entries, engine-loadable).
	srv, _ := singleFileServer(t, goodCatalogJSON)
	dir := t.TempDir()

	specs := []SourceSpec{{
		Name:   "default",
		URL:    srv.URL + "/catalog.json",
		Verify: VerifyOff,
	}}
	fs := buildFeedSet(t, srv, dir, specs, "", nil)

	path, ver, err := fs.Ensure(context.Background())
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if path == "" || ver == "" {
		t.Fatalf("empty path/ver")
	}
	merged, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if err := merged.Validate(); err != nil {
		t.Fatalf("merged catalog invalid: %v", err)
	}
	if len(merged.Entries) == 0 {
		t.Fatal("merged catalog has no entries")
	}
}

func TestFeedSet_Freshness(t *testing.T) {
	catA := perAdvisoryAJSON
	srv := multiSourceServer(t, map[string]string{"a.json": catA}, nil)
	dir := t.TempDir()
	now := time.Date(2026, 5, 24, 0, 0, 0, 0, time.UTC)
	cfg := MultiConfig{
		CacheDir:   dir,
		Sources:    []SourceSpec{{Name: "s", URL: srv.URL + "/a.json", Verify: VerifyOff}},
		TTL:        time.Hour,
		HTTPClient: srv.Client(),
		now:        func() time.Time { return now },
	}
	fs, err := NewFeedSet(cfg)
	if err != nil {
		t.Fatalf("NewFeedSet: %v", err)
	}

	_, _, err = fs.Ensure(context.Background())
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}

	ver, fa, stale, err := fs.Freshness(context.Background())
	if err != nil {
		t.Fatalf("Freshness: %v", err)
	}
	if ver == "" {
		t.Fatal("Freshness version is empty")
	}
	if fa.IsZero() {
		t.Fatal("Freshness fetchedAt is zero")
	}
	if stale {
		t.Fatal("catalog should be fresh (just fetched)")
	}
}

func TestFeedSet_SanitizeName(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"default", "default"},
		{"my-feed", "my-feed"},
		{"My Feed!", "my_feed_"},
		{"", "_unnamed"},
		{"source/1", "source_1"},
	}
	for _, tc := range cases {
		got := sanitizeName(tc.in)
		if got != tc.want {
			t.Errorf("sanitizeName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestFeedSetFreshness_FeedMeta(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 5, 24, 10, 0, 0, 0, time.UTC)
	fm := FeedMeta{
		Version:   "2026-abc",
		FetchedAt: now,
		SHA256:    "deadbeef",
		Sources: []FeedSourceMeta{
			{Name: "s", FetchedAt: now, SHA256: "aa"},
		},
	}
	b, _ := json.MarshalIndent(fm, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "feed.meta.json"), b, 0o640); err != nil {
		t.Fatal(err)
	}

	ver, fa, stale, err := FeedSetFreshness(dir, time.Hour)
	if err != nil {
		t.Fatalf("FeedSetFreshness: %v", err)
	}
	if ver != "2026-abc" {
		t.Fatalf("version = %q", ver)
	}
	if fa.IsZero() {
		t.Fatal("fetchedAt is zero")
	}
	_ = stale // stale depends on actual time.Now; just ensure no error
}

func TestFeedSetFreshness_LegacyMeta(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 5, 24, 10, 0, 0, 0, time.UTC)
	meta := Meta{Version: "old-ver", FetchedAt: now, SHA256: "abc", EntryCount: 5}
	b, _ := json.MarshalIndent(meta, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "catalog.meta.json"), b, 0o640); err != nil {
		t.Fatal(err)
	}

	ver, _, _, err := FeedSetFreshness(dir, time.Hour)
	if err != nil {
		t.Fatalf("FeedSetFreshness(legacy): %v", err)
	}
	if ver != "old-ver" {
		t.Fatalf("version = %q, want old-ver", ver)
	}
}

func TestResolvePublicKey_FeedSet(t *testing.T) {
	// Inline key from feedSigner.
	s := newFeedSigner(t)

	pk, set, err := ResolvePublicKey(s.pubKeyText())
	if err != nil || !set {
		t.Fatalf("ResolvePublicKey(inline): err=%v set=%v", err, set)
	}
	if pk.KeyID != s.keyID {
		t.Fatal("key id mismatch")
	}

	// Empty → disabled.
	_, set, err = ResolvePublicKey("")
	if err != nil || set {
		t.Fatalf("empty: err=%v set=%v", err, set)
	}
}
