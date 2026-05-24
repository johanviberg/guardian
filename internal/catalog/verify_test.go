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

// signer is an in-test minisign signer used to produce public keys and detached
// signatures without depending on the external minisign CLI.
type signer struct {
	pub   ed25519.PublicKey
	priv  ed25519.PrivateKey
	keyID [8]byte
}

func newSigner(t *testing.T) signer {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return signer{pub: pub, priv: priv, keyID: [8]byte{10, 20, 30, 40, 50, 60, 70, 80}}
}

func (s signer) pubKeyText() string {
	raw := make([]byte, 0, 42)
	raw = append(raw, 'E', 'd')
	raw = append(raw, s.keyID[:]...)
	raw = append(raw, s.pub...)
	return "untrusted comment: test pubkey\n" + base64.StdEncoding.EncodeToString(raw) + "\n"
}

func (s signer) parsedPubKey(t *testing.T) minisign.PublicKey {
	t.Helper()
	pk, err := minisign.ParsePublicKey(s.pubKeyText())
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	return pk
}

// sign builds a prehashed ("ED") detached .minisig over message.
func (s signer) sign(message []byte) []byte {
	h := blake2b.Sum512(message)
	sig := ed25519.Sign(s.priv, h[:])

	payload := make([]byte, 0, 74)
	payload = append(payload, 'E', 'D')
	payload = append(payload, s.keyID[:]...)
	payload = append(payload, sig...)

	tc := "timestamp:1716500000"
	globalMsg := append(append([]byte(nil), sig...), []byte(tc)...)
	globalSig := ed25519.Sign(s.priv, globalMsg)

	blob := fmt.Sprintf("untrusted comment: sig\n%s\ntrusted comment: %s\n%s\n",
		base64.StdEncoding.EncodeToString(payload), tc, base64.StdEncoding.EncodeToString(globalSig))
	return []byte(blob)
}

// signedSingleFileServer serves a catalog at /catalog.json and (optionally) its
// signature at /catalog.json.minisig. If sig is nil, the .minisig path 404s.
func signedSingleFileServer(t *testing.T, body string, sig []byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/catalog.json":
			_, _ = w.Write([]byte(body))
		case "/catalog.json.minisig":
			if sig == nil {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write(sig)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newVerifyManager(t *testing.T, srv *httptest.Server, dir, mode string, pk minisign.PublicKey, set bool, warn *bytes.Buffer) *Manager {
	t.Helper()
	cfg := Config{
		CacheDir:     dir,
		SourceURL:    srv.URL + "/catalog.json",
		TTL:          time.Hour,
		HTTPClient:   srv.Client(),
		Verify:       mode,
		PublicKey:    pk,
		PublicKeySet: set,
		WarnWriter:   warn,
		now:          time.Now,
	}
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return m
}

func catalogCached(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, catalogFileName))
	return err == nil
}

// ---- single-file mode: behavior matrix ----

func TestVerifySingleFile_RequireValid(t *testing.T) {
	s := newSigner(t)
	body := goodCatalogJSON
	srv := signedSingleFileServer(t, body, s.sign([]byte(body)))
	dir := t.TempDir()
	m := newVerifyManager(t, srv, dir, VerifyRequire, s.parsedPubKey(t), true, nil)

	if _, _, err := m.Ensure(context.Background()); err != nil {
		t.Fatalf("Ensure = %v, want nil", err)
	}
	if !catalogCached(dir) {
		t.Fatal("catalog should be cached after valid signature")
	}
}

func TestVerifySingleFile_RequireMissing(t *testing.T) {
	s := newSigner(t)
	srv := signedSingleFileServer(t, goodCatalogJSON, nil) // no .minisig
	dir := t.TempDir()
	m := newVerifyManager(t, srv, dir, VerifyRequire, s.parsedPubKey(t), true, nil)

	_, _, err := m.Ensure(context.Background())
	if !errors.Is(err, ErrSignature) {
		t.Fatalf("Ensure = %v, want ErrSignature", err)
	}
	if catalogCached(dir) {
		t.Fatal("catalog must NOT be cached when required signature is missing")
	}
}

func TestVerifySingleFile_RequireInvalid(t *testing.T) {
	s := newSigner(t)
	// Sign different content than what is served → invalid.
	srv := signedSingleFileServer(t, goodCatalogJSON, s.sign([]byte("other content")))
	dir := t.TempDir()
	m := newVerifyManager(t, srv, dir, VerifyRequire, s.parsedPubKey(t), true, nil)

	_, _, err := m.Ensure(context.Background())
	if !errors.Is(err, ErrSignature) {
		t.Fatalf("Ensure = %v, want ErrSignature", err)
	}
	if catalogCached(dir) {
		t.Fatal("catalog must NOT be cached when required signature is invalid")
	}
}

func TestVerifySingleFile_RequireWrongKey(t *testing.T) {
	s := newSigner(t)
	other := newSigner(t) // different key entirely
	srv := signedSingleFileServer(t, goodCatalogJSON, s.sign([]byte(goodCatalogJSON)))
	dir := t.TempDir()
	m := newVerifyManager(t, srv, dir, VerifyRequire, other.parsedPubKey(t), true, nil)

	_, _, err := m.Ensure(context.Background())
	if !errors.Is(err, ErrSignature) {
		t.Fatalf("Ensure = %v, want ErrSignature (wrong key)", err)
	}
	if catalogCached(dir) {
		t.Fatal("catalog must NOT be cached when key id mismatches")
	}
}

func TestVerifySingleFile_WarnValid(t *testing.T) {
	s := newSigner(t)
	body := goodCatalogJSON
	srv := signedSingleFileServer(t, body, s.sign([]byte(body)))
	dir := t.TempDir()
	var warn bytes.Buffer
	m := newVerifyManager(t, srv, dir, VerifyWarn, s.parsedPubKey(t), true, &warn)

	if _, _, err := m.Ensure(context.Background()); err != nil {
		t.Fatalf("Ensure = %v, want nil", err)
	}
	if !catalogCached(dir) {
		t.Fatal("catalog should be cached")
	}
	if warn.Len() != 0 {
		t.Fatalf("unexpected warning on valid sig: %q", warn.String())
	}
}

func TestVerifySingleFile_WarnMissingProceeds(t *testing.T) {
	s := newSigner(t)
	srv := signedSingleFileServer(t, goodCatalogJSON, nil)
	dir := t.TempDir()
	var warn bytes.Buffer
	m := newVerifyManager(t, srv, dir, VerifyWarn, s.parsedPubKey(t), true, &warn)

	if _, _, err := m.Ensure(context.Background()); err != nil {
		t.Fatalf("Ensure = %v, want nil (warn proceeds)", err)
	}
	if !catalogCached(dir) {
		t.Fatal("catalog should be cached in warn mode even without signature")
	}
	if warn.Len() == 0 {
		t.Fatal("expected a warning about missing signature")
	}
}

func TestVerifySingleFile_WarnInvalidProceeds(t *testing.T) {
	s := newSigner(t)
	srv := signedSingleFileServer(t, goodCatalogJSON, s.sign([]byte("tampered")))
	dir := t.TempDir()
	var warn bytes.Buffer
	m := newVerifyManager(t, srv, dir, VerifyWarn, s.parsedPubKey(t), true, &warn)

	if _, _, err := m.Ensure(context.Background()); err != nil {
		t.Fatalf("Ensure = %v, want nil (warn proceeds)", err)
	}
	if !catalogCached(dir) {
		t.Fatal("catalog should be cached in warn mode even with invalid signature")
	}
	if warn.Len() == 0 {
		t.Fatal("expected a warning about invalid signature")
	}
}

func TestVerifySingleFile_OffSkips(t *testing.T) {
	// Off mode: even with a key set and a bogus signature present, no
	// verification happens.
	s := newSigner(t)
	srv := signedSingleFileServer(t, goodCatalogJSON, s.sign([]byte("tampered")))
	dir := t.TempDir()
	m := newVerifyManager(t, srv, dir, VerifyOff, s.parsedPubKey(t), true, nil)

	if _, _, err := m.Ensure(context.Background()); err != nil {
		t.Fatalf("Ensure = %v, want nil (off skips)", err)
	}
	if !catalogCached(dir) {
		t.Fatal("catalog should be cached in off mode")
	}
}

// ---- directory mode ----

// signedDirServer serves a GitHub Contents API listing including sibling
// .minisig entries, the JSON files, and the signatures.
func signedDirServer(t *testing.T, bodies map[string]string, sigs map[string][]byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/listing":
			host := r.Host
			var files []ghFile
			for name := range bodies {
				files = append(files, ghFile{Name: name, Type: "file",
					DownloadURL: fmt.Sprintf("https://%s/files/%s", host, name)})
			}
			for name := range sigs {
				files = append(files, ghFile{Name: name, Type: "file",
					DownloadURL: fmt.Sprintf("https://%s/files/%s", host, name)})
			}
			enc, _ := json.Marshal(files)
			_, _ = w.Write(enc)
		case len(r.URL.Path) > len("/files/") && r.URL.Path[:len("/files/")] == "/files/":
			name := r.URL.Path[len("/files/"):]
			if b, ok := bodies[name]; ok {
				_, _ = w.Write([]byte(b))
				return
			}
			if sg, ok := sigs[name]; ok {
				_, _ = w.Write(sg)
				return
			}
			http.NotFound(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newVerifyDirManager(t *testing.T, srv *httptest.Server, dir, mode string, pk minisign.PublicKey, warn *bytes.Buffer) *Manager {
	t.Helper()
	cfg := Config{
		CacheDir:     dir,
		SourceURL:    srv.URL + "/listing",
		TTL:          time.Hour,
		HTTPClient:   srv.Client(),
		Verify:       mode,
		PublicKey:    pk,
		PublicKeySet: true,
		WarnWriter:   warn,
		now:          time.Now,
	}
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return m
}

func TestVerifyDir_RequireAllSigned(t *testing.T) {
	s := newSigner(t)
	bodies := map[string]string{"a.json": perAdvisoryAJSON, "b.json": perAdvisoryBJSON}
	sigs := map[string][]byte{
		"a.json.minisig": s.sign([]byte(perAdvisoryAJSON)),
		"b.json.minisig": s.sign([]byte(perAdvisoryBJSON)),
	}
	srv := signedDirServer(t, bodies, sigs)
	dir := t.TempDir()
	m := newVerifyDirManager(t, srv, dir, VerifyRequire, s.parsedPubKey(t), nil)

	if _, _, err := m.Ensure(context.Background()); err != nil {
		t.Fatalf("Ensure = %v, want nil", err)
	}
	if !catalogCached(dir) {
		t.Fatal("merged catalog should be cached")
	}
}

func TestVerifyDir_RequireOneMissing(t *testing.T) {
	s := newSigner(t)
	bodies := map[string]string{"a.json": perAdvisoryAJSON, "b.json": perAdvisoryBJSON}
	sigs := map[string][]byte{
		"a.json.minisig": s.sign([]byte(perAdvisoryAJSON)),
		// b.json.minisig deliberately absent
	}
	srv := signedDirServer(t, bodies, sigs)
	dir := t.TempDir()
	m := newVerifyDirManager(t, srv, dir, VerifyRequire, s.parsedPubKey(t), nil)

	_, _, err := m.Ensure(context.Background())
	if !errors.Is(err, ErrSignature) {
		t.Fatalf("Ensure = %v, want ErrSignature", err)
	}
	if catalogCached(dir) {
		t.Fatal("nothing should be cached when one file lacks a signature in require mode")
	}
}

func TestVerifyDir_WarnOneMissingProceeds(t *testing.T) {
	s := newSigner(t)
	bodies := map[string]string{"a.json": perAdvisoryAJSON, "b.json": perAdvisoryBJSON}
	sigs := map[string][]byte{
		"a.json.minisig": s.sign([]byte(perAdvisoryAJSON)),
	}
	srv := signedDirServer(t, bodies, sigs)
	dir := t.TempDir()
	var warn bytes.Buffer
	m := newVerifyDirManager(t, srv, dir, VerifyWarn, s.parsedPubKey(t), &warn)

	if _, _, err := m.Ensure(context.Background()); err != nil {
		t.Fatalf("Ensure = %v, want nil (warn proceeds)", err)
	}
	if !catalogCached(dir) {
		t.Fatal("merged catalog should be cached in warn mode")
	}
	if warn.Len() == 0 {
		t.Fatal("expected a warning about the missing signature")
	}
}

// ---- ResolvePublicKey ----

func TestResolvePublicKey(t *testing.T) {
	s := newSigner(t)

	// Empty → disabled.
	if _, set, err := ResolvePublicKey(""); err != nil || set {
		t.Fatalf("empty: set=%v err=%v, want false/nil", set, err)
	}

	// Inline key.
	pk, set, err := ResolvePublicKey(s.pubKeyText())
	if err != nil || !set {
		t.Fatalf("inline: set=%v err=%v", set, err)
	}
	if pk.KeyID != s.keyID {
		t.Fatal("inline key id mismatch")
	}

	// Path to a key file.
	dir := t.TempDir()
	p := filepath.Join(dir, "k.pub")
	if err := os.WriteFile(p, []byte(s.pubKeyText()), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, set, err := ResolvePublicKey(p); err != nil || !set {
		t.Fatalf("path: set=%v err=%v", set, err)
	}

	// Neither valid key nor existing path.
	if _, _, err := ResolvePublicKey("/no/such/file.pub"); err == nil {
		t.Fatal("expected error for bogus public_key")
	}
}
