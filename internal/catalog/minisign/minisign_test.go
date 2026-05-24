package minisign

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/blake2b"
)

// testKey is a generated Ed25519 keypair plus a fixed minisign key id, with
// helpers to hand-build minisign public-key and .minisig blobs for testing.
type testKey struct {
	pub   ed25519.PublicKey
	priv  ed25519.PrivateKey
	keyID [8]byte
}

func newTestKey(t *testing.T) testKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return testKey{pub: pub, priv: priv, keyID: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}}
}

// pubKeyBlob renders the minisign public key file text (with a comment line).
func (k testKey) pubKeyBlob() string {
	raw := make([]byte, 0, 2+8+ed25519.PublicKeySize)
	raw = append(raw, algoLegacy[0], algoLegacy[1])
	raw = append(raw, k.keyID[:]...)
	raw = append(raw, k.pub...)
	return "untrusted comment: minisign public key TEST\n" +
		base64.StdEncoding.EncodeToString(raw) + "\n"
}

// signBlob builds a .minisig blob signing message with the given algorithm and
// trusted comment, using overrideKeyID for the embedded key id (so tests can
// inject a mismatching id).
func (k testKey) signBlob(t *testing.T, message []byte, algo [2]byte, trustedComment string, overrideKeyID *[8]byte) []byte {
	t.Helper()

	var toSign []byte
	switch algo {
	case algoLegacy:
		toSign = message
	case algoPrehashed:
		h := blake2b.Sum512(message)
		toSign = h[:]
	default:
		t.Fatalf("unknown algo")
	}
	sig := ed25519.Sign(k.priv, toSign)

	keyID := k.keyID
	if overrideKeyID != nil {
		keyID = *overrideKeyID
	}

	sigPayload := make([]byte, 0, 2+8+ed25519.SignatureSize)
	sigPayload = append(sigPayload, algo[0], algo[1])
	sigPayload = append(sigPayload, keyID[:]...)
	sigPayload = append(sigPayload, sig...)

	// Global signature over sig || trusted_comment_text.
	globalMsg := make([]byte, 0, len(sig)+len(trustedComment))
	globalMsg = append(globalMsg, sig...)
	globalMsg = append(globalMsg, []byte(trustedComment)...)
	globalSig := ed25519.Sign(k.priv, globalMsg)

	blob := fmt.Sprintf("untrusted comment: signature from TEST\n%s\ntrusted comment: %s\n%s\n",
		base64.StdEncoding.EncodeToString(sigPayload),
		trustedComment,
		base64.StdEncoding.EncodeToString(globalSig),
	)
	return []byte(blob)
}

func mustParsePub(t *testing.T, k testKey) PublicKey {
	t.Helper()
	pk, err := ParsePublicKey(k.pubKeyBlob())
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	return pk
}

func TestVerify_Legacy_Valid(t *testing.T) {
	k := newTestKey(t)
	msg := []byte("hello exposure catalog")
	blob := k.signBlob(t, msg, algoLegacy, "timestamp:1716500000", nil)

	pk := mustParsePub(t, k)
	sig, err := ParseSignature(blob)
	if err != nil {
		t.Fatalf("ParseSignature: %v", err)
	}
	if err := pk.Verify(msg, sig); err != nil {
		t.Fatalf("Verify (legacy) = %v, want nil", err)
	}
}

func TestVerify_Prehashed_Valid(t *testing.T) {
	k := newTestKey(t)
	msg := []byte(`{"schema_version":"0.1.0","entries":[]}`)
	blob := k.signBlob(t, msg, algoPrehashed, "file:catalog.json", nil)

	pk := mustParsePub(t, k)
	sig, err := ParseSignature(blob)
	if err != nil {
		t.Fatalf("ParseSignature: %v", err)
	}
	if sig.Algorithm != algoPrehashed {
		t.Fatalf("algorithm = %q, want prehashed", string(sig.Algorithm[:]))
	}
	if err := pk.Verify(msg, sig); err != nil {
		t.Fatalf("Verify (prehashed) = %v, want nil", err)
	}
}

func TestVerify_TamperedMessage(t *testing.T) {
	for _, algo := range [][2]byte{algoLegacy, algoPrehashed} {
		algo := algo
		t.Run(string(algo[:]), func(t *testing.T) {
			k := newTestKey(t)
			msg := []byte("original content")
			blob := k.signBlob(t, msg, algo, "tc", nil)

			pk := mustParsePub(t, k)
			sig, err := ParseSignature(blob)
			if err != nil {
				t.Fatalf("ParseSignature: %v", err)
			}
			err = pk.Verify([]byte("tampered content"), sig)
			if !errors.Is(err, ErrInvalidSignature) {
				t.Fatalf("Verify(tampered) = %v, want ErrInvalidSignature", err)
			}
		})
	}
}

func TestVerify_TamperedTrustedComment(t *testing.T) {
	k := newTestKey(t)
	msg := []byte("payload")
	blob := k.signBlob(t, msg, algoLegacy, "genuine comment", nil)

	pk := mustParsePub(t, k)
	sig, err := ParseSignature(blob)
	if err != nil {
		t.Fatalf("ParseSignature: %v", err)
	}
	// Tamper the trusted comment after parsing: the message signature still
	// verifies, but the global signature must fail.
	sig.TrustedComment = "attacker controlled comment"
	err = pk.Verify(msg, sig)
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("Verify(tampered tc) = %v, want ErrInvalidSignature", err)
	}
}

func TestVerify_WrongKeyID(t *testing.T) {
	k := newTestKey(t)
	msg := []byte("payload")
	other := [8]byte{9, 9, 9, 9, 9, 9, 9, 9}
	blob := k.signBlob(t, msg, algoLegacy, "tc", &other)

	pk := mustParsePub(t, k)
	sig, err := ParseSignature(blob)
	if err != nil {
		t.Fatalf("ParseSignature: %v", err)
	}
	err = pk.Verify(msg, sig)
	if !errors.Is(err, ErrWrongKey) {
		t.Fatalf("Verify(wrong key id) = %v, want ErrWrongKey", err)
	}
}

func TestVerify_WrongKey(t *testing.T) {
	// Signature made by k1 but verified against a different public key sharing
	// the same key id — must fail cryptographic verification.
	k1 := newTestKey(t)
	k2 := newTestKey(t)
	k2.keyID = k1.keyID // force matching id so we reach crypto verification

	msg := []byte("payload")
	blob := k1.signBlob(t, msg, algoLegacy, "tc", nil)

	pk := mustParsePub(t, k2)
	sig, err := ParseSignature(blob)
	if err != nil {
		t.Fatalf("ParseSignature: %v", err)
	}
	err = pk.Verify(msg, sig)
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("Verify(wrong key) = %v, want ErrInvalidSignature", err)
	}
}

func TestParsePublicKey_Malformed(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"only comment", "untrusted comment: nothing here\n"},
		{"bad base64", "untrusted comment: x\n!!!not base64!!!\n"},
		{"wrong length", "AAAA\n"}, // valid base64, too short
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParsePublicKey(tc.in)
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("ParsePublicKey(%q) = %v, want ErrMalformed", tc.name, err)
			}
		})
	}
}

func TestParseSignature_Malformed(t *testing.T) {
	k := newTestKey(t)
	good := k.signBlob(t, []byte("m"), algoLegacy, "tc", nil)

	cases := []struct {
		name string
		in   []byte
	}{
		{"empty", []byte("")},
		{"missing trusted comment", []byte("untrusted comment: x\n" +
			base64.StdEncoding.EncodeToString(make([]byte, 2+8+ed25519.SignatureSize)) + "\n")},
		{"sig bad base64", []byte("untrusted comment: x\n!!!!\ntrusted comment: tc\n" +
			base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)) + "\n")},
		{"sig wrong length", []byte("untrusted comment: x\nAAAA\ntrusted comment: tc\n" +
			base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)) + "\n")},
		{"unknown algo", buildUnknownAlgoSig()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseSignature(tc.in)
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("ParseSignature(%q) = %v, want ErrMalformed", tc.name, err)
			}
		})
	}

	// Sanity: the good blob still parses.
	if _, err := ParseSignature(good); err != nil {
		t.Fatalf("ParseSignature(good) = %v, want nil", err)
	}
}

func buildUnknownAlgoSig() []byte {
	payload := make([]byte, 2+8+ed25519.SignatureSize)
	payload[0] = 'Z'
	payload[1] = 'z'
	return []byte("untrusted comment: x\n" +
		base64.StdEncoding.EncodeToString(payload) + "\n" +
		"trusted comment: tc\n" +
		base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)) + "\n")
}

func TestLoadPublicKey(t *testing.T) {
	k := newTestKey(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "test.pub")
	if err := os.WriteFile(path, []byte(k.pubKeyBlob()), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	pk, err := LoadPublicKey(path)
	if err != nil {
		t.Fatalf("LoadPublicKey: %v", err)
	}
	if pk.KeyID != k.keyID {
		t.Fatalf("KeyID = %x, want %x", pk.KeyID, k.keyID)
	}

	if _, err := LoadPublicKey(filepath.Join(dir, "missing.pub")); err == nil {
		t.Fatalf("LoadPublicKey(missing) = nil, want error")
	}
}

func TestParsePublicKey_BareBase64(t *testing.T) {
	// A bare base64 line (no comment) must also parse.
	k := newTestKey(t)
	raw := make([]byte, 0, 2+8+ed25519.PublicKeySize)
	raw = append(raw, algoLegacy[0], algoLegacy[1])
	raw = append(raw, k.keyID[:]...)
	raw = append(raw, k.pub...)
	bare := base64.StdEncoding.EncodeToString(raw)
	pk, err := ParsePublicKey(bare)
	if err != nil {
		t.Fatalf("ParsePublicKey(bare) = %v", err)
	}
	if pk.KeyID != k.keyID {
		t.Fatalf("KeyID mismatch")
	}
}
