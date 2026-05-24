// Package minisign implements verify-only, minisign-compatible Ed25519
// signature verification.
//
// It is compatible with the reference minisign CLI
// (https://jedisct1.github.io/minisign/) and OpenBSD signify for detached
// signatures. Guardian uses it to verify downloaded exposure-catalog feeds
// against a trusted public key; signing is out of scope (users sign with the
// standard minisign CLI).
//
// # Public key format
//
// A minisign public key file is an optional `untrusted comment:` line followed
// by a single base64 line. The base64 decodes to 42 bytes:
//
//	2 bytes  signature algorithm  ("Ed")
//	8 bytes  key id
//	32 bytes Ed25519 public key
//
// # Signature (.minisig) format
//
// A detached signature file has four lines:
//
//	untrusted comment: <text>
//	<base64 signature>          (2-byte algo, 8-byte key id, 64-byte Ed25519 sig)
//	trusted comment: <text>
//	<base64 global signature>   (64-byte Ed25519 sig over sig_bytes || trusted_comment_text)
//
// # Algorithms
//
//	"Ed" (0x45 0x64) — LEGACY / pure: ed25519(pub, message, sig).
//	"ED" (0x45 0x44) — PREHASHED:     ed25519(pub, BLAKE2b-512(message), sig).
//
// The global signature binds the trusted comment to the signed message.
package minisign

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/blake2b"
)

// Signature algorithm identifiers (the leading two bytes of the signature and
// public-key payloads).
var (
	// algoLegacy ("Ed") signs/verifies the message directly (pure Ed25519).
	algoLegacy = [2]byte{0x45, 0x64} // "Ed"
	// algoPrehashed ("ED") signs/verifies BLAKE2b-512(message).
	algoPrehashed = [2]byte{0x45, 0x44} // "ED"
)

const (
	untrustedCommentPrefix = "untrusted comment: "
	trustedCommentPrefix   = "trusted comment: "
)

// Sentinel errors so callers can distinguish failure classes. All are wrapped
// with %w by the functions that return them; test with errors.Is.
var (
	// ErrMalformed indicates the key or signature could not be parsed (bad
	// base64, wrong length, missing lines, unknown algorithm).
	ErrMalformed = errors.New("minisign: malformed input")

	// ErrWrongKey indicates the signature was produced by a different key than
	// the trusted public key (key id mismatch).
	ErrWrongKey = errors.New("minisign: signature key id does not match public key")

	// ErrInvalidSignature indicates the cryptographic verification failed: the
	// signature (or its global/trusted-comment signature) does not check out
	// against the public key for the given message.
	ErrInvalidSignature = errors.New("minisign: invalid signature")
)

// PublicKey is a parsed minisign public key.
type PublicKey struct {
	// Algorithm is the two-byte signature algorithm declared by the key file
	// (typically "Ed"). It does not constrain which signature algorithm may be
	// verified; the per-signature algorithm selects pure vs. prehashed.
	Algorithm [2]byte
	// KeyID is the 8-byte key identifier. A signature must carry the same KeyID.
	KeyID [8]byte
	// key is the raw 32-byte Ed25519 public key.
	key ed25519.PublicKey
}

// Signature is a parsed minisign detached signature (.minisig).
type Signature struct {
	// Algorithm is the two-byte algorithm: algoLegacy (pure) or algoPrehashed.
	Algorithm [2]byte
	// KeyID is the 8-byte key identifier the signature claims to be from.
	KeyID [8]byte
	// sig is the 64-byte Ed25519 signature over the (possibly prehashed) message.
	sig []byte
	// TrustedComment is the free-form text bound by the global signature.
	TrustedComment string
	// globalSig is the 64-byte Ed25519 signature over sig || TrustedComment.
	globalSig []byte
}

// ParsePublicKey parses a minisign public key from its textual representation.
// The input may be the full key file (optional `untrusted comment:` line then a
// base64 line) or just the bare base64 line.
func ParsePublicKey(s string) (PublicKey, error) {
	b64 := lastNonCommentLine(s)
	if b64 == "" {
		return PublicKey{}, fmt.Errorf("%w: public key has no base64 content", ErrMalformed)
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return PublicKey{}, fmt.Errorf("%w: public key base64: %v", ErrMalformed, err)
	}
	// 2 (algo) + 8 (key id) + 32 (ed25519 public key) = 42 bytes.
	if len(raw) != 2+8+ed25519.PublicKeySize {
		return PublicKey{}, fmt.Errorf("%w: public key is %d bytes, want %d",
			ErrMalformed, len(raw), 2+8+ed25519.PublicKeySize)
	}

	var pk PublicKey
	copy(pk.Algorithm[:], raw[0:2])
	copy(pk.KeyID[:], raw[2:10])
	pk.key = ed25519.PublicKey(append([]byte(nil), raw[10:]...))
	return pk, nil
}

// LoadPublicKey reads and parses a minisign public key from a file path.
func LoadPublicKey(path string) (PublicKey, error) {
	// #nosec G304 -- path is the user-configured trusted public key location;
	// reading it for a read-only parse is the documented function of this API.
	b, err := os.ReadFile(path)
	if err != nil {
		return PublicKey{}, fmt.Errorf("minisign: read public key %s: %w", path, err)
	}
	return ParsePublicKey(string(b))
}

// lastNonCommentLine returns the last non-empty line that is not an
// `untrusted comment:` / `trusted comment:` line, trimmed. minisign public key
// files have exactly one base64 line; we tolerate surrounding blank lines.
func lastNonCommentLine(s string) string {
	var last string
	sc := bufio.NewScanner(strings.NewReader(s))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, untrustedCommentPrefix) || strings.HasPrefix(line, trustedCommentPrefix) {
			continue
		}
		last = line
	}
	return last
}

// ParseSignature parses a minisign detached signature (.minisig) from raw bytes.
//
// Expected layout (line-oriented):
//
//	untrusted comment: <text>
//	<base64: 2-byte algo, 8-byte key id, 64-byte ed25519 sig>
//	trusted comment: <text>
//	<base64: 64-byte ed25519 global sig>
//
// The untrusted-comment line is optional/ignored. The trusted-comment line and
// global signature are required (they are what bind the trusted comment).
func ParseSignature(b []byte) (Signature, error) {
	var (
		sigB64      string
		globalB64   string
		trustedText string
		haveSig     bool
		haveTrusted bool
		haveGlobal  bool
	)

	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		// Preserve the line verbatim except for a trailing CR (CRLF tolerance);
		// the trusted comment text is part of the signed bytes, so we must not
		// alter it beyond stripping the line terminator.
		line := strings.TrimRight(sc.Text(), "\r")
		switch {
		case strings.HasPrefix(line, untrustedCommentPrefix):
			// Ignored: not covered by any signature.
		case strings.HasPrefix(line, trustedCommentPrefix):
			trustedText = line[len(trustedCommentPrefix):]
			haveTrusted = true
		case strings.TrimSpace(line) == "":
			// Skip blank lines.
		case !haveSig:
			sigB64 = strings.TrimSpace(line)
			haveSig = true
		case haveTrusted && !haveGlobal:
			globalB64 = strings.TrimSpace(line)
			haveGlobal = true
		default:
			// Extra unexpected content.
			return Signature{}, fmt.Errorf("%w: unexpected extra line in signature", ErrMalformed)
		}
	}
	if err := sc.Err(); err != nil {
		return Signature{}, fmt.Errorf("%w: read signature: %v", ErrMalformed, err)
	}

	if !haveSig {
		return Signature{}, fmt.Errorf("%w: signature line missing", ErrMalformed)
	}
	if !haveTrusted {
		return Signature{}, fmt.Errorf("%w: trusted comment line missing", ErrMalformed)
	}
	if !haveGlobal {
		return Signature{}, fmt.Errorf("%w: global signature line missing", ErrMalformed)
	}

	sigRaw, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return Signature{}, fmt.Errorf("%w: signature base64: %v", ErrMalformed, err)
	}
	// 2 (algo) + 8 (key id) + 64 (ed25519 sig) = 74 bytes.
	if len(sigRaw) != 2+8+ed25519.SignatureSize {
		return Signature{}, fmt.Errorf("%w: signature payload is %d bytes, want %d",
			ErrMalformed, len(sigRaw), 2+8+ed25519.SignatureSize)
	}
	globalRaw, err := base64.StdEncoding.DecodeString(globalB64)
	if err != nil {
		return Signature{}, fmt.Errorf("%w: global signature base64: %v", ErrMalformed, err)
	}
	if len(globalRaw) != ed25519.SignatureSize {
		return Signature{}, fmt.Errorf("%w: global signature is %d bytes, want %d",
			ErrMalformed, len(globalRaw), ed25519.SignatureSize)
	}

	var s Signature
	copy(s.Algorithm[:], sigRaw[0:2])
	copy(s.KeyID[:], sigRaw[2:10])
	s.sig = append([]byte(nil), sigRaw[10:]...)
	s.TrustedComment = trustedText
	s.globalSig = append([]byte(nil), globalRaw...)

	if s.Algorithm != algoLegacy && s.Algorithm != algoPrehashed {
		return Signature{}, fmt.Errorf("%w: unknown signature algorithm %q", ErrMalformed, string(s.Algorithm[:]))
	}
	return s, nil
}

// Verify checks sig against message using pk.
//
// It returns:
//   - ErrWrongKey if the signature's key id does not match pk's key id;
//   - ErrInvalidSignature if either the message signature or the global
//     (trusted-comment) signature fails to verify;
//   - nil if both signatures verify.
//
// For algorithm "Ed" the message is verified directly; for "ED" the
// BLAKE2b-512 hash of the message is verified. The global signature, computed
// over sig || trusted_comment_text, is always checked — this is what binds the
// trusted comment to the signed payload.
func (pk PublicKey) Verify(message []byte, sig Signature) error {
	if sig.KeyID != pk.KeyID {
		return ErrWrongKey
	}

	var signed []byte
	switch sig.Algorithm {
	case algoLegacy:
		signed = message
	case algoPrehashed:
		h := blake2b.Sum512(message)
		signed = h[:]
	default:
		return fmt.Errorf("%w: unknown signature algorithm %q", ErrMalformed, string(sig.Algorithm[:]))
	}

	if !ed25519.Verify(pk.key, signed, sig.sig) {
		return fmt.Errorf("%w: message signature does not verify", ErrInvalidSignature)
	}

	// The global signature binds the trusted comment: ed25519(pub, sig || tc).
	globalMessage := make([]byte, 0, len(sig.sig)+len(sig.TrustedComment))
	globalMessage = append(globalMessage, sig.sig...)
	globalMessage = append(globalMessage, []byte(sig.TrustedComment)...)
	if !ed25519.Verify(pk.key, globalMessage, sig.globalSig) {
		return fmt.Errorf("%w: global (trusted comment) signature does not verify", ErrInvalidSignature)
	}
	return nil
}
