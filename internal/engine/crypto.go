package engine

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"

	"golang.org/x/crypto/nacl/secretbox"
)

// Room-level symmetric encryption using the NaCl secretbox (XSalsa20-Poly1305).
// Every member of a room derives the same key from the token, so any member can
// read any room message but a non-member (and the storage) cannot. Per-message
// attribution is handled separately by the ed25519 signature in the envelope.

var (
	ErrSeal   = errors.New("seal failed")
	ErrUnseal = errors.New("unseal failed (wrong key or tampered)")
)

const (
	nonceLen    = 24
	keyLen      = 32
	overheadLen = 16
)

// nonce is freshly generated per message and appended before the ciphertext.
func sealRoom(key [32]byte, plaintext []byte) ([]byte, error) {
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, ErrSeal
	}
	sealed := secretbox.Seal(nil, plaintext, &nonce, &key)
	out := make([]byte, 0, nonceLen+len(sealed))
	out = append(out, nonce[:]...)
	out = append(out, sealed...)
	return out, nil
}

// unsealRoom reverses sealRoom. It returns an error on tamper/wrong key.
func unsealRoom(key [32]byte, sealed []byte) ([]byte, error) {
	if len(sealed) < nonceLen+overheadLen {
		return nil, ErrUnseal
	}
	var nonce [24]byte
	copy(nonce[:], sealed[:nonceLen])
	open, ok := secretbox.Open(nil, sealed[nonceLen:], &nonce, &key)
	if !ok {
		return nil, ErrUnseal
	}
	return open, nil
}

// Seal encrypts plaintext with the given 32-byte key (fresh nonce prepended).
// It is the generic box used to make anything stored in the DHT opaque to the
// storage operator (the mesh roster records, chat envelopes, ...).
func Seal(key [32]byte, plaintext []byte) ([]byte, error) {
	return sealRoom(key, plaintext)
}

// Open decrypts a blob produced by Seal. It returns an error on tamper or a
// mismatched key, which callers treat as "not for us / foreign value".
func Open(key [32]byte, sealed []byte) ([]byte, error) {
	return unsealRoom(key, sealed)
}

// SealDeterministic encrypts plaintext with a nonce derived from the plaintext
// itself (sha256), so identical plaintext always yields identical ciphertext.
// This makes stored values content-addressed: re-publishing the same envelope
// produces the same bytes, which dedup and TTL-refresh rely on. Distinct
// plaintexts produce distinct nonces with overwhelming probability, so no
// nonce is ever reused across differing plaintexts under the same key.
func SealDeterministic(key [32]byte, plaintext []byte) []byte {
	sum := sha256.Sum256(plaintext)
	var nonce [24]byte
	copy(nonce[:], sum[:nonceLen])
	out := make([]byte, 0, nonceLen+len(plaintext)+overheadLen)
	out = append(out, nonce[:]...)
	return secretbox.Seal(out, plaintext, &nonce, &key)
}

// b64 and b64dec wrap base64 encoding used across the wire format.
func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
func b64dec(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

// randomBytes returns n random bytes (used for salts/entropy only).
func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := io.ReadFull(rand.Reader, b)
	return b, err
}
