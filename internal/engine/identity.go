package engine

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
)

// Identity is a node's self-owned ed25519 keypair. The public key is the
// user's handle / address, exactly like a WireGuard key in stunmesh. It is
// used both for the per-sender signature in every envelope (attribution) and
// later for per-member key exchange in direct messaging.
type Identity struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

// ParseHexSeed converts a 64-char hex string into a fixed-size identity seed.
func ParseHexSeed(s string) ([32]byte, error) {
	b, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil || len(b) != 32 {
		return [32]byte{}, errors.New("seed must be 64 hex chars")
	}
	var out [32]byte
	copy(out[:], b)
	return out, nil
}

// NewIdentityFromHexSeed builds an identity from a hex seed string.
func NewIdentityFromHexSeed(s string) (*Identity, error) {
	seed, err := ParseHexSeed(s)
	if err != nil {
		return nil, err
	}
	return NewIdentityFromSeed(seed), nil
}

// PubKey is the fixed-sized public identity.
type PubKey [32]byte

func NewIdentityFromSeed(seed [32]byte) *Identity {
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub := priv.Public().(ed25519.PublicKey)
	return &Identity{priv: priv, pub: pub}
}

func NewIdentity() (*Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Identity{priv: priv, pub: pub}, nil
}

// Public returns the identity's public key.
func (i *Identity) Public() PubKey {
	return PubKey(i.pub)
}

// PublicString returns the standard base64 display form.
func (i *Identity) PublicString() string {
	return base64.StdEncoding.EncodeToString(i.pub)
}

// Sign signs msg. Wrap in envelope signing.
func (i *Identity) Sign(msg []byte) []byte {
	return ed25519.Sign(i.priv, msg)
}

func (i *Identity) PrivateSeed() []byte { return i.priv.Seed() }

// DeriveRoomKey hashes the room token with a scheme/salt constant into the
// 32-byte secret used for the room-wide secretbox. In a fuller design this
// would be a KDF (argon2) so a weak passphrase becomes a strong key; a SHA-256
// is fine for the transport scaffold and is cheap to upgrade in place.
func DeriveRoomKey(token string) [32]byte {
	return sha256.Sum256([]byte("stunmeshchat/v1/room\x00" + token))
}

// roomKeyID is the public DHT key for a room: a deterministically derived
// 40-hex InfoHash that the OpenDHT plugin can address directly. It reveals
// only that a room with this token exists, not its content.
func roomKeyID(token string) string {
	sum := sha256.Sum256([]byte("stunmeshchat/v1/roomkey\x00" + token))
	return cut40(sum[:])
}

func cut40(b []byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, 40)
	for i := 0; i < 20; i++ {
		out[i*2] = hex[b[i]>>4]
		out[i*2+1] = hex[b[i]&0x0f]
	}
	return string(out)
}

// VerifySig reports whether sig is a valid ed25519 signature of msg by pub.
// Sized so unknown senders can be authed without an error value.
func VerifySig(pub PubKey, msg, sig []byte) bool {
	return ed25519.Verify(ed25519.PublicKey(pub[:]), msg, sig)
}
