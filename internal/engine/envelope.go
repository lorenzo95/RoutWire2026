package engine

import (
	"encoding/json"
	"errors"
	"strconv"
)

// wireEnvelope is the stable wire format stored under a room key. Field order
// on the JSON is fixed; SigningBytes renders the same fields canonically for
// ed25519 verification and is what makes dedup keys stable across refreshes.
type wireEnvelope struct {
	V    int    `json:"v"`
	Kind string `json:"kind"`
	PK   string `json:"pk"`
	Name string `json:"name"`
	Seq  uint64 `json:"seq"`
	TS   int64  `json:"ts"`
	Room string `json:"room"`
	Box  string `json:"box"`
	Sig  string `json:"sig"`
}

var ErrInvalidPubKey = errors.New("invalid public key")

// Envelope wraps a parsed wireEnvelope. Raw bytes are preserved on decode so a
// value round-trips unchanged over the store (identity for TTL refresh/dedup).
type Envelope struct {
	Msg *wireEnvelope
}

// NewEnvelope builds a signed chat envelope sealed under the derived room key.
// The room token is recorded for filtering; ts is the sender's wall clock used
// to sort the window (ordering is heuristic, as with any DHT).
func NewEnvelope(me *Identity, name, roomToken string, roomKey [32]byte, seq uint64, ts int64, text string) (*Envelope, error) {
	sealed, err := sealRoom(roomKey, []byte(text))
	if err != nil {
		return nil, err
	}
	w := &wireEnvelope{
		V:    1,
		Kind: "chat",
		PK:   me.PublicString(),
		Name: name,
		Seq:  seq,
		TS:   ts,
		Room: roomToken,
		Box:  b64(sealed),
	}
	canonical, err := w.SigningBytes()
	if err != nil {
		return nil, err
	}
	w.Sig = b64(me.Sign(canonical))
	return &Envelope{Msg: w}, nil
}

// NewEnvelopeFor stores a prebuilt envelope without re-signing (decode path).
func DecodeEnvelope(roomKey [32]byte, raw []byte) (*Envelope, error) {
	plain, err := unsealRoom(roomKey, raw)
	if err != nil {
		return nil, err
	}
	var w wireEnvelope
	if err := json.Unmarshal(plain, &w); err != nil {
		return nil, err
	}
	return &Envelope{Msg: &w}, nil
}

// ID is the deterministic message id (sender pubkey + sender seq). It is the
// dedup identity and, later, the "seen up to seq N" / ack watermark.
func (e *Envelope) ID() string {
	return e.Msg.PK + "#" + strconv.FormatUint(e.Msg.Seq, 10)
}

// SenderPK decodes the sender public key.
func (e *Envelope) SenderPK() (PubKey, error) {
	b, err := b64dec(e.Msg.PK)
	if err != nil || len(b) != len(PubKey{}) {
		return PubKey{}, ErrInvalidPubKey
	}
	var pk PubKey
	copy(pk[:], b)
	return pk, nil
}

// Verify checks the ed25519 signature over the canonical fields.
func (e *Envelope) Verify() (bool, error) {
	pk, err := e.SenderPK()
	if err != nil {
		return false, err
	}
	sig, err := b64dec(e.Msg.Sig)
	if err != nil {
		return false, err
	}
	canonical, err := e.Msg.SigningBytes()
	if err != nil {
		return false, err
	}
	return VerifySig(pk, canonical, sig), nil
}

// Open decrypts and returns the message text if the room key matches.
func (e *Envelope) Open(roomKey [32]byte) (string, error) {
	sealed, err := b64dec(e.Msg.Box)
	if err != nil {
		return "", err
	}
	plain, err := unsealRoom(roomKey, sealed)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// Marshal seals the entire envelope under the room key and returns the blob
// for storage. The DHT therefore holds only ciphertext: sender name, public
// key, room token, and message are all unreadable without the room key.
func (e *Envelope) Marshal(roomKey [32]byte) (Value, error) {
	raw, err := json.Marshal(e.Msg)
	if err != nil {
		return nil, err
	}
	return SealDeterministic(roomKey, raw), nil
}

// SigningBytes renders the fields covered by the signature in a stable order.
// It excludes Sig and V (version is trusted from the parse context).
func (w *wireEnvelope) SigningBytes() ([]byte, error) {
	s := w.Kind + "\x00" + w.PK + "\x00" + w.Name + "\x00" +
		strconv.FormatUint(w.Seq, 10) + "\x00" +
		strconv.FormatInt(w.TS, 10) + "\x00" + w.Room + "\x00" + w.Box
	return []byte(s), nil
}
