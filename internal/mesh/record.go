package mesh

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"

	"routewire/internal/engine"
)

type CandType string

const (
	CandHost   CandType = "host"
	CandSRFLX  CandType = "srflx"
	CandPRFLX  CandType = "prflx" // observed from the peer's own authenticated traffic; never published
)

// Candidate is one reachable socket for a node: host = a LAN/interface
// address, srflx = a STUN-reflexive public mapping.
type Candidate struct {
	Type CandType `json:"t"`
	Addr string   `json:"a"`

	score int `json:"-"`
}

// Record is what every node publishes under the roster key: who it is, its
// overlay address, where it might be reachable, and which subnets it serves.
// Signed by the node's derived ed25519 identity; consumers re-derive that key
// from PSK+name, so records are self-authenticating without any key exchange.
type Record struct {
	Name       string      `json:"name"`
	IP         string      `json:"ip"`
	Port       int         `json:"port"`
	Candidates []Candidate `json:"c,omitempty"`
	Adv        []string    `json:"adv,omitempty"`
	TS         int64       `json:"ts"`
	Seq        uint64      `json:"sq"`
	PK         string      `json:"pk"`
	Sig        string      `json:"sig,omitempty"`
}

func (r *Record) Sign(id *engine.Identity) error {
	r.PK = id.PublicString()
	r.Sig = ""
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	r.Sig = base64.StdEncoding.EncodeToString(id.Sign(b))
	return nil
}

// DecodeRecord verifies the embedded signature against the embedded public
// key and returns the record. Binding checks (does PK/IP match what PSK+name
// derive?) are separate: VerifyBinding.
func DecodeRecord(v engine.Value) (*Record, error) {
	var r Record
	if err := json.Unmarshal(v, &r); err != nil {
		return nil, fmt.Errorf("decode record: %w", err)
	}
	sigB64 := r.Sig
	r.Sig = ""
	b, err := json.Marshal(&r)
	if err != nil {
		return nil, err
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil || len(sig) != ed25519SigLen {
		return nil, fmt.Errorf("record %q: bad signature encoding", r.Name)
	}
	pk, err := decodePubKey(r.PK)
	if err != nil {
		return nil, fmt.Errorf("record %q: %w", r.Name, err)
	}
	if !engine.VerifySig(pk, b, sig) {
		return nil, fmt.Errorf("record %q: signature mismatch", r.Name)
	}
	return &r, nil
}

// VerifyBinding rejects records whose claimed identity or overlay IP does not
// match what PSK+name deterministically produce — i.e. only genuine PSK
// holders can publish as a given name.
func (r *Record) VerifyBinding(d *Deriver, cidr *net.IPNet) error {
	wantPK := d.PublicKeyOf(r.Name)
	gotPK, err := decodePubKey(r.PK)
	if err != nil || gotPK != wantPK {
		return fmt.Errorf("record name/pk binding failed for %q", r.Name)
	}
	ip, err := d.OverlayIP(r.Name, cidr)
	if err != nil {
		return err
	}
	if r.IP != ip.String() {
		return fmt.Errorf("record ip binding failed for %q", r.Name)
	}
	return nil
}

func decodePubKey(s string) (engine.PubKey, error) {
	var pk engine.PubKey
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(raw) != len(pk) {
		return pk, fmt.Errorf("bad public key")
	}
	copy(pk[:], raw)
	return pk, nil
}

const ed25519SigLen = 64
