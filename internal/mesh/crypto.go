package mesh

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"

	"golang.org/x/crypto/hkdf"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"routewire/internal/engine"
)

const domain = "routewire/v1"

// Deriver is the single root of trust: the mesh PSK. Every node key, DHT
// address, and overlay IP is a pure function of PSK + node name, so joining
// the mesh requires nothing but the PSK and a name.
type Deriver struct {
	psk []byte
}

func NewDeriver(psk string) *Deriver {
	return &Deriver{psk: []byte(psk)}
}

// ValidateName enforces the normalized form used in all derivations.
func ValidateName(name string) error {
	if len(name) < 1 || len(name) > 32 {
		return fmt.Errorf("name must be 1-32 chars")
	}
	for _, c := range name {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-':
		default:
			return fmt.Errorf("name may only contain a-z 0-9 and -")
		}
	}
	return nil
}

func NormalizeName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

func (d *Deriver) derive(info string, n int) []byte {
	r := hkdf.New(sha256.New, d.psk, []byte(domain+"/salt"), []byte(info))
	out := make([]byte, n)
	if _, err := io.ReadFull(r, out); err != nil {
		panic("hkdf: " + err.Error())
	}
	return out
}

// NodeWGKey returns the node's WireGuard private key.
func (d *Deriver) NodeWGKey(name string) (wgtypes.Key, error) {
	name = NormalizeName(name)
	if err := ValidateName(name); err != nil {
		return wgtypes.Key{}, fmt.Errorf("node %q: %w", name, err)
	}
	return wgtypes.NewKey(d.derive("wg/"+name, 32))
}

// NodeWGPubKey returns the public key peers must configure for this node:
// the public half of the derived private key. Never configure a peer with
// anything else — the kernel authenticates incoming handshakes against it.
func (d *Deriver) NodeWGPubKey(name string) (wgtypes.Key, error) {
	priv, err := d.NodeWGKey(name)
	if err != nil {
		return wgtypes.Key{}, err
	}
	return priv.PublicKey(), nil
}

// NodeIdentity returns the node's ed25519 signing identity for records.
func (d *Deriver) NodeIdentity(name string) (*engine.Identity, error) {
	name = NormalizeName(name)
	if err := ValidateName(name); err != nil {
		return nil, fmt.Errorf("node %q: %w", name, err)
	}
	var seed [32]byte
	copy(seed[:], d.derive("id/"+name, 32))
	return engine.NewIdentityFromSeed(seed), nil
}

// PublicKeyOf returns the ed25519 public key records from `name` must carry.
func (d *Deriver) PublicKeyOf(name string) engine.PubKey {
	id, err := d.NodeIdentity(name)
	if err != nil {
		return engine.PubKey{}
	}
	return id.Public()
}

func (d *Deriver) keyID(kind, arg string) string {
	sum := sha256.Sum256([]byte(domain + "/" + kind + "\x00" + string(d.psk) + "\x00" + arg))
	return cutHex40(sum[:])
}

// RosterKey is the shared InfoHash under which every node publishes its record.
func (d *Deriver) RosterKey() string { return d.keyID("roster", "") }

// RosterBoxKey derives the symmetric key used to seal records before they are
// stored in the DHT. The InfoHash locates the value; this key hides its
// contents — so a storage operator (e.g. the DHT proxies) can host our records
// without being able to read node names, overlay IPs, or candidates.
func (d *Deriver) RosterBoxKey() [32]byte {
	var k [32]byte
	copy(k[:], d.derive("mesh/box", 32))
	return k
}

// OverlayIP maps a node onto the mesh CIDR deterministically: network bits
// fixed, host bits taken from a hash of its WireGuard public key. Collisions
// are birthday-bounded by half the host space; fine for home-scale meshes.
func (d *Deriver) OverlayIP(name string, cidr *net.IPNet) (net.IP, error) {
	key, err := d.NodeWGKey(name)
	if err != nil {
		return nil, err
	}
	base4 := cidr.IP.To4()
	if base4 == nil {
		return nil, fmt.Errorf("overlay cidr must be IPv4")
	}
	ones, bits := cidr.Mask.Size()
	if bits != 32 || ones > 30 {
		return nil, fmt.Errorf("overlay cidr must be IPv4 with prefix <= /30")
	}
	sum := sha256.Sum256(key[:])
	hostMask := uint32(1)<<(32-ones) - 1
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip,
		binary.BigEndian.Uint32(base4)|(binary.BigEndian.Uint32(sum[:4])&hostMask))
	return ip, nil
}

// OverlayIPNet returns OverlayIP as an /32 net usable as AllowedIPs.
func (d *Deriver) OverlayIPNet(name string, cidr *net.IPNet) (*net.IPNet, error) {
	ip, err := d.OverlayIP(name, cidr)
	if err != nil {
		return nil, err
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}, nil
}

func cutHex40(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 40)
	for i := 0; i < 20; i++ {
		out[i*2] = digits[b[i]>>4]
		out[i*2+1] = digits[b[i]&0x0f]
	}
	return string(out)
}
