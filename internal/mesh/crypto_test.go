package mesh

import (
	"encoding/hex"
	"net"
	"testing"

	"routewire/internal/engine"
)

const (
	testPSK  = "correct horse battery staple"
	testCIDR = "10.99.0.0/16"
)

func mustDeriver(t *testing.T, psk string) *Deriver {
	t.Helper()
	return NewDeriver(psk)
}

func TestNodeWGKeyDeterministic(t *testing.T) {
	d := mustDeriver(t, testPSK)
	a1, err := d.NodeWGKey("alpha")
	if err != nil {
		t.Fatal(err)
	}
	a2, err := d.NodeWGKey(" alpha ")
	if err != nil {
		t.Fatal(err)
	}
	if a1 != a2 {
		t.Fatal("normalization mismatch: same node derived different keys")
	}
	b, err := d.NodeWGKey("beta")
	if err != nil {
		t.Fatal(err)
	}
	if a1 == b || a1.PublicKey() == b.PublicKey() {
		t.Fatal("distinct names must derive distinct keypairs")
	}
}

func TestNodeWGKeyRejectsBadNames(t *testing.T) {
	d := mustDeriver(t, testPSK)
	for _, name := range []string{"", "sp ace", "café", string(make([]byte, 64))} {
		if _, err := d.NodeWGKey(name); err == nil {
			t.Fatalf("expected error for name %q", name)
		}
	}
	upper, err := d.NodeWGKey("UPPER")
	if err != nil {
		t.Fatal(err)
	}
	lower, err := d.NodeWGKey("upper")
	if err != nil {
		t.Fatal(err)
	}
	if upper != lower {
		t.Fatal("uppercase names must normalize")
	}
}

func TestNodeIdentityMatchesPublicKeyOf(t *testing.T) {
	d := mustDeriver(t, testPSK)
	id, err := d.NodeIdentity("alpha")
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("payload")
	sig := id.Sign(msg)
	if !engine.VerifySig(d.PublicKeyOf("ALPHA"), msg, sig) {
		t.Fatal("identity signature does not verify against derived public key")
	}
	if engine.VerifySig(d.PublicKeyOf("beta"), msg, sig) {
		t.Fatal("signature verified under the wrong node's key")
	}
}

func TestOverlayIPStableAndDistinct(t *testing.T) {
	d := mustDeriver(t, testPSK)
	_, cidr, err := net.ParseCIDR(testCIDR)
	if err != nil {
		t.Fatal(err)
	}
	a1, err := d.OverlayIP("alpha", cidr)
	if err != nil {
		t.Fatal(err)
	}
	a2, err := d.OverlayIP("alpha", cidr)
	if err != nil {
		t.Fatal(err)
	}
	if !a1.Equal(a2) {
		t.Fatalf("overlay ip unstable: %v vs %v", a1, a2)
	}
	if !cidr.Contains(a1) {
		t.Fatalf("%v outside overlay cidr", a1)
	}
	for _, name := range []string{"beta", "gamma", "delta", "epsilon"} {
		other, err := d.OverlayIP(name, cidr)
		if err != nil {
			t.Fatal(err)
		}
		if a1.Equal(other) {
			t.Fatalf("collision between alpha and %s", name)
		}
	}
}

func TestOverlayIPRespectsPrefix(t *testing.T) {
	d := mustDeriver(t, testPSK)
	_, cidr, _ := net.ParseCIDR("192.168.77.4/30")
	ip, err := d.OverlayIP("alpha", cidr)
	if err != nil {
		t.Fatal(err)
	}
	if !cidr.Contains(ip) {
		t.Fatalf("%v outside /30", ip)
	}
}

func TestOverlayIPNetIsHostRoute(t *testing.T) {
	d := mustDeriver(t, testPSK)
	_, cidr, _ := net.ParseCIDR(testCIDR)
	ipn, err := d.OverlayIPNet("alpha", cidr)
	if err != nil {
		t.Fatal(err)
	}
	if ones, bits := ipn.Mask.Size(); ones != 32 || bits != 32 {
		t.Fatalf("allowed-ips must be /32, got /%d", ones)
	}
}

func TestRosterKeyShapeAndBinding(t *testing.T) {
	d := mustDeriver(t, testPSK)
	key := d.RosterKey()
	if len(key) != 40 {
		t.Fatalf("roster key must be 40-hex infohash, got %d chars", len(key))
	}
	if _, err := hex.DecodeString(key); err != nil {
		t.Fatalf("roster key not hex: %v", err)
	}
	other := mustDeriver(t, "different psk").RosterKey()
	if key == other {
		t.Fatal("roster key must be PSK-bound")
	}
}
