package mesh

import (
	"encoding/json"
	"net"
	"testing"

	"routewire/internal/engine"
)

func testRecord(t *testing.T, d *Deriver, name string) *Record {
	t.Helper()
	id, err := d.NodeIdentity(name)
	if err != nil {
		t.Fatal(err)
	}
	_, cidr, _ := net.ParseCIDR(testCIDR)
	ip, err := d.OverlayIP(name, cidr)
	if err != nil {
		t.Fatal(err)
	}
	r := &Record{
		Name:       name,
		IP:         ip.String(),
		Port:       51820,
		Candidates: []Candidate{{Type: CandHost, Addr: "192.168.1.50:51820"}, {Type: CandSRFLX, Addr: "203.0.113.7:40000"}},
		TS:         1700000000,
		Seq:        42,
	}
	if err := r.Sign(id); err != nil {
		t.Fatal(err)
	}
	return r
}

func marshalRecord(t *testing.T, r *Record) engine.Value {
	t.Helper()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRecordRoundTrip(t *testing.T) {
	d := mustDeriver(t, testPSK)
	r := testRecord(t, d, "alpha")
	got, err := DecodeRecord(marshalRecord(t, r))
	if err != nil {
		t.Fatalf("decode signed record: %v", err)
	}
	if got.Name != r.Name || got.IP != r.IP || got.Port != r.Port || got.Seq != r.Seq ||
		len(got.Candidates) != len(r.Candidates) {
		t.Fatalf("round trip mismatch: %+v vs %+v", got, r)
	}
}

func TestDecodeRejectsTampering(t *testing.T) {
	d := mustDeriver(t, testPSK)
	mutations := map[string]func(r *Record){
		"port":      func(r *Record) { r.Port = 9999 },
		"ip":        func(r *Record) { r.IP = "10.99.9.9" },
		"name":      func(r *Record) { r.Name = "beta" },
		"ts":        func(r *Record) { r.TS = 1 },
		"seq":       func(r *Record) { r.Seq = 1e9 },
		"candidate": func(r *Record) { r.Candidates[0].Addr = "10.0.0.1:1" },
	}
	for label, mutate := range mutations {
		r := testRecord(t, d, "alpha")
		mutate(r)
		if _, err := DecodeRecord(marshalRecord(t, r)); err == nil {
			t.Fatalf("%s: tampered record accepted", label)
		}
	}
}

func TestDecodeRejectsGarbage(t *testing.T) {
	for _, v := range []engine.Value{nil, []byte("not json"), []byte(`{"name":"x"}`)} {
		if _, err := DecodeRecord(v); err == nil && v != nil {
			t.Fatalf("accepted garbage %q", v)
		}
	}
}

func TestVerifyBinding(t *testing.T) {
	d := mustDeriver(t, testPSK)
	_, cidr, _ := net.ParseCIDR(testCIDR)

	if err := testRecord(t, d, "alpha").VerifyBinding(d, cidr); err != nil {
		t.Fatalf("legit record rejected: %v", err)
	}

	impersonator := mustDeriver(t, testPSK)
	betaID, _ := impersonator.NodeIdentity("beta")
	claimed := &Record{Name: "alpha", IP: "10.99.123.123", Port: 51820, Seq: 1}
	_ = claimed.Sign(betaID)
	if err := claimed.VerifyBinding(d, cidr); err == nil {
		t.Fatal("foreign identity claiming another name accepted")
	}

	otherMesh := mustDeriver(t, "some other psk")
	r := testRecord(t, otherMesh, "alpha")
	_, cidrB, _ := net.ParseCIDR(testCIDR)
	if err := r.VerifyBinding(d, cidrB); err == nil {
		t.Fatal("record from a different PSK accepted into this mesh")
	}
}

func TestSignIsDeterministicPerContent(t *testing.T) {
	d := mustDeriver(t, testPSK)
	a := testRecord(t, d, "alpha")
	b := testRecord(t, d, "alpha")
	if string(marshalRecord(t, a)) != string(marshalRecord(t, b)) {
		t.Fatal("identical content produced different wire bytes (breaks put-confirm-get)")
	}
}
