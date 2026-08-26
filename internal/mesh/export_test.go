package mesh

import (
	"net"
	"strings"
	"testing"
)

func mustCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, cidr, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatal(err)
	}
	return cidr
}

func parseINI(t *testing.T, conf []byte) map[string]map[string]string {
	t.Helper()
	out := map[string]map[string]string{"": {}}
	cur := ""
	for _, line := range strings.Split(string(conf), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			cur = strings.Trim(line, "[]")
			out[cur] = map[string]string{}
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatalf("bad ini line %q", line)
		}
		out[cur][strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return out
}

func TestExportConfGolden(t *testing.T) {
	d := NewDeriver("test-psk")
	cidr := mustCIDR(t, "10.99.0.0/16")

	conf, err := ExportConf(ExportConfInput{
		Deriver:     d,
		CIDR:        cidr,
		LocalName:   "alpha",
		RemoteName:  "phone-1",
		Endpoint:    "192.168.1.10:51820",
		ExtraRoutes: []string{"192.168.50.0/24", "bogus"},
		MTU:         1420,
	})
	if err != nil {
		t.Fatal(err)
	}

	ini := parseINI(t, conf)
	ifc := ini["Interface"]
	peer := ini["Peer"]
	if ifc == nil || peer == nil {
		t.Fatalf("missing sections: %v", ini)
	}

	wantPriv, err := d.NodeWGKey("phone-1")
	if err != nil {
		t.Fatal(err)
	}
	if ifc["PrivateKey"] != wantPriv.String() {
		t.Fatalf("private key must be derived phone-1 key:\n got %s\nwant %s", ifc["PrivateKey"], wantPriv.String())
	}
	wantIP, _ := d.OverlayIP("phone-1", cidr)
	if ifc["Address"] != wantIP.String()+"/32" {
		t.Fatalf("address: got %q want %q", ifc["Address"], wantIP.String()+"/32")
	}
	if ifc["MTU"] != "1420" {
		t.Fatalf("mtu: %q", ifc["MTU"])
	}

	hubPub, _ := d.NodeWGKey("alpha")
	if peer["PublicKey"] != hubPub.PublicKey().String() {
		t.Fatalf("peer pubkey must be alpha's: %q", peer["PublicKey"])
	}
	if peer["Endpoint"] != "192.168.1.10:51820" {
		t.Fatalf("endpoint: %q", peer["Endpoint"])
	}
	gotAllowed := strings.Split(peer["AllowedIPs"], ", ")
	want := map[string]bool{"10.99.0.0/16": true, "192.168.50.0/24": true}
	if len(gotAllowed) != len(want) {
		t.Fatalf("allowedips must contain exactly cidr+valid routes: %v", gotAllowed)
	}
	for _, a := range gotAllowed {
		if !want[a] {
			t.Fatalf("unexpected allowedip %q (bogus leaked?)", a)
		}
	}
	if peer["PersistentKeepalive"] != "25" {
		t.Fatalf("keepalive: %q", peer["PersistentKeepalive"])
	}
}

func TestExportConfRejects(t *testing.T) {
	d := NewDeriver("k")
	cidr := mustCIDR(t, "10.99.0.0/16")

	if _, err := ExportConf(ExportConfInput{Deriver: d, CIDR: cidr, LocalName: "a", RemoteName: "a", Endpoint: "1.2.3.4:5"}); err == nil {
		t.Fatal("remote==local must fail")
	}
	if _, err := ExportConf(ExportConfInput{Deriver: d, CIDR: cidr, LocalName: "a", RemoteName: "UPPER_case!", Endpoint: "1.2.3.4:5"}); err == nil {
		t.Fatal("invalid remote name must fail")
	}
	if _, err := ExportConf(ExportConfInput{Deriver: d, CIDR: cidr, LocalName: "a", RemoteName: "ok", Endpoint: "no-port"}); err == nil {
		t.Fatal("endpoint without port must fail")
	}
}
