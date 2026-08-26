//go:build linux

package mesh

import (
	"net"
	"strings"
	"testing"
	"time"
)

func TestLinuxDeviceSetupApplyHandshake(t *testing.T) {
	ld, err := NewLinuxDevice("wgmesh-test0")
	if err != nil {
		t.Skipf("wgctrl unavailable: %v", err)
	}
	defer func() {
		_ = ld.Delete()
		_ = ld.Close()
	}()

	d := mustDeriver(t, testPSK)
	key, err := d.NodeWGKey("alpha")
	if err != nil {
		t.Fatal(err)
	}
	_, cidr, _ := net.ParseCIDR(testCIDR)
	ip, err := d.OverlayIP("alpha", cidr)
	if err != nil {
		t.Fatal(err)
	}
	addr := &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}

	if err := ld.Setup(key, 45820, 1420, addr, cidr); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "permission") || strings.Contains(err.Error(), "not permitted") {
			t.Skipf("no netlink privileges in this environment: %v", err)
		}
		t.Fatalf("setup: %v", err)
	}

	betaKey, err := d.NodeWGKey("beta")
	if err != nil {
		t.Fatal(err)
	}
	betaIP, err := d.OverlayIP("beta", cidr)
	if err != nil {
		t.Fatal(err)
	}
	desire := PeerDesire{
		Name:      "beta",
		Pub:       betaKey,
		Endpoint:  &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 51820},
		AllowedIPs: []net.IPNet{{IP: betaIP, Mask: net.CIDRMask(32, 32)}},
		Keepalive: 25 * time.Second,
	}
	if err := ld.Apply([]PeerDesire{desire}); err != nil {
		t.Fatalf("apply: %v", err)
	}

	clDev, err := ld.cl.Device("wgmesh-test0")
	if err != nil {
		t.Fatal(err)
	}
	if clDev.ListenPort != 45820 {
		t.Fatalf("listen port = %d, want 45820", clDev.ListenPort)
	}
	if len(clDev.Peers) != 1 || clDev.Peers[0].PublicKey != betaKey {
		t.Fatalf("peer not applied correctly: %+v", clDev.Peers)
	}
	ep := clDev.Peers[0].Endpoint
	if ep == nil || ep.String() != "192.0.2.10:51820" {
		t.Fatalf("endpoint not applied: %+v", ep)
	}
	if got := ld.Handshake(betaKey); !got.IsZero() {
		t.Fatalf("fresh peer must have zero handshake, got %v", got)
	}

	if err := ld.Apply(nil); err != nil {
		t.Fatalf("apply empty: %v", err)
	}
	clDev, err = ld.cl.Device("wgmesh-test0")
	if err != nil {
		t.Fatal(err)
	}
	if len(clDev.Peers) != 0 {
		t.Fatal("ReplacePeers semantics violated: peers survived empty apply")
	}
}
