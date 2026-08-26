package mesh

import (
	"context"
	"net"
	"testing"
	"time"

	"routewire/internal/engine"
)

func TestE2EAnnouncedSubnetsReachPeer(t *testing.T) {
	store := engine.NewReliable(engine.NewMockStore(30*time.Minute, time.Now))
	devA, devB := NewFakeDevice(), NewFakeDevice()

	alpha, dA := newNamedDaemon(t, "alpha", "192.168.1.10:51820", store, devA)
	beta, _ := newNamedDaemon(t, "beta", "192.168.1.20:51820", store, devB)

	alpha.cfg.Announce = []string{"192.168.50.0/24", "not a cidr", "10.55.0.0/16"}

	betaPub := pubKeyOf(t, dA, "beta")
	alphaPub := pubKeyOf(t, dA, "alpha")
	lan := map[string]bool{"192.168.1.10:51820": true, "192.168.1.20:51820": true}
	reach := func(ep *net.UDPAddr) bool { return ep != nil && lan[ep.String()] }
	devA.Reachable = reach
	devB.Reachable = reach
	alpha.probe = func(net.IP, int) { devA.Traffic(betaPub) }
	beta.probe = func(net.IP, int) { devB.Traffic(alphaPub) }

	ctx := context.Background()
	for _, dm := range []*Daemon{alpha, beta} {
		if err := dm.Setup(); err != nil {
			t.Fatal(err)
		}
		if err := dm.Tick(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if err := alpha.Tick(ctx); err != nil {
		t.Fatal(err)
	}

	want := map[string]bool{"192.168.50.0/24": true, "10.55.0.0/16": true}
	gotRoutes := map[string]bool{}
	for i := range devB.Routes {
		gotRoutes[devB.Routes[i].String()] = true
	}
	for cidr := range want {
		if !gotRoutes[cidr] {
			t.Fatalf("beta missing route for announced %s (routes: %v)", cidr, devB.Routes)
		}
	}
	if gotRoutes["not a cidr"] || len(devB.Routes) != len(want) {
		t.Fatalf("route set wrong: %v", devB.Routes)
	}

	var alphaState []PeerDesire
	if len(devB.History) > 0 {
		alphaState = lastDesiresFor(devB, "alpha")
	}
	found := false
	for _, ipn := range alphaState[0].AllowedIPs {
		if ipn.String() == "10.55.0.0/16" {
			found = true
		}
	}
	if !found {
		t.Fatalf("beta's AllowedIPs for alpha must include alpha's announcement: %v", alphaState[0].AllowedIPs)
	}

	overlayIP, _ := dA.OverlayIP("alpha", beta.cfg.CIDR)
	hasOverlay := false
	for _, ipn := range alphaState[0].AllowedIPs {
		if ipn.IP.Equal(overlayIP) && oneIP(ipn) {
			hasOverlay = true
		}
	}
	if !hasOverlay {
		t.Fatalf("overlay /32 must stay in AllowedIPs: %v", alphaState[0].AllowedIPs)
	}
}

func lastDesiresFor(dev *FakeDevice, name string) []PeerDesire {
	last := dev.History[len(dev.History)-1]
	var out []PeerDesire
	for _, p := range last {
		if p.Name == name {
			out = append(out, p)
		}
	}
	return out
}

func oneIP(ipn net.IPNet) bool {
	ones, bits := ipn.Mask.Size()
	return bits == 32 && ones == 32
}
