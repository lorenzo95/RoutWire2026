package mesh

import (
	"context"
	"net"
	"testing"
	"time"

	"routewire/internal/engine"
)

// TestE2ETwoDaemonsConverge runs the full pipeline — derive, announce,
// discover, race, converge — for two in-process daemons sharing a MockStore.
func TestE2ETwoDaemonsConverge(t *testing.T) {
	store := engine.NewReliable(engine.NewMockStore(30*time.Minute, time.Now))
	devA, devB := NewFakeDevice(), NewFakeDevice()

	alpha, dA := newNamedDaemon(t, "alpha", "192.168.1.10:51820", store, devA)
	beta, _ := newNamedDaemon(t, "beta", "192.168.1.20:51820", store, devB)

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
	}
	if err := alpha.Tick(ctx); err != nil {
		t.Fatalf("alpha tick: %v", err)
	}
	if err := beta.Tick(ctx); err != nil {
		t.Fatalf("beta tick: %v", err)
	}
	if got := beta.lastGood["alpha"].Addr; got != "192.168.1.10:51820" {
		t.Fatalf("beta should converge on first sight of alpha, got %q", got)
	}
	if err := alpha.Tick(ctx); err != nil {
		t.Fatalf("alpha tick 2: %v", err)
	}

	if got := alpha.lastGood["beta"].Addr; got != "192.168.1.20:51820" {
		t.Fatalf("alpha should converge on beta's LAN candidate, got %q", got)
	}
	if got := beta.lastGood["alpha"].Addr; got != "192.168.1.10:51820" {
		t.Fatalf("beta should converge on alpha's LAN candidate, got %q", got)
	}
	if devA.Handshake(betaPub).IsZero() || devB.Handshake(alphaPub).IsZero() {
		t.Fatal("both sides must record handshakes")
	}

	appliesA, appliesB := devA.Applies(), devB.Applies()
	if err := alpha.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if err := beta.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if devA.Applies() != appliesA+1 || devB.Applies() != appliesB+1 {
		t.Fatalf("steady state must be one idempotent apply per tick (A +%d, B +%d)",
			devA.Applies()-appliesA, devB.Applies()-appliesB)
	}
}

func newNamedDaemon(t *testing.T, name, hostPort string, store *engine.ReliableStore, dev Device) (*Daemon, *Deriver) {
	t.Helper()
	d := mustDeriver(t, testPSK)
	cidrIP, cidrNet, _ := net.ParseCIDR(testCIDR)
	_ = cidrIP
	dm, err := NewDaemon(Config{
		Name: name,
		CIDR: cidrNet,
	}, d, store, dev, nil)
	if err != nil {
		t.Fatal(err)
	}
	dm.gatherLocal = func(int) []Candidate { return []Candidate{{Type: CandHost, Addr: hostPort}} }
	dm.racePoll = 5 * time.Millisecond
	dm.raceWait = 50 * time.Millisecond
	return dm, d
}
