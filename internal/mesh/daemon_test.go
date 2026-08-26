package mesh

import (
	"context"
	"io"
	"log"
	"net"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"routewire/internal/engine"
)

func hostC(addr string) Candidate  { return Candidate{Type: CandHost, Addr: addr} }
func srflxC(addr string) Candidate { return Candidate{Type: CandSRFLX, Addr: addr} }

func TestOrderEndpointsSameNAT(t *testing.T) {
	mine := []Candidate{hostC("192.168.1.10:51820"), srflxC("203.0.113.7:40000")}
	theirs := []Candidate{srflxC("203.0.113.7:50000"), hostC("192.168.1.20:51820")}
	got := OrderEndpoints(mine, theirs)
	if got[0].Type != CandHost || got[0].Addr != "192.168.1.20:51820" {
		t.Fatalf("same NAT must try LAN host first, got %+v", got)
	}
}

func TestOrderEndpointsDifferentSites(t *testing.T) {
	mine := []Candidate{hostC("192.168.1.10:51820"), srflxC("203.0.113.7:40000")}
	theirs := []Candidate{hostC("192.168.1.99:51820"), srflxC("198.51.100.9:55555")}
	got := OrderEndpoints(mine, theirs)
	if got[0].Type != CandSRFLX {
		t.Fatalf("different sites must try reflexive first, got %+v", got)
	}
	if got[len(got)-1].Addr != "192.168.1.99:51820" {
		t.Fatalf("foreign LAN hosts must rank last, got %+v", got)
	}
}

func TestOrderEndpointsUnknownFavorsLocal(t *testing.T) {
	mine := []Candidate{hostC("192.168.1.10:51820")}
	theirs := []Candidate{srflxC("198.51.100.9:55555"), hostC("192.168.1.20:51820")}
	got := OrderEndpoints(mine, theirs)
	if got[0].Type != CandHost {
		t.Fatalf("no srflx info anywhere → assume local, got %+v", got)
	}
}

func TestOrderEndpointsStableAndTotal(t *testing.T) {
	mine := []Candidate{hostC("10.0.0.1:1"), srflxC("203.0.113.7:40000")}
	theirs := []Candidate{
		hostC("192.168.1.21:51820"),
		srflxC("198.51.100.9:55555"),
		hostC("192.168.1.20:51820"),
	}
	got := OrderEndpoints(mine, theirs)
	if len(got) != len(theirs) {
		t.Fatal("ordering must not drop candidates")
	}
	for i := 1; i < len(got); i++ {
		if got[i-1].score > got[i].score {
			t.Fatalf("not sorted by score: %+v", got)
		}
	}
}

func newTestDaemon(t *testing.T, name string, store *engine.ReliableStore, dev Device) (*Daemon, *Deriver) {
	t.Helper()
	d := mustDeriver(t, testPSK)
	_, cidr, _ := net.ParseCIDR(testCIDR)
	dm, err := NewDaemon(Config{Name: name, CIDR: cidr}, d, store, dev, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	dm.probe = func(net.IP, int) {}
	dm.racePoll = 5 * time.Millisecond
	dm.raceWait = 50 * time.Millisecond
	return dm, d
}

func pubKeyOf(t *testing.T, d *Deriver, name string) wgtypes.Key {
	t.Helper()
	k, err := d.NodeWGPubKey(name)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func publishBeta(t *testing.T, alpha *Daemon, d *Deriver, cands []Candidate) {
	t.Helper()
	id, err := d.NodeIdentity("beta")
	if err != nil {
		t.Fatal(err)
	}
	ip, err := d.OverlayIP("beta", alpha.cfg.CIDR)
	if err != nil {
		t.Fatal(err)
	}
	rec := &Record{
		Name: "beta", IP: ip.String(), Port: 51820,
		Candidates: cands, TS: time.Now().Unix(), Seq: uint64(time.Now().UnixNano()),
	}
	if err := rec.Sign(id); err != nil {
		t.Fatal(err)
	}
	sealed, err := sealRecord(d, rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := alpha.store.Publish(context.Background(), alpha.d.RosterKey(), sealed); err != nil {
		t.Fatal(err)
	}
}

func TestTickRacesAndRemembersWinner(t *testing.T) {
	store := engine.NewReliable(engine.NewMockStore(10*time.Minute, time.Now))
	dev := NewFakeDevice()
	lanPeer := "192.168.77.20:51820"

	alpha, d := newTestDaemon(t, "alpha", store, dev)
	betaPub := pubKeyOf(t, d, "beta")
	publishBeta(t, alpha, d, []Candidate{srflxC("198.51.100.9:55555"), hostC(lanPeer)})
	dev.Reachable = func(ep *net.UDPAddr) bool { return ep != nil && ep.String() == lanPeer }
	alpha.probe = func(net.IP, int) { dev.Traffic(betaPub) }

	ctx := context.Background()
	if err := alpha.Setup(); err != nil {
		t.Fatal(err)
	}
	if err := alpha.Tick(ctx); err != nil {
		t.Fatalf("tick: %v", err)
	}

	if dev.Handshake(pubKeyOf(t, d, "beta")).IsZero() {
		t.Fatal("expected simulated handshake after racing")
	}
	if alpha.lastGood["beta"].Addr != lanPeer {
		t.Fatalf("winner should be the reachable LAN candidate, got %+v", alpha.lastGood["beta"])
	}

	appliesAfterRace := dev.Applies()
	if err := alpha.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if dev.Applies() != appliesAfterRace+1 {
		t.Fatalf("steady-state tick should be a single idempotent apply, saw %d", dev.Applies()-appliesAfterRace)
	}
}

type recRouter struct {
	fwd     int
	added   []string
	removed []string
}

func (n *recRouter) Forwarding() error        { n.fwd++; return nil }
func (n *recRouter) AddSource(ip net.IP) error { n.added = append(n.added, ip.String()); return nil }
func (n *recRouter) RemoveSource(ip net.IP) error {
	n.removed = append(n.removed, ip.String())
	return nil
}
func (n *recRouter) Close() error { return nil }

func TestSpokePeerAndNat(t *testing.T) {
	store := engine.NewReliable(engine.NewMockStore(10*time.Minute, time.Now))
	dm, d := newTestDaemon(t, "alpha", store, NewFakeDevice())
	n := &recRouter{}
	dm.router = n

	publishBeta(t, dm, d, []Candidate{hostC("192.168.77.20:51820")}) // a real agent
	dm.spokes["spoke-a"] = true                                        // our NAT'd spoke

	plans, err := dm.buildPlans(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, p := range plans {
		names[p.name] = true
		if p.name == "spoke-a" && len(p.ordered) != 0 {
			t.Fatal("spoke must be endpointless (no candidates to race)")
		}
	}
	if !names["beta"] || !names["spoke-a"] {
		t.Fatalf("agent and spoke must both be peers, got %v", names)
	}

	dm.syncNat()
	wantIP, _ := d.OverlayIP("spoke-a", dm.cfg.CIDR)
	if len(n.added) != 1 || n.added[0] != wantIP.String() {
		t.Fatalf("only the spoke should be NATed, got %v", n.added)
	}
}

func TestTickReracesWhenHandshakeGoesStale(t *testing.T) {
	store := engine.NewReliable(engine.NewMockStore(10*time.Minute, time.Now))
	dev := NewFakeDevice()

	alpha, d := newTestDaemon(t, "alpha", store, dev)
	betaPub := pubKeyOf(t, d, "beta")
	publishBeta(t, alpha, d, []Candidate{hostC("192.168.77.20:51820")})

	ctx := context.Background()
	dev.Reachable = func(*net.UDPAddr) bool { return true }
	alpha.probe = func(net.IP, int) { dev.Traffic(betaPub) }
	if err := alpha.Setup(); err != nil {
		t.Fatal(err)
	}
	if err := alpha.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	firstConvergence := dev.Applies()

	dev.Reachable = func(*net.UDPAddr) bool { return false }
	dev.SetHandshake(betaPub, time.Now().Add(-10*time.Minute))
	if err := alpha.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if dev.Applies() <= firstConvergence {
		t.Fatal("stale handshake must trigger re-racing attempts")
	}
	if alpha.lastGood["beta"].Addr != "" {
		t.Fatal("failed race must clear lastGood")
	}
}
