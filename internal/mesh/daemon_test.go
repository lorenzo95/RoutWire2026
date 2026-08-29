package mesh

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
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
	theirs := []Candidate{hostC("192.168.1.99:51820"), srflxC("198.51.100.9:55555"), hostC("8.8.8.9:51820")}
	got := OrderEndpoints(mine, theirs)
	if got[0].Type != CandSRFLX {
		t.Fatalf("different sites must try reflexive first, got %+v", got)
	}
	for _, c := range got {
		if c.Type == CandHost && c.Addr == "192.168.1.99:51820" {
			t.Fatalf("private foreign host candidate must be dropped across sites, got %+v", got)
		}
		if got[0].Type != CandSRFLX && c.Addr == "8.8.8.9:51820" {
			t.Fatalf("public host must rank after reflexive, got %+v", got)
		}
	}
	if len(got) != 2 {
		t.Fatalf("want srflx + public host only (2), got %+v", got)
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
		srflxC("203.0.113.7:55555"),
		hostC("192.168.1.20:51820"),
	}
	got := OrderEndpoints(mine, theirs)
	if len(got) != len(theirs) {
		t.Fatalf("same-NAT ordering must not drop candidates: got %d want %d", len(got), len(theirs))
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
	fwd      int
	added    []string
	removed  []string
	announce []string
}

func (n *recRouter) Forwarding() error        { n.fwd++; return nil }
func (n *recRouter) AddSource(ip net.IP) error { n.added = append(n.added, ip.String()); return nil }
func (n *recRouter) AnnounceNAT(overlay *net.IPNet, subnets []net.IPNet) error {
	n.announce = append(n.announce, overlay.String()+" "+fmt.Sprint(subnets))
	return nil
}
func (n *recRouter) EnsurePort() error {
	return nil
}
func (n *recRouter) RemoveSource(ip net.IP) error {
	n.removed = append(n.removed, ip.String())
	return nil
}
func (n *recRouter) Close() error { return nil }

// A node that announces subnets must reconcile masquerade rules so overlay
// visitors can reach LAN devices that cannot route overlay addresses back.
func TestSyncNatReconcilesAnnounceMasquerade(t *testing.T) {
	store := engine.NewReliable(engine.NewMockStore(10*time.Minute, time.Now))
	n := &recRouter{}
	dm, _ := newTestDaemon(t, "alpha", store, NewFakeDevice())
	dm.router = n
	dm.cfg.Announce = []string{"192.168.1.0/24"}

	dm.syncNat()

	if len(n.announce) == 0 {
		t.Fatal("syncNat must reconcile announce masquerade rules")
	}
	if !strings.Contains(n.announce[0], "10.99.0.0/16") || !strings.Contains(n.announce[0], "192.168.1.0") {
		t.Fatalf("announce nat must masquerade the overlay into the announced subnet, got %v", n.announce)
	}

	// Dropping the announcement removes the rule.
	dm.cfg.Announce = nil
	dm.syncNat()
	if !strings.Contains(n.announce[len(n.announce)-1], "[]") {
		t.Fatalf("empty announcements must reconcile to no rules, got %v", n.announce)
	}
}

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

func TestOrderedForPrependsObserved(t *testing.T) {
	store := engine.NewReliable(engine.NewMockStore(10*time.Minute, time.Now))
	dev := NewFakeDevice()
	alpha, d := newTestDaemon(t, "alpha", store, dev)
	betaPub := pubKeyOf(t, d, "beta")
	rec := &Record{
		Name: "beta",
		Candidates: []Candidate{
			srflxC("198.51.100.9:55555"),
			hostC("192.168.1.99:51820"), // foreign private host — must be dropped
		},
	}
	mine := []Candidate{hostC("192.168.1.10:51820"), srflxC("203.0.113.7:40000")}

	obsEP, _ := net.ResolveUDPAddr("udp", "172.219.208.229:48000")
	dev.SetObserved(betaPub, obsEP)

	order := alpha.orderedFor(betaPub, mine, rec)
	if len(order) == 0 || order[0].Type != CandPRFLX {
		t.Fatalf("observed endpoint must be the first (prflx) candidate, got %+v", order)
	}
	if order[0].Addr != "172.219.208.229:48000" {
		t.Fatalf("wrong observed addr: %+v", order[0])
	}
	foundSrflx := false
	for _, c := range order[1:] {
		if c.Addr == "192.168.1.99:51820" {
			t.Fatalf("private foreign host must be dropped across sites, got %+v", order)
		}
		if c.Type == CandSRFLX {
			foundSrflx = true
		}
	}
	if !foundSrflx {
		t.Fatalf("advertised srflx must remain dialable, got %+v", order)
	}
}

func TestTickPreservesFreshObservedWinner(t *testing.T) {
	store := engine.NewReliable(engine.NewMockStore(10*time.Minute, time.Now))
	dev := NewFakeDevice()
	alpha, d := newTestDaemon(t, "alpha", store, dev)
	betaPub := pubKeyOf(t, d, "beta")
	obsAddr := "198.51.100.9:60000" // public observed endpoint

	publishBeta(t, alpha, d, []Candidate{srflxC("198.51.100.9:55555")})
	obsEP, _ := net.ResolveUDPAddr("udp", obsAddr)
	dev.SetObserved(betaPub, obsEP)
	dev.Reachable = func(ep *net.UDPAddr) bool { return ep != nil && ep.String() == obsAddr }
	alpha.probe = func(net.IP, int) { dev.Traffic(betaPub) }

	ctx := context.Background()
	if err := alpha.Setup(); err != nil {
		t.Fatal(err)
	}
	if err := alpha.Tick(ctx); err != nil {
		t.Fatalf("tick: %v", err)
	}
	if alpha.lastGood["beta"].Addr != obsAddr {
		t.Fatalf("expected observed endpoint to win the race, got %+v", alpha.lastGood["beta"])
	}
	applies := dev.Applies()

	// A keepalive keeps the handshake fresh; the next tick must preserve the
	// observed winner instead of flapping back to the advertised candidate.
	if err := alpha.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if dev.Applies() > applies+1 {
		t.Fatalf("fresh observed winner must be preserved (one idempotent apply), saw %d", dev.Applies()-applies)
	}
}

func TestTickCreditsKernelEndpointAfterHandshake(t *testing.T) {
	store := engine.NewReliable(engine.NewMockStore(10*time.Minute, time.Now))
	dev := NewFakeDevice()
	alpha, d := newTestDaemon(t, "alpha", store, dev)
	betaPub := pubKeyOf(t, d, "beta")
	dialed := "198.51.100.9:55555" // advertised candidate we dial
	roamed := "198.51.100.9:60000" // where the peer actually is

	publishBeta(t, alpha, d, []Candidate{srflxC(dialed)})
	roamedEP, _ := net.ResolveUDPAddr("udp", roamed)
	// The handshake completes because the peer's own traffic arrives — not
	// because our dial worked — and WireGuard roams to the peer's true
	// source. Simulate that roam at the moment traffic lands: write the
	// observed map directly, since Traffic holds the fake's mutex (a
	// re-entrant SetObserved here would deadlock) and the roam must be
	// recorded before the handshake timestamp for determinism.
	dev.Reachable = func(*net.UDPAddr) bool {
		dev.observed[betaPub] = roamedEP
		return true
	}
	alpha.probe = func(net.IP, int) { dev.Traffic(betaPub) }

	ctx := context.Background()
	if err := alpha.Setup(); err != nil {
		t.Fatal(err)
	}
	if err := alpha.Tick(ctx); err != nil {
		t.Fatalf("tick: %v", err)
	}
	if alpha.lastGood["beta"].Addr != roamed {
		t.Fatalf("winner must be the kernel-roamed endpoint %s, got %+v", roamed, alpha.lastGood["beta"])
	}
}

func TestTickAdoptsKernelEndpointForLiveSession(t *testing.T) {
	store := engine.NewReliable(engine.NewMockStore(10*time.Minute, time.Now))
	dev := NewFakeDevice()
	alpha, d := newTestDaemon(t, "alpha", store, dev)
	betaPub := pubKeyOf(t, d, "beta")
	live := "198.51.100.9:60000"

	publishBeta(t, alpha, d, []Candidate{srflxC("198.51.100.9:55555")})
	liveEP, _ := net.ResolveUDPAddr("udp", live)
	// A live session predates this process (daemon restart): the handshake is
	// fresh and the kernel tracks the working endpoint, but lastGood is empty.
	dev.SetHandshake(betaPub, time.Now())
	dev.SetObserved(betaPub, liveEP)
	// If meshd raced anyway, the probe would produce no handshake (nothing is
	// Reachable) and it would exhaust — a second Apply per candidate. Adoption
	// must skip racing entirely: exactly one (idempotent) Apply.
	dev.Reachable = func(*net.UDPAddr) bool { return false }

	ctx := context.Background()
	if err := alpha.Setup(); err != nil {
		t.Fatal(err)
	}
	if err := alpha.Tick(ctx); err != nil {
		t.Fatalf("tick: %v", err)
	}
	if alpha.lastGood["beta"].Addr != live {
		t.Fatalf("live session must adopt the kernel endpoint %s, got %+v", live, alpha.lastGood["beta"])
	}
	if dev.Applies() != 1 {
		t.Fatalf("live session must not be re-raced (1 apply expected), saw %d", dev.Applies())
	}
}

func TestTickDoesNotClobberRoamedEndpointOfLiveSession(t *testing.T) {
	store := engine.NewReliable(engine.NewMockStore(10*time.Minute, time.Now))
	dev := NewFakeDevice()
	alpha, d := newTestDaemon(t, "alpha", store, dev)
	betaPub := pubKeyOf(t, d, "beta")

	publishBeta(t, alpha, d, []Candidate{srflxC("198.51.100.9:55555")})
	dev.Reachable = func(*net.UDPAddr) bool { return true }
	alpha.probe = func(net.IP, int) { dev.Traffic(betaPub) }

	ctx := context.Background()
	if err := alpha.Setup(); err != nil {
		t.Fatal(err)
	}
	if err := alpha.Tick(ctx); err != nil {
		t.Fatalf("tick 1: %v", err)
	}

	// The peer then roams: WireGuard tracks a fresher source than our last
	// recorded winner. A live session owns its endpoint — the idempotent
	// Apply must omit it (nil = leave unchanged), never re-assert the winner.
	newEP, _ := net.ResolveUDPAddr("udp", "198.51.100.9:60000")
	dev.SetObserved(betaPub, newEP)
	if err := alpha.Tick(ctx); err != nil {
		t.Fatalf("tick 2: %v", err)
	}
	last := dev.History[len(dev.History)-1]
	for _, p := range last {
		if p.Name == "beta" && p.Endpoint != nil {
			t.Fatalf("live session endpoint must not be re-asserted (kernel roams), got %s", p.Endpoint)
		}
	}
}

func TestOrderedForDedupesObservedByAddr(t *testing.T) {
	store := engine.NewReliable(engine.NewMockStore(10*time.Minute, time.Now))
	dev := NewFakeDevice()
	alpha, d := newTestDaemon(t, "alpha", store, dev)
	betaPub := pubKeyOf(t, d, "beta")
	same := "198.51.100.9:55555" // observed == advertised

	rec := &Record{Name: "beta", Candidates: []Candidate{srflxC(same)}}
	mine := []Candidate{srflxC("203.0.113.7:40000")}
	obsEP, _ := net.ResolveUDPAddr("udp", same)
	dev.SetObserved(betaPub, obsEP)

	order := alpha.orderedFor(betaPub, mine, rec)
	count := 0
	for _, c := range order {
		if c.Addr == same {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("observed addr equal to advertised must be dialed once, got %d: %+v", count, order)
	}
}

func TestOrderedForGatesPrivateObserved(t *testing.T) {
	store := engine.NewReliable(engine.NewMockStore(10*time.Minute, time.Now))
	dev := NewFakeDevice()
	alpha, d := newTestDaemon(t, "alpha", store, dev)
	betaPub := pubKeyOf(t, d, "beta")
	privAddr := "192.168.1.50:51820"
	priv, _ := net.ResolveUDPAddr("udp", privAddr)
	mine := []Candidate{srflxC("203.0.113.7:40000")}

	// Cross-site: a LAN observation from the peer's past visit must not be
	// dialed — it addresses our own private space now.
	cross := &Record{Name: "beta", Candidates: []Candidate{srflxC("198.51.100.9:55555")}}
	dev.SetObserved(betaPub, priv)
	order := alpha.orderedFor(betaPub, mine, cross)
	for _, c := range order {
		if c.Addr == privAddr {
			t.Fatalf("private observed endpoint must be dropped across sites, got %+v", order)
		}
	}

	// Shared edge: the LAN observation IS the fast path (vm1<->vm2 case).
	shared := &Record{Name: "beta", Candidates: []Candidate{srflxC("203.0.113.7:55555")}}
	order = alpha.orderedFor(betaPub, mine, shared)
	if len(order) == 0 || order[0].Type != CandPRFLX || order[0].Addr != privAddr {
		t.Fatalf("private observed endpoint must lead the race on a shared edge, got %+v", order)
	}
}
