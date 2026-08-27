package mesh

import (
	"context"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"routewire/internal/engine"
)

type Config struct {
	Name        string
	IFace       string
	CIDR        *net.IPNet
	Port        int
	MTU         int
	Poll        time.Duration
	StaleAfter  time.Duration
	StunServers []string
	StunTimeout time.Duration
	Announce    []string // extra subnets this node serves, e.g. "192.168.50.0/24"
	Router      Router   // kernel routing/firewall integration (nil = disabled)
	SpokesFile  string   // path to the persisted spoke set ("" = in-memory only)
}

// Daemon ties derivation, roster, candidate gathering, and device control
// into one reconcile loop.
type Daemon struct {
	cfg      Config
	d        *Deriver
	id       *engine.Identity
	key      wgtypes.Key
	myIP     net.IP
	store    *engine.ReliableStore
	dev      Device
	router   Router
	spokeSrc map[string]net.IP
	spokes   map[string]bool
	fwdWarned bool
	log      *log.Logger
	seq      uint64
	lastGood map[string]Candidate

	gatherLocal func(port int) []Candidate
	gatherSRFLX func(ctx context.Context) []Candidate
	probe       func(peerIP net.IP, port int)
	racePoll    time.Duration
	raceWait    time.Duration
}

func NewDaemon(cfg Config, d *Deriver, store *engine.ReliableStore, dev Device, logger *log.Logger) (*Daemon, error) {
	if cfg.IFace == "" {
		cfg.IFace = "wgmesh0"
	}
	if cfg.Port == 0 {
		cfg.Port = 51820
	}
	if cfg.MTU == 0 {
		cfg.MTU = 1420
	}
	if cfg.Poll <= 0 {
		cfg.Poll = 15 * time.Second
	}
	if cfg.StaleAfter <= 0 {
		cfg.StaleAfter = 180 * time.Second
	}
	if cfg.StunTimeout <= 0 {
		cfg.StunTimeout = 800 * time.Millisecond
	}
	if logger == nil {
		logger = log.Default()
	}
	name := NormalizeName(cfg.Name)
	if err := ValidateName(name); err != nil {
		return nil, err
	}
	cfg.Name = name

	key, err := d.NodeWGKey(name)
	if err != nil {
		return nil, err
	}
	id, err := d.NodeIdentity(name)
	if err != nil {
		return nil, err
	}
	ip, err := d.OverlayIP(name, cfg.CIDR)
	if err != nil {
		return nil, err
	}
	spokes, err := LoadSpokes(cfg.SpokesFile)
	if err != nil {
		logger.Printf("spokes: load %s: %v", cfg.SpokesFile, err)
		spokes = map[string]bool{}
	}
	dm := &Daemon{
		cfg: cfg, d: d, id: id, key: key, myIP: ip,
		store: store, dev: dev, log: logger,
		router:      cfg.Router,
		spokeSrc:    make(map[string]net.IP),
		spokes:      spokes,
		seq:         uint64(time.Now().UnixNano()),
		lastGood:    make(map[string]Candidate),
	}
	if dm.router == nil {
		dm.router = noopRouter{}
	}
	dm.gatherLocal = func(port int) []Candidate { return LocalCandidates(port) }
	dm.gatherSRFLX = func(ctx context.Context) []Candidate {
		return GatherSRFLX(ctx, cfg.StunServers, cfg.StunTimeout)
	}
	dm.probe = probeUDP
	dm.racePoll = 150 * time.Millisecond
	dm.raceWait = 2500 * time.Millisecond
	return dm, nil
}

func (dm *Daemon) OverlayAddr() *net.IPNet {
	return &net.IPNet{IP: dm.myIP, Mask: net.CIDRMask(32, 32)}
}

func (dm *Daemon) Setup() error {
	if err := dm.dev.Setup(dm.key, dm.cfg.Port, dm.cfg.MTU, dm.OverlayAddr(), dm.cfg.CIDR); err != nil {
		return err
	}
	if len(dm.cfg.Announce) > 0 {
		if err := dm.router.Forwarding(); err != nil {
			dm.log.Printf("forwarding: %v", err)
		}
	}
	return nil
}

// Name returns the normalized node name.
func (dm *Daemon) Name() string { return dm.cfg.Name }

// Run drives Tick at cfg.Poll until ctx is cancelled.
func (dm *Daemon) Run(ctx context.Context) {
	ticker := time.NewTicker(dm.cfg.Poll)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := dm.Tick(ctx); err != nil {
				dm.log.Printf("tick: %v", err)
			}
		}
	}
}

// nextSeq returns a monotonically increasing sequence number that survives
// process restarts: the first value in a process's life is the current unix
// time, so records published after a restart always beat stale values still
// living in the DHT from previous runs (whose seqs started at small counts).
func (dm *Daemon) nextSeq() uint64 {
	if dm.seq == 0 {
		dm.seq = uint64(time.Now().Unix())
	}
	dm.seq++
	return dm.seq
}

type peerPlan struct {
	name     string
	rec      *Record
	pub      wgtypes.Key
	desire   PeerDesire
	ordered  []Candidate
	winner   Candidate
	haveWin  bool
	freshNow bool
}

// Tick runs one full reconcile pass: announce, learn, converge endpoints.
func (dm *Daemon) Tick(ctx context.Context) error {
	dm.reloadSpokes()

	mine := append(
		dm.gatherLocal(dm.cfg.Port),
		dm.gatherSRFLX(ctx)...,
	)
	rec := &Record{
		Name:       dm.cfg.Name,
		IP:         dm.myIP.String(),
		Port:       dm.cfg.Port,
		Candidates: mine,
		Adv:        dm.cfg.Announce,
		TS:         time.Now().Unix(),
		Seq:        dm.nextSeq(),
	}
	if err := rec.Sign(dm.id); err != nil {
		return fmt.Errorf("sign record: %w", err)
	}
	sealed, err := sealRecord(dm.d, rec)
	if err != nil {
		return err
	}
	if err := dm.store.Publish(ctx, dm.d.RosterKey(), sealed); err != nil {
		dm.log.Printf("publish failed (continuing): %v", err)
	}

	plans, err := dm.buildPlans(ctx, mine)
	if err != nil {
		return err
	}

	state := make([]PeerDesire, 0, len(plans))
	for i := range plans {
		pickInitial(&plans[i])
		state = append(state, plans[i].desire)
	}
	for i := range plans {
		plans[i].freshNow = time.Since(dm.dev.Handshake(plans[i].pub)) < dm.cfg.StaleAfter
	}
	if err := dm.dev.Apply(state); err != nil {
		return fmt.Errorf("apply: %w", err)
	}

	for i := range plans {
		p := &plans[i]
		if p.freshNow {
			if !p.haveWin {
				// A live session we can't account for (daemon restart, or
				// the peer roamed in on its own): adopt the kernel's tracked
				// endpoint as the winner instead of re-racing — racing a
				// working session only churns endpoints and log noise.
				if ep := dm.dev.Endpoint(p.pub); ep != nil && ep.IP != nil {
					win := Candidate{Type: CandPRFLX, Addr: ep.String()}
					dm.lastGood[p.name] = win
					p.winner, p.haveWin = win, true
					p.desire.Endpoint = ep
					dm.log.Printf("peer %s: adopted live session via %s", p.name, win.Addr)
				}
			}
			// A live, freshly-handshaken winner — even one observed from the
			// peer's own traffic (not advertised) — is left undisturbed so we
			// never flap back to a stale advertised candidate.
			continue
		}
		won := false
		for _, cand := range p.ordered {
			ep, err := net.ResolveUDPAddr("udp", cand.Addr)
			if err != nil {
				continue
			}
			p.desire.Endpoint = ep
			if err := dm.dev.Apply(stateWith(plans, i, p.desire)); err != nil {
				dm.log.Printf("peer %s: apply: %v", p.name, err)
				break
			}
			if dm.tryConnect(p.pub, dm.overlayIPFor(p.name), p.rec.Port) {
				// The handshake proves reachability but not which dial caused
				// it: the peer's own racing can complete one too, and
				// WireGuard roams to the source of authenticated traffic. The
				// kernel's current endpoint is the authoritative path —
				// credit that when it disagrees with the dialed candidate.
				win := cand
				if ep := dm.dev.Endpoint(p.pub); ep != nil && ep.IP != nil && ep.String() != cand.Addr {
					win = Candidate{Type: CandPRFLX, Addr: ep.String()}
					p.desire.Endpoint = ep
				}
				dm.lastGood[p.name] = win
				p.winner, p.haveWin = win, true
				dm.log.Printf("peer %s: converged via %s %s", p.name, win.Type, win.Addr)
				won = true
				break
			}
			dm.log.Printf("peer %s: no handshake via %s %s", p.name, cand.Type, cand.Addr)
		}
		if !won && len(p.ordered) > 0 {
			dm.lastGood[p.name] = Candidate{}
			dm.log.Printf("peer %s: exhausted %d candidates", p.name, len(p.ordered))
		}
	}

	var announced []string
	for i := range plans {
		announced = append(announced, plans[i].rec.Adv...)
	}
	if len(announced) > 0 {
		if err := dm.dev.ApplyRoutes(parseCIDRs(announced)); err != nil {
			dm.log.Printf("routes: %v", err)
		}
	}
	dm.syncNat()
	dm.evictStaleSpokes()
	return nil
}

// reloadSpokes re-reads the persisted spoke set every tick: `export` writes it
// from a separate process, so this is how the running hub picks up new spokes
// (and drops ones evicted elsewhere).
func (dm *Daemon) reloadSpokes() {
	if dm.cfg.SpokesFile == "" {
		return
	}
	set, err := LoadSpokes(dm.cfg.SpokesFile)
	if err != nil {
		dm.log.Printf("spokes: reload: %v", err)
		return
	}
	dm.spokes = set
}

// evictStaleSpokes drops a spoke once it has connected and then gone quiet for
// longer than the eviction window, and persists the change. A spoke that never
// connected is left alone (its phone may still arrive).
func (dm *Daemon) evictStaleSpokes() {
	changed := false
	for name := range dm.spokes {
		pub, err := dm.d.NodeWGPubKey(name)
		if err != nil {
			continue
		}
		hs := dm.dev.Handshake(pub)
		if hs.IsZero() || time.Since(hs) < dm.spokeEvictAfter() {
			continue
		}
		delete(dm.spokes, name)
		changed = true
		dm.log.Printf("spoke %s: stale (last handshake %s ago) — dropped", name, time.Since(hs).Round(time.Second))
	}
	if changed && dm.cfg.SpokesFile != "" {
		if err := SaveSpokes(dm.cfg.SpokesFile, dm.spokes); err != nil {
			dm.log.Printf("spokes: save: %v", err)
		}
	}
}

func (dm *Daemon) spokeEvictAfter() time.Duration {
	if dm.cfg.StaleAfter > 0 {
		return 3 * dm.cfg.StaleAfter
	}
	return 9 * time.Minute
}

// syncNat keeps masquerade rules in step with the spoke set: our spokes get a
// source-NAT rule so the mesh can reply to them; departed spokes are removed.
func (dm *Daemon) syncNat() {
	if !dm.fwdWarned {
		if err := dm.router.Forwarding(); err != nil {
			dm.log.Printf("router: enable forwarding: %v (spoke NAT needs it; enable net.ipv4.ip_forward=1 on the HOST — containers mount /proc/sys read-only)", err)
		}
		dm.fwdWarned = true
	}
	want := make(map[string]net.IP)
	for name := range dm.spokes {
		if ip, err := dm.d.OverlayIP(name, dm.cfg.CIDR); err == nil {
			want[name] = ip
		}
	}
	for name := range dm.spokeSrc {
		if _, ok := want[name]; !ok {
			_ = dm.router.RemoveSource(dm.spokeSrc[name])
			delete(dm.spokeSrc, name)
		}
	}
	for name, ip := range want {
		if _, ok := dm.spokeSrc[name]; ok {
			continue
		}
		if err := dm.router.AddSource(ip); err != nil {
			dm.log.Printf("nat %s: %v", name, err)
			continue
		}
		dm.spokeSrc[name] = ip
	}
}

// allowedIPsFor parses a record's announced subnets; invalid entries are
// skipped silently (records are untrusted-ish input).
func allowedIPsFor(rec *Record) []net.IPNet {
	return parseCIDRs(rec.Adv)
}

// ParseCIDRs validates a list of CIDR strings, dropping junk and duplicates.
func ParseCIDRs(ss []string) []net.IPNet {
	return parseCIDRs(ss)
}

func parseCIDRs(ss []string) []net.IPNet {
	var out []net.IPNet
	seen := map[string]bool{}
	for _, s := range ss {
		_, ipnet, err := net.ParseCIDR(strings.TrimSpace(s))
		if err != nil || seen[ipnet.String()] {
			continue
		}
		seen[ipnet.String()] = true
		out = append(out, *ipnet)
	}
	return out
}

func (dm *Daemon) buildPlans(ctx context.Context, mine []Candidate) ([]peerPlan, error) {
	roster, err := NewRoster(dm.d, dm.cfg.Name, dm.store, dm.cfg.CIDR)
	if err != nil {
		return nil, err
	}
	peers, err := roster.FetchStable(ctx, 3, 400*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("fetch roster: %w", err)
	}
	var plans []peerPlan
	for _, name := range Names(peers) {
		rec := peers[name]
		pubKey, err := dm.d.NodeWGPubKey(name)
		if err != nil {
			continue
		}
		allowed, err := dm.d.OverlayIPNet(name, dm.cfg.CIDR)
		if err != nil {
			continue
		}
		plans = append(plans, peerPlan{
			name: name,
			rec:  rec,
			pub:  pubKey,
			desire: PeerDesire{
				Name:       name,
				Pub:        pubKey,
				AllowedIPs: append(allowedIPsFor(rec), *allowed),
				Keepalive:  25 * time.Second,
			},
		ordered: dm.orderedFor(pubKey, mine, rec),
		winner:  dm.lastGood[name],
		haveWin: dm.lastGood[name].Addr != "",
	})
	}
	// Spokes live only on this hub (see syncNat): no roster record, but they
	// still need a WireGuard peer so the phone's roaming handshake can land.
	for name := range dm.spokes {
		if _, ok := peers[name]; ok {
			continue
		}
		pubKey, err := dm.d.NodeWGPubKey(name)
		if err != nil {
			continue
		}
		allowed, err := dm.d.OverlayIPNet(name, dm.cfg.CIDR)
		if err != nil {
			continue
		}
		plans = append(plans, peerPlan{
			name: name,
			rec:  &Record{Name: name, IP: allowed.IP.String(), Port: 0},
			pub:  pubKey,
			desire: PeerDesire{
				Name:       name,
				Pub:        pubKey,
				AllowedIPs: []net.IPNet{*allowed},
				Keepalive:  25 * time.Second,
			},
		})
	}
	return plans, nil
}

func pickInitial(p *peerPlan) {
	if p.haveWin {
		p.desire.Endpoint = udpAddrOf(p.winner)
		return
	}
	if len(p.ordered) > 0 {
		p.desire.Endpoint = udpAddrOf(p.ordered[0])
	}
}

// orderedFor builds a peer's dial order from its advertised candidates, then
// prepends the endpoint WireGuard has observed from the peer's own traffic
// (peer-reflexive) when it differs from what we'd otherwise dial. The observed
// address is the authoritative "where the peer actually is right now" — it
// survives symmetric NAT where an advertised srflx is only valid toward the
// STUN server.
func (dm *Daemon) orderedFor(pub wgtypes.Key, mine []Candidate, rec *Record) []Candidate {
	order := OrderEndpoints(mine, rec.Candidates)
	obs := dm.dev.Endpoint(pub)
	if obs == nil || obs.IP == nil || obs.IP.IsLinkLocalUnicast() {
		return order
	}
	obsCand := Candidate{Type: CandPRFLX, Addr: obs.String()}
	if containsAddr(order, obsCand.Addr) {
		return order
	}
	// A private observation is only meaningful inside a shared edge: a peer
	// that roamed to a LAN address while it was here and has since moved
	// sites would otherwise send us dialing our own private space.
	if mode, _ := sameNAT(mine, rec.Candidates); mode == modeDifferentSites && isPrivateCandidate(obsCand) {
		return order
	}
	return append([]Candidate{obsCand}, order...)
}

func stateWith(plans []peerPlan, i int, d PeerDesire) []PeerDesire {
	out := make([]PeerDesire, len(plans))
	for j := range plans {
		out[j] = plans[j].desire
	}
	out[i] = d
	return out
}

func (dm *Daemon) overlayIPFor(name string) net.IP {
	ip, _ := dm.d.OverlayIP(name, dm.cfg.CIDR)
	return ip
}

func udpAddrOf(c Candidate) *net.UDPAddr {
	a, _ := net.ResolveUDPAddr("udp", c.Addr)
	return a
}

// tryConnect pokes the tunnel to trigger a handshake and waits for one.
func (dm *Daemon) tryConnect(pub wgtypes.Key, peerIP net.IP, port int) bool {
	start := time.Now()
	go dm.probe(peerIP, port)
	for deadline := start.Add(dm.raceWait); time.Now().Before(deadline); {
		time.Sleep(dm.racePoll)
		if hs := dm.dev.Handshake(pub); hs.After(start) {
			return true
		}
	}
	return false
}

func probeUDP(peerIP net.IP, port int) {
	conn, err := net.DialTimeout("udp", net.JoinHostPort(peerIP.String(), strconv.Itoa(port)), time.Second)
	if err != nil {
		return
	}
	defer conn.Close()
	_, _ = conn.Write([]byte("routewire-probe"))
}
