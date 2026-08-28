package mesh

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// ErrNoIptables is returned by NewLinuxRouter when the iptables binary is
// unavailable (e.g. minimal containers). Callers may fall back to a no-op
// router and manage firewall/forwarding on the host themselves.
var ErrNoIptables = errors.New("iptables executable not found")

// nftComment tags rules meshd inserts into foreign firewalls so operators can
// see why they exist and Close can find them again.
const nftComment = "routewire-meshd"

// iptComment is the iptables comment marking rules meshd owns (the v4
// analog of the nft userdata tag) so stop-cleanup can find them even when
// the config no longer mentions the announcement.
const iptComment = "routewire-meshd"

// Router integrates the daemon with kernel routing + firewall state that a
// mesh node needs beyond the WireGuard interface itself:
//
//   - IPv4 forwarding (to serve announced subnets and to NAT spokes),
//   - a firewall rule admitting WireGuard's UDP listen port, and
//   - per-spoke source-NAT so an agent-less device can be reached back.
//
// Everything added is tracked and removed on Close, and the prior forwarding
// value is restored.
type Router interface {
	// Forwarding enables net.ipv4.ip_forward (idempotent).
	Forwarding() error
	// AddSource ensures traffic from spoke/32 is masqueraded.
	AddSource(spoke net.IP) error
	// RemoveSource stops masquerading spoke/32.
	RemoveSource(spoke net.IP) error
	// AnnounceNAT reconciles source-NAT rules that masquerade overlay
	// visitors into announced subnets (whose devices cannot route back over
	// the overlay). Pass the current announcements every tick; rules for
	// dropped announcements are removed.
	AnnounceNAT(overlay *net.IPNet, subnets []net.IPNet) error
	// Close removes firewall + masquerade rules and restores forwarding.
	Close() error
}

// noopRouter is used when routing integration is disabled (dry-run, tests).
type noopRouter struct{}

func (noopRouter) Forwarding() error         { return nil }
func (noopRouter) AddSource(net.IP) error    { return nil }
func (noopRouter) RemoveSource(net.IP) error { return nil }
func (noopRouter) AnnounceNAT(*net.IPNet, []net.IPNet) error { return nil }
func (noopRouter) Close() error              { return nil }

// Package-level binary names so tests can shim them via PATH.
var (
	iptablesBin  = "iptables"
	ip6tablesBin = "ip6tables"
)

// linuxRouter implements Router with iptables + /proc/sys/net/ipv4/ip_forward.
type linuxRouter struct {
	iface        string
	port         int
	log          *log.Logger
	mu           sync.Mutex
	added        map[string]bool
	announceNAT  map[string]string
	fwdSet       bool
	fwdFixed     bool
	priorFwd     string
	hasIP6       bool
	taggedChains []*nftables.Chain
}

// nftRule is an accept we inserted into a foreign input-hook chain that would
// otherwise drop our listen port. Tagged with a routewire comment in the
// ruleset so operators can see why they exist; removed on Close.

// NewLinuxRouter opens the WireGuard UDP listen port in the firewall and
// prepares forwarding (enabled lazily via Forwarding). It must be called with
// the interface name the daemon manages. log (nil-tolerant) receives notices
// about foreign firewalls: chains that would drop the listen port get an
// accept inserted (tracked, removed on Close); chains meshd cannot open are
// reported as warnings.
func NewLinuxRouter(iface string, port int, log *log.Logger) (Router, error) {
	if iface == "" {
		return nil, fmt.Errorf("router: empty iface")
	}
	if port <= 0 {
		return nil, fmt.Errorf("router: invalid port %d", port)
	}
	prior, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if err != nil {
		return nil, fmt.Errorf("router: read ip_forward: %w", err)
	}
	if _, err := exec.LookPath(iptablesBin); err != nil {
		return noopRouter{}, fmt.Errorf("%w", ErrNoIptables)
	}
	r := &linuxRouter{
		iface:       iface,
		port:        port,
		log:         log,
		added:       make(map[string]bool),
		announceNAT: make(map[string]string),
		priorFwd:    strings.TrimSpace(string(prior)),
	}
	if _, err := exec.LookPath(ip6tablesBin); err == nil {
		r.hasIP6 = true
	}
	if err := r.openPort(); err != nil {
		return nil, fmt.Errorf("router: open port: %w", err)
	}
	r.remediateForeignDropChains(log, uint16(port))
	warnBlockedPort(log, port)
	return r, nil
}

// netfilter has no cross-chain exemption: an ACCEPT in one base chain does
// not carry past another chain's DROP at the same hook, and DROP is terminal.
// So a host firewall whose input hook has a drop policy that lacks our port
// will silently eat every inbound handshake no matter what meshd adds
// elsewhere — and nothing in wg's counters admits to it. The only fix is an
// allowlist entry in that chain; the only thing meshd can do is say so
// loudly at startup instead of letting the operator discover it forensically.

// warnBlockedPort scans nft and iptables-save for input-hook chains with a
// drop policy that never mention the listen port, and warns about each.
// Best-effort on every front: missing tools are skipped, and the scan cannot
// express every rule form (e.g. ipset references), so it errs toward silence.
// remediateForeignDropChains finds input-hook base chains with a drop policy
// and inserts an accept for the listen port into each. This is the only
// effective self-help against a hostile host firewall: netfilter has no
// cross-chain exemption — an accept in any other chain never survives a
// foreign chain's drop — so the rule must live in the blocking chain itself.
// Inserted rules carry our comment (visible in `nft list ruleset`), are
// tracked, and are removed on Close. Chains already carrying our tag are
// left alone.
func (r *linuxRouter) remediateForeignDropChains(log *log.Logger, port uint16) {
	conn, err := nftables.New()
	if err != nil {
		return // no netlink access; nothing netfilter-side we can do here
	}
	chains, err := conn.ListChains()
	if err != nil {
		return
	}
	portBE := []byte{byte(port >> 8), byte(port)}
	for _, chain := range chains {
		if chain.Table == nil || chain.Hooknum == nil || chain.Policy == nil {
			continue
		}
		if *chain.Hooknum != *nftables.ChainHookInput || *chain.Policy != nftables.ChainPolicyDrop {
			continue
		}
		rules, err := conn.GetRules(chain.Table, chain)
		if err != nil {
			continue
		}
		tagged := false
		for _, rule := range rules {
			if string(rule.UserData) == nftComment {
				tagged = true
				break
			}
		}
		if tagged {
			continue
		}
		nr := &nftables.Rule{
			Table: chain.Table,
			Chain: chain,
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_UDP}},
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: portBE},
				&expr.Verdict{Kind: expr.VerdictAccept},
			},
			UserData: []byte(nftComment),
		}
		// Insert at the TOP of the chain: an appended accept can sit after a
		// foreign terminal drop and never be reached. The kernel positions an
		// insert by rule HANDLE (position 0 does not exist), so anchor on the
		// first rule; a ruleless chain takes a plain append.
		if len(rules) > 0 {
			nr.Position = rules[0].Handle
			nr.Flags = 1 << unix.NFTA_RULE_POSITION
		}
		conn.AddRule(nr)
		if err := conn.Flush(); err != nil {
			log.Printf("router: could not open udp/%d in firewall %q chain %q: %v", port, chain.Table.Name, chain.Name, err)
			continue
		}
		r.mu.Lock()
		r.taggedChains = append(r.taggedChains, chain)
		r.mu.Unlock()
		log.Printf("router: opened udp/%d in firewall %q chain %q (its drop policy would have blocked it)", port, chain.Table.Name, chain.Name)
	}
}

// warnBlockedPort covers the legacy iptables family: chains there have no
// independent name-spacing problem, and hosts meshd can fully serve are
// handled by openPort already — but a DROP policy without our port is worth
// shouting about. Best-effort: missing tools are skipped, and the scan cannot
// express every rule form (e.g. ipset references), so it errs toward silence.
func warnBlockedPort(log *log.Logger, port int) {
	if log == nil {
		return
	}
	pat := fmt.Sprintf("%d", port)
	for _, tool := range []string{"iptables-save", "ip6tables-save"} {
		if out, err := exec.Command(tool).CombinedOutput(); err == nil {
			warnBlockedFromSave(log, tool, pat, string(out))
		}
	}
}

// mentionsPort reports whether a rule line references the port as a whole
// field — covering "dport 51822" and set literals "{ 443, 21820, 51820 }"
// while keeping 5182 from matching 51820.
func mentionsPort(line, port string) bool {
	for _, f := range strings.Fields(strings.Trim(line, "{}")) {
		if strings.Trim(f, ",") == port {
			return true
		}
	}
	return false
}

func warnBlockedFromSave(log *log.Logger, tool, port, dump string) {
	chain, policy := "", ""
	var body []string
	found := func() {
		if chain == "" || policy != "DROP" {
			return
		}
		for _, line := range body {
			if mentionsPort(line, port) {
				return
			}
		}
		log.Printf("router: firewall %s chain %q has policy DROP and no rule for udp/%s — inbound handshakes will be dropped; add e.g. 'iptables -I INPUT -p udp --dport %s -j ACCEPT'", tool, chain, port, port)
	}
	for _, line := range strings.Split(dump, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, ":"):
			found()
			f := strings.Fields(strings.TrimPrefix(line, ":"))
			// Only the INPUT chain binds the input hook — FORWARD/OUTPUT
			// DROP policies are normal (docker sets them) and none of our
			// business, so non-INPUT chains reset to untracked.
			if len(f) >= 2 && f[0] == "INPUT" {
				chain, policy, body = f[0], f[1], nil
			} else {
				chain, policy, body = "", "", nil
			}
		case strings.HasPrefix(line, "-A ") && strings.Fields(line)[1] == "INPUT":
			body = append(body, line)
		case strings.HasPrefix(line, "COMMIT"):
			found()
			chain, policy, body = "", "", nil
		}
	}
	found()
}

// openPort inserts an INPUT accept for the UDP listen port in BOTH address
// families. The tunnel payload is IPv4, but WireGuard's transport is
// dual-stack and the daemon advertises IPv6 candidates — a family-specific
// host firewall with a restrictive v6 policy would otherwise silently close
// half the transport. ip6tables is used when available.
func (r *linuxRouter) openPort() error {
	port := fmt.Sprintf("%d", r.port)
	probe := []string{"-C", "INPUT", "-p", "udp", "--dport", port, "-j", "ACCEPT"}
	insert := []string{"-I", "INPUT", "1", "-p", "udp", "--dport", port, "-j", "ACCEPT"}
	if err := r.run("filter", probe...); err != nil {
		if err := r.run("filter", insert...); err != nil {
			return err
		}
	}
	if r.hasIP6 {
		if err := r.run6("filter", probe...); err != nil {
			if err := r.run6("filter", insert...); err != nil {
				return err
			}
		}
	}
	return nil
}

// ipForwardPath is a package var so tests can point it at a temp file.
var ipForwardPath = "/proc/sys/net/ipv4/ip_forward"

func (r *linuxRouter) Forwarding() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fwdSet {
		return nil
	}
	// Already on? Common on Docker hosts (dockerd enables it globally for its
	// own bridge NAT) — treat as satisfied instead of failing on their
	// read-only /proc/sys mount.
	if b, err := os.ReadFile(ipForwardPath); err == nil && strings.TrimSpace(string(b)) == "1" {
		r.fwdSet = true
	} else {
		if err := os.WriteFile(ipForwardPath, []byte("1"), 0o644); err != nil {
			return fmt.Errorf("router: enable ip_forward: %w", err)
		}
		r.fwdSet = true
	}
	// Forwarding is only requested when the node serves spokes or announced
	// subnets — exactly when host firewalls with drop-policies on the forward
	// hook would silently break spoke routing. Same self-heal as the input
	// hook: insert tagged accepts into every drop-policy forward chain.
	r.remediateForwardChains()
	return nil
}

// remediateForwardChains inserts tagged accepts for the mesh interface into
// every forward-hook base chain with a drop policy, in every family — spoke
// traffic enters and leaves through the mesh interface, so the pair covers
// both directions. Idempotent via the userdata tag; legacy iptables-family
// hosts get a warning instead (their rules live in a separate database the
// library cannot reach). Caller must hold r.mu (called from Forwarding).
func (r *linuxRouter) remediateForwardChains() {
	if r.fwdFixed {
		return
	}
	r.fwdFixed = true
	conn, err := nftables.New()
	if err != nil {
		r.warnLegacyForward()
		return
	}
	chains, err := conn.ListChains()
	if err != nil {
		r.warnLegacyForward()
		return
	}
	inserted := 0
	for _, chain := range chains {
		if chain.Table == nil || chain.Hooknum == nil {
			continue
		}
		// Every forward-hook base chain is patched regardless of its policy:
		// docker's layout keeps policy accept but hides a terminal DROP
		// inside DOCKER-FORWARD, which an appended rule can never outrun.
		if *chain.Hooknum != *nftables.ChainHookForward {
			continue
		}
		rules, err := conn.GetRules(chain.Table, chain)
		if err != nil {
			continue
		}
		tagged := false
		for _, rule := range rules {
			if string(rule.UserData) == nftComment {
				tagged = true
				break
			}
		}
		if tagged {
			continue
		}
		mkrule := func(metaKey expr.MetaKey) *nftables.Rule {
			nr := &nftables.Rule{
				Table: chain.Table,
				Chain: chain,
				Exprs: []expr.Any{
					&expr.Meta{Key: metaKey, Register: 1},
					&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifnameBytes(r.iface)},
					&expr.Verdict{Kind: expr.VerdictAccept},
				},
				UserData: []byte(nftComment),
			}
			// Insert at the TOP of the chain, ahead of docker's jumps and
			// any foreign terminal drops. The kernel positions an insert by
			// rule HANDLE (position 0 does not exist), so anchor on the
			// first rule; a ruleless chain takes a plain append.
			if len(rules) > 0 {
				nr.Position = rules[0].Handle
				nr.Flags = 1 << unix.NFTA_RULE_POSITION
			}
			return nr
		}
		conn.AddRule(mkrule(expr.MetaKeyIIFNAME))
		conn.AddRule(mkrule(expr.MetaKeyOIFNAME))
		if err := conn.Flush(); err != nil {
			if r.log != nil {
				r.log.Printf("router: could not open forwarding for %q in firewall %q chain %q: %v", r.iface, chain.Table.Name, chain.Name, err)
			}
			continue
		}
		r.taggedChains = append(r.taggedChains, chain)
		inserted++
		if r.log != nil {
			r.log.Printf("router: opened forwarding for %q in firewall %q chain %q (foreign rules would have blocked it)", r.iface, chain.Table.Name, chain.Name)
		}
	}
	if inserted == 0 {
		r.warnLegacyForward()
	}
}

// warnLegacyForward covers hosts whose filtering runs in the iptables-legacy
// database, which netlink nft calls cannot reach.
func (r *linuxRouter) warnLegacyForward() {
	for _, tool := range []string{"iptables-save", "ip6tables-save"} {
		out, err := exec.Command(tool).CombinedOutput()
		if err != nil {
			continue
		}
		chain, policy := "", ""
		var body []string
		found := func() {
			if chain == "" || policy != "DROP" {
				return
			}
			for _, line := range body {
				if strings.Contains(line, "-i "+r.iface) || strings.Contains(line, "-o "+r.iface) {
					return
				}
			}
			if r.log != nil {
				r.log.Printf("router: firewall %s chain %q has policy DROP and no rule for %q — spoke routing will be dropped; add e.g. 'iptables -I FORWARD -i %s -j ACCEPT'", tool, chain, r.iface, r.iface)
			}
		}
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			switch {
			case strings.HasPrefix(line, ":"):
				found()
				f := strings.Fields(strings.TrimPrefix(line, ":"))
				if len(f) >= 2 && f[0] == "FORWARD" {
					chain, policy, body = f[0], f[1], nil
				} else {
					chain, policy, body = "", "", nil
				}
			case strings.HasPrefix(line, "-A ") && strings.Fields(line)[1] == "FORWARD":
				body = append(body, line)
			case strings.HasPrefix(line, "COMMIT"):
				found()
				chain, policy, body = "", "", nil
			}
		}
		found()
	}
}

// ifnameBytes renders an interface name the way nft compares iifname/oifname:
// NUL-padded to IFNAMSIZ.
func ifnameBytes(name string) []byte {
	b := make([]byte, 16)
	copy(b, name)
	return b
}

// CleanupFirewall removes every firewall trace of a meshd run: the
// transport-port accepts (both families), per-spoke masquerades, announce
// masquerades, and the tagged self-heal rules inside foreign chains.
// Intended for `meshd stop`, which runs without the daemon's in-memory
// tracking — removal is driven by the resolved config plus the userdata
// tag. Best-effort: absent rules and unreachable tools are skipped.
func CleanupFirewall(log *log.Logger, iface string, port int, overlay *net.IPNet, announce []net.IPNet, spokeIPs []net.IP) {
	// Transport-port accepts, both families.
	for _, fam := range []string{iptablesBin, ip6tablesBin} {
		args := []string{"-D", "INPUT", "-p", "udp", "--dport", fmt.Sprintf("%d", port), "-j", "ACCEPT"}
		if out, err := exec.Command(fam, args...).CombinedOutput(); err != nil && log != nil {
			log.Printf("router cleanup: %s %s: %v (%s)", fam, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
	}
	// Per-spoke masquerades.
	for _, ip := range spokeIPs {
		if ip4 := ip.To4(); ip4 != nil {
			args := []string{"-t", "nat", "-D", "POSTROUTING", "-s", ip4.String() + "/32", "-o", iface, "-m", "comment", "--comment", iptComment, "-j", "MASQUERADE"}
			if _, err := exec.Command(iptablesBin, args...).CombinedOutput(); err != nil && log != nil {
				log.Printf("router cleanup: iptables %s: %v", strings.Join(args, " "), err)
			}
		}
	}
	// Announce masquerades.
	if overlay != nil {
		for _, sub := range announce {
			if sub.IP.To4() == nil {
				continue
			}
			args := []string{"-t", "nat", "-D", "POSTROUTING", "-s", overlay.String(), "-d", sub.String(), "-m", "comment", "--comment", iptComment, "-j", "MASQUERADE"}
			if _, err := exec.Command(iptablesBin, args...).CombinedOutput(); err != nil && log != nil {
				log.Printf("router cleanup: iptables %s: %v", strings.Join(args, " "), err)
			}
		}
	}
	// Tagged NAT rules (announce/spoke masquerades carry an iptables
	// comment): swept so rules whose announcement was already removed from
	// the config are still cleaned up at stop.
	for _, tool := range []string{"iptables-save", "ip6tables-save"} {
		out, err := exec.Command(tool, "-t", "nat").CombinedOutput()
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "-A POSTROUTING") || !strings.Contains(line, iptComment) {
				continue
			}
			args := append([]string{"-t", "nat"}, strings.Fields(strings.Replace(line, "-A POSTROUTING", "-D POSTROUTING", 1))...)
			if _, err := exec.Command(iptablesBin, args...).CombinedOutput(); err != nil && log != nil {
				log.Printf("router cleanup: iptables %s: %v", strings.Join(args, " "), err)
			}
		}
	}
	// Tagged self-heal rules across every nft chain (input + forward, both
	// families) — these live in foreign chains, so the userdata tag is the
	// only reliable way to find them.
	conn, err := nftables.New()
	if err != nil {
		return
	}
	chains, err := conn.ListChains()
	if err != nil {
		return
	}
	flush := false
	for _, chain := range chains {
		rules, err := conn.GetRules(chain.Table, chain)
		if err != nil {
			continue
		}
		for _, rule := range rules {
			if string(rule.UserData) != nftComment {
				continue
			}
			if err := conn.DelRule(rule); err == nil {
				flush = true
				if log != nil {
					log.Printf("router cleanup: removed tagged rule from %q chain %q", chain.Table.Name, chain.Name)
				}
			}
		}
	}
	if flush {
		_ = conn.Flush()
	}
}

func (r *linuxRouter) AddSource(spoke net.IP) error {
	ip4 := spoke.To4()
	if ip4 == nil {
		return fmt.Errorf("router: %s is not IPv4", spoke)
	}
	// Best-effort: forwarding may be preset outside our control (e.g.
	// `docker run --sysctl net.ipv4.ip_forward=1`); don't fail the NAT rule
	// for it — the masquerade itself is what we own. Callers warn separately
	// if Forwarding() keeps failing.
	_ = r.Forwarding()
	src := ip4.String() + "/32"

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.added[src] {
		return nil
	}
	if err := r.run("nat", "-I", "POSTROUTING", "1", "-s", src, "-o", r.iface, "-m", "comment", "--comment", iptComment, "-j", "MASQUERADE"); err != nil {
		return err
	}
	r.added[src] = true
	return nil
}

// AnnounceNAT reconciles source-NAT rules that let overlay visitors reach
// announced subnets. Devices inside an announced subnet (a home LAN, for
// example) reply through their default gateway and cannot route overlay
// addresses back — so traffic leaving this node toward an announced subnet
// is masqueraded to this node's address on the egress interface, and the
// return path rides conntrack. Reconciling: rules for announcements absent
// from the current set are removed. All rules are removed on Close.
func (r *linuxRouter) AnnounceNAT(overlay *net.IPNet, subnets []net.IPNet) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	want := make(map[string]string, len(subnets)) // key -> dst subnet
	for _, sub := range subnets {
		if sub.IP.To4() == nil {
			continue
		}
		want[overlay.String()+"|"+sub.String()] = sub.String()
	}
	// Remove rules for announcements that disappeared.
	for key, dst := range r.announceNAT {
		if _, ok := want[key]; ok {
			continue
		}
		src := strings.SplitN(key, "|", 2)[0]
		if err := r.run("nat", "-D", "POSTROUTING", "-s", src, "-d", dst, "-m", "comment", "--comment", iptComment, "-j", "MASQUERADE"); err != nil && r.log != nil {
			r.log.Printf("router: remove announce nat %s: %v", key, err)
		}
		delete(r.announceNAT, key)
	}
	// Add rules for new announcements.
	for key, dst := range want {
		if _, ok := r.announceNAT[key]; ok {
			continue
		}
		src := strings.SplitN(key, "|", 2)[0]
		if err := r.run("nat", "-I", "POSTROUTING", "1", "-s", src, "-d", dst, "-m", "comment", "--comment", iptComment, "-j", "MASQUERADE"); err != nil {
			if r.log != nil {
				r.log.Printf("router: announce nat %s: %v", key, err)
			}
			continue
		}
		r.announceNAT[key] = dst
	}
	return nil
}

func (r *linuxRouter) RemoveSource(spoke net.IP) error {
	ip4 := spoke.To4()
	if ip4 == nil {
		return nil
	}
	src := ip4.String() + "/32"

	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.added[src] {
		return nil
	}
	if err := r.run("nat", "-D", "POSTROUTING", "-s", src, "-o", r.iface, "-m", "comment", "--comment", iptComment, "-j", "MASQUERADE"); err != nil {
		return err
	}
	delete(r.added, src)
	return nil
}

func (r *linuxRouter) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	var first error
	for key, dst := range r.announceNAT {
		src := strings.SplitN(key, "|", 2)[0]
		if err := r.run("nat", "-D", "POSTROUTING", "-s", src, "-d", dst, "-m", "comment", "--comment", iptComment, "-j", "MASQUERADE"); err != nil && first == nil {
			first = err
		}
	}
	r.announceNAT = make(map[string]string)
	for src := range r.added {
		if err := r.run("nat", "-D", "POSTROUTING", "-s", src, "-o", r.iface, "-m", "comment", "--comment", iptComment, "-j", "MASQUERADE"); err != nil && first == nil {
			first = err
		}
	}
	r.added = make(map[string]bool)
	if err := r.run("filter", "-D", "INPUT", "-p", "udp", "--dport", fmt.Sprintf("%d", r.port), "-j", "ACCEPT"); err != nil && first == nil {
		first = err
	}
	if r.hasIP6 {
		if err := r.run6("filter", "-D", "INPUT", "-p", "udp", "--dport", fmt.Sprintf("%d", r.port), "-j", "ACCEPT"); err != nil && first == nil {
			first = err
		}
	}
	if len(r.taggedChains) > 0 {
		if conn, err := nftables.New(); err == nil {
			for _, ch := range r.taggedChains {
				rules, err := conn.GetRules(ch.Table, ch)
				if err != nil {
					continue
				}
				for _, rule := range rules {
					if string(rule.UserData) == nftComment {
						if err := conn.DelRule(rule); err != nil && first == nil {
							first = fmt.Errorf("router: remove nft accept from %q chain %q: %w", ch.Table.Name, ch.Name, err)
						}
					}
				}
			}
			if err := conn.Flush(); err != nil && first == nil {
				first = fmt.Errorf("router: remove nft accepts: %w", err)
			}
		}
	}
	r.taggedChains = nil
	if r.fwdSet && r.priorFwd != "" {
		if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte(r.priorFwd), 0o644); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (r *linuxRouter) run(table string, args ...string) error {
	full := append([]string{"-t", table}, args...)
	cmd := exec.Command(iptablesBin, full...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s %s: %w (%s)", iptablesBin, strings.Join(full, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// run6 mirrors run for the IPv6 family (transport-port rules only; the
// overlay, routes, and masquerade are IPv4 by design).
func (r *linuxRouter) run6(table string, args ...string) error {
	full := append([]string{"-t", table}, args...)
	cmd := exec.Command(ip6tablesBin, full...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s %s: %w (%s)", ip6tablesBin, strings.Join(full, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
