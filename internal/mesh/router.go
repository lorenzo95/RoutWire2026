package mesh

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
)

// ErrNoIptables is returned by NewLinuxRouter when the iptables binary is
// unavailable (e.g. minimal containers). Callers may fall back to a no-op
// router and manage firewall/forwarding on the host themselves.
var ErrNoIptables = errors.New("iptables executable not found")

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
	// Close removes firewall + masquerade rules and restores forwarding.
	Close() error
}

// noopRouter is used when routing integration is disabled (dry-run, tests).
type noopRouter struct{}

func (noopRouter) Forwarding() error        { return nil }
func (noopRouter) AddSource(net.IP) error   { return nil }
func (noopRouter) RemoveSource(net.IP) error { return nil }
func (noopRouter) Close() error             { return nil }

// linuxRouter implements Router with iptables + /proc/sys/net/ipv4/ip_forward.
type linuxRouter struct {
	iface    string
	port     int
	mu       sync.Mutex
	added    map[string]bool
	fwdSet   bool
	priorFwd string
}

// NewLinuxRouter opens the WireGuard UDP listen port in the firewall and
// prepares forwarding (enabled lazily via Forwarding). It must be called with
// the interface name the daemon manages.
func NewLinuxRouter(iface string, port int) (Router, error) {
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
	if _, err := exec.LookPath("iptables"); err != nil {
		return noopRouter{}, fmt.Errorf("%w", ErrNoIptables)
	}
	r := &linuxRouter{
		iface:    iface,
		port:     port,
		added:    make(map[string]bool),
		priorFwd: strings.TrimSpace(string(prior)),
	}
	if err := r.openPort(); err != nil {
		return nil, fmt.Errorf("router: open port: %w", err)
	}
	return r, nil
}

// openPort inserts an INPUT accept for the UDP listen port if not already
// present, so a restrictive host firewall cannot block handshakes.
func (r *linuxRouter) openPort() error {
	if err := r.run("filter", "-C", "INPUT", "-p", "udp", "--dport", fmt.Sprintf("%d", r.port), "-j", "ACCEPT"); err == nil {
		return nil // already present (admin rule counts too)
	}
	return r.run("filter", "-I", "INPUT", "1", "-p", "udp", "--dport", fmt.Sprintf("%d", r.port), "-j", "ACCEPT")
}

func (r *linuxRouter) Forwarding() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fwdSet {
		return nil
	}
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0o644); err != nil {
		return fmt.Errorf("router: enable ip_forward: %w", err)
	}
	r.fwdSet = true
	return nil
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
	err := r.run("nat", "-I", "POSTROUTING", "1", "-s", src, "-o", r.iface, "-j", "MASQUERADE")
	if err != nil {
		return err
	}
	r.added[src] = true
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
	if err := r.run("nat", "-D", "POSTROUTING", "-s", src, "-o", r.iface, "-j", "MASQUERADE"); err != nil {
		return err
	}
	delete(r.added, src)
	return nil
}

func (r *linuxRouter) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	var first error
	for src := range r.added {
		if err := r.run("nat", "-D", "POSTROUTING", "-s", src, "-o", r.iface, "-j", "MASQUERADE"); err != nil && first == nil {
			first = err
		}
	}
	r.added = make(map[string]bool)
	if err := r.run("filter", "-D", "INPUT", "-p", "udp", "--dport", fmt.Sprintf("%d", r.port), "-j", "ACCEPT"); err != nil && first == nil {
		first = err
	}
	if r.fwdSet && r.priorFwd != "" {
		if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte(r.priorFwd), 0o644); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (r *linuxRouter) run(table string, args ...string) error {
	full := append([]string{"-t", table}, args...)
	cmd := exec.Command("iptables", full...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("iptables %s: %w (%s)", strings.Join(full, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}