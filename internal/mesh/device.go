package mesh

import (
	"net"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// PeerDesire is one node's complete intended WireGuard peer state. AllowedIPs
// always includes the peer's overlay /32 plus whatever subnets it announces.
type PeerDesire struct {
	Name       string
	Pub        wgtypes.Key
	Endpoint   *net.UDPAddr
	AllowedIPs []net.IPNet
	Keepalive  time.Duration
}

// Device is the kernel-interface control plane. Implementations must treat
// Apply as declarative full-state convergence (idempotent diff-safe updates,
// never bouncing existing sessions). ApplyRoutes converges the set of
// on-link routes for announced subnets (replacing previously installed ones).
type Device interface {
	Setup(key wgtypes.Key, listenPort, mtu int, addr *net.IPNet, route *net.IPNet) error
	Apply(peers []PeerDesire) error
	ApplyRoutes(routes []net.IPNet) error
	Handshake(pub wgtypes.Key) time.Time
	// Endpoint returns the currently tracked endpoint for a peer — the one
	// WireGuard has roamed to from the peer's own authenticated traffic, or
	// nil if the peer has not engaged. This is the observed/peer-reflexive
	// address, which is authoritative for reachability across NAT.
	Endpoint(pub wgtypes.Key) *net.UDPAddr
}
