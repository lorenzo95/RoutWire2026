//go:build linux

package mesh

import (
	"fmt"
	"net"
	"os"
	"time"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// LinuxDevice drives a kernel WireGuard link via rtnetlink and the WireGuard
// netlink API. Apply is declarative: every call replaces the full desired
// peer set, updating endpoints in place without disturbing live sessions.
type LinuxDevice struct {
	iface  string
	cl     *wgctrl.Client
	link   netlink.Link
	routes []net.IPNet
}

var _ Device = (*LinuxDevice)(nil)

func NewLinuxDevice(iface string) (*LinuxDevice, error) {
	cl, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("wgctrl: %w", err)
	}
	return &LinuxDevice{iface: iface, cl: cl}, nil
}

func (ld *LinuxDevice) Setup(key wgtypes.Key, listenPort, mtu int, addr *net.IPNet, route *net.IPNet) error {
	l, err := netlink.LinkByName(ld.iface)
	if err != nil {
		wgLink := &netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: ld.iface}}
		if mtu > 0 {
			wgLink.MTU = mtu
		}
		if err := netlink.LinkAdd(wgLink); err != nil {
			return fmt.Errorf("create %s: %w", ld.iface, err)
		}
		if l, err = netlink.LinkByName(ld.iface); err != nil {
			return fmt.Errorf("find new %s: %w", ld.iface, err)
		}
	} else if l.Type() != "wireguard" {
		return fmt.Errorf("%s exists but is a %s link", ld.iface, l.Type())
	}
	ld.link = l

	if mtu > 0 && l.Attrs().MTU != mtu {
		if err := netlink.LinkSetMTU(l, mtu); err != nil {
			return fmt.Errorf("mtu: %w", err)
		}
	}

	// Reconfigure BEFORE bringing the link up: a pre-existing interface may
	// hold a stale UDP listen port whose socket only re-binds cleanly while
	// the device is down.
	priv := key
	port := listenPort
	if err := ld.cl.ConfigureDevice(ld.iface, wgtypes.Config{
		PrivateKey: &priv,
		ListenPort: &port,
	}); err != nil {
		return fmt.Errorf("configure: %w", err)
	}
	if err := netlink.LinkSetUp(l); err != nil {
		return fmt.Errorf("up (is another process/interface using port %d?): %w", port, err)
	}

	hostAddr := &netlink.Addr{IPNet: &net.IPNet{IP: addr.IP, Mask: net.CIDRMask(32, 32)}}
	if err := netlink.AddrReplace(l, hostAddr); err != nil {
		return fmt.Errorf("address: %w", err)
	}
	if route != nil {
		if err := netlink.RouteReplace(&netlink.Route{
			LinkIndex: l.Attrs().Index,
			Dst:       route,
		}); err != nil {
			return fmt.Errorf("route: %w", err)
		}
	}
	return nil
}

// Apply converges the interface to exactly the desired peer set with
// minimal churn: missing peers are added, stale ones removed, known ones
// updated in place. Never uses wholesale replacement — a transient roster
// gap must not destroy live sessions (WireGuard roaming endpoints included).
func (ld *LinuxDevice) Apply(peers []PeerDesire) error {
	dev, err := ld.cl.Device(ld.iface)
	if err != nil {
		return err
	}
	current := make(map[wgtypes.Key]bool, len(dev.Peers))
	for _, p := range dev.Peers {
		current[p.PublicKey] = true
	}

	want := make(map[wgtypes.Key]bool, len(peers))
	var cfg wgtypes.Config
	for _, p := range peers {
		if len(p.AllowedIPs) == 0 {
			continue
		}
		want[p.Pub] = true
		pc := wgtypes.PeerConfig{
			PublicKey:                   p.Pub,
			AllowedIPs:                  p.AllowedIPs,
			PersistentKeepaliveInterval: &p.Keepalive,
		}
		if p.Endpoint != nil {
			pc.Endpoint = p.Endpoint
		}
		cfg.Peers = append(cfg.Peers, pc)
	}
	for pub := range current {
		if !want[pub] {
			pub := pub
			cfg.Peers = append(cfg.Peers, wgtypes.PeerConfig{
				PublicKey: pub,
				Remove:    true,
			})
		}
	}
	if len(cfg.Peers) == 0 {
		return nil
	}
	return ld.cl.ConfigureDevice(ld.iface, cfg)
}

// ApplyRoutes converges on-link routes for announced subnets, removing ones
// no longer announced.
func (ld *LinuxDevice) ApplyRoutes(routes []net.IPNet) error {
	want := map[string]bool{}
	for i := range routes {
		r := &routes[i]
		key := r.String()
		want[key] = true
		if err := netlink.RouteReplace(&netlink.Route{
			LinkIndex: ld.link.Attrs().Index,
			Dst:       r,
		}); err != nil {
			return fmt.Errorf("route %s: %w", key, err)
		}
	}
	for _, prev := range ld.routes {
		if !want[prev.String()] {
			dst := prev
			if err := netlink.RouteDel(&netlink.Route{
				LinkIndex: ld.link.Attrs().Index,
				Dst:       &dst,
			}); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("del route %s: %w", prev.String(), err)
			}
		}
	}
	ld.routes = append([]net.IPNet(nil), routes...)
	return nil
}

func (ld *LinuxDevice) Handshake(pub wgtypes.Key) time.Time {
	dev, err := ld.cl.Device(ld.iface)
	if err != nil {
		return time.Time{}
	}
	for _, p := range dev.Peers {
		if p.PublicKey == pub {
			return p.LastHandshakeTime
		}
	}
	return time.Time{}
}

func (ld *LinuxDevice) Close() error { return ld.cl.Close() }

// Delete removes the interface entirely (for `meshd stop` style cleanup).
func (ld *LinuxDevice) Delete() error {
	l, err := netlink.LinkByName(ld.iface)
	if err != nil {
		return nil
	}
	return netlink.LinkDel(l)
}
