package mesh

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// ExportConfInput describes one generated remote-device config.
type ExportConfInput struct {
	Deriver     *Deriver
	CIDR        *net.IPNet
	LocalName   string   // generating node; becomes the [Peer] hub
	RemoteName  string   // agent-less device receiving this config
	Endpoint    string   // host:port where the remote can reach the local node
	ExtraRoutes []string // announced subnets to bake into AllowedIPs
	MTU         int
}

// ExportConf renders a wg-quick(8)-compatible config for a device that cannot
// run meshd. The remote's private key is derived from PSK+name exactly like an
// agent's, so agents that later see its roster record interoperate with zero
// extra state.
func ExportConf(in ExportConfInput) ([]byte, error) {
	if in.Deriver == nil || in.CIDR == nil {
		return nil, errors.New("export: deriver and cidr required")
	}
	local := NormalizeName(in.LocalName)
	remote := NormalizeName(in.RemoteName)
	if err := ValidateName(remote); err != nil {
		return nil, fmt.Errorf("export: remote name: %w", err)
	}
	if remote == local {
		return nil, errors.New("export: remote name must differ from this node's name")
	}
	if _, _, err := net.SplitHostPort(in.Endpoint); err != nil {
		return nil, fmt.Errorf("export: endpoint must be host:port: %w", err)
	}
	mtu := in.MTU
	if mtu <= 0 {
		mtu = 1420
	}

	priv, err := in.Deriver.NodeWGKey(remote)
	if err != nil {
		return nil, err
	}
	ip, err := in.Deriver.OverlayIP(remote, in.CIDR)
	if err != nil {
		return nil, err
	}
	hubPub, err := in.Deriver.NodeWGKey(local)
	if err != nil {
		return nil, err
	}

	routes := parseCIDRs(in.ExtraRoutes)
	allowed := make([]string, 0, len(routes)+1)
	allowed = append(allowed, in.CIDR.String())
	for i := range routes {
		allowed = append(allowed, routes[i].String())
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# routewire/meshd exported config for %q\n", remote)
	fmt.Fprintf(&b, "# generated %s by node %q from its live routing knowledge.\n",
		time.Now().UTC().Format(time.RFC3339), local)
	fmt.Fprintf(&b, "# regenerate to refresh endpoints/routes; keep this file secret (0600).\n")
	b.WriteString("\n[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", priv.String())
	fmt.Fprintf(&b, "Address = %s/32\n", ip)
	fmt.Fprintf(&b, "MTU = %d\n", mtu)
	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "# routewire hub %q (regenerate there after topology changes)\n", local)
	fmt.Fprintf(&b, "PublicKey = %s\n", hubPub.PublicKey().String())
	fmt.Fprintf(&b, "Endpoint = %s\n", in.Endpoint)
	fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(allowed, ", "))
	b.WriteString("PersistentKeepalive = 25\n")

	return []byte(b.String()), nil
}
