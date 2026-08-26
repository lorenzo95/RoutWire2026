package mesh

import (
	"net"
	"strconv"
	"strings"
)

// LocalCandidates enumerates host candidates: every globally-routable
// (non-loopback, non-link-local) address on interfaces worth announcing,
// joined with our WireGuard listen port.
func LocalCandidates(port int) []Candidate {
	var ips []net.IP
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for _, ifc := range ifaces {
		if !announceIface(ifc) {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ips = append(ips, ipNet.IP)
		}
	}
	return ipCandidates(ips, port)
}

func announceIface(ifc net.Interface) bool {
	if ifc.Flags&net.FlagLoopback != 0 || ifc.Flags&net.FlagPointToPoint != 0 {
		return false
	}
	name := strings.ToLower(ifc.Name)
	for _, p := range []string{"lo", "wg", "docker", "br-", "veth", "virbr", "tun", "tap", "vrf", "zt"} {
		if strings.HasPrefix(name, p) {
			return false
		}
	}
	return true
}

func ipCandidates(ips []net.IP, port int) []Candidate {
	var out []Candidate
	for _, ip := range ips {
		ip4 := ip.To4()
		switch {
		case ip4 != nil:
			if ip4.IsLoopback() || ip4.IsLinkLocalUnicast() || ip4.IsUnspecified() {
				continue
			}
		default:
			if ip.IsLinkLocalUnicast() || ip.IsLoopback() || ip.IsUnspecified() {
				continue
			}
		}
		out = append(out, Candidate{Type: CandHost, Addr: net.JoinHostPort(ip.String(), strconv.Itoa(port))})
	}
	return out
}
