package mesh

import (
	"net"
	"sort"
)

// natMode is what the srflx comparison concluded about two nodes.
type natMode int

const (
	modeUnknown        natMode = iota // can't tell (missing reflexive data)
	modeSharedNAT                     // same reflexive IP → likely same LAN
	modeDifferentSites                // different reflexive IPs
)

func srflxIP(cands []Candidate) string {
	for _, c := range cands {
		if c.Type == CandSRFLX {
			return hostOnly(c.Addr)
		}
	}
	return ""
}

func hostOnly(hostPort string) string {
	h, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		return hostPort
	}
	return h
}

func sameNAT(mine, theirs []Candidate) (natMode, bool) {
	m, o := srflxIP(mine), srflxIP(theirs)
	switch {
	case m == "" || o == "":
		return modeUnknown, false
	case m == o:
		return modeSharedNAT, true
	default:
		return modeDifferentSites, false
	}
}

// OrderEndpoints ranks a peer's candidates for dialing. Same-NAT: LAN hosts
// first (hairpin rarely works), reflexive as fallback. Different sites: only
// reflexive/public addresses are dialed — private RFC1918 host candidates are
// ambiguous across edges (another site's 192.168.1.0/24 is not ours) and so
// are dropped outright, never left as a footgun tail. Unknown: assume
// local-first.
func OrderEndpoints(mine, theirs []Candidate) []Candidate {
	mode, _ := sameNAT(mine, theirs)

	cands := append([]Candidate(nil), theirs...)
	if mode == modeDifferentSites {
		kept := cands[:0]
		for _, c := range cands {
			if c.Type == CandHost && isPrivateCandidate(c) {
				continue
			}
			kept = append(kept, c)
		}
		cands = kept
	}

	hostScore := map[natMode]int{modeSharedNAT: 0, modeUnknown: 0, modeDifferentSites: 20}[mode]
	srflxScore := map[natMode]int{modeSharedNAT: 10, modeUnknown: 10, modeDifferentSites: 10}[mode]

	scored := cands
	for i := range scored {
		if scored[i].Type == CandSRFLX {
			scored[i].score = srflxScore
		} else {
			scored[i].score = hostScore
		}
	}
	stableSortCandidates(scored)
	return scored
}

func stableSortCandidates(cs []Candidate) {
	sort.SliceStable(cs, func(i, j int) bool { return cs[i].score < cs[j].score })
}

// containsAddr reports whether any candidate (of any type) targets addr.
// Type-blind on purpose: a prflx observation equal to an advertised address
// must not be dialed twice.
func containsAddr(cands []Candidate, addr string) bool {
	for _, x := range cands {
		if x.Addr == addr {
			return true
		}
	}
	return false
}

// isPrivateCandidate reports whether a host candidate's address is a private
// (RFC1918) or CGNAT range. Such addresses are only meaningful inside the edge
// that owns them; dialing them from a different site is at best useless and at
// worst addresses our own private space.
func isPrivateCandidate(c Candidate) bool {
	h := hostOnly(c.Addr)
	ip := net.ParseIP(h)
	if ip == nil {
		return false
	}
	return isPrivateIP(ip)
}

func isPrivateIP(ip net.IP) bool {
	if p := ip.To4(); p != nil {
		switch {
		case p[0] == 10:
			return true
		case p[0] == 172 && p[1] >= 16 && p[1] <= 31:
			return true
		case p[0] == 192 && p[1] == 168:
			return true
		case p[0] == 100 && p[1] >= 64 && p[1] <= 127: // CGNAT
			return true
		}
	}
	return false
}
