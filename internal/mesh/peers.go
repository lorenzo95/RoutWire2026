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
// first (hairpin rarely works). Different sites: reflexive only is sensible,
// hosts kept as harmless tail. Unknown: assume local-first.
func OrderEndpoints(mine, theirs []Candidate) []Candidate {
	mode, _ := sameNAT(mine, theirs)
	hostScore := map[natMode]int{modeSharedNAT: 0, modeUnknown: 0, modeDifferentSites: 20}[mode]
	srflxScore := map[natMode]int{modeSharedNAT: 10, modeUnknown: 10, modeDifferentSites: 10}[mode]

	scored := append([]Candidate(nil), theirs...)
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

func containsCandidate(cands []Candidate, c Candidate) bool {
	for _, x := range cands {
		if x.Type == c.Type && x.Addr == c.Addr {
			return true
		}
	}
	return false
}
