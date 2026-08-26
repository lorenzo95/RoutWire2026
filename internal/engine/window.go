package engine

import (
	"sort"
)

// window.go holds the rolling-scrollback logic: given all live values under a
// room key we keep only the most recent N (by ts, tie-broken by seq) and order
// oldest→newest so a joiner's "last N pop up" reads naturally. Relies on the
// no self-hosted list hard: we never know who is in the room; the window is
// the room.

// sortWindow sorts envelopes newest-first (for picking the top N).
func sortWindow(envs []*Envelope) {
	sort.SliceStable(envs, func(i, j int) bool {
		a, b := envs[i].Msg, envs[j].Msg
		if a.TS != b.TS {
			return a.TS > b.TS // newer first
		}
		return a.Seq > b.Seq
	})
}

// keepTop returns the n newest envelopes, ordered newest-first.
func keepTop(envs []*Envelope, n int) []*Envelope {
	sortWindow(envs)
	if len(envs) > n {
		envs = envs[:n]
	}
	return envs
}

// sortAscending reorders oldest-first for handoff to handlers.
func sortAscending(envs []*Envelope) {
	sort.SliceStable(envs, func(i, j int) bool {
		a, b := envs[i].Msg, envs[j].Msg
		if a.TS != b.TS {
			return a.TS < b.TS
		}
		return a.Seq < b.Seq
	})
}

// dedupeByID collapses values that are refreshes of the same message id. A DHT
// stores the original put plus each TTL refresh as separate entries, so the
// same logical message can appear multiple times under a key; keep the newest.
func dedupeByID(envs []*Envelope) []*Envelope {
	index := make(map[string]*Envelope, len(envs))
	for _, e := range envs {
		index[e.ID()] = e
	}
	out := make([]*Envelope, 0, len(index))
	for _, e := range index {
		out = append(out, e)
	}
	return out
}
