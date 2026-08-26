package mesh

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"time"

	"routewire/internal/engine"
)

// Roster publishes our record and folds everyone's records out of the shared
// DHT key. The key holds a *set* of values (one per publish), so folding
// means: decode, verify, bind-check, freshness-filter, keep highest Seq per
// name.
type Roster struct {
	d       *Deriver
	cidr    *net.IPNet
	me      string
	store   *engine.ReliableStore
	maxAge  time.Duration
	nowFunc func() time.Time
}

func NewRoster(d *Deriver, me string, store *engine.ReliableStore, cidr *net.IPNet) (*Roster, error) {
	if cidr == nil {
		return nil, fmt.Errorf("nil overlay cidr")
	}
	return &Roster{
		d:       d,
		me:      NormalizeName(me),
		store:   store,
		cidr:    cidr,
		maxAge:  24 * time.Hour,
		nowFunc: time.Now,
	}, nil
}

// Publish puts our signed record under the shared roster key (put-confirm-get
// via ReliableStore). The record is sealed before storage so the DHT holds
// ciphertext only.
func (ro *Roster) Publish(ctx context.Context, rec *Record) error {
	sealed, err := sealRecord(ro.d, rec)
	if err != nil {
		return err
	}
	return ro.store.Publish(ctx, ro.d.RosterKey(), sealed)
}

// sealRecord marshals and encrypts a record for storage in the DHT.
func sealRecord(d *Deriver, rec *Record) (engine.Value, error) {
	b, err := json.Marshal(rec)
	if err != nil {
		return nil, err
	}
	return engine.Seal(d.RosterBoxKey(), b)
}

// Fetch returns the latest valid record per node, excluding ourselves,
// sorted deterministically by the caller via Names.
func (ro *Roster) Fetch(ctx context.Context) (map[string]*Record, error) {
	vals, err := ro.store.Read(ctx, ro.d.RosterKey())
	if err != nil {
		return nil, err
	}
	freshBefore := ro.nowFunc().Add(-ro.maxAge).Unix()
	boxKey := ro.d.RosterBoxKey()
	out := make(map[string]*Record)
	for _, v := range vals {
		plain, err := engine.Open(boxKey, v)
		if err != nil {
			continue // foreign value or plaintext leftovers — not ours to read
		}
		rec, err := DecodeRecord(plain)
		if err != nil || rec.TS < freshBefore || rec.Name == ro.me {
			continue
		}
		if err := rec.VerifyBinding(ro.d, ro.cidr); err != nil {
			continue
		}
		if cur, ok := out[rec.Name]; ok && cur.Seq >= rec.Seq {
			continue
		}
		out[rec.Name] = rec
	}
	return out, nil
}

// FetchStable runs several fetches and merges the folded views, keeping the
// highest-Seq record per name across attempts. A single DHT GET may return
// only a subset of the stored values (eventual consistency), which would
// otherwise silently hide records — e.g. freshly re-published announcements.
func (ro *Roster) FetchStable(ctx context.Context, attempts int, pause time.Duration) (map[string]*Record, error) {
	if attempts < 1 {
		attempts = 1
	}
	merged := make(map[string]*Record)
	var lastErr error
	for i := 0; i < attempts; i++ {
		if ctx.Err() != nil {
			break
		}
		got, err := ro.Fetch(ctx)
		if err != nil {
			lastErr = err
		}
		for name, rec := range got {
			if cur, ok := merged[name]; !ok || cur.Seq < rec.Seq {
				merged[name] = rec
			}
		}
		if i < attempts-1 {
			select {
			case <-time.After(pause):
			case <-ctx.Done():
				return merged, nil
			}
		}
	}
	if len(merged) == 0 && lastErr != nil {
		return nil, lastErr
	}
	return merged, nil
}

// Names returns sorted peer names for deterministic iteration.
func Names(peers map[string]*Record) []string {
	names := make([]string, 0, len(peers))
	for n := range peers {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
