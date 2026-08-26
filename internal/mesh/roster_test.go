package mesh

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"

	"routewire/internal/engine"
)

func newTestRoster(t *testing.T, d *Deriver, name string, store *engine.ReliableStore) (*Roster, *Record) {
	t.Helper()
	_, cidr, _ := net.ParseCIDR(testCIDR)
	ro, err := NewRoster(d, name, store, cidr)
	if err != nil {
		t.Fatal(err)
	}
	id, err := d.NodeIdentity(name)
	if err != nil {
		t.Fatal(err)
	}
	ip, err := d.OverlayIP(name, cidr)
	if err != nil {
		t.Fatal(err)
	}
	rec := &Record{
		Name: NormalizeName(name), IP: ip.String(), Port: 51820,
		Candidates: []Candidate{{Type: CandHost, Addr: "192.168.1." + name[len(name)-1:] + ":51820"}},
		TS:         time.Now().Unix(), Seq: 7,
	}
	if err := rec.Sign(id); err != nil {
		t.Fatal(err)
	}
	return ro, rec
}

func TestRosterTwoNodeConvergence(t *testing.T) {
	d := mustDeriver(t, testPSK)
	mock := engine.NewMockStore(10*time.Minute, time.Now)
	store := engine.NewReliable(mock)

	a, recA := newTestRoster(t, d, "alpha", store)
	b, recB := newTestRoster(t, d, "beta", store)

	ctx := context.Background()
	if err := a.Publish(ctx, recA); err != nil {
		t.Fatal(err)
	}
	if err := b.Publish(ctx, recB); err != nil {
		t.Fatal(err)
	}

	gotA, err := a.Fetch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(gotA) != 1 || gotA["beta"] == nil {
		t.Fatalf("alpha should see exactly beta, got %v", gotA)
	}
	if gotA["beta"].IP != recB.IP {
		t.Fatal("wrong record folded for beta")
	}

	gotB, err := b.Fetch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(gotB) != 1 || gotB["alpha"] == nil {
		t.Fatalf("beta should see exactly alpha, got %v", gotB)
	}
	if gotB["alpha"].IP != recA.IP {
		t.Fatal("wrong record folded for alpha")
	}
}

func TestRosterKeepsHighestSeqAndFiltersStale(t *testing.T) {
	d := mustDeriver(t, testPSK)
	mock := engine.NewMockStore(10*time.Minute, time.Now)
	store := engine.NewReliable(mock)
	a, _ := newTestRoster(t, d, "alpha", store)

	idB, _ := d.NodeIdentity("beta")
	_, cidr, _ := net.ParseCIDR(testCIDR)
	ipB, _ := d.OverlayIP("beta", cidr)

	oldRec := &Record{Name: "beta", IP: ipB.String(), Port: 1, TS: time.Now().Add(-2 * time.Hour).Unix(), Seq: 9}
	newRec := &Record{Name: "beta", IP: ipB.String(), Port: 2, TS: time.Now().Unix(), Seq: 10}
	for _, r := range []*Record{oldRec, newRec} {
		if err := r.Sign(idB); err != nil {
			t.Fatal(err)
		}
		if err := a.Publish(context.Background(), r); err != nil {
			t.Fatal(err)
		}
	}

	got, err := a.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("expected only fresh record to survive, got %d", len(got))
	}
	if got["beta"].Port != 2 {
		t.Fatalf("highest seq should win, got port %d (seq %d)", got["beta"].Port, got["beta"].Seq)
	}
}

func TestRosterRejectsForeignMesh(t *testing.T) {
	d := mustDeriver(t, testPSK)
	dOther := mustDeriver(t, "other mesh psk")
	mock := engine.NewMockStore(10*time.Minute, time.Now)
	store := engine.NewReliable(mock)

	a, recA := newTestRoster(t, d, "alpha", store)
	bOther, recOther := newTestRoster(t, dOther, "beta", store)

	ctx := context.Background()
	_ = a.Publish(ctx, recA)
	_ = bOther.Publish(ctx, recOther)

	got, err := a.Fetch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got["beta"]; ok {
		t.Fatal("record from another PSK's mesh must not appear in ours")
	}
}

func TestRosterRecordsAreSealedAtRest(t *testing.T) {
	d := mustDeriver(t, testPSK)
	mock := engine.NewMockStore(10*time.Minute, time.Now)
	store := engine.NewReliable(mock)
	a, recA := newTestRoster(t, d, "alpha", store)

	if err := a.Publish(context.Background(), recA); err != nil {
		t.Fatal(err)
	}
	vals, err := store.Read(context.Background(), d.RosterKey())
	if err != nil || len(vals) == 0 {
		t.Fatalf("expected a stored value, got %v (%v)", vals, err)
	}
	plain, _ := json.Marshal(recA)
	for _, v := range vals {
		if bytes.Contains(v, []byte(recA.Name)) || bytes.Contains(v, []byte(recA.IP)) {
			t.Fatalf("stored value leaks plaintext record: %q", v)
		}
		if bytes.Equal(v, plain) {
			t.Fatal("stored value is unencrypted record JSON")
		}
	}
}

func TestNamesSortedDeterministically(t *testing.T) {
	in := map[string]*Record{"zeta": nil, "alpha": nil, "mid": nil}
	got := Names(in)
	want := []string{"alpha", "mid", "zeta"}
	if len(got) != 3 || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Fatalf("Names() = %v, want %v", got, want)
	}
}
