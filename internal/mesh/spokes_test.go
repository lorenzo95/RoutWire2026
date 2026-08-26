package mesh

import (
	"path/filepath"
	"testing"
	"time"

	"routewire/internal/engine"
)

func TestSpokePersistenceRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "meshd.spokes")
	if err := AddSpoke(path, "phone-1"); err != nil {
		t.Fatal(err)
	}
	if err := AddSpoke(path, "Phone-1 "); err != nil { // duplicate, normalized
		t.Fatal(err)
	}
	if err := AddSpoke(path, "tablet"); err != nil {
		t.Fatal(err)
	}

	set, err := LoadSpokes(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(set) != 2 || !set["phone-1"] || !set["tablet"] {
		t.Fatalf("unexpected spoke set: %v", set)
	}

	if err := RemoveSpoke(path, "tablet"); err != nil {
		t.Fatal(err)
	}
	set, _ = LoadSpokes(path)
	if len(set) != 1 || !set["phone-1"] || set["tablet"] {
		t.Fatalf("remove failed: %v", set)
	}
}

func TestEvictsStaleSpokeAndPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "meshd.spokes")
	if err := AddSpoke(path, "spoke-a"); err != nil {
		t.Fatal(err)
	}
	if err := AddSpoke(path, "spoke-b"); err != nil {
		t.Fatal(err)
	}

	store := engine.NewReliable(engine.NewMockStore(10*time.Minute, time.Now))
	dev := NewFakeDevice()
	dm, d := newTestDaemon(t, "alpha", store, dev)
	dm.cfg.SpokesFile = path
	set, err := LoadSpokes(path)
	if err != nil {
		t.Fatal(err)
	}
	dm.spokes = set

	dev.SetHandshake(pubKeyOf(t, d, "spoke-a"), time.Now().Add(-20*time.Minute))

	dm.evictStaleSpokes()

	if dm.spokes["spoke-a"] {
		t.Fatal("stale spoke should be evicted")
	}
	if !dm.spokes["spoke-b"] {
		t.Fatal("never-connected spoke must not be evicted")
	}

	persisted, err := LoadSpokes(path)
	if err != nil {
		t.Fatal(err)
	}
	if persisted["spoke-a"] || !persisted["spoke-b"] {
		t.Fatalf("persisted set wrong: %v", persisted)
	}
}
