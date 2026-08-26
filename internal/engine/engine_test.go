package engine

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

// fakeClock simulates a monotonic clock for TTL tests.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func twoRoom(t *testing.T, ttl time.Duration, n int) (*Room, *Room, *MockStore, *fakeClock) {
	t.Helper()
	clk := &fakeClock{t: time.Unix(0, 0)}
	store := NewMockStore(ttl, clk.Now)
	rel := NewReliable(store)

	alice, _ := NewIdentity()
	bob, _ := NewIdentity()

	r1 := NewRoom("shared-room", alice, "Alice", rel, WithPollInterval(time.Hour), WithWindowSize(n))
	r2 := NewRoom("shared-room", bob, "Bob", rel, WithPollInterval(time.Hour), WithWindowSize(n))
	if r1.Key() != r2.Key() {
		t.Fatal("rooms should converge on the same DHT key")
	}
	return r1, r2, store, clk
}

func TestRoomSendAndReconcileDelivers(t *testing.T) {
	r1, r2, _, clk := twoRoom(t, time.Hour, 20)

	var (
		mu    sync.Mutex
		got   []string
		fired = make(chan struct{}, 10)
	)
	r2.events = RoomEvents{
		OnMessage: func(m Message) { mu.Lock(); got = append(got, m.Text); mu.Unlock(); fired <- struct{}{} },
	}

	if _, err := r1.Send(context.Background(), "hello from alice"); err != nil {
		t.Fatal(err)
	}
	clk.Advance(time.Millisecond)
	if err := r2.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-fired:
	case <-time.After(time.Second):
		t.Fatal("OnMessage never fired")
	}
	mu.Lock()
	if len(got) != 1 || got[0] != "hello from alice" {
		mu.Unlock()
		t.Fatalf("unexpected messages: %v", got)
	}
	mu.Unlock()
}

func TestRoomDedupAcrossPolls(t *testing.T) {
	r1, r2, _, clk := twoRoom(t, time.Hour, 20)
	var count int
	r2.events.OnMessage = func(m Message) { count++ }

	r1.Send(context.Background(), "once") // ignore err; store confirmed
	clk.Advance(time.Millisecond)
	r2.Reconcile(context.Background()) // first sees the message
	clk.Advance(time.Millisecond)
	if err := r2.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Refresh should not re-deliver a message that was already seen.
	clk.Advance(time.Millisecond)
	if err := r2.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected exactly one delivery, got %d", count)
	}
}

func TestRoomWindowKeepsTopN(t *testing.T) {
	N := 3
	ttl := 10 * time.Minute
	r1, r2, store, clk := twoRoom(t, ttl, N)

	// Batch 1: messages 0..2.
	for i := 0; i < 3; i++ {
		if _, err := r1.Send(context.Background(), fmt.Sprintf("msg-%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := r2.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Let a full TTL elapse (old messages have expired on their own).
	clk.Advance(ttl)

	// Batch 2: newer messages.
	for i := 3; i < 6; i++ {
		if _, err := r1.Send(context.Background(), fmt.Sprintf("msg-%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := r2.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Window is capped at N, newest last.
	if got := r2.Current(); len(got) != N || got[N-1].Text != "msg-5" {
		t.Fatalf("window should be top-N=%d with newest last, got %v", N, got)
	}

	// The old, non-refreshed batch is gone from the store; the new top-N lives.
	if n := store.Len(r1.Key()); n != N {
		t.Fatalf("expected %d live values, store has %d", N, n)
	}

	// Advancing a further TTL then reconciling should show nothing.
	clk.Advance(ttl)
	if n := store.Len(r1.Key()); n != 0 {
		t.Fatalf("store should be empty after TTL without refresh, got %d live", n)
	}
	if err := r2.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if i := len(r2.Current()); i != 0 {
		t.Fatalf("window should be empty after TTL without refresh, got %d", i)
	}
}

func TestRoomTTLExpiryRemovesValues(t *testing.T) {
	r1, r2, store, clk := twoRoom(t, 10*time.Minute, 20)
	r1.Send(context.Background(), "ephemeral")
	clk.Advance(time.Millisecond)
	r2.Reconcile(context.Background())
	if store.Len(r1.Key()) == 0 {
		t.Fatal("value should be present before TTL")
	}
	// Advance past TTL without any refresh and confirm it expires.
	clk.Advance(11 * time.Minute)
	if store.Len(r1.Key()) != 0 {
		t.Fatal("value should expire after TTL")
	}
	if err := r2.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(r2.Current()) != 0 {
		t.Fatal("window should be empty after expiry")
	}
}

func TestReliableStoreConfirmsPut(t *testing.T) {
	store := NewMockStore(time.Hour, nil)
	rel := storeReliable(store)
	if err := rel.Publish(context.Background(), "k", Value("v1")); err != nil {
		t.Fatal(err)
	}
	got, _ := store.Get(context.Background(), "k")
	if len(got) != 1 || string(got[0]) != "v1" {
		t.Fatalf("confirm-get failed: %v", got)
	}
}

func storeReliable(s Store) *ReliableStore {
	return NewReliable(s, WithRetries(2, time.Millisecond))
}
