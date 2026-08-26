package engine

import (
	"context"
	"sync"
	"time"
)

// MockStore is an in-memory Store that mimics the load-bearing parts of a DHT:
// a key holds a set of values, every value has a TTL and expires, and calls
// happen against an injectable clock so tests can advance time without waiting.
// It is the transport used by unit tests and by the CLI when run with no
// backend, mirroring "someone else runs the DHT".
type MockStore struct {
	mu     sync.Mutex
	now    func() time.Time
	ttl    time.Duration
	values map[string][]entryValue // key -> values (live set)
}

type entryValue struct {
	v   Value
	exp time.Time
}

// NewMockStore returns a MockStore with the given TTL (OpenDHT-mandated TTL
// in production; tests pass what they like).
func NewMockStore(ttl time.Duration, now func() time.Time) *MockStore {
	if now == nil {
		now = time.Now
	}
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	return &MockStore{
		now:    now,
		ttl:    ttl,
		values: make(map[string][]entryValue),
	}
}

func (m *MockStore) Get(_ context.Context, key string) ([]Value, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.purgeLocked(key)
	out := make([]Value, 0, len(m.values[key]))
	for _, e := range m.values[key] {
		out = append(out, e.v)
	}
	return out, nil
}

// Put replaces the value under key. Like a DHT it accepts any Value and adds
// it to the set (a refresh with identical bytes is idempotent-in-effect).
func (m *MockStore) Put(_ context.Context, key string, v Value) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.purgeLocked(key)
	now := m.now()
	var replaced bool
	for i := range m.values[key] {
		if string(m.values[key][i].v) == string(v) {
			m.values[key][i].exp = now.Add(m.ttl) // refresh existing TTL
			replaced = true
			break
		}
	}
	if !replaced {
		m.values[key] = append(m.values[key], entryValue{v: append(Value(nil), v...), exp: now.Add(m.ttl)})
	}
	return nil
}

// Delete removes a specific identical value (best-effort; DHTs may not offer it).
func (m *MockStore) Delete(_ context.Context, key string, v Value) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur := m.values[key]
	out := cur[:0]
	for _, e := range cur {
		if string(e.v) != string(v) {
			out = append(out, e)
		}
	}
	m.values[key] = out
	return nil
}

// Len returns the live value count for a key (test helper).
func (m *MockStore) Len(key string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.purgeLocked(key)
	return len(m.values[key])
}

func (m *MockStore) purgeLocked(key string) {
	now := m.now()
	cur := m.values[key]
	out := cur[:0]
	for _, e := range cur {
		if e.exp.After(now) {
			out = append(out, e)
		}
	}
	if len(out) == 0 {
		delete(m.values, key)
	} else {
		m.values[key] = out
	}
}
