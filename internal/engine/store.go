package engine

import (
	"bytes"
	"context"
	"errors"
	"log"
	"time"
)

// Value is an opaque blob stored under a key. For a chat room the value is a
// serialized Envelope; the store never inspects or understands it, so it is
// safe for storage operators to see.
type Value []byte

// Store is the raw key-value substrate the engine is built on. Concrete
// backends are OpenDHT (via the Jami proxies), a Cloudflare DNS plugin, a
// Nostr relay adapter, or the in-memory MockStore used in tests. Everything
// above this line is transport-agnostic.
type Store interface {
	// Get returns every value currently stored under key (a key holds a set).
	Get(ctx context.Context, key string) ([]Value, error)
	// Put adds value under key. It must not validate or mutate value.
	Put(ctx context.Context, key string, v Value) error
}

var (
	ErrNotStored    = errors.New("value could not be confirmed in store")
	ErrNotPublished = errors.New("value not confirmed after retries")
	ErrUnavailable  = errors.New("store unavailable")
	ErrInvalidKey   = errors.New("invalid key")
	ErrInvalidValue = errors.New("invalid value")
)

// Server stores internally implement Delete to best-effort remove a message
// when it is acknowledged. Absent TTL semantics make it optional.
type Deleter interface {
	Delete(ctx context.Context, key string, v Value) error
}

// ReliableStore decorates a raw Store with the reliability contract from the
// design: Put then confirm via Get, retry with backoff on failure, and never
// report success until the value is actually visible from our own vantage.
// Persistence over the TTL horizon is the caller's job (see Room.refresh).
type ReliableStore struct {
	raw Store
	// maxRetries is how many confirm attempts happen after the initial Put.
	maxRetries int
	retryDelay time.Duration
	logger     *log.Logger
}

// NewReliable returns a ReliableStore wrapping raw.
func NewReliable(raw Store, opts ...ReliableOption) *ReliableStore {
	r := &ReliableStore{
		raw:        raw,
		maxRetries: 3,
		retryDelay: 200 * time.Millisecond,
		logger:     log.Default(),
	}
	for _, o := range opts {
		o(r)
	}
	return r
}

type ReliableOption func(*ReliableStore)

func WithRetries(n int, delay time.Duration) ReliableOption {
	return func(r *ReliableStore) {
		r.maxRetries = n
		r.retryDelay = delay
	}
}

func WithLogger(l *log.Logger) ReliableOption { return func(r *ReliableStore) { r.logger = l } }

// Publish performs the put-then-confirm-get loop and returns an error only if
// the value could not be confirmed to be present after retries.
func (r *ReliableStore) Publish(ctx context.Context, key string, v Value) error {
	for attempt := 0; ; attempt++ {
		if err := r.raw.Put(ctx, key, v); err != nil {
			r.logger.Printf("relstore: put unavailable (key=%s attempt=%d): %v", key, attempt, err)
			if attempt >= r.maxRetries {
				return ErrUnavailable
			}
			if err := sleep(ctx, r.retryDelay); err != nil {
				return err
			}
			continue
		}
		// Confirm the value is now visible from our vantage, with backoff.
		ok, err := r.confirm(ctx, key, v)
		if err == nil && ok {
			return nil
		}
		if attempt >= r.maxRetries {
			return ErrNotPublished
		}
		if err := sleep(ctx, r.retryDelay); err != nil {
			return err
		}
	}
}

func (r *ReliableStore) confirm(ctx context.Context, key string, v Value) (bool, error) {
	got, err := r.raw.Get(ctx, key)
	if err != nil {
		return false, err
	}
	for _, g := range got {
		if bytes.Equal(g, v) {
			return true, nil
		}
	}
	return false, nil
}

// Read returns the set of values under key (the unconfirmed analogue of Get).
func (r *ReliableStore) Read(ctx context.Context, key string) ([]Value, error) {
	return r.raw.Get(ctx, key)
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// WithContext is a small helper used by the reconciler.
func WithContext(ctx context.Context, d time.Duration) error { return sleep(ctx, d) }
