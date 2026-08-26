package engine

import (
	"context"
	"sync"
	"time"
)

// Room is the serverless-ntfy chat room. It owns the room key, the identity,
// and the reconcile loop (poll + refresh the top-N window). It is transport
// agnostic — it only talks to a *ReliableStore. Web and CLI are thin bindings.
type Room struct {
	token     string
	key       string   // public DHT key (roomKeyID)
	roomKey   [32]byte // secretbox key (DeriveRoomKey)
	me        *Identity
	name      string
	store     *ReliableStore
	windowN   int
	anyMember bool // refresh the whole window regardless of author

	seq int64 // monotonic, seeded random to avoid collide on restart

	mu          sync.Mutex
	seen        map[string]*Envelope // id -> last envelope (dedup)
	window      []*Envelope          // current top-N, oldest-first
	contactSeen map[PubKey]bool
	seqPtr      int64

	pollInterval time.Duration
	events       RoomEvents
}

type RoomEvents struct {
	OnMessage func(m Message)
	OnContact func(pk PubKey, name string)
}

type Message struct {
	ID       string
	Kind     string
	From     PubKey
	FromText string
	Name     string
	Seq      uint64
	TS       int64
	Text     string
	Verified bool
	Mine     bool
}

type RoomOption func(*Room)

func WithWindowSize(n int) RoomOption { return func(r *Room) { r.windowN = n } }
func WithAnyMember(b bool) RoomOption { return func(r *Room) { r.anyMember = b } }
func WithPollInterval(d time.Duration) RoomOption {
	return func(r *Room) { r.pollInterval = d }
}
func WithEvents(e RoomEvents) RoomOption { return func(r *Room) { r.events = e } }

func NewRoom(token string, me *Identity, name string, store *ReliableStore, opts ...RoomOption) *Room {
	r := &Room{
		token:        token,
		me:           me,
		name:         name,
		store:        store,
		windowN:      20,
		anyMember:    true,
		pollInterval: 60 * time.Second,
		seen:         make(map[string]*Envelope),
		window:       nil,
		contactSeen:  make(map[PubKey]bool),
		seq:          int64(time.Now().UnixNano()),
	}
	r.key = roomKeyID(token)
	r.roomKey = DeriveRoomKey(token)
	for _, o := range opts {
		o(r)
	}
	return r
}

func (r *Room) Key() string   { return r.key }
func (r *Room) Token() string { return r.token }

// SetEvents wires event callbacks (front-ends bind here after NewRoom).
func (r *Room) SetEvents(e RoomEvents) { r.events = e }

// Send publishes a signed, room-encrypted chat message with reliable
// put-confirm-refresh, returning its deterministic ID.
func (r *Room) Send(ctx context.Context, text string) (string, error) {
	r.mu.Lock()
	r.seq++
	seq := uint64(r.seq)
	r.mu.Unlock()

	env, err := NewEnvelope(r.me, r.name, r.token, r.roomKey, seq, time.Now().Unix(), text)
	if err != nil {
		return "", err
	}
	val, err := env.Marshal(r.roomKey)
	if err != nil {
		return "", err
	}
	if err := r.store.Publish(ctx, r.key, val); err != nil {
		return "", err
	}
	return env.ID(), nil
}

// Reconcile runs one poll: fetch, verify, decrypt, dedup, emit new messages
// (and newly-seen contacts), rebuild the top-N window, and refresh it to fight
// the store TTL. Call it on an interval (see Run).
func (r *Room) Reconcile(ctx context.Context) error {
	vals, err := r.store.Read(ctx, r.key)
	if err != nil {
		return err
	}

	envs := make([]*Envelope, 0, len(vals))
	for _, v := range vals {
		if e, err := DecodeEnvelope(r.roomKey, v); err == nil {
			envs = append(envs, e)
		}
	}
	envs = dedupeByID(envs)
	top := keepTop(envs, r.windowN)
	sortAscending(top)

	// Detect, in ascending order, what is new since last poll.
	r.mu.Lock()
	seen := r.seen
	contacts := r.contactSeen
	r.mu.Unlock()

	var newContacts []contactHit
	var newMsg []*Envelope
	for _, e := range top {
		if pk, err := e.SenderPK(); err == nil && !contacts[pk] {
			newContacts = append(newContacts, contactHit{pk: pk, name: e.Msg.Name})
		}
		if _, ok := seen[e.ID()]; !ok {
			newMsg = append(newMsg, e)
		}
	}

	// Commit dedup + window.
	r.mu.Lock()
	for _, e := range top {
		r.seen[e.ID()] = e
	}
	r.window = top
	for _, c := range newContacts {
		r.contactSeen[c.pk] = true
	}
	r.mu.Unlock()

	// Events outside the lock.
	for _, c := range newContacts {
		if r.events.OnContact != nil {
			r.events.OnContact(c.pk, c.name)
		}
	}
	for _, e := range newMsg {
		if m, ok := r.decode(e); ok && r.events.OnMessage != nil {
			r.events.OnMessage(m)
		}
	}

	// Refresh the kept window so it survives TTL expiry.
	var toRefresh []*Envelope
	if r.anyMember {
		toRefresh = top
	} else {
		for _, e := range top {
			if e.Msg.PK == r.me.PublicString() {
				toRefresh = append(toRefresh, e)
			}
		}
	}
	for _, e := range toRefresh {
		if val, err := e.Marshal(r.roomKey); err == nil {
			_ = r.store.Publish(ctx, r.key, val) // best-effort TTL refresh
		}
	}
	return nil
}

type contactHit struct {
	pk   PubKey
	name string
}

// Run drives Reconcile at pollInterval until ctx is done.
func (r *Room) Run(ctx context.Context) {
	go func() {
		t := time.NewTicker(r.pollInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				_ = r.Reconcile(ctx)
			}
		}
	}()
}

// Current returns a copy of the current window, oldest-first.
func (r *Room) Current() []Message {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Message, 0, len(r.window))
	for _, e := range r.window {
		if m, ok := r.decode(e); ok {
			out = append(out, m)
		}
	}
	return out
}

// HasSeen reports whether this message id has already been observed.
func (r *Room) HasSeen(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.seen[id]
	return ok
}

func (r *Room) PublicKey() PubKey { return r.me.Public() }

func (r *Room) decode(e *Envelope) (Message, bool) {
	verified, _ := e.Verify()
	text, err := e.Open(r.roomKey)
	if err != nil {
		return Message{}, false
	}
	pk, _ := e.SenderPK()
	return Message{
		ID:       e.ID(),
		Kind:     e.Msg.Kind,
		From:     pk,
		FromText: shortAddr(pk),
		Name:     e.Msg.Name,
		Seq:      e.Msg.Seq,
		TS:       e.Msg.TS,
		Text:     text,
		Verified: verified,
		Mine:     e.Msg.PK == r.me.PublicString(),
	}, true
}

func shortAddr(pk PubKey) string {
	s := b64(pk[:])
	if len(s) > 8 {
		s = s[:8]
	}
	return "…" + s
}

// ShortAddr returns a short human-readable form of a pubkey for display.
func ShortAddr(pk PubKey) string { return shortAddr(pk) }

// PubKeyString returns the full base64 form of a public key.
func PubKeyString(pk PubKey) string { return b64(pk[:]) }
