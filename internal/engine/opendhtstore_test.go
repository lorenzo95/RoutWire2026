package engine

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeProxy simulates the OpenDHT REST proxy: a key holds NDJSON entries,
// each {"data": b64( {"magic","ts","data": b64(value)} )}.
type fakeProxy struct {
	mu    sync.Mutex
	store map[string][]dhtInner
}

func newFakeProxy() *fakeProxy {
	return &fakeProxy{store: map[string][]dhtInner{}}
}

func (p *fakeProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	path := strings.TrimPrefix(r.URL.Path, "/key/")
	key := path

	switch r.Method {
	case http.MethodGet:
		var b strings.Builder
		for _, inner := range p.store[key] {
			raw, _ := json.Marshal(dhtOuter{Data: b64(mustMarshal(inner))})
			b.Write(raw)
			b.WriteByte('\n')
		}
		w.Write([]byte(b.String()))
	case http.MethodPut, http.MethodPost:
		var outer dhtOuter
		if err := json.NewDecoder(r.Body).Decode(&outer); err != nil {
			w.WriteHeader(400)
			return
		}
		innerBytes, err := base64.StdEncoding.DecodeString(outer.Data)
		if err != nil {
			w.WriteHeader(400)
			return
		}
		var inner dhtInner
		if json.Unmarshal(innerBytes, &inner) != nil {
			w.WriteHeader(400)
			return
		}
		p.store[key] = append(p.store[key], inner)
		w.WriteHeader(204)
	default:
		w.WriteHeader(405)
	}
}

func mustMarshal(v interface{}) []byte {
	b, _ := json.Marshal(v)
	return b
}

func TestOpenDHTRoundTrip(t *testing.T) {
	p := newFakeProxy()
	srv := httptest.NewServer(p)
	defer srv.Close()

	store := NewOpenDHT([]string{srv.URL})
	key := "aabbccddeeff00112233445566778899aabbccdd" // 40 hex

	if err := store.Put(context.Background(), key, Value("message-one")); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(context.Background(), key, Value("message-two")); err != nil {
		t.Fatal(err)
	}

	got, err := store.Get(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 values, got %d: %v", len(got), got)
	}
	if string(got[0]) != "message-one" || string(got[1]) != "message-two" {
		t.Fatalf("unexpected values: %q", got)
	}
}

func TestOpenDHTFiltersForeignMagic(t *testing.T) {
	p := newFakeProxy()
	// Inject a foreign entry (e.g. stunmesh, our different magic) under the key.
	p.mu.Lock()
	p.store["aabbccddeeff00112233445566778899aabbccdd"] = []dhtInner{
		{Magic: "some-other-app", TS: 1, Data: b64([]byte("nope"))},
	}
	p.mu.Unlock()

	srv := httptest.NewServer(p)
	defer srv.Close()
	store := NewOpenDHT([]string{srv.URL})
	got, err := store.Get(context.Background(), "aabbccddeeff00112233445566778899aabbccdd")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("foreign magic entries must be filtered, got %d", len(got))
	}
}

func TestOpenDHTRejectsInvalidKey(t *testing.T) {
	store := NewOpenDHT([]string{"http://localhost:1"})
	if _, err := store.Get(context.Background(), "short"); err != ErrInvalidKey {
		t.Fatalf("expected ErrInvalidKey, got %v", err)
	}
}

func TestOpenDHTFailsOverEndpoints(t *testing.T) {
	p := newFakeProxy()
	srv := httptest.NewServer(p)
	defer srv.Close()
	meh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", 500)
	}))
	defer meh.Close()

	store := NewOpenDHT([]string{meh.URL, srv.URL})
	key := "aabbccddeeff00112233445566778899aabbccdd"
	if err := store.Put(context.Background(), key, Value("ok")); err != nil {
		t.Fatalf("should fail over to healthy proxy: %v", err)
	}
	got, err := store.Get(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || string(got[0]) != "ok" {
		t.Fatalf("unexpected: %v", got)
	}
}
