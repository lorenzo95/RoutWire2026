package engine

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// OpenDHT implements Store over the public OpenDHT REST proxies that
// Savoir-faire Linux run for Jami (e.g. https://dhtproxy2.jami.net) — the same
// proxies stunmesh-go's contrib/opendht plugin targets. This is what makes the
// system "serverless": the DHT itself is the rendezvous; nobody runs a node.
//
// Wire format (matching contrib/opendht.sh):
//
//	get:  GET  /key/<key> → NDJSON, each line {"data": b64(inner)}
//	      inner = {"magic":..,"ts":..,"data": b64(<Value>)}
//	put:  PUT  /key/<key> body {"data": b64(inner)}
//
// Only 40-hex InfoHash keys are valid (roomKeyID already produces those).
type OpenDHT struct {
	base    []string
	magic   string
	client  *http.Client
	timeout time.Duration
}

var _ Store = (*OpenDHT)(nil)

func NewOpenDHT(endpoints []string, opts ...OpenDHTOption) *OpenDHT {
	o := &OpenDHT{
		magic:   "stunmeshchat-v1",
		base:    []string{},
		timeout: 15 * time.Second,
	}
	for _, e := range endpoints {
		o.base = append(o.base, strings.TrimRight(strings.TrimSpace(e), "/"))
	}
	for _, opt := range opts {
		opt(o)
	}
	o.client = &http.Client{Timeout: o.timeout}
	return o
}

type OpenDHTOption func(*OpenDHT)

func WithMagic(m string) OpenDHTOption { return func(o *OpenDHT) { o.magic = m } }
func WithTimeTo(d time.Duration) OpenDHTOption {
	return func(o *OpenDHT) { o.timeout = d }
}

type dhtOuter struct {
	Data string `json:"data"`
}

type dhtInner struct {
	Magic string `json:"magic"`
	TS    int64  `json:"ts"`
	Data  string `json:"data"`
}

// Get returns every live, magic-matching value under key.
func (o *OpenDHT) Get(ctx context.Context, key string) ([]Value, error) {
	if err := checkInfoHash(key); err != nil {
		return nil, err
	}
	body, err := o.raw(ctx, http.MethodGet, key, nil)
	if err != nil {
		return nil, err
	}
	return o.decodeBody(body)
}

// Put publishes a value under key.
func (o *OpenDHT) Put(ctx context.Context, key string, v Value) error {
	if err := checkInfoHash(key); err != nil {
		return err
	}
	inner, err := json.Marshal(dhtInner{Magic: o.magic, TS: time.Now().Unix(), Data: b64(v)})
	if err != nil {
		return err
	}
	payload, err := json.Marshal(dhtOuter{Data: b64(inner)})
	if err != nil {
		return err
	}
	_, err = o.raw(ctx, http.MethodPost, key, payload)
	return err
}

func (o *OpenDHT) raw(ctx context.Context, method, key string, body []byte) ([]byte, error) {
	var lastErr error
	for _, ep := range o.base {
		u := ep + "/key/" + key
		req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := o.client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		got, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if readErr != nil {
			lastErr = readErr
			continue
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return got, nil
		}
		lastErr = fmt.Errorf("proxy %s: %d", ep, resp.StatusCode)
	}
	if lastErr == nil {
		lastErr = ErrUnavailable
	}
	return nil, lastErr
}

// decodeBody parses the NDJSON response into decoded Values.
func (o *OpenDHT) decodeBody(body []byte) ([]Value, error) {
	var out []Value
	sc := bufio.NewScanner(bytes.NewReader(body))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var outer dhtOuter
		if json.Unmarshal([]byte(line), &outer) != nil {
			continue
		}
		innerBytes, err := b64dec(outer.Data)
		if err != nil {
			continue
		}
		var inner dhtInner
		if json.Unmarshal(innerBytes, &inner) != nil {
			continue
		}
		if inner.Magic != o.magic {
			continue
		}
		val, err := base64.StdEncoding.DecodeString(inner.Data)
		if err != nil {
			continue
		}
		out = append(out, Value(val))
	}
	return out, nil
}

// checkInfoHash validates a 40-hex InfoHash key (proxy constraint).
func checkInfoHash(key string) error {
	if len(key) != 40 {
		return ErrInvalidKey
	}
	for _, c := range key {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return ErrInvalidKey
		}
	}
	return nil
}
