package engine

import (
	"bytes"
	"strings"
	"testing"
)

func TestSealUnsealRoundTrip(t *testing.T) {
	key := DeriveRoomKey("room-secret-1")
	sealed, err := sealRoom(key, []byte("hello world"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := unsealRoom(key, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello world" {
		t.Fatalf("round trip mismatch: %q", got)
	}
}

func TestUnsealWrongKey(t *testing.T) {
	sealed, _ := sealRoom(DeriveRoomKey("a"), []byte("secret"))
	if _, err := unsealRoom(DeriveRoomKey("b"), sealed); err == nil {
		t.Fatal("expected error unsealing with wrong key")
	}
}

func TestSignVerify(t *testing.T) {
	me, _ := NewIdentity()
	sig := me.Sign([]byte("data"))
	if !VerifySig(me.Public(), []byte("data"), sig) {
		t.Fatal("valid signature rejected")
	}
	if VerifySig(me.Public(), []byte("tampered"), sig) {
		t.Fatal("tampered data accepted")
	}
	sig[0] ^= 0xff
	if VerifySig(me.Public(), []byte("data"), sig) {
		t.Fatal("tampered signature accepted")
	}
}

func TestEnvelopeRoundTripVerifyAndOpen(t *testing.T) {
	me, _ := NewIdentity()
	key := DeriveRoomKey("room")
	env, err := NewEnvelope(me, "Alice", "room", key, 7, 1234, "ping")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := env.Marshal(key)
	if err != nil {
		t.Fatal(err)
	}
	// transport round-trip: decode fresh from bytes
	dec, err := DecodeEnvelope(key, raw)
	if err != nil {
		t.Fatal(err)
	}
	if dec.ID() != env.ID() {
		t.Fatalf("id mismatch: %s vs %s", dec.ID(), env.ID())
	}
	if !strings.HasSuffix(dec.ID(), "#7") {
		t.Fatalf("id should include seq: %s", dec.ID())
	}
	ok, err := dec.Verify()
	if err != nil || !ok {
		t.Fatalf("signature verify failed: ok=%v err=%v", ok, err)
	}
	text, err := dec.Open(key)
	if err != nil {
		t.Fatal(err)
	}
	if text != "ping" {
		t.Fatalf("decrypt mismatch: %q", text)
	}
}

func TestEnvelopeTamperFailsVerify(t *testing.T) {
	me, _ := NewIdentity()
	key := DeriveRoomKey("room")
	env, _ := NewEnvelope(me, "Bob", "room", key, 1, 1, "msg")
	raw, _ := env.Marshal(key)
	dec, _ := DecodeEnvelope(key, raw)
	// tamper with the sealed payload after the fact
	dec.Msg.Box = strings.ReplaceAll(dec.Msg.Box, "A", "B") + "\u0000"
	ok, _ := dec.Verify()
	if ok {
		t.Fatal("tampered envelope still verified")
	}
}

func TestEnvelopeMarshalIsOpaque(t *testing.T) {
	me, _ := NewIdentity()
	key := DeriveRoomKey("room")
	env, _ := NewEnvelope(me, "Alice", "room", key, 7, 1234, "sensitive message body")
	raw, err := env.Marshal(key)
	if err != nil {
		t.Fatal(err)
	}
	// The stored blob must reveal nothing about the message, sender, or room.
	for _, needle := range []string{"Alice", "room", "sensitive", "chat", "msg"} {
		if bytes.Contains(raw, []byte(needle)) {
			t.Fatalf("sealed envelope leaks %q: %s", needle, raw)
		}
	}
	// Deterministic: re-marshaling the same envelope yields identical bytes.
	raw2, _ := env.Marshal(key)
	if !bytes.Equal(raw, raw2) {
		t.Fatal("envelope sealing must be deterministic for dedup/refresh")
	}
}

func TestMessageIDDeterministic(t *testing.T) {
	me, _ := NewIdentity()
	k1 := DeriveRoomKey("room")
	k2 := DeriveRoomKey("anotherroom")
	a, _ := NewEnvelope(me, "x", "room", k1, 3, 1, "a")
	b, _ := NewEnvelope(me, "x", "room2", k2, 3, 1, "b")
	if a.ID() != b.ID() {
		t.Fatal("message id should depend only on sender+seq")
	}
	// different seq differs
	c, _ := NewEnvelope(me, "x", "room", k1, 4, 1, "c")
	if a.ID() == c.ID() {
		t.Fatal("message id should change with seq")
	}
}
