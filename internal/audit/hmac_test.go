package audit

import (
	"bytes"
	"testing"

	"edr/internal/event"
)

// TestHMACForgeryDetected verifies that a keyed chain rejects both a wrong key
// and a body modified without the key, which is the point of wiring HMAC.
func TestHMACForgeryDetected(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	ch := NewChain(key)
	line, err := ch.Seal(&event.Event{Kind: event.KindExec, PID: 7})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if res, _ := Verify(bytes.NewReader(line), key); !res.OK {
		t.Fatalf("valid keyed chain rejected: %+v", res.Issues)
	}
	wrong := []byte("ffffffffffffffffffffffffffffffff")
	if res, _ := Verify(bytes.NewReader(line), wrong); res.OK {
		t.Fatal("chain verified with the wrong key")
	}
	if res, _ := Verify(bytes.NewReader(line), nil); res.OK {
		t.Fatal("keyed chain verified without a key (should be hmac_unverified)")
	}
}
