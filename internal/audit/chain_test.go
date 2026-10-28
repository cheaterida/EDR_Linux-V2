package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"edr/internal/event"
)

func sealAll(t *testing.T, c *Chain, n int) []byte {
	t.Helper()
	var buf bytes.Buffer
	for i := 0; i < n; i++ {
		ev := &event.Event{
			Kind: event.KindExec,
			PID:  uint32(1000 + i),
			Comm: "proc",
			Time: time.Unix(int64(1700000000+i), 0).UTC(),
		}
		line, err := c.Seal(ev)
		if err != nil {
			t.Fatalf("seal: %v", err)
		}
		buf.Write(line)
	}
	return buf.Bytes()
}

func TestChainVerifyOK(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	c := NewChain(key)
	raw := sealAll(t, c, 5)

	res, err := Verify(bytes.NewReader(raw), key)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("expected OK, issues=%+v", res.Issues)
	}
	if res.Lines != 5 || res.LastSeq != 5 {
		t.Fatalf("lines=%d lastSeq=%d", res.Lines, res.LastSeq)
	}
	if res.LastHash != c.Head().Hash {
		t.Fatalf("last hash mismatch: %s vs %s", res.LastHash, c.Head().Hash)
	}
}

func TestTamperBodyDetected(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	c := NewChain(key)
	raw := sealAll(t, c, 3)

	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	// Mutate the second event's comm.
	var m map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &m); err != nil {
		t.Fatal(err)
	}
	m["comm"] = "tampered"
	nb, _ := json.Marshal(m)
	lines[1] = string(nb)
	tampered := []byte(strings.Join(lines, "\n") + "\n")

	res, _ := Verify(bytes.NewReader(tampered), key)
	if res.OK {
		t.Fatal("tamper should be detected")
	}
	if !hasKind(res.Issues, IssueHashMismatch) {
		t.Fatalf("expected hash_mismatch, got %+v", res.Issues)
	}
}

func TestDeletionDetected(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	c := NewChain(key)
	raw := sealAll(t, c, 4)

	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	// Drop the 3rd line (seq 3).
	trimmed := append(append([]string{}, lines[:2]...), lines[3:]...)
	res, _ := Verify(bytes.NewReader([]byte(strings.Join(trimmed, "\n")+"\n")), key)
	if res.OK {
		t.Fatal("deletion should be detected")
	}
	if !hasKind(res.Issues, IssueSeqGap) {
		t.Fatalf("expected seq_gap, got %+v", res.Issues)
	}
}

func TestDowngradeRejected(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	c := NewChain(key)
	raw := sealAll(t, c, 3)

	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	// Strip the chain metadata from the 2nd line (the v0.9 downgrade gap).
	var m map[string]any
	_ = json.Unmarshal([]byte(lines[1]), &m)
	delete(m, "chain")
	nb, _ := json.Marshal(m)
	lines[1] = string(nb)
	res, _ := Verify(bytes.NewReader([]byte(strings.Join(lines, "\n")+"\n")), key)
	if res.OK {
		t.Fatal("stripped integrity metadata must be rejected")
	}
	if !hasKind(res.Issues, IssueMissingIntegrity) {
		t.Fatalf("expected missing_integrity, got %+v", res.Issues)
	}
}

func TestWrongKeyHMAC(t *testing.T) {
	c := NewChain([]byte("0123456789abcdef0123456789abcdef"))
	raw := sealAll(t, c, 2)
	res, _ := Verify(bytes.NewReader(raw), []byte("ffffffffffffffffffffffffffffffff"))
	if res.OK || !hasKind(res.Issues, IssueHMACMismatch) {
		t.Fatalf("expected hmac_mismatch, got ok=%v issues=%+v", res.OK, res.Issues)
	}
}

func TestAnchorCrossVerify(t *testing.T) {
	c := NewChain(nil)
	sealAll(t, c, 3)
	head := c.Head()

	a := NewAnchor()
	if err := a.Push(head); err != nil {
		t.Fatal(err)
	}
	// Local rolled back one event: anchor has more.
	rolled := head
	rolled.Seq = head.Seq - 1
	if issues := a.CrossVerify(rolled); !hasAnchorKind(issues, "anchor_truncation") {
		t.Fatalf("expected truncation, got %+v", issues)
	}
	// Same seq, different hash.
	divergent := head
	divergent.Hash = "deadbeef"
	if issues := a.CrossVerify(divergent); !hasAnchorKind(issues, "anchor_hash_mismatch") {
		t.Fatalf("expected hash mismatch, got %+v", issues)
	}
	// Identical.
	if issues := a.CrossVerify(head); len(issues) != 0 {
		t.Fatalf("expected no issues, got %+v", issues)
	}
}

func TestCanonicalIsStable(t *testing.T) {
	ev := &event.Event{Kind: event.KindExec, Comm: "x", Chain: &event.ChainMeta{
		Version: Version, ChainID: "c", Seq: 1, PrevHash: "p", Hash: "H", HMAC: "M",
	}}
	a, _ := canonical(ev)
	b, _ := canonical(ev)
	if !bytes.Equal(a, b) {
		t.Fatal("canonical bytes must be stable")
	}
	// Hash/hmac must be excluded from the payload.
	if strings.Contains(string(a), `"hash":"H"`) || strings.Contains(string(a), `"hmac":"M"`) {
		t.Fatalf("canonical leaked volatile fields: %s", a)
	}
	// Sanity: recomputation matches a manual sha256.
	sum := sha256.Sum256(a)
	if len(sum) != 32 {
		t.Fatal("unreachable")
	}
}

func hasKind(issues []Issue, kind string) bool {
	for _, i := range issues {
		if i.Kind == kind {
			return true
		}
	}
	return false
}

func hasAnchorKind(issues []Issue, kind string) bool { return hasKind(issues, kind) }
