package audit

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"edr/internal/event"
)

func sealToFile(t *testing.T, c *Chain, path string, n int) []byte {
	t.Helper()
	var all []byte
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for i := 0; i < n; i++ {
		line, err := c.Seal(&event.Event{Kind: event.KindExec, PID: uint32(i + 1), Comm: "p"})
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, line...)
		if _, err := f.Write(line); err != nil {
			t.Fatal(err)
		}
	}
	return all
}

func TestVerifyFileAcrossRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	key := []byte("0123456789abcdef0123456789abcdef")
	c := NewChain(key)
	sealToFile(t, c, path, 3)
	// Rotate: current -> .1, continue writing a fresh file.
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	sealToFile(t, c, path, 3)

	res, err := VerifyFile(path, key)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("expected OK across rotation, issues=%+v", res.Issues)
	}
	if res.Lines != 6 || res.LastSeq != 6 {
		t.Fatalf("lines=%d lastSeq=%d", res.Lines, res.LastSeq)
	}
}

func TestVerifyFileDetectsTailTruncationViaAnchor(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	anchorPath := filepath.Join(dir, "anchor.json")
	key := []byte("0123456789abcdef0123456789abcdef")
	c := NewChain(key)
	sealToFile(t, c, path, 5)

	an := NewAnchorWithOptions(AnchorOptions{FilePath: anchorPath})
	if err := an.Push(c.Head()); err != nil {
		t.Fatal(err)
	}

	// Attacker truncates the last 2 events.
	raw, _ := os.ReadFile(path)
	lines := bytes.Split(bytes.TrimSpace(raw), []byte("\n"))
	truncated := bytes.Join(lines[:3], []byte("\n"))
	truncated = append(truncated, '\n')
	if err := os.WriteFile(path, truncated, 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := VerifyFile(path, key)
	if err != nil {
		t.Fatal(err)
	}
	// The remaining chain is internally consistent...
	if !res.OK {
		t.Fatalf("internal chain unexpectedly broken: %+v", res.Issues)
	}
	// ...but the anchor reveals the truncation.
	issues := an.CrossVerify(Head{ChainID: res.ChainID, Seq: res.LastSeq, Hash: res.LastHash})
	found := false
	for _, i := range issues {
		if i.Kind == "anchor_truncation" {
			found = true
		}
	}
	if !found {
		t.Fatalf("anchor did not detect truncation: %+v", issues)
	}
}

func TestFileSinkRotates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	s, err := NewFileSink(path, 64, 2)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		if _, err := s.Write([]byte("012345678901234567890123456789\n")); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatal("expected a rotated file .1")
	}
}
