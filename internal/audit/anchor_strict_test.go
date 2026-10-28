package audit

import (
	"os"
	"path/filepath"
	"testing"
)

// TestFetchStrictAnchorFile verifies the fail-closed behavior: a missing anchor
// is a legitimate first start, but a corrupt or empty one must be an error
// rather than silently starting a fresh chain.
func TestFetchStrictAnchorFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "anchor.json")
	a := NewAnchorWithOptions(AnchorOptions{FilePath: path})

	if _, ok, err := a.FetchStrict(); err != nil || ok {
		t.Fatalf("missing anchor: ok=%v err=%v", ok, err)
	}

	if err := os.WriteFile(path, []byte("{not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.FetchStrict(); err == nil {
		t.Fatal("corrupt anchor accepted")
	}

	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.FetchStrict(); err == nil {
		t.Fatal("empty anchor head accepted")
	}

	valid := `{"chain_id":"c1","seq":7,"hash":"abc","pushed_at":"2026-01-01T00:00:00Z"}`
	if err := os.WriteFile(path, []byte(valid), 0o600); err != nil {
		t.Fatal(err)
	}
	h, ok, err := a.FetchStrict()
	if err != nil || !ok || h == nil || h.ChainID != "c1" || h.Seq != 7 {
		t.Fatalf("valid anchor: h=%+v ok=%v err=%v", h, ok, err)
	}
}
