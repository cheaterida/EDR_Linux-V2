package capmatrix

import (
	"bytes"
	"strings"
	"testing"
)

func TestRenderAndCounts(t *testing.T) {
	r := New()
	r.Check("a", true, "ok")
	r.Check("b", false, "bad | pipe")
	if r.AllPassed() {
		t.Fatal("AllPassed should be false")
	}
	var buf bytes.Buffer
	if err := r.Render(&buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "Total: **2**") {
		t.Fatalf("missing total: %s", out)
	}
	if !strings.Contains(out, "| a | PASS |") {
		t.Fatalf("missing pass row: %s", out)
	}
	if !strings.Contains(out, `\|`) {
		t.Fatalf("pipe should be escaped: %s", out)
	}
}
