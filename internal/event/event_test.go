package event

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestKindStringAndValid(t *testing.T) {
	if KindExec.String() != "exec" {
		t.Fatalf("KindExec.String() = %q", KindExec.String())
	}
	if !KindFileOp.Valid() {
		t.Fatal("KindFileOp should be valid")
	}
	if KindUnknown.Valid() {
		t.Fatal("KindUnknown should not be valid")
	}
	if !strings.HasPrefix(Kind(999).String(), "kind(") {
		t.Fatalf("unknown kind should be rendered generically, got %q", Kind(999).String())
	}
}

func TestEventRoundTrip(t *testing.T) {
	ev := &Event{
		Kind: KindExec,
		PID:  4321,
		Comm: "curl",
		Proc: &ProcInfo{
			Exe:        "/usr/bin/curl",
			Cmdline:    []string{"curl", "http://x"},
			CapEff:     0x1,
			StartTicks: 998877,
		},
		Detail: map[string]any{"argv0": "curl"},
	}
	ev.Normalize()
	if ev.SchemaVersion != SchemaVersion {
		t.Fatalf("schema version = %q", ev.SchemaVersion)
	}
	if ev.Time.IsZero() {
		t.Fatal("time should be normalized")
	}

	raw, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back Event
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.Kind != KindExec || back.Proc == nil || back.Proc.Exe != "/usr/bin/curl" {
		t.Fatalf("round trip mismatch: %+v", back)
	}
}

func TestNormalizeKeepsExistingTime(t *testing.T) {
	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ev := &Event{Time: ts}
	ev.Normalize()
	if !ev.Time.Equal(ts) {
		t.Fatalf("Normalize overwrote existing time: %v", ev.Time)
	}
}
