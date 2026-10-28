package detect

import (
	"testing"

	"edr/internal/event"
	"edr/internal/policy"
)

func seqPolicy(t *testing.T, samePID bool) *policy.Policy {
	t.Helper()
	p := &policy.Policy{
		SchemaVersion: policy.SchemaVersion,
		Sequences: []policy.SequenceRule{{
			ID: "SEQ-DROP-EXEC", Category: policy.CategoryProcess, Severity: "critical",
			Decision: policy.DecisionAlert, Action: policy.ActionLog,
			WithinSec: 60, SamePID: samePID,
			Stages: []policy.Node{
				{Op: policy.OpEq, Field: policy.FieldProcessName, Value: "curl"},
				{Op: policy.OpEq, Field: policy.FieldProcessName, Value: "bash"},
			},
		}},
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("invalid sequence policy: %v", err)
	}
	return p
}

func execNamed(pid uint32, comm string) *event.Event {
	return &event.Event{Kind: event.KindExec, PID: pid, Comm: comm}
}

func TestSequenceFiresInOrder(t *testing.T) {
	p := seqPolicy(t, true)
	eng := New(p)
	seq := NewSequenceEngine()

	if got := seq.Observe(eng, p, execNamed(42, "curl")); len(got) != 0 {
		t.Fatalf("should not fire after stage 1: %v", got)
	}
	got := seq.Observe(eng, p, execNamed(42, "bash"))
	if len(got) != 1 || got[0].ID != "SEQ-DROP-EXEC" {
		t.Fatalf("expected sequence to fire, got %v", got)
	}
}

func TestSequenceOrderMatters(t *testing.T) {
	p := seqPolicy(t, true)
	eng := New(p)
	seq := NewSequenceEngine()
	seq.Observe(eng, p, execNamed(42, "bash"))
	if got := seq.Observe(eng, p, execNamed(42, "curl")); len(got) != 0 {
		t.Fatalf("reversed order must not fire: %v", got)
	}
}

func TestSequenceSamePIDIsolation(t *testing.T) {
	p := seqPolicy(t, true)
	eng := New(p)
	seq := NewSequenceEngine()
	seq.Observe(eng, p, execNamed(1, "curl"))
	if got := seq.Observe(eng, p, execNamed(2, "bash")); len(got) != 0 {
		t.Fatalf("different PIDs must not complete a same_pid chain: %v", got)
	}
}

func TestHolderReloadSwapsEngine(t *testing.T) {
	p := &policy.Policy{
		SchemaVersion: policy.SchemaVersion,
		Rules: []policy.Rule{{
			ID: "R1", Category: policy.CategoryProcess, Severity: "high",
			Decision: policy.DecisionBlock, Action: policy.ActionKill,
			When: &policy.Node{Op: policy.OpEq, Field: policy.FieldProcessName, Value: "nc"},
		}},
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	h := NewHolder(p)
	if len(h.Match(execNamed(1, "nc"))) != 1 {
		t.Fatal("expected match before reload")
	}
	// Reload with an empty rule set.
	empty := &policy.Policy{SchemaVersion: policy.SchemaVersion}
	if err := empty.Validate(); err != nil {
		t.Fatal(err)
	}
	h.Reload(empty)
	if len(h.Match(execNamed(1, "nc"))) != 0 {
		t.Fatal("engine not swapped on reload")
	}
}
