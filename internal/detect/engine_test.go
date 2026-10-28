package detect

import (
	"testing"

	"edr/internal/event"
	"edr/internal/policy"
)

func build(t *testing.T, rules ...policy.Rule) *Engine {
	t.Helper()
	p := &policy.Policy{SchemaVersion: policy.SchemaVersion, Rules: rules}
	if err := p.Validate(); err != nil {
		t.Fatalf("policy invalid: %v", err)
	}
	return New(p)
}

func execEv(comm, exe string) *event.Event {
	return &event.Event{
		Kind: event.KindExec,
		PID:  100,
		Comm: comm,
		Proc: &event.ProcInfo{Exe: exe, Cmdline: []string{exe, "--flag"}},
	}
}

func TestIndexOnlyEvaluatesRelevantKind(t *testing.T) {
	e := build(t, policy.Rule{
		ID: "curl", Category: policy.CategoryProcess, Severity: "high",
		Decision: policy.DecisionBlock, Action: policy.ActionKill,
		When: &policy.Node{Op: policy.OpEq, Field: policy.FieldProcessName, Value: "curl"},
	})
	// A file event must not match a process rule.
	if got := e.Match(&event.Event{Kind: event.KindFileOp, File: &event.FileInfo{Path: "/x"}}); len(got) != 0 {
		t.Fatalf("file event matched process rule: %v", got)
	}
	if got := e.Match(execEv("curl", "/usr/bin/curl")); len(got) != 1 {
		t.Fatalf("expected 1 match, got %d", len(got))
	}
}

func TestAndOrNot(t *testing.T) {
	rule := policy.Rule{
		ID: "complex", Category: policy.CategoryProcess, Severity: "high",
		Decision: policy.DecisionAlert, Action: policy.ActionLog,
		When: &policy.Node{Op: policy.OpAnd, Args: []policy.Node{
			{Op: policy.OpEq, Field: policy.FieldProcessName, Value: "nc"},
			{Op: policy.OpNot, Args: []policy.Node{
				{Op: policy.OpContains, Field: policy.FieldCmdline, Value: "127.0.0.1"},
			}},
		}},
	}
	e := build(t, rule)
	if got := e.Match(execEv("nc", "/usr/bin/nc")); len(got) != 1 {
		t.Fatalf("expected match for nc without loopback, got %d", len(got))
	}
	ev := execEv("nc", "/usr/bin/nc")
	ev.Proc.Cmdline = []string{"nc", "127.0.0.1", "22"}
	if got := e.Match(ev); len(got) != 0 {
		t.Fatalf("NOT guard should suppress match, got %d", len(got))
	}
}

func TestAllowOverride(t *testing.T) {
	rule := policy.Rule{
		ID: "block-curl", Category: policy.CategoryProcess, Severity: "high",
		Decision: policy.DecisionBlock, Action: policy.ActionKill,
		When:  &policy.Node{Op: policy.OpEq, Field: policy.FieldProcessName, Value: "curl"},
		Allow: &policy.Node{Op: policy.OpContains, Field: policy.FieldCmdline, Value: "trusted"},
	}
	e := build(t, rule)
	plain := e.Match(execEv("curl", "/usr/bin/curl"))
	if len(plain) != 1 || plain[0].Decision != policy.DecisionBlock {
		t.Fatalf("expected block, got %+v", plain)
	}
	allowed := execEv("curl", "/usr/bin/curl")
	allowed.Proc.Cmdline = []string{"curl", "trusted.example"}
	got := e.Match(allowed)
	if len(got) != 1 || got[0].Decision != policy.DecisionAllow || got[0].Action != policy.ActionNone {
		t.Fatalf("expected allow override, got %+v", got)
	}
}

func TestRegexAndNumeric(t *testing.T) {
	e := build(t,
		policy.Rule{
			ID: "re", Category: policy.CategoryFile, Severity: "high",
			Decision: policy.DecisionAlert, Action: policy.ActionLog,
			When: &policy.Node{Op: policy.OpRegex, Field: policy.FieldFilePath, Value: `^/tmp/.*\.sh$`},
		},
		policy.Rule{
			ID: "port", Category: policy.CategoryNetwork, Severity: "high",
			Decision: policy.DecisionAlert, Action: policy.ActionLog,
			When: &policy.Node{Op: policy.OpGt, Field: policy.FieldLocalPort, Value: "1024"},
		},
	)
	if got := e.Match(&event.Event{Kind: event.KindFileOp, File: &event.FileInfo{Path: "/tmp/x.sh"}}); len(got) != 1 {
		t.Fatalf("regex should match, got %d", len(got))
	}
	if got := e.Match(&event.Event{Kind: event.KindConnect, Net: &event.NetInfo{LocalPort: 80}}); len(got) != 0 {
		t.Fatalf("port 80 should not match gt 1024, got %d", len(got))
	}
	if got := e.Match(&event.Event{Kind: event.KindConnect, Net: &event.NetInfo{LocalPort: 8080}}); len(got) != 1 {
		t.Fatalf("port 8080 should match gt 1024, got %d", len(got))
	}
}

func TestPriorityOrder(t *testing.T) {
	e := build(t,
		policy.Rule{ID: "low-first", Priority: 20, Category: policy.CategoryProcess, Severity: "low",
			Decision: policy.DecisionAlert, Action: policy.ActionLog,
			When: &policy.Node{Op: policy.OpEq, Field: policy.FieldProcessName, Value: "nc"}},
		policy.Rule{ID: "high-first", Priority: 5, Category: policy.CategoryProcess, Severity: "high",
			Decision: policy.DecisionBlock, Action: policy.ActionKill,
			When: &policy.Node{Op: policy.OpEq, Field: policy.FieldProcessName, Value: "nc"}},
	)
	got := e.Match(execEv("nc", "/usr/bin/nc"))
	if len(got) != 2 || got[0].ID != "high-first" {
		t.Fatalf("priority order wrong: %+v", got)
	}
	resp, _ := policy.AggregatedDecision(got)
	if resp == nil || resp.ID != "high-first" {
		t.Fatalf("response rule should be highest priority: %+v", resp)
	}
}
