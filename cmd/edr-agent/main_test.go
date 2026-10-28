package main

import (
	"bytes"
	"testing"

	"edr/internal/audit"
	"edr/internal/event"
	"edr/internal/respond"
)

// TestRespondStageSealsVerifiable guards the audit-chain contract: an event
// carrying response_result must survive seal -> JSON round-trip -> verify with
// an identical hash. Storing the Result struct (whose field order differs from
// alphabetical) made the canonical bytes differ after unmarshal and broke
// chain verification.
func TestRespondStageSealsVerifiable(t *testing.T) {
	ev := &event.Event{
		Kind:   event.KindExec,
		PID:    4242,
		Detail: map[string]any{"response_action": respond.ActionKill, "response_rule": "T-RULE"},
	}
	ev.Normalize()

	st := respondStage{r: &respond.Local{DryRun: true}}
	if _, err := st.Handle(ev); err != nil {
		t.Fatalf("respond stage: %v", err)
	}
	if _, ok := ev.Detail["response_result"].(map[string]any); !ok {
		t.Fatalf("response_result must be a map, got %T", ev.Detail["response_result"])
	}

	ch := audit.NewChain(nil)
	line, err := ch.Seal(ev)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	res, err := audit.Verify(bytes.NewReader(line), nil)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !res.OK {
		t.Fatalf("chain verification failed after response_result: %+v", res.Issues)
	}
}
