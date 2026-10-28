package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func boolPtr(b bool) *bool { return &b }

func samplePolicy() *Policy {
	return &Policy{
		SchemaVersion: SchemaVersion,
		Rules: []Rule{
			{
				ID:       "R-BLOCK-CURL",
				Category: CategoryProcess,
				Severity: "high",
				Decision: DecisionBlock,
				Action:   ActionKill,
				When:     &Node{Op: OpEq, Field: FieldProcessName, Value: "curl"},
			},
		},
	}
}

func TestValidateOK(t *testing.T) {
	if err := samplePolicy().Validate(); err != nil {
		t.Fatalf("expected valid policy: %v", err)
	}
}

func TestValidateRejectsBadAction(t *testing.T) {
	p := samplePolicy()
	p.Rules[0].Action = ActionLog // alert action with block decision
	if err := p.Validate(); err == nil {
		t.Fatal("expected validation error for block+log")
	}
}

func TestValidateRejectsBadNode(t *testing.T) {
	p := samplePolicy()
	p.Rules[0].When = &Node{Op: OpAnd, Args: []Node{{Op: OpEq, Field: FieldProcessName, Value: "x"}}}
	if err := p.Validate(); err != nil {
		t.Fatalf("and with 1 arg should be valid: %v", err)
	}
	p.Rules[0].When = &Node{Op: OpNot, Args: []Node{{Op: OpEq}, {Op: OpEq}}}
	if err := p.Validate(); err == nil {
		t.Fatal("not with 2 args should be invalid")
	}
	p.Rules[0].When = &Node{Op: "bogus"}
	if err := p.Validate(); err == nil {
		t.Fatal("unknown op should be invalid")
	}
}

func TestLoadDisallowUnknownFields(t *testing.T) {
	raw := `{"schema_version":"v2.0","rules":[],"surprise":true}`
	if _, err := Load(strings.NewReader(raw)); err == nil {
		t.Fatal("unknown field should be rejected")
	}
}

func TestPriorityOrdering(t *testing.T) {
	r := []Rule{{ID: "b", Priority: 50}, {ID: "a", Priority: 10}, {ID: "c"}}
	SortByPriority(r)
	got := []string{r[0].ID, r[1].ID, r[2].ID}
	want := []string{"a", "b", "c"} // c defaults to 100
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order = %v, want %v", got, want)
		}
	}
}

func TestAggregatedDecision(t *testing.T) {
	rules := []Rule{
		{ID: "audit-only", Severity: "low", Decision: DecisionAlert, Action: ActionLog, Effect: []string{EffectAudit}},
		{ID: "resp", Severity: "high", Decision: DecisionBlock, Action: ActionKill, Effect: []string{EffectAudit, EffectResponse}},
	}
	resp, audit := AggregatedDecision(rules)
	if resp == nil || resp.ID != "resp" {
		t.Fatalf("response rule = %+v", resp)
	}
	if len(audit) != 2 {
		t.Fatalf("audit rules = %d, want 2", len(audit))
	}
}

func TestSignAndVerifyPolicy(t *testing.T) {
	dir := t.TempDir()
	key, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	polPath := filepath.Join(dir, "policy.json")
	raw, _ := json.Marshal(samplePolicy())
	if err := os.WriteFile(polPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SignPolicy(key, polPath); err != nil {
		t.Fatal(err)
	}
	ok, err := VerifyPolicyFile(key.Public, polPath)
	if err != nil || !ok {
		t.Fatalf("verify failed: ok=%v err=%v", ok, err)
	}
	// Tamper.
	if err := os.WriteFile(polPath, append(raw, ' '), 0o600); err != nil {
		t.Fatal(err)
	}
	if ok, _ := VerifyPolicyFile(key.Public, polPath); ok {
		t.Fatal("tampered policy should not verify")
	}
}

func TestLoadSigned(t *testing.T) {
	dir := t.TempDir()
	key, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	polPath := filepath.Join(dir, "policy.json")
	raw, _ := json.Marshal(samplePolicy())
	if err := os.WriteFile(polPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SignPolicy(key, polPath); err != nil {
		t.Fatal(err)
	}
	// Signed + matching key: OK.
	if _, err := LoadSigned(polPath, key.Public); err != nil {
		t.Fatalf("signed load failed: %v", err)
	}
	// Tamper: rejected.
	if err := os.WriteFile(polPath, append(raw, ' '), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSigned(polPath, key.Public); err == nil {
		t.Fatal("tampered signed policy must be rejected")
	}
}
