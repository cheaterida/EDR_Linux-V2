package datapath

import (
	"testing"

	"edr/internal/policy"
)

func TestCompileFileRules(t *testing.T) {
	p := &policy.Policy{
		SchemaVersion: policy.SchemaVersion,
		Rules: []policy.Rule{
			{
				ID: "BLOCK-WATCH", Category: policy.CategoryFile, Severity: "high",
				Decision: policy.DecisionBlock, Action: policy.ActionFanotifyDeny,
				When: &policy.Node{Op: policy.OpStartsWith, Field: policy.FieldFilePath, Value: "/tmp/edr-watch/"},
			},
			{
				ID: "ALERT-ONLY", Category: policy.CategoryFile, Severity: "low",
				Decision: policy.DecisionAlert, Action: policy.ActionLog,
				When: &policy.Node{Op: policy.OpStartsWith, Field: policy.FieldFilePath, Value: "/tmp/"},
			},
			{
				ID: "EXACT", Category: policy.CategoryFile, Severity: "high",
				Decision: policy.DecisionBlock, Action: policy.ActionFanotifyDeny,
				When: &policy.Node{Op: policy.OpEq, Field: policy.FieldFilePath, Value: "/etc/ld.so.preload"},
			},
		},
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("policy invalid: %v", err)
	}
	rules := CompileFileRules(p)
	if len(rules) != 2 {
		t.Fatalf("expected 2 block rules, got %d: %+v", len(rules), rules)
	}
	byID := map[string]FileRule{}
	for _, r := range rules {
		byID[r.ID] = r
	}
	if byID["BLOCK-WATCH"].PathPrefix != "/tmp/edr-watch/" {
		t.Fatalf("prefix not compiled: %+v", byID["BLOCK-WATCH"])
	}
	if byID["EXACT"].PathExact != "/etc/ld.so.preload" {
		t.Fatalf("exact not compiled: %+v", byID["EXACT"])
	}
	if _, ok := byID["ALERT-ONLY"]; ok {
		t.Fatal("alert rule must not become a daemon deny rule")
	}
}

func TestFrameRoundTrip(t *testing.T) {
	orig := Message{
		Type:    "policy",
		Version: 7,
		Rules:   []FileRule{{ID: "r1", PathPrefix: "/tmp/x/", Decision: "block"}},
	}
	frame, err := EncodeFrame(orig)
	if err != nil {
		t.Fatal(err)
	}
	// Skip the 4-byte length prefix, decode the body.
	got, err := DecodeFrame(frame[4:])
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != "policy" || got.Version != 7 || len(got.Rules) != 1 || got.Rules[0].PathPrefix != "/tmp/x/" {
		t.Fatalf("round trip mismatch: %+v", got)
	}
}

func TestDecodeRejectsBadVersion(t *testing.T) {
	_, err := DecodeFrame([]byte{99, '{', '}'})
	if err == nil {
		t.Fatal("expected version rejection")
	}
}
