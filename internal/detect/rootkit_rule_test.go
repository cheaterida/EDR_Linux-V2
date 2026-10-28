package detect

import (
	"testing"

	"edr/internal/event"
	"edr/internal/policy"
)

// TestRootkitPolicyRule guards the end-to-end wiring: a KindRootkit event must
// be matched by the baseline rootkit rules shipped in configs/policy.host.json.
func TestRootkitPolicyRule(t *testing.T) {
	pol, err := policy.LoadFile("../../configs/policy.host.json")
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	eng := New(pol)

	cases := map[string]string{
		"hidden_process":    "HOST-ROOTKIT-HIDDEN-PROCESS",
		"hidden_module":     "HOST-ROOTKIT-HIDDEN-MODULE",
		"hidden_connection": "HOST-ROOTKIT-HIDDEN-CONNECTION",
		"syscall_hook":      "HOST-ROOTKIT-SYSCALL-HOOK",
	}
	for rtype, wantID := range cases {
		ev := &event.Event{Kind: event.KindRootkit, Detail: map[string]any{"rootkit_type": rtype}}
		ev.Normalize()
		matched := eng.Match(ev)
		found := false
		for _, r := range matched {
			if r.ID == wantID {
				found = true
			}
		}
		if !found {
			t.Fatalf("rootkit_type=%s not matched by %s (matched=%v)", rtype, wantID, matched)
		}
	}
}
