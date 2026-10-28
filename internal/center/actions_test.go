package center

import "testing"

func TestActionLifecycle(t *testing.T) {
	s, err := OpenActions(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// Closed enumeration: arbitrary actions rejected.
	if _, err := s.Create("h1", "rm -rf /", 0, "", "", 0, "", "op"); err == nil {
		t.Fatal("arbitrary action must be rejected")
	}
	a, err := s.Create("h1", "kill", 4321, "", "/usr/bin/sleep", 999, "test", "op")
	if err != nil {
		t.Fatal(err)
	}
	if a.State != "pending" {
		t.Fatalf("state = %s", a.State)
	}
	// Not approved yet: agent gets nothing.
	if got := s.PendingFor("h1"); len(got) != 0 {
		t.Fatalf("pending-before-approve = %d", len(got))
	}
	if err := s.Approve(a.ID, "approver"); err != nil {
		t.Fatal(err)
	}
	got := s.PendingFor("h1")
	if len(got) != 1 || got[0].State != "dispatched" {
		t.Fatalf("dispatch = %+v", got)
	}
	if err := s.Complete(a.ID, true, true, "killed via pidfd"); err != nil {
		t.Fatal(err)
	}
	final, _ := s.Get(a.ID)
	if final.State != "completed" || !final.Enforced {
		t.Fatalf("final = %+v", final)
	}
}

func TestActionRejectAndWrongState(t *testing.T) {
	s, _ := OpenActions(t.TempDir())
	a, _ := s.Create("h1", "quarantine", 0, "/tmp/x", "", 0, "", "op")
	if err := s.Reject(a.ID, "op", "false positive"); err != nil {
		t.Fatal(err)
	}
	if err := s.Approve(a.ID, "op"); err == nil {
		t.Fatal("approving a rejected action should fail")
	}
	if err := s.Complete("missing", true, true, ""); err == nil {
		t.Fatal("unknown action accepted")
	}
}
