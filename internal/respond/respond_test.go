package respond

import (
	"os"
	"path/filepath"
	"testing"
)

func TestKillDryRunIsNotEnforced(t *testing.T) {
	l := &Local{DryRun: true}
	res := l.Apply(Request{Action: ActionKill, PID: 4242})
	if !res.Success || res.Enforced {
		t.Fatalf("dry-run kill must succeed but not enforce: %+v", res)
	}
}

func TestKillRefusesPID1(t *testing.T) {
	l := &Local{DryRun: false}
	res := l.Apply(Request{Action: ActionKill, PID: 1})
	if res.Success {
		t.Fatal("must refuse to kill pid 1")
	}
}

func TestKillIdentityMismatchRejected(t *testing.T) {
	l := &Local{DryRun: false}
	res := l.Apply(Request{Action: ActionKill, PID: os.Getpid(), Exe: "/nonexistent/binary"})
	if res.Success {
		t.Fatalf("identity mismatch must be rejected: %+v", res)
	}
}

func TestQuarantineMovesFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "suspect.sh")
	if err := os.WriteFile(target, []byte("payload"), 0o755); err != nil {
		t.Fatal(err)
	}
	qdir := filepath.Join(dir, "quarantine")
	l := &Local{DryRun: false, QuarantineDir: qdir}
	res := l.Apply(Request{Action: ActionQuarantine, Path: target, RuleID: "T1"})
	if !res.Success || !res.Enforced {
		t.Fatalf("quarantine failed: %+v", res)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatal("original file should be gone")
	}
	entries, err := os.ReadDir(qdir)
	if err != nil || len(entries) == 0 {
		t.Fatalf("quarantine dir empty: %v", err)
	}
	// Metadata sidecar must exist.
	foundMeta := false
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".meta" {
			foundMeta = true
		}
	}
	if !foundMeta {
		t.Fatal("quarantine .meta missing")
	}
}

func TestQuarantineDryRunKeepsFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "keep.txt")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	l := &Local{DryRun: true, QuarantineDir: filepath.Join(dir, "q")}
	res := l.Apply(Request{Action: ActionQuarantine, Path: target})
	if res.Enforced {
		t.Fatal("dry-run quarantine must not enforce")
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatal("file must remain in dry-run")
	}
}
