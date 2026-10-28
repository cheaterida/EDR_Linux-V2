package respond

import (
	"os"
	"path/filepath"
	"testing"
)

func TestQuarantineRestoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	orig := filepath.Join(dir, "evil.sh")
	if err := os.WriteFile(orig, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	l := &Local{DryRun: false, QuarantineDir: filepath.Join(dir, "q")}
	if r := l.Apply(Request{Action: ActionQuarantine, Path: orig, RuleID: "T1"}); !r.Success || !r.Enforced {
		t.Fatalf("quarantine failed: %+v", r)
	}
	if _, err := os.Stat(orig); !os.IsNotExist(err) {
		t.Fatal("file should have been moved")
	}
	metas, err := l.ListQuarantine()
	if err != nil || len(metas) != 1 {
		t.Fatalf("list quarantine: %+v err=%v", metas, err)
	}
	if r := l.RestoreQuarantine(orig); !r.Success || !r.Enforced {
		t.Fatalf("restore failed: %+v", r)
	}
	if _, err := os.Stat(orig); err != nil {
		t.Fatal("file should be restored")
	}
	if metas, _ := l.ListQuarantine(); len(metas) != 0 {
		t.Fatalf("quarantine not empty after restore: %+v", metas)
	}
}

func TestQuarantineRestoreDryRun(t *testing.T) {
	l := &Local{DryRun: true}
	if r := l.RestoreQuarantine("/tmp/none"); r.Enforced {
		t.Fatal("dry-run restore must not enforce")
	}
}
