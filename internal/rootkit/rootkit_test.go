package rootkit

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"edr/internal/event"
)

func mkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func types(evs []event.Event) map[string]int {
	out := map[string]int{}
	for _, e := range evs {
		out[e.Detail["rootkit_type"].(string)]++
	}
	return out
}

func TestHiddenProcess(t *testing.T) {
	proc := t.TempDir()
	mkdir(t, filepath.Join(proc, "4243")) // a normal, visible process
	// Backdate the clock by an hour so the MinLifetime guard is satisfied.
	tr := NewTrackerWithClock(func() time.Time { return time.Now().Add(-time.Hour) })
	tr.Learn(&event.Event{Kind: event.KindExec, PID: 4242}) // hidden
	tr.Learn(&event.Event{Kind: event.KindExec, PID: 4243}) // visible
	d := NewDetector(Config{ProcRoot: proc, SysRoot: proc}, tr)
	got := d.detectHiddenProcesses()
	if len(got) != 1 || got[0].PID != 4242 {
		t.Fatalf("expected hidden pid 4242, got %+v", got)
	}
}

func TestExitClearsProcess(t *testing.T) {
	proc := t.TempDir()
	tr := NewTrackerWithClock(func() time.Time { return time.Now().Add(-time.Hour) })
	tr.Learn(&event.Event{Kind: event.KindFork, PID: 7})
	tr.Learn(&event.Event{Kind: event.KindExit, PID: 7})
	d := NewDetector(Config{ProcRoot: proc, SysRoot: proc}, tr)
	if got := d.detectHiddenProcesses(); len(got) != 0 {
		t.Fatalf("exited pid must not be flagged: %+v", got)
	}
}

func TestHiddenModule(t *testing.T) {
	proc := t.TempDir()
	sys := t.TempDir()
	writeFile(t, filepath.Join(proc, "modules"), "visible_mod 1234 0 - Live 0x0\n")
	// visible module in both views
	mkdir(t, filepath.Join(sys, "module", "visible_mod"))
	writeFile(t, filepath.Join(sys, "module", "visible_mod", "refcnt"), "1\n")
	// hidden module: in sysfs (runtime) but not in /proc/modules
	mkdir(t, filepath.Join(sys, "module", "hidden_mod"))
	writeFile(t, filepath.Join(sys, "module", "hidden_mod", "refcnt"), "2\n")
	// built-in pseudo module: bare dir, no state -> ignored
	mkdir(t, filepath.Join(sys, "module", "kernel"))

	d := NewDetector(Config{ProcRoot: proc, SysRoot: sys}, NewTracker())
	got := d.detectHiddenModules()
	if len(got) != 1 || got[0].Detail["module"] != "hidden_mod" {
		t.Fatalf("expected hidden_mod, got %+v", got)
	}
}

func TestSyscallIntegrity(t *testing.T) {
	proc := t.TempDir()
	// _text=0x1000 _etext=0x2000; kill inside, bpf hooked outside.
	kallsyms := "" +
		"0000000000001000 T _text\n" +
		"0000000000001500 T __x64_sys_kill\n" +
		"0000000000009000 T __x64_sys_bpf\n" +
		"0000000000002000 T _etext\n"
	writeFile(t, filepath.Join(proc, "kallsyms"), kallsyms)
	d := NewDetector(Config{ProcRoot: proc, SysRoot: proc}, NewTracker())
	got := d.checkSyscallIntegrity()
	if len(got) != 1 || got[0].Detail["syscall"] != "__x64_sys_bpf" {
		t.Fatalf("expected bpf hook, got %+v", got)
	}
}

func TestTrackerPrunesStaleEntries(t *testing.T) {
	now := time.Now()
	tr := NewTrackerWithClock(func() time.Time { return now })
	tr.Learn(&event.Event{Kind: event.KindConnect, Net: &event.NetInfo{RemoteAddr: "203.0.113.5"}})
	tr.Learn(&event.Event{Kind: event.KindFork, PID: 1234})
	if p, a := tr.Len(); p != 1 || a != 1 {
		t.Fatalf("expected 1 proc/1 addr, got %d/%d", p, a)
	}
	// Past addrTTL but not procTTL.
	now = now.Add(addrTTL + time.Minute)
	for i := 0; i < pruneEvery; i++ {
		tr.Learn(&event.Event{Kind: event.KindExec, PID: uint32(900000 + i)})
	}
	if _, a := tr.Len(); a != 0 {
		t.Fatalf("stale addresses not pruned: %d", a)
	}
	// Past procTTL: the old PID must be evicted too.
	now = now.Add(procTTL + time.Minute)
	for i := 0; i < pruneEvery; i++ {
		tr.Learn(&event.Event{Kind: event.KindExec, PID: uint32(800000 + i)})
	}
	p, _ := tr.Len()
	if p != pruneEvery {
		t.Fatalf("stale processes not pruned: got %d, want %d", p, pruneEvery)
	}
}

func TestHiddenConnectionsIgnoresIPv6(t *testing.T) {
	proc := t.TempDir()
	writeFile(t, filepath.Join(proc, "net", "tcp"), "  sl  local_address rem_address st\n")
	tr := NewTracker()
	tr.Learn(&event.Event{Kind: event.KindConnect, Net: &event.NetInfo{RemoteAddr: "203.0.113.9"}})
	tr.Learn(&event.Event{Kind: event.KindConnect, Net: &event.NetInfo{RemoteAddr: "2001:db8::1"}})
	d := NewDetector(Config{ProcRoot: proc, SysRoot: proc, Grace: time.Hour}, tr)
	got := d.detectHiddenConnections()
	if len(got) != 1 || got[0].Detail["remote_addr"] != "203.0.113.9" {
		t.Fatalf("expected only the IPv4 addr, got %+v", got)
	}
}
