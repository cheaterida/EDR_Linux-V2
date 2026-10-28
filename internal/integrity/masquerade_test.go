package integrity

import "testing"

func TestLooksKernelThread(t *testing.T) {
	for _, c := range []string{"kworker/0:1", "ksoftirqd/0", "kthreadd", "migration/1", "rcu_sched"} {
		if !LooksKernelThread(c) {
			t.Fatalf("%q should look like a kernel thread", c)
		}
	}
	for _, c := range []string{"bash", "nginx", "systemd", "python3"} {
		if LooksKernelThread(c) {
			t.Fatalf("%q should not look like a kernel thread", c)
		}
	}
}

func TestDetectMasquerade(t *testing.T) {
	procs := []Proc{
		{PID: 10, Comm: "kworker/0:1", PPID: 2, Exe: ""},       // genuine thread
		{PID: 20, Comm: "kworker/0:2", PPID: 1, Exe: ""},       // no exe => still a thread
		{PID: 30, Comm: "kthreadd", PPID: 2, Exe: "/tmp/fake"}, // forged: userspace exe
		{PID: 40, Comm: "bash", PPID: 1, Exe: "/usr/bin/bash"}, // normal
	}
	findings := Detect(procs)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].PID != 30 {
		t.Fatalf("expected pid 30, got %+v", findings[0])
	}
}

func TestDetectEmpty(t *testing.T) {
	if len(Detect(nil)) != 0 {
		t.Fatal("nil procs should yield no findings")
	}
}
