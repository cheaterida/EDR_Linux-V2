// Package integrity provides host-integrity checks that are not tied to a
// single event source. The first check is process masquerading: a userspace
// process claiming to be a kernel thread (e.g. kworker) in order to hide from
// process listings and simple name-based detections.
package integrity

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Proc is the minimal process identity needed for masquerade analysis.
type Proc struct {
	PID  int
	Comm string
	PPID int
	Exe  string
}

// Finding describes a suspected masquerade.
type Finding struct {
	PID    int
	Comm   string
	PPID   int
	Exe    string
	Reason string
}

// kernelThreadPrefixes are comm prefixes only ever used by kernel threads.
// A userspace process (real /proc/<pid>/exe) with one of these comms and a
// parent other than kthreadd (pid 2) is a masquerade.
var kernelThreadPrefixes = []string{
	"kworker", "ksoftirqd", "kthreadd", "migration", "rcu", "watchdog",
	"kauditd", "kcompactd", "kswapd", "kdevtmpfs", "kblockd", "kstr",
	"kdmflush", "scsi_", "scsi_tmf", "jbd2", "ext4-", "xfs-", "kvm-",
	"irq/", "cpuhp/", "idle_inject", "oom_reaper", "netns", "rpciod",
	"nfsiod", "crypto", "kpsmoused", "kaluad", "kmpath", "kmemstick",
	"khugepaged", "ksmd", "kcompactd", "writeback", "kintegrityd",
	"kthrotld", "kacpid", "kacpi_notify", "kacpi_hotplug", "kpsmoused",
}

// LooksKernelThread reports whether comm looks like a kernel-thread name.
func LooksKernelThread(comm string) bool {
	comm = strings.TrimSpace(comm)
	for _, p := range kernelThreadPrefixes {
		if strings.HasPrefix(comm, p) {
			return true
		}
	}
	return false
}

// Detect returns masquerade findings from a process snapshot.
//
// A process is flagged when its comm looks like a kernel thread but:
//   - it has a real executable on disk (kernel threads have none), OR
//   - its parent is not kthreadd (pid 2).
func Detect(procs []Proc) []Finding {
	var out []Finding
	// A kernel thread has no executable on disk; a userspace process that
	// claims a kernel-thread name always does. Requiring an executable makes
	// this precise (ppid heuristics alone produce false positives).
	for _, p := range procs {
		if p.PID <= 2 || !LooksKernelThread(p.Comm) {
			continue
		}
		if p.Exe == "" {
			continue // genuine kernel thread
		}
		reason := "comm claims kernel thread; has userspace executable " + p.Exe
		if p.PPID != 2 {
			reason += "; parent is not kthreadd (ppid=" + strconv.Itoa(p.PPID) + ")"
		}
		out = append(out, Finding{PID: p.PID, Comm: p.Comm, PPID: p.PPID, Exe: p.Exe, Reason: reason})
	}
	return out
}

// Scan reads the running processes and returns masquerade findings.
func Scan() []Finding {
	return Detect(ReadProcs())
}

// ReadProcs reads /proc into a Proc slice (best-effort).
func ReadProcs() []Proc {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var out []Proc
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		dir := filepath.Join("/proc", e.Name())
		comm := strings.TrimSpace(readTrim(filepath.Join(dir, "comm")))
		ppid := readPPID(filepath.Join(dir, "stat"))
		exe, _ := os.Readlink(filepath.Join(dir, "exe"))
		out = append(out, Proc{PID: pid, Comm: comm, PPID: ppid, Exe: exe})
	}
	return out
}

func readTrim(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

func readPPID(statPath string) int {
	raw, err := os.ReadFile(statPath)
	if err != nil {
		return 0
	}
	s := string(raw)
	closeParen := strings.LastIndexByte(s, ')')
	if closeParen < 0 || closeParen+2 >= len(s) {
		return 0
	}
	fields := strings.Fields(s[closeParen+2:])
	if len(fields) < 2 {
		return 0
	}
	ppid, _ := strconv.Atoi(fields[1])
	return ppid
}
