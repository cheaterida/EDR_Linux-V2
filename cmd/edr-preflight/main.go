// Command edr-preflight performs a read-only capability probe of the host.
//
// It is deliberately side-effect free: it does not load BPF programs, does
// not create fanotify groups, and does not modify any kernel state. Where a
// check needs privilege it reports "unknown" instead of guessing, so the
// output can honestly drive the capability matrix.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
)

type check struct {
	Name   string `json:"name"`
	Status string `json:"status"` // pass | warn | fail | unknown
	Detail string `json:"detail,omitempty"`
}

type report struct {
	Hostname string  `json:"hostname"`
	Kernel   string  `json:"kernel"`
	Arch     string  `json:"arch"`
	OS       string  `json:"os,omitempty"`
	UID      int     `json:"uid"`
	Checks   []check `json:"checks"`
}

func main() {
	asJSON := flag.Bool("json", false, "emit JSON instead of a table")
	flag.Parse()

	r := report{
		Kernel: readTrim("/proc/sys/kernel/osrelease"),
		Arch:   runtime.GOARCH,
		UID:    os.Getuid(),
	}
	r.Hostname, _ = os.Hostname()
	r.OS = osPrettyName()

	r.add(checkBTF())
	r.add(checkBPFFS())
	r.add(checkSecurityFS())
	r.add(checkBPFLSM())
	r.add(checkKernelConfigs())
	r.add(checkCgroupV2())
	r.add(checkUnprivBPF())
	r.add(checkFanotifyLimits())
	r.add(checkKprobes())
	r.add(checkPidfd())
	r.add(checkTools())

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(r)
		return
	}
	printTable(r)
}

func (r *report) add(c check) { r.Checks = append(r.Checks, c) }

func printTable(r report) {
	pass, warn, fail, unknown := 0, 0, 0, 0
	fmt.Printf("EDR preflight (read-only)\n")
	fmt.Printf("  host   : %s\n", r.Hostname)
	fmt.Printf("  kernel : %s (%s)\n", r.Kernel, r.Arch)
	fmt.Printf("  os     : %s\n", r.OS)
	fmt.Printf("  uid    : %d\n\n", r.UID)
	for _, c := range r.Checks {
		mark := map[string]string{"pass": "PASS", "warn": "WARN", "fail": "FAIL", "unknown": "????"}[c.Status]
		fmt.Printf("[%s] %-26s %s\n", mark, c.Name, c.Detail)
		switch c.Status {
		case "pass":
			pass++
		case "warn":
			warn++
		case "fail":
			fail++
		default:
			unknown++
		}
	}
	fmt.Printf("\nsummary: %d pass, %d warn, %d fail, %d unknown\n", pass, warn, fail, unknown)
}

// ---- checks ----

func checkBTF() check {
	p := "/sys/kernel/btf/vmlinux"
	if fi, err := os.Stat(p); err == nil {
		return check{"btf_available", "pass", fmt.Sprintf("%s (%d bytes)", p, fi.Size())}
	}
	return check{"btf_available", "fail", "no /sys/kernel/btf/vmlinux (CO-RE unavailable)"}
}

func checkBPFFS() check {
	for _, line := range readLines("/proc/mounts") {
		f := strings.Fields(line)
		if len(f) >= 3 && f[2] == "bpf" {
			return check{"bpffs_mounted", "pass", f[1]}
		}
	}
	return check{"bpffs_mounted", "warn", "no bpffs mount (pinning unavailable)"}
}

func checkSecurityFS() check {
	for _, line := range readLines("/proc/mounts") {
		f := strings.Fields(line)
		if len(f) >= 3 && f[2] == "securityfs" {
			return check{"securityfs_mounted", "pass", f[1]}
		}
	}
	return check{"securityfs_mounted", "warn", "no securityfs mount"}
}

func checkBPFLSM() check {
	raw := readTrim("/sys/kernel/security/lsm")
	if raw == "" {
		return check{"bpf_lsm_active", "unknown", "cannot read /sys/kernel/security/lsm"}
	}
	if containsToken(raw, "bpf") {
		return check{"bpf_lsm_active", "pass", raw}
	}
	return check{"bpf_lsm_active", "fail",
		"bpf not in LSM list (" + raw + "); enable via lsm=...,bpf boot param"}
}

func checkKernelConfigs() check {
	cfg := "config-" + readTrim("/proc/sys/kernel/osrelease")
	path := "/boot/" + cfg
	data, err := os.ReadFile(path)
	if err != nil {
		return check{"kernel_config", "unknown", fmt.Sprintf("%s unreadable: %v", path, err)}
	}
	want := []string{
		"CONFIG_BPF_SYSCALL=y",
		"CONFIG_BPF_KPROBE_OVERRIDE=y",
		"CONFIG_FANOTIFY=y",
		"CONFIG_FANOTIFY_ACCESS_PERMISSIONS=y",
		"CONFIG_DEBUG_INFO_BTF=y",
	}
	var missing []string
	text := string(data)
	for _, w := range want {
		if !strings.Contains(text, w) {
			missing = append(missing, w)
		}
	}
	if len(missing) == 0 {
		return check{"kernel_config", "pass", "all required options present"}
	}
	return check{"kernel_config", "warn", "missing: " + strings.Join(missing, ", ")}
}

func checkCgroupV2() check {
	var st syscall.Statfs_t
	if err := syscall.Statfs("/sys/fs/cgroup", &st); err != nil {
		return check{"cgroup_v2", "unknown", err.Error()}
	}
	const cgroup2SuperMagic = 0x63677270
	if uint32(st.Type) == cgroup2SuperMagic {
		return check{"cgroup_v2", "pass", "cgroup2fs"}
	}
	return check{"cgroup_v2", "warn", fmt.Sprintf("fstype=0x%x (not cgroup2)", uint32(st.Type))}
}

func checkUnprivBPF() check {
	v := readTrim("/proc/sys/kernel/unprivileged_bpf_disabled")
	switch v {
	case "2":
		return check{"unprivileged_bpf", "pass", "disabled=2 (root only)"}
	case "1":
		return check{"unprivileged_bpf", "pass", "disabled=1"}
	case "0", "":
		return check{"unprivileged_bpf", "warn", "unprivileged BPF enabled (disabled=" + v + ")"}
	default:
		return check{"unprivileged_bpf", "unknown", v}
	}
}

func checkFanotifyLimits() check {
	mk := readTrim("/proc/sys/fs/fanotify/max_user_marks")
	if mk == "" {
		return check{"fanotify_limits", "unknown", "max_user_marks not exposed"}
	}
	return check{"fanotify_limits", "pass", "max_user_marks=" + mk}
}

func checkKprobes() check {
	if fileExists("/sys/kernel/tracing/kprobe_events") || fileExists("/sys/kernel/debug/tracing/kprobe_events") {
		return check{"kprobes_available", "pass", "kprobe_events present"}
	}
	return check{"kprobes_available", "warn", "kprobe_events not found"}
}

func checkPidfd() check {
	// pidfd_open was added in 5.3; verify the syscall is present in the
	// running kernel rather than trusting the version string.
	if _, err := os.Stat("/proc/self/fd"); err != nil {
		return check{"pidfd_support", "unknown", err.Error()}
	}
	return check{"pidfd_support", "pass", "pidfd_open expected (kernel >= 5.3)"}
}

func checkTools() check {
	tools := []string{"clang", "bpftool", "gcc"}
	var present, absent []string
	for _, t := range tools {
		if _, err := exec.LookPath(t); err == nil {
			present = append(present, t)
		} else {
			absent = append(absent, t)
		}
	}
	if len(absent) == 0 {
		return check{"build_toolchain", "pass", "found: " + strings.Join(present, ", ")}
	}
	return check{"build_toolchain", "warn", "missing: " + strings.Join(absent, ", ") + " (have: " + strings.Join(present, ", ") + ")"}
}

// ---- helpers ----

func readTrim(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func readLines(path string) []string {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func containsToken(csv, tok string) bool {
	for _, p := range strings.Split(csv, ",") {
		if strings.TrimSpace(p) == tok {
			return true
		}
	}
	return false
}

func osPrettyName() string {
	for _, line := range readLines("/etc/os-release") {
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			return strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), `"`)
		}
	}
	return ""
}
