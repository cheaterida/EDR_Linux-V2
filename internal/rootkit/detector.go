package rootkit

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"edr/internal/event"
)

// Config tunes the detector. Roots are injectable so the checks are testable
// without root and against fixture trees.
type Config struct {
	ProcRoot    string
	SysRoot     string
	Grace       time.Duration // connection sightings newer than this are considered "current"
	MinLifetime time.Duration // a PID must be tracked at least this long before it can be "hidden"
	Connections bool          // enable the /proc/net/tcp comparison (opt-in: inherently racy)
	Now         func() time.Time
}

// Detector runs the cross-source checks. It holds no state beyond the tracker.
type Detector struct {
	cfg Config
	tr  *Tracker
}

// NewDetector builds a detector with defaults for any unset field.
func NewDetector(cfg Config, tr *Tracker) *Detector {
	if cfg.ProcRoot == "" {
		cfg.ProcRoot = "/proc"
	}
	if cfg.SysRoot == "" {
		cfg.SysRoot = "/sys"
	}
	if cfg.Grace <= 0 {
		cfg.Grace = 120 * time.Second
	}
	if cfg.MinLifetime <= 0 {
		cfg.MinLifetime = 10 * time.Second
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Detector{cfg: cfg, tr: tr}
}

// RunOnce executes every check and returns the findings as events.
func (d *Detector) RunOnce() []event.Event {
	var out []event.Event
	out = append(out, d.detectHiddenProcesses()...)
	out = append(out, d.detectHiddenModules()...)
	if d.cfg.Connections {
		out = append(out, d.detectHiddenConnections()...)
	}
	out = append(out, d.checkSyscallIntegrity()...)
	return out
}

func rootkitEvent(rtype, reason string, pid int, extra map[string]any) event.Event {
	detail := map[string]any{"rootkit_type": rtype, "reason": reason}
	for k, v := range extra {
		detail[k] = v
	}
	ev := event.Event{Kind: event.KindRootkit, PID: uint32(pid), Detail: detail}
	ev.Normalize()
	return ev
}

// detectHiddenProcesses flags a PID the probes saw for long enough to be real
// yet which /proc does not list — the signature of a DKOM hidden process.
func (d *Detector) detectHiddenProcesses() []event.Event {
	if d.tr == nil {
		return nil
	}
	seen := d.tr.procSightings()
	if len(seen) == 0 {
		return nil
	}
	pids, err := readProcPIDs(d.cfg.ProcRoot)
	if err != nil {
		return nil
	}
	now := d.cfg.Now()
	var out []event.Event
	for pid, s := range seen {
		if now.Sub(s.first) < d.cfg.MinLifetime {
			continue // too young; /proc may not have caught up yet
		}
		if pids[pid] {
			continue
		}
		out = append(out, rootkitEvent("hidden_process",
			"PID seen by probes but absent from /proc", pid, map[string]any{
				"first_seen": s.first.UTC().Format(time.RFC3339Nano),
				"last_seen":  s.last.UTC().Format(time.RFC3339Nano),
			}))
	}
	return out
}

// detectHiddenModules compares /sys/module (runtime modules have refcnt or
// initstate) with /proc/modules; a mismatch means module hiding.
func (d *Detector) detectHiddenModules() []event.Event {
	sys, err := readSysModules(d.cfg.SysRoot)
	if err != nil {
		return nil
	}
	proc, err := readProcModules(d.cfg.ProcRoot)
	if err != nil {
		return nil
	}
	var out []event.Event
	for name := range sys {
		if proc[name] {
			continue
		}
		out = append(out, rootkitEvent("hidden_module",
			"module present in /sys/module but absent from /proc/modules", 0,
			map[string]any{"module": name}))
	}
	return out
}

// detectHiddenConnections flags a remote address the probes saw recently but
// which /proc/net/tcp no longer lists. Only IPv4 is compared (the probes and
// the parser agree on dotted-quad); short-lived connections are excluded by
// the tracker's exit handling on the process side, and by Grace here.
func (d *Detector) detectHiddenConnections() []event.Event {
	if d.tr == nil {
		return nil
	}
	seen := d.tr.addrSightings()
	if len(seen) == 0 {
		return nil
	}
	procAddrs, err := readProcNetAddrs(d.cfg.ProcRoot)
	if err != nil {
		return nil
	}
	now := d.cfg.Now()
	var out []event.Event
	for addr, last := range seen {
		if strings.Contains(addr, ":") {
			continue // IPv6 form differs; skip to avoid false positives
		}
		if now.Sub(last) > d.cfg.Grace {
			continue
		}
		if procAddrs[addr] {
			continue
		}
		out = append(out, rootkitEvent("hidden_connection",
			"remote address seen by probes but absent from /proc/net/tcp", 0,
			map[string]any{"remote_addr": addr}))
	}
	return out
}

// syscallSymbols are the kernel entry points whose addresses must stay inside
// the kernel text segment.
var syscallSymbols = []string{
	"__x64_sys_kill", "__x64_sys_ptrace",
	"__x64_sys_init_module", "__x64_sys_delete_module",
	"__x64_sys_openat", "__x64_sys_getdents64",
	"__x64_sys_process_vm_writev", "__x64_sys_bpf",
}

// checkSyscallIntegrity verifies that key syscall addresses fall within
// _text.._etext in /proc/kallsyms, which catches syscall-table hooks.
func (d *Detector) checkSyscallIntegrity() []event.Event {
	textStart, textEnd, addrs, err := readKallsyms(d.cfg.ProcRoot, syscallSymbols)
	if err != nil {
		return nil
	}
	if textStart == 0 || textEnd == 0 {
		return nil // cannot locate boundaries (e.g. kptr_restrict); not a finding
	}
	var out []event.Event
	for name, addr := range addrs {
		if addr == 0 {
			continue
		}
		if addr < textStart || addr > textEnd {
			out = append(out, rootkitEvent("syscall_hook",
				"key syscall address outside kernel .text segment", 0,
				map[string]any{
					"syscall":    name,
					"address":    fmt.Sprintf("0x%x", addr),
					"text_start": fmt.Sprintf("0x%x", textStart),
					"text_end":   fmt.Sprintf("0x%x", textEnd),
				}))
		}
	}
	return out
}

// ---- /proc & /sys readers (root-injectable) ----

func readProcPIDs(root string) (map[int]bool, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	out := make(map[int]bool, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if pid, err := strconv.Atoi(e.Name()); err == nil {
			out[pid] = true
		}
	}
	return out, nil
}

func readSysModules(sysRoot string) (map[string]bool, error) {
	dir := filepath.Join(sysRoot, "module")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(entries))
	for _, e := range entries {
		if !e.IsDir() || isBuiltinPseudoModule(e.Name()) {
			continue
		}
		// Only modules loaded at runtime (including hidden ones) carry these
		// attributes; built-ins expose a bare directory.
		modDir := filepath.Join(dir, e.Name())
		if hasModuleState(modDir) {
			out[e.Name()] = true
		}
	}
	return out, nil
}

func hasModuleState(modDir string) bool {
	if _, err := os.Stat(filepath.Join(modDir, "refcnt")); err == nil {
		return true
	}
	if _, err := os.Stat(filepath.Join(modDir, "initstate")); err == nil {
		return true
	}
	return false
}

func isBuiltinPseudoModule(name string) bool {
	switch name {
	case "kernel", "block", "firmware", "fs", "net", "crypto",
		"drivers", "arch", "lib", "sound", "virt", "power":
		return true
	}
	return false
}

func readProcModules(procRoot string) (map[string]bool, error) {
	f, err := os.Open(filepath.Join(procRoot, "modules"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := make(map[string]bool)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if fields := strings.Fields(sc.Text()); len(fields) > 0 {
			out[fields[0]] = true
		}
	}
	return out, sc.Err()
}

func readProcNetAddrs(procRoot string) (map[string]bool, error) {
	out := make(map[string]bool)
	for _, name := range []string{"tcp", "tcp6"} {
		f, err := os.Open(filepath.Join(procRoot, "net", name))
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		first := true
		for sc.Scan() {
			if first {
				first = false
				continue // header
			}
			fields := strings.Fields(sc.Text())
			if len(fields) < 3 {
				continue
			}
			if ip := hexToIPv4(fields[1]); ip != "" {
				out[ip] = true
			}
			if ip := hexToIPv4(fields[2]); ip != "" {
				out[ip] = true
			}
		}
		f.Close()
	}
	return out, nil
}

// hexToIPv4 converts a little-endian hex address (as stored in /proc/net/tcp)
// to dotted-quad, or "" when the input is not a 32-bit (IPv4) address.
func hexToIPv4(hexAddr string) string {
	if idx := strings.LastIndex(hexAddr, ":"); idx > 0 {
		hexAddr = hexAddr[:idx]
	}
	if len(hexAddr) != 8 {
		return ""
	}
	b := make([]byte, 4)
	for i := 0; i < 4; i++ {
		v, err := strconv.ParseUint(hexAddr[i*2:i*2+2], 16, 8)
		if err != nil {
			return ""
		}
		b[3-i] = byte(v)
	}
	return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
}

// readKallsyms returns the text segment bounds and the addresses of the
// requested symbols.
func readKallsyms(procRoot string, names []string) (start, end uint64, addrs map[string]uint64, err error) {
	f, err := os.Open(filepath.Join(procRoot, "kallsyms"))
	if err != nil {
		return 0, 0, nil, err
	}
	defer f.Close()
	want := make(map[string]bool, len(names))
	for _, n := range names {
		want[n] = true
	}
	addrs = make(map[string]uint64)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 3 {
			continue
		}
		if fields[1] != "T" && fields[1] != "t" {
			continue
		}
		name := fields[2]
		if name != "_text" && name != "_etext" && !want[name] {
			continue
		}
		addr, perr := strconv.ParseUint(fields[0], 16, 64)
		if perr != nil {
			continue
		}
		switch name {
		case "_text":
			start = addr
		case "_etext":
			end = addr
		default:
			addrs[name] = addr
		}
	}
	return start, end, addrs, sc.Err()
}
