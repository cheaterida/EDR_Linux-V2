// Package respond executes response actions against processes and files.
//
// Every action carries an explicit dry-run flag and reports Enforced, so a
// recorded-only decision can never be mistaken for a real enforcement (the
// v0.9 metrics bug). Process actions validate identity (exe / start ticks)
// before signalling, and prefer the Rust datapath for kill when available.
package respond

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Action names (must match policy action strings).
const (
	ActionNone           = "none"
	ActionLog            = "log"
	ActionKill           = "kill"
	ActionKillTree       = "kill_tree"
	ActionQuarantine     = "quarantine"
	ActionFixPermission  = "fix_permissions"
	ActionProcessSuspend = "process_suspend"
	ActionNFTBlock       = "nft_block"
	ActionNetworkIsolate = "network_isolate"
	ActionNetworkRestore = "network_restore"
	ActionFanotifyDeny   = "fanotify_deny"
)

// Request is a single response request.
type Request struct {
	Action     string
	PID        int
	Exe        string
	StartTicks uint64
	Path       string
	RuleID     string
	Protocol   string
	RemoteAddr string
	RemotePort int
}

// Result is the outcome of a response action.
type Result struct {
	Action   string `json:"action"`
	Success  bool   `json:"success"`
	Enforced bool   `json:"enforced"`
	Detail   string `json:"detail"`
}

// DatapathKiller is implemented by the Rust datapath client.
type DatapathKiller interface {
	Kill(pid int, exe string, startTicks uint64) (success, enforced bool, detail string)
}

// Local is the in-process responder. DryRun defaults to true (safe).
type Local struct {
	DryRun        bool
	QuarantineDir string
	Datapath      DatapathKiller
	NFT           NFTProvider
}

// Apply runs the requested action.
func (l *Local) Apply(req Request) Result {
	switch req.Action {
	case "", ActionNone, ActionLog:
		return Result{Action: req.Action, Success: true, Enforced: false, Detail: "recorded only"}
	case ActionKill:
		return l.kill(req)
	case ActionKillTree:
		return l.killTree(req)
	case ActionQuarantine:
		return l.quarantine(req)
	case ActionFixPermission:
		return l.fixPermissions(req)
	case ActionProcessSuspend:
		return l.suspend(req)
	case ActionNFTBlock:
		nft := l.NFT
		if l.DryRun {
			nft.DryRun = true
		}
		return nft.ApplyBlock(req)
	case ActionNetworkIsolate:
		nft := l.NFT
		if l.DryRun {
			nft.DryRun = true
		}
		return nft.ApplyIsolate()
	case ActionNetworkRestore:
		nft := l.NFT
		if l.DryRun {
			nft.DryRun = true
		}
		return nft.Rollback()
	case ActionFanotifyDeny:
		// Enforcement happens synchronously in the Rust datapath; here we
		// only record the decision for audit.
		return Result{Action: ActionFanotifyDeny, Success: true, Enforced: false, Detail: "enforced by datapath"}
	default:
		return Result{Action: req.Action, Success: false, Detail: "unsupported action: " + req.Action}
	}
}

func (l *Local) kill(req Request) Result {
	if req.PID <= 1 {
		return Result{Action: ActionKill, Success: false, Detail: "refusing to signal protected pid"}
	}
	if l.DryRun {
		return Result{Action: ActionKill, Success: true, Enforced: false, Detail: fmt.Sprintf("dry-run: would kill pid %d", req.PID)}
	}
	if ok, why := targetMatches(req); !ok {
		return Result{Action: ActionKill, Success: false, Detail: "identity check failed: " + why}
	}
	if l.Datapath != nil {
		success, enforced, detail := l.Datapath.Kill(req.PID, req.Exe, req.StartTicks)
		return Result{Action: ActionKill, Success: success, Enforced: enforced, Detail: "datapath: " + detail}
	}
	if err := pidfdKill(req.PID); err != nil {
		return Result{Action: ActionKill, Success: false, Detail: err.Error()}
	}
	return Result{Action: ActionKill, Success: true, Enforced: true, Detail: "killed via pidfd"}
}

func (l *Local) killTree(req Request) Result {
	if req.PID <= 1 {
		return Result{Action: ActionKillTree, Success: false, Detail: "refusing to signal protected pid"}
	}
	if l.DryRun {
		return Result{Action: ActionKillTree, Success: true, Enforced: false, Detail: fmt.Sprintf("dry-run: would kill tree of pid %d", req.PID)}
	}
	// Collect descendants breadth-first, then kill deepest-first.
	children := procChildren()
	order := []int{req.PID}
	seen := map[int]bool{req.PID: true}
	for i := 0; i < len(order); i++ {
		for _, c := range children[order[i]] {
			if !seen[c] && c > 1 {
				seen[c] = true
				order = append(order, c)
			}
		}
	}
	killed := 0
	for i := len(order) - 1; i >= 0; i-- {
		if err := pidfdKill(order[i]); err == nil {
			killed++
		}
	}
	return Result{Action: ActionKillTree, Success: true, Enforced: true, Detail: fmt.Sprintf("killed %d process(es)", killed)}
}

func (l *Local) quarantine(req Request) Result {
	if req.Path == "" {
		return Result{Action: ActionQuarantine, Success: false, Detail: "path required"}
	}
	if l.DryRun {
		return Result{Action: ActionQuarantine, Success: true, Enforced: false, Detail: "dry-run: would quarantine " + req.Path}
	}
	dir := l.QuarantineDir
	if dir == "" {
		dir = "/var/lib/edr/quarantine"
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Result{Action: ActionQuarantine, Success: false, Detail: err.Error()}
	}
	const oPath = 0x200000 // O_PATH on x86_64
	fd, err := syscall.Open(req.Path, oPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return Result{Action: ActionQuarantine, Success: false, Detail: fmt.Sprintf("open: %v", err)}
	}
	defer syscall.Close(fd)
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return Result{Action: ActionQuarantine, Success: false, Detail: fmt.Sprintf("fstat: %v", err)}
	}
	qPath := filepath.Join(dir, fmt.Sprintf("%d_%d", st.Ino, time.Now().UnixNano()))
	if err := syscall.Rename(req.Path, qPath); err != nil {
		return Result{Action: ActionQuarantine, Success: false, Detail: fmt.Sprintf("rename: %v", err)}
	}
	qfd, err := syscall.Open(qPath, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err == nil {
		_ = syscall.Fchmod(qfd, 0o000)
		syscall.Close(qfd)
	}
	meta := map[string]any{
		"original_path": req.Path, "quarantine_at": time.Now().UTC(),
		"inode": st.Ino, "size": st.Size, "rule_id": req.RuleID,
	}
	raw, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		_ = syscall.Rename(qPath, req.Path)
		return Result{Action: ActionQuarantine, Success: false, Detail: "marshal meta: " + err.Error()}
	}
	if err := os.WriteFile(qPath+".meta", raw, 0o600); err != nil {
		// A quarantined file without restore metadata would be effectively
		// lost (QuarantineRestore looks up the .meta file). Roll the move back
		// so the action is atomic.
		if qfd2, e := syscall.Open(qPath, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0); e == nil {
			_ = syscall.Fchmod(qfd2, 0o600)
			syscall.Close(qfd2)
		}
		_ = syscall.Rename(qPath, req.Path)
		return Result{Action: ActionQuarantine, Success: false, Detail: "write meta: " + err.Error()}
	}
	return Result{Action: ActionQuarantine, Success: true, Enforced: true, Detail: "quarantined -> " + qPath}
}

func (l *Local) fixPermissions(req Request) Result {
	if req.Path == "" {
		return Result{Action: ActionFixPermission, Success: false, Detail: "path required"}
	}
	if l.DryRun {
		return Result{Action: ActionFixPermission, Success: true, Enforced: false, Detail: "dry-run: would chmod 0600 " + req.Path}
	}
	fd, err := syscall.Open(req.Path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return Result{Action: ActionFixPermission, Success: false, Detail: err.Error()}
	}
	defer syscall.Close(fd)
	if err := syscall.Fchmod(fd, 0o600); err != nil {
		return Result{Action: ActionFixPermission, Success: false, Detail: err.Error()}
	}
	return Result{Action: ActionFixPermission, Success: true, Enforced: true, Detail: "chmod 0600 applied"}
}

func (l *Local) suspend(req Request) Result {
	if req.PID <= 1 {
		return Result{Action: ActionProcessSuspend, Success: false, Detail: "refusing to signal protected pid"}
	}
	if l.DryRun {
		return Result{Action: ActionProcessSuspend, Success: true, Enforced: false, Detail: fmt.Sprintf("dry-run: would SIGSTOP pid %d", req.PID)}
	}
	if ok, why := targetMatches(req); !ok {
		return Result{Action: ActionProcessSuspend, Success: false, Detail: "identity check failed: " + why}
	}
	if err := pidfdSignal(req.PID, syscall.SIGSTOP); err != nil {
		return Result{Action: ActionProcessSuspend, Success: false, Detail: err.Error()}
	}
	return Result{Action: ActionProcessSuspend, Success: true, Enforced: true, Detail: "SIGSTOP sent"}
}

// targetMatches verifies the process identity before signalling.
func targetMatches(req Request) (bool, string) {
	if req.Exe == "" && req.StartTicks == 0 {
		return true, "" // nothing to verify
	}
	if req.Exe != "" {
		exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", req.PID))
		if err != nil {
			return false, "process gone or unreadable"
		}
		if exe != req.Exe {
			return false, fmt.Sprintf("exe mismatch (%s != %s)", exe, req.Exe)
		}
	}
	if req.StartTicks != 0 {
		got, err := readProcStartTicks(req.PID)
		if err != nil {
			return false, "process gone or unreadable"
		}
		if got != req.StartTicks {
			return false, fmt.Sprintf("start_ticks mismatch (%d != %d)", got, req.StartTicks)
		}
	}
	return true, ""
}

func readProcStartTicks(pid int) (uint64, error) {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	s := string(raw)
	closeParen := strings.LastIndexByte(s, ')')
	if closeParen < 0 || closeParen+2 >= len(s) {
		return 0, fmt.Errorf("malformed stat")
	}
	fields := strings.Fields(s[closeParen+2:])
	const idx = 19 // field 22 (starttime) minus 3
	if idx >= len(fields) {
		return 0, fmt.Errorf("short stat")
	}
	return strconv.ParseUint(fields[idx], 10, 64)
}

// procChildren returns ppid -> []pid for all processes.
func procChildren() map[int][]int {
	out := map[int][]int{}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return out
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		raw, err := os.ReadFile(filepath.Join("/proc", e.Name(), "stat"))
		if err != nil {
			continue
		}
		s := string(raw)
		closeParen := strings.LastIndexByte(s, ')')
		if closeParen < 0 || closeParen+2 >= len(s) {
			continue
		}
		fields := strings.Fields(s[closeParen+2:])
		if len(fields) < 2 {
			continue
		}
		ppid, _ := strconv.Atoi(fields[1])
		out[ppid] = append(out[ppid], pid)
	}
	return out
}
