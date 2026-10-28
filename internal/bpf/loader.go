package bpf

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"edr/internal/event"
)

// Loader owns the loaded CO-RE collection, its tracepoint links and the
// ring-buffer reader.
type Loader struct {
	objs  bpfObjects
	lsm   *lsmObjects
	links []link.Link
	rd    *ringbuf.Reader

	agentPID uint32
	guard    uint32

	out     chan event.Event
	dropped atomic.Uint64
	read    atomic.Uint64
	badRec  atomic.Uint64
	readErr atomic.Uint64
	closed  atomic.Bool
	wg      sync.WaitGroup
}

// Stats reports reader counters for diagnostics.
type Stats struct {
	Read    uint64
	Dropped uint64
	BadRec  uint64
	ReadErr uint64
}

// Stats returns a snapshot of reader counters.
func (l *Loader) Stats() Stats {
	return Stats{
		Read:    l.read.Load(),
		Dropped: l.dropped.Load(),
		BadRec:  l.badRec.Load(),
		ReadErr: l.readErr.Load(),
	}
}

type attachment struct {
	group    string
	name     string
	prog     *ebpf.Program
	required bool
}

// Load loads the probes and attaches every tracepoint. Core hooks (exec,
// fork, exit, connect) are required; file-operation hooks are best-effort
// and their failure is reported but non-fatal.
func Load() (*Loader, error) {
	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("bpf: load objects: %w", err)
	}

	l := &Loader{objs: objs, out: make(chan event.Event, 1024)}

	atts := []attachment{
		{"sched", "sched_process_exec", objs.HandleExec, true},
		{"sched", "sched_process_fork", objs.HandleFork, true},
		{"sched", "sched_process_exit", objs.HandleExit, true},
		{"sock", "inet_sock_set_state", objs.HandleConnect, true},
		{"syscalls", "sys_enter_unlinkat", objs.HandleUnlinkat, false},
		{"syscalls", "sys_enter_unlink", objs.HandleUnlink, false},
		{"syscalls", "sys_enter_renameat", objs.HandleRenameat, false},
		{"syscalls", "sys_enter_setuid", objs.HandleSetuid, false},
		{"syscalls", "sys_enter_setgid", objs.HandleSetgid, false},
		{"syscalls", "sys_enter_capset", objs.HandleCapset, false},
		{"syscalls", "sys_enter_init_module", objs.HandleInitModule, false},
		{"syscalls", "sys_enter_finit_module", objs.HandleFinitModule, false},
		{"syscalls", "sys_enter_delete_module", objs.HandleDeleteModule, false},
		{"syscalls", "sys_enter_bpf", objs.HandleBpf, false},
		{"syscalls", "sys_enter_getpid", objs.EdrHeartbeat, false},
	}
	for _, a := range atts {
		lnk, err := link.Tracepoint(a.group, a.name, a.prog, nil)
		if err != nil {
			if a.required {
				_ = l.Close()
				return nil, fmt.Errorf("bpf: attach %s/%s: %w", a.group, a.name, err)
			}
			fmt.Printf("bpf: (best-effort) attach %s/%s failed: %v\n", a.group, a.name, err)
			continue
		}
		l.links = append(l.links, lnk)
	}

	// Self-protection kprobes (best-effort; failure degrades to no enforcement).
	kprobes := []struct {
		sym  string
		prog *ebpf.Program
	}{
		{"__x64_sys_kill", objs.EdrSelfprotectKill},
		{"__x64_sys_tgkill", objs.EdrSelfprotectTgkill},
		{"__x64_sys_rt_sigqueueinfo", objs.EdrSelfprotectSigqueue},
		{"__x64_sys_ptrace", objs.EdrSelfprotectPtrace},
		{"__x64_sys_process_vm_readv", objs.EdrSelfprotectVmReadv},
		{"__x64_sys_process_vm_writev", objs.EdrSelfprotectVmWritev},
		{"__x64_sys_pidfd_send_signal", objs.EdrSelfprotectPidfd},
		{"__x64_sys_bpf", objs.EdrBpfGuard},
		{"__x64_sys_init_module", objs.EdrInitModuleGuard},
		{"__x64_sys_finit_module", objs.EdrFinitModuleGuard},
		{"__x64_sys_io_uring_enter", objs.EdrIoUringEnter},
		{"vfs_unlink", objs.EdrVfsUnlink},
		{"vfs_rename", objs.EdrVfsRename},
	}
	for _, k := range kprobes {
		if k.prog == nil {
			continue
		}
		lnk, err := link.Kprobe(k.sym, k.prog, nil)
		if err != nil {
			fmt.Printf("bpf: (best-effort) kprobe %s failed: %v\n", k.sym, err)
			continue
		}
		l.links = append(l.links, lnk)
	}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		_ = l.Close()
		return nil, fmt.Errorf("bpf: ringbuf reader: %w", err)
	}
	l.rd = rd
	return l, nil
}

// Events returns the decoded event stream. Call Start to begin reading.
func (l *Loader) Events() <-chan event.Event { return l.out }

// SetAgentPID writes the agent PID into the self-protection map.
func (l *Loader) SetAgentPID(pid uint32) error {
	if l.objs.AgentPid == nil {
		return errors.New("bpf: agent_pid map missing")
	}
	if err := l.objs.AgentPid.Put(uint32(0), pid); err != nil {
		return err
	}
	l.agentPID = pid
	if l.lsm != nil && l.lsm.AgentPid != nil {
		if err := l.lsm.AgentPid.Put(uint32(0), pid); err != nil {
			return fmt.Errorf("lsm agent_pid mirror: %w", err)
		}
	}
	return nil
}

// Guard bits — must match internal/bpf/probes/common.h.
const (
	GuardSignal      uint32 = 1 // block signals/memory access to the agent
	GuardBPFObject   uint32 = 2 // block tampering with the agent's own BPF objects
	GuardCounterKill uint32 = 4 // counter-kill the offending process when a guard fires
	GuardModule      uint32 = 8 // opt-in: block non-agent kernel module loading
)

// SetGuardConfig arms the kernel-side guards (OR of the Guard* bits).
func (l *Loader) SetGuardConfig(bits uint32) error {
	if l.objs.EdrGuardCfg == nil {
		return errors.New("bpf: edr_guard_cfg map missing")
	}
	l.guard = bits
	// Arm the LSM (kernel-authoritative: its task_kill hook covers *all*
	// signal paths) before the kprobe layer, so the brief interval between the
	// two writes is never a fully-unprotected one. Keep the main guard armed
	// even if the LSM mirror fails, but surface the error.
	var lsmErr error
	if l.lsm != nil && l.lsm.EdrGuardCfg != nil {
		lsmErr = l.lsm.EdrGuardCfg.Put(uint32(0), bits)
	}
	if err := l.objs.EdrGuardCfg.Put(uint32(0), bits); err != nil {
		return err
	}
	if lsmErr != nil {
		return fmt.Errorf("lsm guard mirror: %w", lsmErr)
	}
	return nil
}

// LSMAvailable reports whether the kernel exposes BPF LSM ("bpf" in
// /sys/kernel/security/lsm). Best-effort: false on read error.
func LSMAvailable() bool {
	raw, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		return false
	}
	for _, f := range strings.Split(strings.TrimSpace(string(raw)), ",") {
		if strings.TrimSpace(f) == "bpf" {
			return true
		}
	}
	return false
}

// EnableLSM loads and attaches the optional LSM enforcement object (task_kill
// and ptrace_access_check). It is a no-op returning (false, nil) when BPF LSM
// is unavailable; any load/attach error is returned so the caller can log it,
// but is non-fatal — the kprobe layer remains the primary path. On success the
// LSM maps are registered as the agent's own objects so the bpf_guard also
// protects them, and the current agent pid / guard bits are mirrored in.
func (l *Loader) EnableLSM() (bool, error) {
	if !LSMAvailable() {
		return false, nil
	}
	var objs lsmObjects
	if err := loadLsmObjects(&objs, nil); err != nil {
		return false, fmt.Errorf("lsm load: %w", err)
	}
	tk, err := link.AttachLSM(link.LSMOptions{Program: objs.LsmTaskKill})
	if err != nil {
		_ = objs.Close()
		return false, fmt.Errorf("lsm attach task_kill: %w", err)
	}
	pa, err := link.AttachLSM(link.LSMOptions{Program: objs.LsmPtraceAccessCheck})
	if err != nil {
		_ = tk.Close()
		_ = objs.Close()
		return false, fmt.Errorf("lsm attach ptrace_access_check: %w", err)
	}
	l.lsm = &objs
	l.links = append(l.links, tk, pa)

	// Mirror current state into the LSM maps.
	if objs.AgentPid != nil && l.agentPID != 0 {
		_ = objs.AgentPid.Put(uint32(0), l.agentPID)
	}
	if objs.EdrGuardCfg != nil {
		_ = objs.EdrGuardCfg.Put(uint32(0), l.guard)
	}
	if n, err := l.registerOwnMapIDs(objs.AgentPid, objs.EdrGuardCfg); err != nil {
		fmt.Fprintf(os.Stderr, "edr-agent: warning: lsm own-map registration: %v\n", err)
	} else {
		fmt.Fprintf(os.Stderr, "edr-agent: registered %d LSM map(s) for bpf_guard\n", n)
	}
	return true, nil
}

// registerOwnMapIDs adds extra map ids to the kprobe object's edr_own_ids so
// the bpf_guard protects them too (e.g. the LSM object's own maps).
func (l *Loader) registerOwnMapIDs(maps ...*ebpf.Map) (int, error) {
	if l.objs.EdrOwnIds == nil {
		return 0, errors.New("edr_own_ids map missing")
	}
	n := 0
	for _, m := range maps {
		if m == nil {
			continue
		}
		info, err := m.Info()
		if err != nil {
			return n, fmt.Errorf("map info: %w", err)
		}
		id, ok := info.ID()
		if !ok {
			continue
		}
		if err := l.objs.EdrOwnIds.Put(uint32(id), uint32(2)); err != nil { // EDR_OWN_MAP
			return n, fmt.Errorf("register map %d: %w", id, err)
		}
		n++
	}
	return n, nil
}

// GuardConfig reads back the currently armed guard bits.
func (l *Loader) GuardConfig() (uint32, error) {
	if l.objs.EdrGuardCfg == nil {
		return 0, errors.New("bpf: edr_guard_cfg map missing")
	}
	var v uint32
	if err := l.objs.EdrGuardCfg.Lookup(uint32(0), &v); err != nil {
		return 0, err
	}
	return v, nil
}

// ReadAgentPID reads the agent PID stored in the self-protection map.
func (l *Loader) ReadAgentPID() (uint32, error) {
	if l.objs.AgentPid == nil {
		return 0, errors.New("bpf: agent_pid map missing")
	}
	var v uint32
	if err := l.objs.AgentPid.Lookup(uint32(0), &v); err != nil {
		return 0, err
	}
	return v, nil
}

// ReadHeartbeat reads the heartbeat timestamp maintained by the getpid probe.
func (l *Loader) ReadHeartbeat() (uint64, error) {
	if l.objs.AgentHeartbeat == nil {
		return 0, errors.New("bpf: agent_heartbeat map missing")
	}
	var v uint64
	if err := l.objs.AgentHeartbeat.Lookup(uint32(0), &v); err != nil {
		return 0, err
	}
	return v, nil
}

// RegisterOwnObjects records the agent's own program/map ids in the
// edr_own_ids map and returns how many were registered.
func (l *Loader) RegisterOwnObjects() (int, error) {
	m := l.objs.EdrOwnIds
	if m == nil {
		return 0, errors.New("bpf: edr_own_ids map missing")
	}
	n := 0
	put := func(id uint32, kind uint32) {
		if id == 0 {
			return
		}
		if err := m.Put(id, kind); err == nil {
			n++
		}
	}
	for _, p := range []*ebpf.Program{
		l.objs.HandleExec, l.objs.HandleConnect, l.objs.HandleFork, l.objs.HandleExit,
		l.objs.HandleUnlink, l.objs.HandleUnlinkat, l.objs.HandleRenameat,
		l.objs.HandleSetuid, l.objs.HandleSetgid, l.objs.HandleCapset,
		l.objs.HandleInitModule, l.objs.HandleFinitModule, l.objs.HandleDeleteModule,
		l.objs.HandleBpf, l.objs.EdrHeartbeat, l.objs.EdrSelfprotectKill,
		l.objs.EdrSelfprotectTgkill, l.objs.EdrSelfprotectSigqueue, l.objs.EdrSelfprotectPtrace,
		l.objs.EdrSelfprotectVmReadv, l.objs.EdrSelfprotectVmWritev,
		l.objs.EdrSelfprotectPidfd, l.objs.EdrBpfGuard,
		l.objs.EdrInitModuleGuard, l.objs.EdrFinitModuleGuard,
		l.objs.EdrIoUringEnter, l.objs.EdrVfsUnlink, l.objs.EdrVfsRename,
	} {
		if p == nil {
			continue
		}
		if info, err := p.Info(); err == nil {
			if id, ok := info.ID(); ok {
				put(uint32(id), 1)
			}
		}
	}
	for _, mm := range []*ebpf.Map{
		l.objs.Events, l.objs.AgentPid, l.objs.AgentHeartbeat, l.objs.EdrOwnIds,
		l.objs.EdrGuardCfg, l.objs.IoUringTasks,
	} {
		if mm == nil {
			continue
		}
		if info, err := mm.Info(); err == nil {
			if id, ok := info.ID(); ok {
				put(uint32(id), 2)
			}
		}
	}
	return n, nil
}

// Dropped returns the number of records dropped because the consumer was slow.
func (l *Loader) Dropped() uint64 { return l.dropped.Load() }

// Start begins reading the ring buffer until Close.
func (l *Loader) Start(ctx context.Context) {
	l.wg.Add(1)
	go func() {
		defer l.wg.Done()
		defer close(l.out)
		for {
			rec, err := l.rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				l.readErr.Add(1)
				continue
			}
			l.read.Add(1)
			ev, ok := decodeRecord(rec.RawSample)
			if !ok {
				l.badRec.Add(1)
				continue
			}
			select {
			case l.out <- ev:
			case <-ctx.Done():
				return
			default:
				// Consumer is falling behind: drop and count, never block
				// the ring-buffer reader.
				l.dropped.Add(1)
			}
		}
	}()
}

// Close detaches links and releases all kernel objects.
func (l *Loader) Close() error {
	if !l.closed.CompareAndSwap(false, true) {
		return nil
	}
	if l.rd != nil {
		_ = l.rd.Close()
	}
	l.wg.Wait()
	for _, lnk := range l.links {
		_ = lnk.Close()
	}
	if l.lsm != nil {
		_ = l.lsm.Close()
	}
	return l.objs.Close()
}
