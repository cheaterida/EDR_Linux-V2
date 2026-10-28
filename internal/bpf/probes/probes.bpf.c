// v2 M1 CO-RE probes: exec, fork, exit, connect, file operations.
//
// Kept in a single translation unit so the shared `events` map and helper
// inlines have exactly one definition (avoids the multi-object weak-symbol
// dance). Additional probes (selfprotect/privesc/module/...) are added in M5.
#include "common.h"

char LICENSE[] SEC("license") = "GPL";

// ---- exec ----
SEC("tracepoint/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	struct edr_event *e = edr_reserve();
	if (!e)
		return 0;
	edr_base(e, EDR_EVENT_EXEC);
	// __data_loc_filename is a 16-bit offset into the variable-length tail.
	__u16 off = (__u16)(ctx->__data_loc_filename & 0xFFFF);
	bpf_probe_read_kernel_str(e->filename, sizeof(e->filename),
				  (const char *)ctx + off);

	// Capture argv in-kernel so cmdline-based rules do not depend on a race
	// with /proc enrichment (short-lived processes would otherwise be missed).
	// argv lives in user memory at mm->arg_start..arg_end (NUL-separated); the
	// Go decoder joins segments with spaces.
	struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
	if (task) {
		struct mm_struct *mm = BPF_CORE_READ(task, mm);
		if (mm) {
			unsigned long as = BPF_CORE_READ(mm, arg_start);
			unsigned long ae = BPF_CORE_READ(mm, arg_end);
			if (ae > as) {
				// Mask (rather than compare) so the verifier can prove the
				// length is in [0, 255]; EDR_CMDLINE_LEN is a power of two.
				__u32 len = (__u32)(ae - as);
				len &= (EDR_CMDLINE_LEN - 1);
				if (len)
					bpf_probe_read_user(e->cmdline, len, (const void *)as);
			}
		}
	}

	bpf_ringbuf_submit(e, 0);
	return 0;
}

// ---- fork ----
SEC("tracepoint/sched/sched_process_fork")
int handle_fork(struct trace_event_raw_sched_process_fork *ctx)
{
	struct edr_event *e = edr_reserve();
	if (!e)
		return 0;
	edr_base(e, EDR_EVENT_FORK);
	e->pid = ctx->child_pid;
	e->ppid = ctx->parent_pid;
	__u16 off = (__u16)(ctx->__data_loc_child_comm & 0xFFFF);
	bpf_probe_read_kernel_str(e->comm, sizeof(e->comm), (const char *)ctx + off);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

// ---- exit ----
SEC("tracepoint/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx)
{
	// The tracepoint runs in the exiting task's context, so current pid/comm
	// are authoritative; reading ctx->pid was unreliable across kernels.
	struct edr_event *e = edr_reserve();
	if (!e)
		return 0;
	edr_base(e, EDR_EVENT_EXIT);
	(void)ctx;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

// ---- connect ----
#define EDR_TCP_ESTABLISHED 1
#define EDR_AF_INET  2
#define EDR_AF_INET6 10

SEC("tracepoint/sock/inet_sock_set_state")
int handle_connect(struct trace_event_raw_inet_sock_set_state *ctx)
{
	if (ctx->newstate != EDR_TCP_ESTABLISHED)
		return 0;

	struct edr_event *e = edr_reserve();
	if (!e)
		return 0;
	edr_base(e, EDR_EVENT_CONNECT);
	e->family = ctx->family;
	e->dport = ctx->dport;
	if (ctx->family == EDR_AF_INET) {
		bpf_probe_read_kernel(&e->daddr_v4, sizeof(e->daddr_v4), ctx->daddr);
	} else if (ctx->family == EDR_AF_INET6) {
		bpf_probe_read_kernel(e->daddr_v6, sizeof(e->daddr_v6), ctx->daddr_v6);
	}
	bpf_ringbuf_submit(e, 0);
	return 0;
}

// ---- file operations (unlink / unlinkat / renameat) ----
SEC("tracepoint/syscalls/sys_enter_unlinkat")
int handle_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
	struct edr_event *e = edr_reserve();
	if (!e)
		return 0;
	edr_base(e, EDR_EVENT_FILE_OP);
	e->file_op = EDR_FILEOP_UNLINKAT;
	bpf_probe_read_user_str(e->filename, sizeof(e->filename),
				(const char *)ctx->args[1]);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlink")
int handle_unlink(struct trace_event_raw_sys_enter *ctx)
{
	struct edr_event *e = edr_reserve();
	if (!e)
		return 0;
	edr_base(e, EDR_EVENT_FILE_OP);
	e->file_op = EDR_FILEOP_UNLINK;
	bpf_probe_read_user_str(e->filename, sizeof(e->filename),
				(const char *)ctx->args[0]);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_renameat")
int handle_renameat(struct trace_event_raw_sys_enter *ctx)
{
	struct edr_event *e = edr_reserve();
	if (!e)
		return 0;
	edr_base(e, EDR_EVENT_FILE_OP);
	e->file_op = EDR_FILEOP_RENAMEAT;
	bpf_probe_read_user_str(e->filename, sizeof(e->filename),
				(const char *)ctx->args[1]);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

// ---- privilege changes (setuid/setgid/capset) ----
// reserved = subtype (1=setuid, 2=setgid, 3=capset); file_op = requested value.
#define EDR_PRIV_SETUID 1
#define EDR_PRIV_SETGID 2
#define EDR_PRIV_CAPSET 3

SEC("tracepoint/syscalls/sys_enter_setuid")
int handle_setuid(struct trace_event_raw_sys_enter *ctx)
{
	struct edr_event *e = edr_reserve();
	if (!e)
		return 0;
	edr_base(e, EDR_EVENT_PRIVESC);
	e->reserved = EDR_PRIV_SETUID;
	e->file_op = (__u32)ctx->args[0];
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setgid")
int handle_setgid(struct trace_event_raw_sys_enter *ctx)
{
	struct edr_event *e = edr_reserve();
	if (!e)
		return 0;
	edr_base(e, EDR_EVENT_PRIVESC);
	e->reserved = EDR_PRIV_SETGID;
	e->file_op = (__u32)ctx->args[0];
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_capset")
int handle_capset(struct trace_event_raw_sys_enter *ctx)
{
	struct edr_event *e = edr_reserve();
	if (!e)
		return 0;
	edr_base(e, EDR_EVENT_PRIVESC);
	e->reserved = EDR_PRIV_CAPSET;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

// ---- kernel module load/unload ----
// reserved = subtype (1=init_module, 2=finit_module, 3=delete_module).
SEC("tracepoint/syscalls/sys_enter_init_module")
int handle_init_module(struct trace_event_raw_sys_enter *ctx)
{
	struct edr_event *e = edr_reserve();
	if (!e)
		return 0;
	edr_base(e, EDR_EVENT_MODULE_LOAD);
	e->reserved = 1;
	bpf_probe_read_user_str(e->filename, sizeof(e->filename),
				(const char *)ctx->args[0]);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_finit_module")
int handle_finit_module(struct trace_event_raw_sys_enter *ctx)
{
	struct edr_event *e = edr_reserve();
	if (!e)
		return 0;
	edr_base(e, EDR_EVENT_MODULE_LOAD);
	e->reserved = 2;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_delete_module")
int handle_delete_module(struct trace_event_raw_sys_enter *ctx)
{
	struct edr_event *e = edr_reserve();
	if (!e)
		return 0;
	edr_base(e, EDR_EVENT_MODULE_UNLOAD);
	e->reserved = 3;
	bpf_probe_read_user_str(e->filename, sizeof(e->filename),
				(const char *)ctx->args[0]);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

// ---- self-protection (precise: only ops targeting the agent are blocked) ----
#define EPERM 1

static __always_inline __u32 edr_agent_tgid(void)
{
	__u32 key = 0;
	__u32 *a = bpf_map_lookup_elem(&agent_pid, &key);
	return a ? *a : 0;
}

// edr_guard_armed reports whether a guard bit is currently armed.
static __always_inline int edr_guard_armed(__u32 bit)
{
	__u32 key = 0;
	__u32 *cfg = bpf_map_lookup_elem(&edr_guard_cfg, &key);
	return cfg && (*cfg & bit);
}

static __always_inline void edr_emit_selfprotect(__u32 target, const char *what, __u32 detail)
{
	struct edr_event *e = edr_reserve();
	if (!e)
		return;
	edr_base(e, EDR_EVENT_SELFPROTECT);
	e->ppid = target;
	e->reserved = detail;
	__builtin_memcpy(e->filename, what, 24);
	bpf_ringbuf_submit(e, 0);
}

// Block (and counter-kill) signals delivered to the agent by other processes.
SEC("kprobe/__x64_sys_kill")
int edr_selfprotect_kill(struct pt_regs *ctx)
{
	if (!edr_guard_armed(EDR_GUARD_SIGNAL))
		return 0;
	struct pt_regs *kr = (struct pt_regs *)ctx->di;
	__u32 pid = 0, sig = 0;
	bpf_probe_read_kernel(&pid, sizeof(pid), &kr->di);
	bpf_probe_read_kernel(&sig, sizeof(sig), &kr->si);
	__u32 agent = edr_agent_tgid();
	if (!agent || pid != agent)
		return 0;
	__u64 id = bpf_get_current_pid_tgid();
	if ((__u32)(id >> 32) == agent)
		return 0;
	bpf_override_return(ctx, -EPERM);
	bpf_send_signal(9);
	edr_emit_selfprotect(agent, "sys_kill", sig);
	return 0;
}

SEC("kprobe/__x64_sys_tgkill")
int edr_selfprotect_tgkill(struct pt_regs *ctx)
{
	if (!edr_guard_armed(EDR_GUARD_SIGNAL))
		return 0;
	struct pt_regs *kr = (struct pt_regs *)ctx->di;
	__u32 tgid = 0, tid = 0, sig = 0;
	bpf_probe_read_kernel(&tgid, sizeof(tgid), &kr->di);
	bpf_probe_read_kernel(&tid, sizeof(tid), &kr->si);
	bpf_probe_read_kernel(&sig, sizeof(sig), &kr->dx);
	__u32 agent = edr_agent_tgid();
	if (!agent || (tgid != agent && tid != agent))
		return 0;
	__u64 id = bpf_get_current_pid_tgid();
	if ((__u32)(id >> 32) == agent)
		return 0;
	bpf_override_return(ctx, -EPERM);
	bpf_send_signal(9);
	edr_emit_selfprotect(agent, "sys_tgkill", sig);
	return 0;
}

SEC("kprobe/__x64_sys_rt_sigqueueinfo")
int edr_selfprotect_sigqueue(struct pt_regs *ctx)
{
	if (!edr_guard_armed(EDR_GUARD_SIGNAL))
		return 0;
	struct pt_regs *kr = (struct pt_regs *)ctx->di;
	__u32 pid = 0;
	bpf_probe_read_kernel(&pid, sizeof(pid), &kr->di);
	__u32 agent = edr_agent_tgid();
	if (!agent || pid != agent)
		return 0;
	__u64 id = bpf_get_current_pid_tgid();
	if ((__u32)(id >> 32) == agent)
		return 0;
	bpf_override_return(ctx, -EPERM);
	bpf_send_signal(9);
	edr_emit_selfprotect(agent, "rt_sigqueueinfo", 0);
	return 0;
}

SEC("kprobe/__x64_sys_ptrace")
int edr_selfprotect_ptrace(struct pt_regs *ctx)
{
	if (!edr_guard_armed(EDR_GUARD_SIGNAL))
		return 0;
	struct pt_regs *kr = (struct pt_regs *)ctx->di;
	__u32 pid = 0;
	bpf_probe_read_kernel(&pid, sizeof(pid), &kr->si);
	__u32 agent = edr_agent_tgid();
	if (!agent || pid != agent)
		return 0;
	__u64 id = bpf_get_current_pid_tgid();
	if ((__u32)(id >> 32) == agent)
		return 0;
	bpf_override_return(ctx, -EPERM);
	bpf_send_signal(9);
	edr_emit_selfprotect(agent, "sys_ptrace", 0);
	return 0;
}

SEC("kprobe/__x64_sys_process_vm_readv")
int edr_selfprotect_vm_readv(struct pt_regs *ctx)
{
	if (!edr_guard_armed(EDR_GUARD_SIGNAL))
		return 0;
	struct pt_regs *kr = (struct pt_regs *)ctx->di;
	__u32 pid = 0;
	bpf_probe_read_kernel(&pid, sizeof(pid), &kr->di);
	__u32 agent = edr_agent_tgid();
	if (!agent || pid != agent)
		return 0;
	__u64 id = bpf_get_current_pid_tgid();
	if ((__u32)(id >> 32) == agent)
		return 0;
	bpf_override_return(ctx, -EPERM);
	bpf_send_signal(9);
	edr_emit_selfprotect(agent, "process_vm_readv", 0);
	return 0;
}

SEC("kprobe/__x64_sys_process_vm_writev")
int edr_selfprotect_vm_writev(struct pt_regs *ctx)
{
	if (!edr_guard_armed(EDR_GUARD_SIGNAL))
		return 0;
	struct pt_regs *kr = (struct pt_regs *)ctx->di;
	__u32 pid = 0;
	bpf_probe_read_kernel(&pid, sizeof(pid), &kr->di);
	__u32 agent = edr_agent_tgid();
	if (!agent || pid != agent)
		return 0;
	__u64 id = bpf_get_current_pid_tgid();
	if ((__u32)(id >> 32) == agent)
		return 0;
	bpf_override_return(ctx, -EPERM);
	bpf_send_signal(9);
	edr_emit_selfprotect(agent, "process_vm_writev", 0);
	return 0;
}

// pidfd_send_signal(pidfd, sig, info, flags): resolve the pidfd to its
// struct pid and block delivery to the agent. This closes the pidfd signal
// path that bypasses kill/tgkill/rt_sigqueueinfo.
SEC("kprobe/__x64_sys_pidfd_send_signal")
int edr_selfprotect_pidfd(struct pt_regs *ctx)
{
	if (!edr_guard_armed(EDR_GUARD_SIGNAL))
		return 0;
	struct pt_regs *kr = (struct pt_regs *)ctx->di;
	__u32 pidfd = 0, sig = 0;
	bpf_probe_read_kernel(&pidfd, sizeof(pidfd), &kr->di);
	bpf_probe_read_kernel(&sig, sizeof(sig), &kr->si);
	__u32 agent = edr_agent_tgid();
	if (!agent)
		return 0;

	struct file *f = edr_file_from_fd(pidfd);
	if (!f)
		return 0;

	// A pidfd's struct pid lives in file->private_data on older kernels and in
	// the pidfs inode's i_private on newer ones (6.9+). Try both; we only act
	// when the resolved pid number matches the agent, so a wrong layout is a
	// harmless no-op.
	__u32 nr = 0;
	struct pid *p = (struct pid *)BPF_CORE_READ(f, private_data);
	if (p)
		nr = BPF_CORE_READ(p, numbers[0].nr);
	if (nr != agent) {
		struct inode *inode = BPF_CORE_READ(f, f_inode);
		if (inode) {
			struct pid *p2 = (struct pid *)BPF_CORE_READ(inode, i_private);
			if (p2)
				nr = BPF_CORE_READ(p2, numbers[0].nr);
		}
	}
	if (nr != agent)
		return 0;

	__u64 id = bpf_get_current_pid_tgid();
	if ((__u32)(id >> 32) == agent)
		return 0;
	bpf_override_return(ctx, -EPERM);
	bpf_send_signal(9);
	edr_emit_selfprotect(agent, "sys_pidfd_send_signal", sig);
	return 0;
}

// Heartbeat: refreshed on any observed getpid() syscall. The agent calls a raw
// getpid() on a timer so a detached probe set is detected as a stale value.
SEC("tracepoint/syscalls/sys_enter_getpid")
int edr_heartbeat(void *ctx)
{
	__u32 key = 0;
	__u64 now = bpf_ktime_get_ns();
	bpf_map_update_elem(&agent_heartbeat, &key, &now, BPF_ANY);
	return 0;
}

// ---- bpf() syscall ----
// reserved = bpf cmd.
SEC("tracepoint/syscalls/sys_enter_bpf")
int handle_bpf(struct trace_event_raw_sys_enter *ctx)
{
	// Ignore EDR's own bpf() syscalls (map/prog management noise): skip by
	// agent PID (when set) or by the "edr-" comm prefix.
	__u32 akey = 0;
	__u32 *agent = bpf_map_lookup_elem(&agent_pid, &akey);
	__u64 cid = bpf_get_current_pid_tgid();
	if (agent && *agent != 0 && (__u32)(cid >> 32) == *agent)
		return 0;
	char comm[16];
	bpf_get_current_comm(&comm, sizeof(comm));
	if (comm[0] == 'e' && comm[1] == 'd' && comm[2] == 'r' && comm[3] == '-')
		return 0;

	struct edr_event *e = edr_reserve();
	if (!e)
		return 0;
	edr_base(e, EDR_EVENT_BPF_OP);
	e->reserved = (__u32)ctx->args[0];
	bpf_ringbuf_submit(e, 0);
	return 0;
}

// ---- BPF object guard (precise, id-based) ----
//
// Blocks any process (including a rogue root) from disabling the agent's own
// BPF protection by mutating/detaching objects that belong to the agent
// (recorded in edr_own_ids by the Go loader). Objects that are not ours are
// never touched, so host tooling (bpftool, Cilium, container runtimes, ...)
// keeps working. This is deliberately narrow rather than a blanket block.
//
// Guarded commands:
//   BPF_MAP_UPDATE_ELEM / BPF_MAP_DELETE_ELEM / BPF_MAP_FREEZE — our maps
//   BPF_PROG_DETACH — detaching one of our programs
//   BPF_LINK_DETACH — detaching a link whose program is ours

// edr_prog_id_from_fd resolves a program fd to (id, EDR_OWN_PROG).
static __always_inline int edr_prog_id_from_fd(__u32 fd, __u32 *id, __u32 *kind)
{
	struct file *f = edr_file_from_fd(fd);
	if (!f)
		return 0;
	struct bpf_prog *p = (struct bpf_prog *)BPF_CORE_READ(f, private_data);
	if (!p)
		return 0;
	*id = BPF_CORE_READ(p, aux, id);
	*kind = EDR_OWN_PROG;
	return 1;
}

// edr_own_object resolves the guarded syscall's target object id. Returns 1 and
// fills id/kind only for commands that act on exactly one BPF object.
static __always_inline int edr_own_object(__u32 cmd, __u64 uattr, __u32 *id, __u32 *kind)
{
	switch (cmd) {
	case BPF_MAP_UPDATE_ELEM:
	case BPF_MAP_DELETE_ELEM:
	case BPF_MAP_FREEZE: {
		__u32 map_fd = 0;
		if (bpf_probe_read_user(&map_fd, sizeof(map_fd), (const void *)uattr))
			return 0;
		struct file *f = edr_file_from_fd(map_fd);
		if (!f)
			return 0;
		struct bpf_map *m = (struct bpf_map *)BPF_CORE_READ(f, private_data);
		if (!m)
			return 0;
		*id = BPF_CORE_READ(m, id);
		*kind = EDR_OWN_MAP;
		return 1;
	}
	case BPF_PROG_DETACH: {
		// union bpf_attr { __u32 target_fd; __u32 attach_bpf_fd; ... }
		__u32 prog_fd = 0;
		if (bpf_probe_read_user(&prog_fd, sizeof(prog_fd), (const void *)(uattr + 4)))
			return 0;
		return edr_prog_id_from_fd(prog_fd, id, kind);
	}
	case BPF_PROG_ATTACH: {
		// attaching one of our programs: attach_bpf_fd sits at offset 4.
		__u32 prog_fd = 0;
		if (bpf_probe_read_user(&prog_fd, sizeof(prog_fd), (const void *)(uattr + 4)))
			return 0;
		return edr_prog_id_from_fd(prog_fd, id, kind);
	}
	case BPF_LINK_CREATE: {
		// union bpf_attr { __u32 prog_fd; ... } (prog_fd at offset 0).
		__u32 prog_fd = 0;
		if (bpf_probe_read_user(&prog_fd, sizeof(prog_fd), (const void *)uattr))
			return 0;
		return edr_prog_id_from_fd(prog_fd, id, kind);
	}
	case BPF_LINK_UPDATE: {
		// union bpf_attr { __u32 link_fd; __u32 new_prog_fd; __u32 flags;
		//                  __u32 old_prog_fd; } — replacing our prog either side.
		__u32 np = 0, op = 0;
		if (bpf_probe_read_user(&np, sizeof(np), (const void *)(uattr + 4)) == 0 &&
		    edr_prog_id_from_fd(np, id, kind))
			return 1;
		if (bpf_probe_read_user(&op, sizeof(op), (const void *)(uattr + 12)) == 0 &&
		    edr_prog_id_from_fd(op, id, kind))
			return 1;
		return 0;
	}
	case BPF_LINK_DETACH: {
		__u32 link_fd = 0;
		if (bpf_probe_read_user(&link_fd, sizeof(link_fd), (const void *)uattr))
			return 0;
		struct file *f = edr_file_from_fd(link_fd);
		if (!f)
			return 0;
		struct bpf_link *l = (struct bpf_link *)BPF_CORE_READ(f, private_data);
		if (!l)
			return 0;
		*id = BPF_CORE_READ(l, prog, aux, id);
		*kind = EDR_OWN_PROG;
		return 1;
	}
	default:
		return 0;
	}
}

SEC("kprobe/__x64_sys_bpf")
int edr_bpf_guard(struct pt_regs *ctx)
{
	if (!edr_guard_armed(EDR_GUARD_BPF))
		return 0;

	struct pt_regs *kr = (struct pt_regs *)ctx->di;
	__u32 cmd = 0;
	if (bpf_probe_read_kernel(&cmd, sizeof(cmd), &kr->di))
		return 0;
	__u64 uattr = 0;
	if (bpf_probe_read_kernel(&uattr, sizeof(uattr), &kr->si))
		return 0;
	if (!uattr)
		return 0;

	__u32 oid = 0, okind = 0;
	if (!edr_own_object(cmd, uattr, &oid, &okind) || !oid)
		return 0;

	// Only objects registered as the agent's own are protected.
	__u32 *owned = bpf_map_lookup_elem(&edr_own_ids, &oid);
	if (!owned || *owned != okind)
		return 0;

	// The agent itself legitimately manages its own objects.
	__u64 id = bpf_get_current_pid_tgid();
	__u32 cur = id >> 32;
	__u32 agent = edr_agent_tgid();
	if (agent && cur == agent)
		return 0;

	bpf_override_return(ctx, -EPERM);
	if (edr_guard_armed(EDR_GUARD_KILL))
		bpf_send_signal(9);

	struct edr_event *e = edr_reserve();
	if (!e)
		return 0;
	edr_base(e, EDR_EVENT_SELFPROTECT);
	e->reserved = cmd;  // which bpf command was blocked
	e->ppid = oid;      // targeted own object id
	e->file_op = okind; // EDR_OWN_MAP / EDR_OWN_PROG
	__builtin_memcpy(e->filename, "bpf_object_guard", 17);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

// ---- strict module-load guard (opt-in) ----
// A malicious LKM can disable userspace/kprobe protection from ring 0. Hosts
// that never load modules at runtime can arm EDR_GUARD_MODULE to deny
// non-agent init_module/finit_module. Counter-kill only when the self-protect
// KILL bit is also armed, so strict-mode alone is a block+alert profile.
static __always_inline int edr_module_blocked(struct pt_regs *ctx, const char *what)
{
	if (!edr_guard_armed(EDR_GUARD_MODULE))
		return 0;
	__u32 agent = edr_agent_tgid();
	__u64 id = bpf_get_current_pid_tgid();
	if (agent && (__u32)(id >> 32) == agent)
		return 0;
	bpf_override_return(ctx, -EPERM);
	if (edr_guard_armed(EDR_GUARD_KILL))
		bpf_send_signal(9);
	edr_emit_selfprotect(0, what, 0);
	return 0;
}

SEC("kprobe/__x64_sys_init_module")
int edr_init_module_guard(struct pt_regs *ctx)
{
	return edr_module_blocked(ctx, "sys_init_module");
}

SEC("kprobe/__x64_sys_finit_module")
int edr_finit_module_guard(struct pt_regs *ctx)
{
	return edr_module_blocked(ctx, "sys_finit_module");
}

// ---- io_uring / VFS file operations ----
// io_uring file ops execute through VFS helpers and bypass the
// sys_enter_unlinkat/renameat tracepoints, so a syscall-only sensor is blind to
// them. These probes emit a basename-level file event when the operation
// originates from io_uring: either an iou-wrk/iou-sqp thread, or a task that
// recently called io_uring_enter (inline execution).
#define EDR_IOURING_WINDOW_NS (5ULL * 1000000000ULL)

SEC("kprobe/__x64_sys_io_uring_enter")
int edr_io_uring_enter(struct pt_regs *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	__u32 tgid = id >> 32;
	__u64 now = bpf_ktime_get_ns();
	bpf_map_update_elem(&io_uring_tasks, &tgid, &now, BPF_ANY);
	return 0;
}

static __always_inline int edr_iouring_op(void)
{
	char comm[16];
	bpf_get_current_comm(&comm, sizeof(comm));
	if (comm[0] == 'i' && comm[1] == 'o' && comm[2] == 'u' && comm[3] == '-')
		return 1;
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	__u64 *ts = bpf_map_lookup_elem(&io_uring_tasks, &tgid);
	if (!ts)
		return 0;
	return (bpf_ktime_get_ns() - *ts) < EDR_IOURING_WINDOW_NS;
}

static __always_inline void edr_emit_vfs_op(struct dentry *d, __u32 op)
{
	if (!d)
		return;
	struct edr_event *e = edr_reserve();
	if (!e)
		return;
	edr_base(e, EDR_EVENT_FILE_OP);
	e->file_op = op;
	const unsigned char *name = BPF_CORE_READ(d, d_name.name);
	if (name)
		bpf_probe_read_kernel_str(e->filename, sizeof(e->filename), name);
	bpf_ringbuf_submit(e, 0);
}

SEC("kprobe/vfs_unlink")
int edr_vfs_unlink(struct pt_regs *ctx)
{
	if (!edr_iouring_op())
		return 0;
	// x86-64 function args: di, si, dx, cx, r8, r9. vfs_unlink's dentry is arg3.
	edr_emit_vfs_op((struct dentry *)ctx->dx, EDR_FILEOP_VFS_UNLINK);
	return 0;
}

SEC("kprobe/vfs_rename")
int edr_vfs_rename(struct pt_regs *ctx)
{
	if (!edr_iouring_op())
		return 0;
	// vfs_rename(old_dir, old_dentry, new_dir, new_dentry, ...): dx/r8 hold them.
	edr_emit_vfs_op((struct dentry *)ctx->dx, EDR_FILEOP_VFS_RENAME);   // source
	edr_emit_vfs_op((struct dentry *)ctx->r8, EDR_FILEOP_VFS_RENAME_TO); // target
	return 0;
}
