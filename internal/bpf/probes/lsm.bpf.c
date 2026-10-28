// EDR optional BPF-LSM enforcement layer (defense in depth).
//
// Loaded ONLY when the kernel exposes BPF LSM. A load or attach failure is
// non-fatal: the kprobe layer in probes.bpf.c stays the primary path, so a
// host without CONFIG_BPF_LSM simply loses the extra kernel-authoritative
// backstop rather than the whole agent.
//
// Telemetry is intentionally NOT emitted here: the kprobe layer already fires
// on the same syscalls, emits the SELFPROTECT event and counter-kills. This
// object only adds an unbypassable deny at the LSM hook.
//
// It keeps its own copies of agent_pid / edr_guard_cfg; the Go loader writes
// the same values into both the kprobe object and this one.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define EPERM 1

// Must match common.h / loader.go.
#define EDR_GUARD_SIGNAL 1

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} agent_pid SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} edr_guard_cfg SEC(".maps");

static __always_inline int lsm_armed(void)
{
	__u32 key = 0;
	__u32 *cfg = bpf_map_lookup_elem(&edr_guard_cfg, &key);
	return cfg && (*cfg & EDR_GUARD_SIGNAL);
}

// external_to_agent reports whether the target task belongs to the agent and
// the caller is someone else. Precise (target based), never comm based.
static __always_inline int external_to_agent(struct task_struct *t)
{
	if (!t)
		return 0;
	__u32 key = 0;
	__u32 *a = bpf_map_lookup_elem(&agent_pid, &key);
	if (!a || !*a)
		return 0;
	if (BPF_CORE_READ(t, tgid) != *a)
		return 0;
	__u64 id = bpf_get_current_pid_tgid();
	if ((__u32)(id >> 32) == *a)
		return 0;
	return 1;
}

// int task_kill(struct task_struct *p, struct kernel_siginfo *info, int sig,
//               const struct cred *cred)
SEC("lsm/task_kill")
int BPF_PROG(lsm_task_kill, struct task_struct *p, struct kernel_siginfo *info,
	     int sig, const struct cred *cred, int ret)
{
	if (ret != 0 || !lsm_armed())
		return ret;
	if (external_to_agent(p))
		return -EPERM;
	return 0;
}

// int ptrace_access_check(struct task_struct *child, unsigned int mode)
SEC("lsm/ptrace_access_check")
int BPF_PROG(lsm_ptrace_access_check, struct task_struct *child,
	     unsigned int mode, int ret)
{
	if (ret != 0 || !lsm_armed())
		return ret;
	if (external_to_agent(child))
		return -EPERM;
	return 0;
}
