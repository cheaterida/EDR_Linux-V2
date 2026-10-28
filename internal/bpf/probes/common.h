// Common CO-RE types and the shared ring-buffer map for the v2 probes.
//
// The on-the-wire struct layout is a binary contract with internal/bpf/decode.go.
// Any change here MUST be mirrored there (offsets are asserted in C below and
// documented in Go).
#pragma once

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Event kinds — must match edr/internal/event Kind values.
#define EDR_EVENT_EXEC          1
#define EDR_EVENT_CONNECT       2
#define EDR_EVENT_FORK          3
#define EDR_EVENT_EXIT          4
#define EDR_EVENT_SELFPROTECT   5
#define EDR_EVENT_PRIVESC       9
#define EDR_EVENT_MODULE_LOAD   10
#define EDR_EVENT_MODULE_UNLOAD 11
#define EDR_EVENT_BPF_OP        12
#define EDR_EVENT_FILE_OP       13

// File-op subtypes.
#define EDR_FILEOP_UNLINKAT 1
#define EDR_FILEOP_UNLINK   2
#define EDR_FILEOP_RENAMEAT 3
// VFS-level operations, emitted only for io_uring-originated work (which
// bypasses the sys_enter_* tracepoints). The filename is the dentry basename.
#define EDR_FILEOP_VFS_UNLINK    4
#define EDR_FILEOP_VFS_RENAME    5
#define EDR_FILEOP_VFS_RENAME_TO 6

#define EDR_COMM_LEN     16
#define EDR_FILENAME_LEN 256
#define EDR_CMDLINE_LEN  256

// edr_event is the fixed-layout payload written to the ring buffer.
//
// Layout (little-endian), total 332 bytes:
//   0   u64 ts_ns
//   8   u32 pid     (tgid)
//   12  u32 tid
//   16  u32 ppid
//   20  u32 uid
//   24  u32 reserved
//   28  u32 file_op
//   32  u8  type
//   33  u8  family
//   34  u8  _pad0[2]
//   36  u16 dport
//   38  u8  _pad1[2]
//   40  u32 daddr_v4
//   44  u8  daddr_v6[16]
//   60  char comm[16]
//   76  char filename[256]
//   332 char cmdline[256]   (exec only: raw NUL-separated argv, joined in decode)
struct edr_event {
	__u64 ts_ns;
	__u32 pid;
	__u32 tid;
	__u32 ppid;
	__u32 uid;
	__u32 reserved;
	__u32 file_op;
	__u8 type;
	__u8 family;
	__u8 _pad0[2];
	__u16 dport;
	__u8 _pad1[2];
	__u32 daddr_v4;
	__u8 daddr_v6[16];
	char comm[EDR_COMM_LEN];
	char filename[EDR_FILENAME_LEN];
	char cmdline[EDR_CMDLINE_LEN];
};

_Static_assert(sizeof(struct edr_event) == 592, "edr_event layout changed; update decode.go");

// events is the single ring buffer consumed by the Go loader.
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

// agent_pid holds the EDR agent tgid so self-protection probes can compare a
// syscall's target against it (precise interception, no blanket blocking).
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} agent_pid SEC(".maps");

// agent_heartbeat is refreshed whenever a getpid() syscall is observed. The
// Go sentinel writes agent_heartbeat's reader cadence by calling getpid() on a
// timer; a stale value means the probes were detached.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} agent_heartbeat SEC(".maps");

// edr_own_ids records the agent's own program/map ids (telemetry + future
// object-precise bpf() protection). key = id, value = kind.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, __u32);
	__type(value, __u32);
} edr_own_ids SEC(".maps");

#define EDR_OWN_PROG 1
#define EDR_OWN_MAP  2

// edr_guard_cfg arms kernel-side guards. Bits:
//   EDR_GUARD_SIGNAL — block/counter-kill signals & memory access to the agent
//   EDR_GUARD_BPF    — block tampering with the agent's own BPF objects
//   EDR_GUARD_KILL   — counter-kill the offending process when a guard fires
// Keeping each concern on its own bit means --bpf-guard does not silently turn
// on signal interception, and signal self-protection does not require the BPF
// object guard.
#define EDR_GUARD_SIGNAL 1
#define EDR_GUARD_BPF    2
#define EDR_GUARD_KILL   4
#define EDR_GUARD_MODULE 8 // opt-in: block kernel module loading (strict hosts)

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} edr_guard_cfg SEC(".maps");

// io_uring_tasks marks tasks that recently submitted io_uring work. VFS probes
// consult it so inline-executed io_uring file ops (performed in the submitting
// task, not an iou-wrk thread) are still attributed to io_uring.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, __u32);
	__type(value, __u64);
} io_uring_tasks SEC(".maps");

static __always_inline struct edr_event *edr_reserve(void)
{
	return bpf_ringbuf_reserve(&events, sizeof(struct edr_event), 0);
}

static __always_inline void edr_base(struct edr_event *e, __u8 type)
{
	__builtin_memset(e, 0, sizeof(*e));
	e->type = type;
	e->ts_ns = bpf_ktime_get_ns();
	__u64 id = bpf_get_current_pid_tgid();
	e->pid = id >> 32;
	e->tid = (__u32)id;
	e->uid = (__u32)bpf_get_current_uid_gid();
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

// edr_file_from_fd resolves a userspace fd to its struct file * for the current
// task, or NULL. CO-RE and identity-agnostic: it does not assume anything about
// the caller's comm, so it is safe to use for precise, target-based decisions.
static __always_inline struct file *edr_file_from_fd(__u32 fd)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
	if (!task)
		return NULL;
	struct files_struct *files = BPF_CORE_READ(task, files);
	if (!files)
		return NULL;
	struct fdtable *fdt = BPF_CORE_READ(files, fdt);
	if (!fdt)
		return NULL;
	unsigned int max = BPF_CORE_READ(fdt, max_fds);
	if (fd >= max)
		return NULL;
	struct file **fdp = BPF_CORE_READ(fdt, fd);
	if (!fdp)
		return NULL;
	struct file *f = NULL;
	if (bpf_probe_read_kernel(&f, sizeof(f), &fdp[fd]))
		return NULL;
	return f;
}
