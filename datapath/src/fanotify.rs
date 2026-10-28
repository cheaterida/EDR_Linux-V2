//! fanotify FAN_OPEN_PERM handling.
//!
//! The Go control plane pushes a decision table; this module matches opens
//! locally and answers the kernel synchronously. Denied opens are streamed
//! back to Go as EVENT frames for the audit chain.

use std::ffi::CString;
use std::fs;
use std::io;
use std::os::unix::io::RawFd;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::ipc::{write_frame, Msg};
use crate::policy::Snapshot;

const FAN_CLOEXEC: u64 = 0x1;
const FAN_NONBLOCK: u64 = 0x2;
const FAN_CLASS_CONTENT: u64 = 0x4;
const FAN_UNLIMITED_QUEUE: u64 = 0x10;
const FAN_UNLIMITED_MARKS: u64 = 0x20;
const FAN_MARK_ADD: u64 = 0x1;
const FAN_OPEN_PERM: u64 = 0x0001_0000;
const FAN_EVENT_ON_CHILD: u64 = 0x0800_0000;
const FAN_ALLOW: u32 = 0x01;
const FAN_DENY: u32 = 0x02;
const FAN_NOFD: i32 = -1;

const SYS_FANOTIFY_INIT: libc::c_long = 300;
const SYS_FANOTIFY_MARK: libc::c_long = 301;
const AT_FDCWD: libc::c_int = -100;

#[repr(C)]
#[derive(Clone, Copy)]
struct FanotifyEventMetadata {
    event_len: u32,
    vers: u8,
    reserved: u8,
    metadata_len: u16,
    mask: u64,
    fd: i32,
    pid: i32,
}

#[derive(Default)]
pub struct Counters {
    pub allowed: AtomicU64,
    pub denied: AtomicU64,
    pub marks: AtomicU64,
}

pub struct Context {
    pub policy: Arc<Mutex<Snapshot>>,
    pub writer: Arc<Mutex<Option<UnixStream>>>,
    pub counters: Arc<Counters>,
    pub stop: Arc<AtomicBool>,
}

fn sys_fanotify_init(flags: u64, event_f_flags: u64) -> io::Result<RawFd> {
    let fd = unsafe { libc::syscall(SYS_FANOTIFY_INIT, flags, event_f_flags) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd as RawFd)
}

fn sys_fanotify_mark(fd: RawFd, flags: u64, mask: u64, path: &str) -> io::Result<()> {
    let c = CString::new(path).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL path"))?;
    let r = unsafe {
        libc::syscall(
            SYS_FANOTIFY_MARK,
            fd,
            flags,
            mask,
            AT_FDCWD,
            c.as_ptr() as *const libc::c_char,
        )
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// mark_path adds a mark for `path`. Directories get FAN_EVENT_ON_CHILD and are
/// walked up to `max_depth` so opens deeper in the tree are intercepted.
pub fn mark_path(fd: RawFd, path: &str, max_depth: u32, max_marks: u64, counters: &Counters) -> io::Result<()> {
    let md = fs::symlink_metadata(path)?;
    if md.is_dir() {
        mark_dir(fd, path, 0, max_depth, max_marks, counters)
    } else {
        sys_fanotify_mark(fd, FAN_MARK_ADD, FAN_OPEN_PERM, path)?;
        counters.marks.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

fn mark_dir(fd: RawFd, path: &str, depth: u32, max_depth: u32, max_marks: u64, counters: &Counters) -> io::Result<()> {
    if depth > max_depth || counters.marks.load(Ordering::Relaxed) >= max_marks {
        return Ok(());
    }
    if sys_fanotify_mark(fd, FAN_MARK_ADD, FAN_OPEN_PERM | FAN_EVENT_ON_CHILD, path).is_ok() {
        counters.marks.fetch_add(1, Ordering::Relaxed);
    }
    if let Ok(entries) = fs::read_dir(path) {
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                let _ = mark_dir(fd, &p.to_string_lossy(), depth + 1, max_depth, max_marks, counters);
            }
        }
    }
    Ok(())
}

pub fn init_group() -> io::Result<RawFd> {
    sys_fanotify_init(
        FAN_CLASS_CONTENT | FAN_CLOEXEC | FAN_NONBLOCK | FAN_UNLIMITED_QUEUE | FAN_UNLIMITED_MARKS,
        0,
    )
}

fn read_meta(p: *const u8) -> FanotifyEventMetadata {
    unsafe { std::ptr::read_unaligned(p as *const FanotifyEventMetadata) }
}

fn readlink(path: &str) -> String {
    fs::read_link(path).map(|p| p.to_string_lossy().into_owned()).unwrap_or_default()
}

fn read_trim(path: &str) -> String {
    fs::read_to_string(path).map(|s| s.trim().to_string()).unwrap_or_default()
}

fn respond(fd: RawFd, event_fd: i32, response: u32) {
    let mut buf = [0u8; 8];
    buf[0..4].copy_from_slice(&event_fd.to_le_bytes());
    buf[4..8].copy_from_slice(&response.to_le_bytes());
    unsafe {
        libc::write(fd, buf.as_ptr() as *const libc::c_void, 8);
    }
}

fn is_self(comm: &str, exe: &str) -> bool {
    matches!(comm, "edr-agent" | "edrctl" | "edr-datapath")
        || exe == "/opt/edr/edr-agent"
        || exe == "/opt/edr/edrctl"
}

pub fn run(fd: RawFd, ctx: Context) {
    let mut buf = vec![0u8; 8192];
    while !ctx.stop.load(Ordering::Relaxed) {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let n = unsafe { libc::poll(&mut pfd, 1, 500) };
        if n <= 0 {
            continue;
        }
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n <= 0 {
            continue;
        }
        let total = n as usize;
        let mut off = 0usize;
        while off + std::mem::size_of::<FanotifyEventMetadata>() <= total {
            let meta = read_meta(unsafe { buf.as_ptr().add(off) });
            let elen = meta.event_len as usize;
            if elen < std::mem::size_of::<FanotifyEventMetadata>() || off + elen > total {
                break;
            }
            if meta.mask & FAN_OPEN_PERM != 0 {
                handle_open_perm(fd, &meta, &ctx);
            }
            if meta.fd != FAN_NOFD {
                unsafe {
                    libc::close(meta.fd);
                }
            }
            off += elen;
        }
    }
}

fn handle_open_perm(fanfd: RawFd, meta: &FanotifyEventMetadata, ctx: &Context) {
    let path = if meta.fd >= 0 {
        readlink(&format!("/proc/self/fd/{}", meta.fd))
    } else {
        String::new()
    };
    let pid = meta.pid;
    let comm = read_trim(&format!("/proc/{}/comm", pid));
    let exe = readlink(&format!("/proc/{}/exe", pid));

    // Never block our own components.
    if is_self(&comm, &exe) {
        if meta.fd != FAN_NOFD {
            respond(fanfd, meta.fd, FAN_ALLOW);
        }
        ctx.counters.allowed.fetch_add(1, Ordering::Relaxed);
        return;
    }

    let verdict = {
        let snap = ctx.policy.lock().unwrap();
        snap.decide(&path)
    };

    match verdict {
        Some((rule_id, true)) => {
            if meta.fd != FAN_NOFD {
                respond(fanfd, meta.fd, FAN_DENY);
            }
            ctx.counters.denied.fetch_add(1, Ordering::Relaxed);
            emit_event(ctx, pid, &comm, &path, "deny", &rule_id);
        }
        Some((_rule_id, false)) => {
            if meta.fd != FAN_NOFD {
                respond(fanfd, meta.fd, FAN_ALLOW);
            }
            ctx.counters.allowed.fetch_add(1, Ordering::Relaxed);
        }
        None => {
            if meta.fd != FAN_NOFD {
                respond(fanfd, meta.fd, FAN_ALLOW);
            }
            ctx.counters.allowed.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn emit_event(ctx: &Context, pid: i32, comm: &str, path: &str, decision: &str, rule_id: &str) {
    let msg = Msg::Event {
        kind: 14, // file-access kind (datapath-local)
        pid,
        comm: comm.to_string(),
        path: path.to_string(),
        op: "open".to_string(),
        decision: decision.to_string(),
        rule_id: rule_id.to_string(),
    };
    if let Ok(mut guard) = ctx.writer.lock() {
        if let Some(stream) = guard.as_mut() {
            let _ = write_frame(stream, &msg);
        }
    }
}
