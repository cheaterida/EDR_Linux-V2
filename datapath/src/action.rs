//! Response primitives executed in the datapath process.
//!
//! M1 implements `kill` via pidfd (PID-reuse safe) with a kill(2) fallback.

use std::io;

const SYS_PIDFD_OPEN: libc::c_long = 434;
const SYS_PIDFD_SEND_SIGNAL: libc::c_long = 424;

/// kill sends SIGKILL to pid, preferring pidfd_open to avoid PID reuse races.
/// When exe / start_ticks are supplied the target is validated first.
pub fn kill(pid: i32, exe: &str, start_ticks: u64) -> io::Result<String> {
    if pid <= 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "refusing to signal protected pid",
        ));
    }
    if !exe.is_empty() {
        match std::fs::read_link(format!("/proc/{}/exe", pid)) {
            Ok(p) => {
                if p.to_string_lossy() != exe {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("exe mismatch ({} != {})", p.to_string_lossy(), exe),
                    ));
                }
            }
            Err(_) => {
                return Err(io::Error::new(io::ErrorKind::NotFound, "process gone or unreadable"));
            }
        }
    }
    if start_ticks != 0 {
        if let Some(got) = read_start_ticks(pid) {
            if got != start_ticks {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("start_ticks mismatch ({} != {})", got, start_ticks),
                ));
            }
        } else {
            return Err(io::Error::new(io::ErrorKind::NotFound, "process gone or unreadable"));
        }
    }

    let fd = unsafe { libc::syscall(SYS_PIDFD_OPEN, pid, 0u32) };
    if fd >= 0 {
        let fd = fd as i32;
        let r = unsafe {
            libc::syscall(
                SYS_PIDFD_SEND_SIGNAL,
                fd,
                libc::SIGKILL,
                std::ptr::null::<libc::siginfo_t>(),
                0u32,
            )
        };
        unsafe { libc::close(fd) };
        if r < 0 {
            return Err(io::Error::last_os_error());
        }
        return Ok("killed via pidfd".to_string());
    }

    let r = unsafe { libc::kill(pid, libc::SIGKILL) };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok("killed via kill(2)".to_string())
}

fn read_start_ticks(pid: i32) -> Option<u64> {
    let s = std::fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;
    let close = s.rfind(')')?;
    let rest = &s[close + 2..];
    let fields: Vec<&str> = rest.split_whitespace().collect();
    // fields[0] = state (field 3); starttime is field 22 -> index 19.
    fields.get(19)?.parse::<u64>().ok()
}
