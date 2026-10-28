//! edr-datapath — the EDR v2 data-plane helper.
//!
//! Responsibilities (small boundary):
//!   * fanotify FAN_OPEN_PERM synchronous decisions (local matching)
//!   * response primitives (pidfd kill)
//!
//! It never owns detection policy: the Go control plane compiles a decision
//! table and pushes it over the IPC socket.

mod action;
mod fanotify;
mod ipc;
mod policy;

use std::io;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use ipc::{read_frame, write_frame, Msg};
use policy::Snapshot;

struct Args {
    socket: String,
    watch: Vec<String>,
    depth: u32,
    max_marks: u64,
}

fn parse_args() -> Args {
    let mut args = Args {
        socket: "/run/edr/datapath.sock".to_string(),
        watch: Vec::new(),
        depth: 8,
        max_marks: 4096,
    };
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--socket" => args.socket = it.next().unwrap_or_default(),
            "--watch" => {
                if let Some(v) = it.next() {
                    args.watch.push(v);
                }
            }
            "--depth" => args.depth = it.next().and_then(|v| v.parse().ok()).unwrap_or(8),
            "--max-marks" => args.max_marks = it.next().and_then(|v| v.parse().ok()).unwrap_or(4096),
            "-h" | "--help" => {
                eprintln!(
                    "usage: edr-datapath [--socket PATH] [--watch PATH]... [--depth N] [--max-marks N]"
                );
                process::exit(0);
            }
            _ => {}
        }
    }
    args
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn send(ctx: &fanotify::Context, msg: &Msg) {
    if let Ok(mut guard) = ctx.writer.lock() {
        if let Some(stream) = guard.as_mut() {
            let _ = write_frame(stream, msg);
        }
    }
}

fn handle_connection(stream: UnixStream, ctx: &fanotify::Context) -> io::Result<()> {
    stream.set_nonblocking(false)?;
    let writer_stream = stream.try_clone()?;
    {
        let mut guard = ctx.writer.lock().unwrap();
        *guard = Some(writer_stream);
    }

    let mut reader = stream;
    while let Some(msg) = read_frame(&mut reader)? {
        match msg {
            Msg::Hello { agent_pid } => {
                eprintln!("datapath: hello from agent pid {}", agent_pid);
            }
            Msg::Policy { version, rules } => {
                let n = rules.len();
                let mut snap = ctx.policy.lock().unwrap();
                snap.replace(version, rules);
                eprintln!("datapath: policy v{} applied ({} rules)", version, n);
            }
            Msg::Heartbeat { .. } => {
                send(ctx, &Msg::Heartbeat { ts_ms: now_ms() });
            }
            Msg::Action {
                id,
                action,
                pid,
                exe,
                start_ticks,
            } => {
                let (success, enforced, detail) = if action == "kill" {
                    match action::kill(pid, &exe, start_ticks) {
                        Ok(d) => (true, true, d),
                        Err(e) => (false, false, e.to_string()),
                    }
                } else {
                    (false, false, format!("unsupported action: {}", action))
                };
                send(
                    ctx,
                    &Msg::ActionResult {
                        id,
                        success,
                        enforced,
                        detail,
                    },
                );
            }
            _ => {}
        }
    }
    let mut guard = ctx.writer.lock().unwrap();
    *guard = None;
    Ok(())
}

fn main() {
    let args = parse_args();

    // fanotify group + marks.
    let fanfd = match fanotify::init_group() {
        Ok(fd) => fd,
        Err(e) => {
            eprintln!("datapath: fanotify_init failed: {} (need CAP_SYS_ADMIN)", e);
            process::exit(1);
        }
    };
    let counters = Arc::new(fanotify::Counters::default());
    for w in &args.watch {
        match fanotify::mark_path(fanfd, w, args.depth, args.max_marks, &counters) {
            Ok(()) => eprintln!("datapath: watching {}", w),
            Err(e) => eprintln!("datapath: mark {} failed: {}", w, e),
        }
    }

    let ctx = fanotify::Context {
        policy: Arc::new(Mutex::new(Snapshot::default())),
        writer: Arc::new(Mutex::new(None)),
        counters: Arc::clone(&counters),
        stop: Arc::new(AtomicBool::new(false)),
    };

    // fanotify event loop.
    {
        let fan_ctx = fanotify::Context {
            policy: Arc::clone(&ctx.policy),
            writer: Arc::clone(&ctx.writer),
            counters: Arc::clone(&ctx.counters),
            stop: Arc::clone(&ctx.stop),
        };
        std::thread::spawn(move || fanotify::run(fanfd, fan_ctx));
    }

    // Socket listener.
    if Path::new(&args.socket).exists() {
        let _ = std::fs::remove_file(&args.socket);
    }
    if let Some(dir) = Path::new(&args.socket).parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let listener = match UnixListener::bind(&args.socket) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("datapath: bind {} failed: {}", args.socket, e);
            process::exit(1);
        }
    };
    let _ = std::fs::set_permissions(&args.socket, std::fs::Permissions::from_mode(0o600));
    eprintln!("datapath: listening on {}", args.socket);

    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                if let Err(e) = handle_connection(stream, &ctx) {
                    eprintln!("datapath: connection error: {}", e);
                }
            }
            Err(e) => {
                eprintln!("datapath: accept error: {}", e);
            }
        }
        // Periodic stats line.
        eprintln!(
            "datapath: marks={} allowed={} denied={}",
            counters.marks.load(Ordering::Relaxed),
            counters.allowed.load(Ordering::Relaxed),
            counters.denied.load(Ordering::Relaxed)
        );
    }
}
