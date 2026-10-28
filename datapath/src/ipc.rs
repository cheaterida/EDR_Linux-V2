//! Versioned, length-prefixed framing over a Unix stream socket.
//!
//! Frame layout: [u32 LE body_len][u8 frame_version][body...]
//! `body` is JSON with a `type` discriminator. Unknown versions or malformed
//! bodies are rejected (the connection is dropped) rather than guessed at.

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;

use serde::{Deserialize, Serialize};

pub const FRAME_VERSION: u8 = 1;
const MAX_FRAME: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileRule {
    pub id: String,
    #[serde(default)]
    pub path_exact: String,
    #[serde(default)]
    pub path_prefix: String,
    #[serde(default)]
    pub path_suffix: String,
    pub decision: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Msg {
    Hello {
        agent_pid: u32,
    },
    Policy {
        version: u64,
        #[serde(default)]
        rules: Vec<FileRule>,
    },
    Event {
        kind: u16,
        pid: i32,
        comm: String,
        path: String,
        op: String,
        decision: String,
        rule_id: String,
    },
    Action {
        id: String,
        action: String,
        pid: i32,
        #[serde(default)]
        exe: String,
        #[serde(default)]
        start_ticks: u64,
    },
    ActionResult {
        id: String,
        success: bool,
        enforced: bool,
        detail: String,
    },
    Heartbeat {
        ts_ms: u64,
    },
}

pub fn write_frame(stream: &mut UnixStream, msg: &Msg) -> io::Result<()> {
    let body = serde_json::to_vec(msg).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    let len = (1 + body.len()) as u32;
    let mut buf = Vec::with_capacity(5 + body.len());
    buf.extend_from_slice(&len.to_le_bytes());
    buf.push(FRAME_VERSION);
    buf.extend_from_slice(&body);
    stream.write_all(&buf)
}

pub fn read_frame(stream: &mut UnixStream) -> io::Result<Option<Msg>> {
    let mut hdr = [0u8; 4];
    match stream.read_exact(&mut hdr) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_le_bytes(hdr) as usize;
    if len == 0 || len > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad frame length"));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;
    if buf[0] != FRAME_VERSION {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "unsupported frame version"));
    }
    match serde_json::from_slice::<Msg>(&buf[1..]) {
        Ok(m) => Ok(Some(m)),
        Err(e) => Err(io::Error::new(io::ErrorKind::InvalidData, e)),
    }
}
