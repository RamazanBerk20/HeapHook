//! The hh-net wire protocol, version 1.
//!
//! # Framing
//!
//! Everything on the TCP stream is a frame:
//!
//! ```text
//! u32 len            length of what follows (little endian, like every integer here)
//! u32 id             request id, chosen by the client; the response carries the same id
//! u8  op             opcode (requests) / status (responses: 0 = ok, 1 = error)
//! ..  body           len - 5 bytes
//! ```
//!
//! The receiver checks `len` against its limit *before* allocating; an oversized, truncated
//! or undecodable frame drops the connection (framing can no longer be trusted).
//! Requests may be pipelined: the client sends several requests without waiting, the server
//! answers each as soon as it is done (possibly out of order), the id pairs them up.
//!
//! # Handshake (ids are 0)
//!
//! ```text
//! C -> S  HELLO      magic "HHNET\0", u16 version, [32] client_nonce
//! S -> C  CHALLENGE  u16 version, [32] server_nonce              (or an error frame)
//! C -> S  AUTH       [32] HMAC-SHA256(token, "hh-net/1 client" | server_nonce | client_nonce)
//! S -> C  AUTH_OK    [32] HMAC-SHA256(token, "hh-net/1 server" | client_nonce | server_nonce),
//!                    u32 max_read (largest batch of read bytes / write the server accepts)
//! ```
//!
//! The token itself never crosses the wire, a fresh server nonce per connection defeats
//! replay, the MAC is compared in constant time, and the server proves it knows the token
//! too. A wrong MAC gets an error frame after a delay, then the connection is closed. Before
//! AUTH_OK the only accepted frames are HELLO and AUTH, each at most [`MAX_HANDSHAKE_FRAME`].
//! There is no encryption: memory contents and requests travel in clear text, so the server
//! is meant for trusted networks or an SSH tunnel.
//!
//! # Requests (op, body -> ok body)
//!
//! Handles are per-connection ids for opened processes; closing the connection closes them.
//!
//! | op | name | body | ok body |
//! |----|------|------|---------|
//! | 1 | LIST | – | u32 n, n × (u32 pid, str name, opt str exe) |
//! | 2 | OPEN | u32 pid | u32 handle, u8 pointer_size |
//! | 3 | CLOSE | u32 handle | – (no response is sent) |
//! | 4 | READ | u32 handle, u32 n, n × (u64 addr, u32 len) | n × result: (u8 0, u32 k, k bytes) or (u8 1, error) |
//! | 5 | WRITE | u32 handle, u64 addr, u32 k, k bytes | – |
//! | 6 | REGIONS | u32 handle | u32 n, n × (u64 start, u64 size, u8 prot, u8 kind, u8 shared, opt str path) |
//! | 7 | MODULES | u32 handle | u32 n, n × (str name, str path, u64 base, u64 size) |
//! | 8 | THREADS | u32 handle | u32 n, n × u32 tid |
//! | 9 | IS_ALIVE | u32 handle | u8 alive |
//! | 10 | ALLOC | u32 handle, u64 size, u8 prot, opt u64 near | u64 addr |
//! | 11 | FREE | u32 handle, u64 addr, u64 size | – |
//! | 12 | PROTECT | u32 handle, u64 addr, u64 size, u8 prot | u8 old prot |
//! | 13 | SUSPEND | u32 handle | – |
//! | 14 | RESUME | u32 handle | – |
//!
//! `str` = u32 byte length + UTF-8; `opt x` = u8 0 (none) or u8 1 + x; `prot` = bits r=1 w=2
//! x=4; `kind` = 0 image, 1 mapped, 2 private. The READ results are the `Memory::read`
//! semantics per range: k ≤ len bytes from the start of the range, or an error. One READ may
//! request at most `max_read` bytes in total and [`MAX_RANGES`] ranges.
//!
//! An error body maps 1:1 onto `hh_core::Error`: u8 tag then
//! 0 Io (u8 kind, str message) · 1 NoAccess (u64 addr) · 2 Permission (str) · 3 ProcessGone ·
//! 4 Parse (str) · 5 Unsupported (str) · 6 Other (str).
//!
//! Compression is not used: on loopback and LAN links the codec would cost more than the
//! bandwidth it saves except for zero pages.
use std::io::{self, ErrorKind, Read, Write};
use std::sync::Mutex;

use hh_core::{Addr, Error, Module, ProcessInfo, Prot, Region, RegionKind, Result};
use hmac::{Hmac, Mac};
use sha2::Sha256;

pub const MAGIC: &[u8; 6] = b"HHNET\0";
pub const VERSION: u16 = 1;
pub const DEFAULT_PORT: u16 = 52736;
pub const MAX_HANDSHAKE_FRAME: usize = 64;
pub const MAX_RANGES: usize = 65536;
/// Default per-request byte budget for READ / WRITE.
pub const DEFAULT_MAX_READ: usize = 16 << 20;
pub const NONCE: usize = 32;

pub mod op {
    pub const HELLO: u8 = 100;
    pub const CHALLENGE: u8 = 101;
    pub const AUTH: u8 = 102;
    pub const AUTH_OK: u8 = 103;
    pub const LIST: u8 = 1;
    pub const OPEN: u8 = 2;
    pub const CLOSE: u8 = 3;
    pub const READ: u8 = 4;
    pub const WRITE: u8 = 5;
    pub const REGIONS: u8 = 6;
    pub const MODULES: u8 = 7;
    pub const THREADS: u8 = 8;
    pub const IS_ALIVE: u8 = 9;
    pub const ALLOC: u8 = 10;
    pub const FREE: u8 = 11;
    pub const PROTECT: u8 = 12;
    pub const SUSPEND: u8 = 13;
    pub const RESUME: u8 = 14;
}
pub const STATUS_OK: u8 = 0;
pub const STATUS_ERR: u8 = 1;

/// One frame without its length prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub id: u32,
    pub op: u8,
    pub body: Vec<u8>,
}

/// Reads one frame; frames longer than `max` (excluding the length prefix) are an error.
/// Allocation is bounded by `max`.
pub fn read_frame(r: &mut impl Read, max: usize) -> io::Result<Frame> {
    let mut h = [0u8; 4];
    r.read_exact(&mut h)?;
    let len = u32::from_le_bytes(h) as usize;
    if !(5..=max).contains(&len) {
        return Err(io::Error::new(ErrorKind::InvalidData, format!("bad frame length {len}")));
    }
    let mut v = vec![0u8; len];
    r.read_exact(&mut v)?;
    let id = u32::from_le_bytes([v[0], v[1], v[2], v[3]]);
    let op = v[4];
    v.drain(..5);
    Ok(Frame { id, op, body: v })
}

/// Builds a complete frame (with length prefix) whose body is written by `f`.
pub fn frame(id: u32, op: u8, f: impl FnOnce(&mut Enc)) -> Vec<u8> {
    let mut e = Enc(Vec::with_capacity(64));
    e.0.extend_from_slice(&[0; 4]);
    e.u32(id);
    e.u8(op);
    f(&mut e);
    let len = (e.0.len() - 4) as u32;
    e.0[..4].copy_from_slice(&len.to_le_bytes());
    e.0
}

pub fn write_all(w: &mut impl Write, buf: &[u8]) -> io::Result<()> {
    w.write_all(buf)?;
    w.flush()
}

// ------------------------------------------------------------------ primitive codec

pub struct Enc(pub Vec<u8>);

impl Enc {
    pub fn u8(&mut self, v: u8) {
        self.0.push(v);
    }
    pub fn u16(&mut self, v: u16) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    pub fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    pub fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    pub fn bytes(&mut self, b: &[u8]) {
        self.u32(b.len() as u32);
        self.0.extend_from_slice(b);
    }
    pub fn str(&mut self, s: &str) {
        self.bytes(s.as_bytes());
    }
    pub fn opt_str(&mut self, s: Option<&str>) {
        match s {
            None => self.u8(0),
            Some(s) => {
                self.u8(1);
                self.str(s);
            }
        }
    }
    pub fn prot(&mut self, p: Prot) {
        self.u8(p.r as u8 | (p.w as u8) << 1 | (p.x as u8) << 2);
    }
}

fn bad(what: &str) -> Error {
    Error::Parse(format!("hh-net: malformed {what}"))
}

/// Bounds-checked reader over a frame body; every method fails instead of panicking.
pub struct Dec<'a>(pub &'a [u8]);

impl<'a> Dec<'a> {
    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.0.len() < n {
            return Err(bad("frame (truncated)"));
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    pub fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap_or_default()))
    }
    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap_or_default()))
    }
    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap_or_default()))
    }
    pub fn bool(&mut self) -> Result<bool> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(bad("bool")),
        }
    }
    pub fn bytes(&mut self) -> Result<&'a [u8]> {
        let n = self.u32()? as usize;
        self.take(n)
    }
    pub fn str(&mut self) -> Result<String> {
        String::from_utf8(self.bytes()?.to_vec()).map_err(|_| bad("string"))
    }
    pub fn opt_str(&mut self) -> Result<Option<String>> {
        Ok(if self.bool()? { Some(self.str()?) } else { None })
    }
    pub fn opt_u64(&mut self) -> Result<Option<u64>> {
        Ok(if self.bool()? { Some(self.u64()?) } else { None })
    }
    pub fn prot(&mut self) -> Result<Prot> {
        let b = self.u8()?;
        if b > 7 {
            return Err(bad("prot"));
        }
        Ok(Prot {
            r: b & 1 != 0,
            w: b & 2 != 0,
            x: b & 4 != 0,
        })
    }
    /// A count of items each at least `min` bytes long; rejects counts the body cannot hold,
    /// so callers may preallocate.
    pub fn count(&mut self, min: usize) -> Result<usize> {
        let n = self.u32()? as usize;
        if n.saturating_mul(min.max(1)) > self.0.len() {
            return Err(bad("count"));
        }
        Ok(n)
    }
    pub fn end(&self) -> Result<()> {
        if self.0.is_empty() { Ok(()) } else { Err(bad("frame (trailing bytes)")) }
    }
}

// ------------------------------------------------------------------ errors

const IO_KINDS: &[ErrorKind] = &[
    ErrorKind::Other,
    ErrorKind::NotFound,
    ErrorKind::PermissionDenied,
    ErrorKind::ConnectionRefused,
    ErrorKind::ConnectionReset,
    ErrorKind::ConnectionAborted,
    ErrorKind::NotConnected,
    ErrorKind::AddrInUse,
    ErrorKind::AddrNotAvailable,
    ErrorKind::BrokenPipe,
    ErrorKind::AlreadyExists,
    ErrorKind::WouldBlock,
    ErrorKind::InvalidInput,
    ErrorKind::InvalidData,
    ErrorKind::TimedOut,
    ErrorKind::WriteZero,
    ErrorKind::Interrupted,
    ErrorKind::Unsupported,
    ErrorKind::UnexpectedEof,
    ErrorKind::OutOfMemory,
];

pub fn enc_error(e: &mut Enc, err: &Error) {
    match err {
        Error::Io(io) => {
            e.u8(0);
            e.u8(IO_KINDS.iter().position(|k| *k == io.kind()).unwrap_or(0) as u8);
            e.str(&io.to_string());
        }
        Error::NoAccess { addr } => {
            e.u8(1);
            e.u64(*addr);
        }
        Error::Permission(s) => {
            e.u8(2);
            e.str(s);
        }
        Error::ProcessGone => e.u8(3),
        Error::Parse(s) => {
            e.u8(4);
            e.str(s);
        }
        Error::Unsupported(s) => {
            e.u8(5);
            e.str(s);
        }
        Error::Other(s) => {
            e.u8(6);
            e.str(s);
        }
    }
}

pub fn dec_error(d: &mut Dec) -> Result<Error> {
    Ok(match d.u8()? {
        0 => {
            let kind = *IO_KINDS.get(d.u8()? as usize).unwrap_or(&ErrorKind::Other);
            Error::Io(io::Error::new(kind, d.str()?))
        }
        1 => Error::NoAccess { addr: d.u64()? },
        2 => Error::Permission(d.str()?),
        3 => Error::ProcessGone,
        4 => Error::Parse(d.str()?),
        5 => Error::Unsupported(intern(d.str()?)),
        6 => Error::Other(d.str()?),
        _ => return Err(bad("error tag")),
    })
}

/// `Error::Unsupported` holds a `&'static str`; remote names are leaked once each, with a cap
/// so a hostile server cannot grow memory without bound.
fn intern(s: String) -> &'static str {
    static SEEN: Mutex<Vec<&'static str>> = Mutex::new(Vec::new());
    let Ok(mut seen) = SEEN.lock() else {
        return "remote operation";
    };
    if let Some(s) = seen.iter().find(|x| **x == s) {
        return s;
    }
    if seen.len() >= 256 || s.len() > 64 {
        return "remote operation";
    }
    let s: &'static str = Box::leak(s.into_boxed_str());
    seen.push(s);
    s
}

/// Body of an error response.
pub fn error_frame(id: u32, err: &Error) -> Vec<u8> {
    frame(id, STATUS_ERR, |e| enc_error(e, err))
}

// ------------------------------------------------------------------ composite types

pub fn enc_process(e: &mut Enc, p: &ProcessInfo) {
    e.u32(p.pid);
    e.str(&p.name);
    e.opt_str(p.exe.as_deref());
}
pub fn dec_process(d: &mut Dec) -> Result<ProcessInfo> {
    Ok(ProcessInfo {
        pid: d.u32()?,
        name: d.str()?,
        exe: d.opt_str()?,
    })
}

pub fn enc_region(e: &mut Enc, r: &Region) {
    e.u64(r.start);
    e.u64(r.size);
    e.prot(r.prot);
    e.u8(match r.kind {
        RegionKind::Image => 0,
        RegionKind::Mapped => 1,
        RegionKind::Private => 2,
    });
    e.u8(r.shared as u8);
    e.opt_str(r.path.as_deref());
}
pub fn dec_region(d: &mut Dec) -> Result<Region> {
    Ok(Region {
        start: d.u64()?,
        size: d.u64()?,
        prot: d.prot()?,
        kind: match d.u8()? {
            0 => RegionKind::Image,
            1 => RegionKind::Mapped,
            2 => RegionKind::Private,
            _ => return Err(bad("region kind")),
        },
        shared: d.bool()?,
        path: d.opt_str()?,
    })
}

pub fn enc_module(e: &mut Enc, m: &Module) {
    e.str(&m.name);
    e.str(&m.path);
    e.u64(m.base);
    e.u64(m.size);
}
pub fn dec_module(d: &mut Dec) -> Result<Module> {
    Ok(Module {
        name: d.str()?,
        path: d.str()?,
        base: d.u64()?,
        size: d.u64()?,
    })
}

/// Encodes a list with a u32 count.
pub fn enc_list<T>(e: &mut Enc, items: &[T], f: impl Fn(&mut Enc, &T)) {
    e.u32(items.len() as u32);
    for i in items {
        f(e, i);
    }
}
/// Decodes a list whose items are at least `min` bytes each, then checks the body is used up.
pub fn dec_list<T>(body: &[u8], min: usize, f: impl Fn(&mut Dec) -> Result<T>) -> Result<Vec<T>> {
    let mut d = Dec(body);
    let n = d.count(min)?;
    let mut v = Vec::with_capacity(n);
    for _ in 0..n {
        v.push(f(&mut d)?);
    }
    d.end()?;
    Ok(v)
}

/// A decoded READ request: handle and (addr, len) ranges, validated against the limits.
pub fn dec_read_req(body: &[u8], max_read: usize) -> Result<(u32, Vec<(Addr, u32)>)> {
    let mut d = Dec(body);
    let h = d.u32()?;
    let n = d.count(12)?;
    if n > MAX_RANGES {
        return Err(Error::Other(format!("hh-net: more than {MAX_RANGES} ranges in one read")));
    }
    let mut v = Vec::with_capacity(n);
    let mut total = 0u64;
    for _ in 0..n {
        let (a, l) = (d.u64()?, d.u32()?);
        total += l as u64;
        v.push((a, l));
    }
    d.end()?;
    if total > max_read as u64 {
        return Err(Error::Other(format!("hh-net: read batch of {total} bytes exceeds the server limit {max_read}")));
    }
    Ok((h, v))
}

// ------------------------------------------------------------------ auth

type HmacSha256 = Hmac<Sha256>;

fn mac(token: &[u8], label: &[u8], a: &[u8], b: &[u8]) -> HmacSha256 {
    // HMAC accepts keys of any length; new_from_slice cannot fail.
    let mut m = <HmacSha256 as Mac>::new_from_slice(token).unwrap_or_else(|_| unreachable!());
    m.update(label);
    m.update(a);
    m.update(b);
    m
}

pub fn client_proof(token: &[u8], server_nonce: &[u8], client_nonce: &[u8]) -> [u8; 32] {
    mac(token, b"hh-net/1 client", server_nonce, client_nonce).finalize().into_bytes().into()
}
pub fn server_proof(token: &[u8], server_nonce: &[u8], client_nonce: &[u8]) -> [u8; 32] {
    mac(token, b"hh-net/1 server", client_nonce, server_nonce).finalize().into_bytes().into()
}
/// Constant-time check of a client proof.
pub fn verify_client(token: &[u8], server_nonce: &[u8], client_nonce: &[u8], proof: &[u8]) -> bool {
    mac(token, b"hh-net/1 client", server_nonce, client_nonce).verify_slice(proof).is_ok()
}
pub fn verify_server(token: &[u8], server_nonce: &[u8], client_nonce: &[u8], proof: &[u8]) -> bool {
    mac(token, b"hh-net/1 server", client_nonce, server_nonce).verify_slice(proof).is_ok()
}

pub fn nonce() -> Result<[u8; NONCE]> {
    let mut n = [0u8; NONCE];
    getrandom::fill(&mut n).map_err(|e| Error::Other(format!("random source: {e}")))?;
    Ok(n)
}

/// A random 128-bit token as 32 hex digits.
pub fn generate_token() -> Result<String> {
    let n = nonce()?;
    Ok(n[..16].iter().map(|b| format!("{b:02x}")).collect())
}
