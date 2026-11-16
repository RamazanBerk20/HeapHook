//! The server side: serves `hh_core` processes to authenticated clients.
use std::collections::{HashMap, VecDeque};
use std::io::{BufReader, ErrorKind, Read};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::sync::mpsc::{Receiver, sync_channel};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use hh_core::{Addr, Error, Pid, Process, ProcessInfo, Prot, Result};

use crate::proto::{self, Dec, Enc, Frame, op};

/// Where the server gets its processes from. [`LocalBackend`] is the real OS.
pub trait Backend: Send + Sync {
    fn list_processes(&self) -> Result<Vec<ProcessInfo>>;
    fn open(&self, pid: Pid) -> Result<Arc<dyn Process>>;
}

/// The local machine through `hh_core::list_processes` / `hh_core::open`.
pub struct LocalBackend;

impl Backend for LocalBackend {
    fn list_processes(&self) -> Result<Vec<ProcessInfo>> {
        hh_core::list_processes()
    }
    fn open(&self, pid: Pid) -> Result<Arc<dyn Process>> {
        hh_core::open(pid)
    }
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Shared secret; never sent over the wire (see the handshake in [`crate::proto`]).
    pub token: String,
    /// Rejects write, alloc, free, protect, suspend and resume with `Error::Permission`.
    pub read_only: bool,
    /// Byte budget of one READ batch and of one WRITE.
    pub max_read: usize,
    /// Authenticated connections. A client that authenticates while all are taken gets an
    /// error instead of AUTH_OK.
    pub max_connections: usize,
    /// Connections still in the handshake. They do not count against `max_connections`; when
    /// this budget is full the oldest one is dropped, so idle or trickling unauthenticated
    /// peers cannot lock real clients out.
    pub max_pending: usize,
    /// Open process handles per connection.
    pub max_handles: usize,
    /// Open process handles over all connections (each one holds file descriptors).
    pub max_total_handles: usize,
    /// Threads executing requests per connection (pipelined requests run in parallel).
    pub workers: usize,
    /// Time an unauthenticated client gets to finish the whole handshake.
    pub handshake_timeout: Duration,
    /// Wait before answering a failed authentication. It is also the server-wide spacing
    /// between failed attempts, however many connections guess in parallel.
    pub auth_delay: Duration,
}

impl ServerConfig {
    pub fn new(token: impl Into<String>) -> Self {
        ServerConfig {
            token: token.into(),
            read_only: false,
            max_read: proto::DEFAULT_MAX_READ,
            max_connections: 16,
            max_pending: 8,
            max_handles: 256,
            max_total_handles: 512,
            workers: std::thread::available_parallelism().map_or(4, |n| n.get().min(8)),
            handshake_timeout: Duration::from_secs(10),
            auth_delay: Duration::from_millis(500),
        }
    }
}

struct Shared {
    cfg: ServerConfig,
    backend: Arc<dyn Backend>,
    stop: AtomicBool,
    /// Authenticated connections.
    conns: Mutex<HashMap<u64, TcpStream>>,
    /// Connections in the handshake, oldest first.
    pending: Mutex<VecDeque<(u64, TcpStream)>>,
    next_conn: AtomicU64,
    /// Earliest time the next AUTH may be checked; every failure pushes it back.
    auth_gate: Mutex<Instant>,
    /// Open process handles over all connections.
    open_handles: Arc<AtomicUsize>,
}

/// Locks, ignoring poisoning: the guarded data stays consistent across a panic here.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

pub struct Server {
    listener: TcpListener,
    shared: Arc<Shared>,
}

/// A running server; dropping it (or [`ServerHandle::shutdown`]) stops it, closes every
/// connection and waits (up to 5 s) for their handles to close.
pub struct ServerHandle {
    addr: SocketAddr,
    shared: Arc<Shared>,
    thread: Option<JoinHandle<()>>,
}

/// Frees a connection's slot however its thread ends, a panic included.
struct Slot {
    sh: Arc<Shared>,
    id: u64,
}

impl Drop for Slot {
    fn drop(&mut self) {
        lock(&self.sh.pending).retain(|(i, _)| *i != self.id);
        if let Some(s) = lock(&self.sh.conns).remove(&self.id) {
            let _ = s.shutdown(Shutdown::Both);
        }
    }
}

impl Server {
    /// Binds the listener. The caller decides which interface; `hh-server` refuses
    /// non-loopback addresses unless asked to.
    pub fn bind(addr: impl ToSocketAddrs, cfg: ServerConfig, backend: Arc<dyn Backend>) -> Result<Server> {
        if cfg.token.is_empty() {
            return Err(Error::Permission("hh-net: an empty token is not allowed".into()));
        }
        Ok(Server {
            listener: TcpListener::bind(addr)?,
            shared: Arc::new(Shared {
                cfg,
                backend,
                stop: AtomicBool::new(false),
                conns: Mutex::default(),
                pending: Mutex::default(),
                next_conn: AtomicU64::new(0),
                auth_gate: Mutex::new(Instant::now()),
                open_handles: Arc::default(),
            }),
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.listener.local_addr()?)
    }

    /// Accepts connections until stopped; each connection gets its own threads.
    pub fn run(self) -> Result<()> {
        let mut backoff = Duration::ZERO;
        for s in self.listener.incoming() {
            if self.shared.stop.load(Relaxed) {
                break;
            }
            let s = match s {
                Ok(s) => {
                    backoff = Duration::ZERO;
                    s
                }
                // E.g. EMFILE: retrying at once would spin a core; the peer waits in the backlog.
                Err(_) => {
                    backoff = (backoff * 2).clamp(Duration::from_millis(10), Duration::from_secs(1));
                    std::thread::sleep(backoff);
                    continue;
                }
            };
            let sh = self.shared.clone();
            let id = sh.next_conn.fetch_add(1, Relaxed);
            let Ok(c) = s.try_clone() else { continue };
            {
                let mut p = lock(&sh.pending);
                if p.len() >= sh.cfg.max_pending.max(1)
                    && let Some((_, old)) = p.pop_front()
                {
                    let _ = old.shutdown(Shutdown::Both);
                }
                p.push_back((id, c));
            }
            let slot = Slot { sh: sh.clone(), id };
            // If the spawn fails, the closure and the slot in it are dropped: nothing leaks.
            let _ = std::thread::Builder::new().name("hh-net conn".into()).spawn(move || {
                let _slot = slot;
                let _ = connection(&sh, id, s);
            });
        }
        Ok(())
    }

    /// Runs the accept loop on a background thread.
    pub fn spawn(self) -> Result<ServerHandle> {
        let addr = self.local_addr()?;
        let shared = self.shared.clone();
        let thread = std::thread::Builder::new().name("hh-net accept".into()).spawn(move || {
            let _ = self.run();
        })?;
        Ok(ServerHandle {
            addr,
            shared,
            thread: Some(thread),
        })
    }
}

impl ServerHandle {
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
    pub fn shutdown(self) {}
}

impl Drop for ServerHandle {
    fn drop(&mut self) {
        self.shared.stop.store(true, Relaxed);
        let mut wake = self.addr;
        if wake.ip().is_unspecified() {
            wake.set_ip(if wake.is_ipv4() { [127, 0, 0, 1].into() } else { std::net::Ipv6Addr::LOCALHOST.into() });
        }
        // Unblocks accept(); the loop then sees `stop`.
        let _ = TcpStream::connect_timeout(&wake, Duration::from_secs(1));
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        for s in lock(&self.shared.conns).values() {
            let _ = s.shutdown(Shutdown::Both);
        }
        for (_, s) in lock(&self.shared.pending).iter() {
            let _ = s.shutdown(Shutdown::Both);
        }
        // Let the connection threads end, so their handles close and resume what they suspended.
        let t = Instant::now();
        while t.elapsed() < Duration::from_secs(5) && !(lock(&self.shared.conns).is_empty() && lock(&self.shared.pending).is_empty()) {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

// ------------------------------------------------------------------ one connection

fn io_err(e: Error) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

fn handshake_timed_out() -> std::io::Error {
    std::io::Error::new(ErrorKind::TimedOut, "hh-net: handshake timed out")
}

/// Reads with one deadline for all reads together: a per-read timeout lets a peer that
/// trickles one byte at a time hold the connection forever.
struct Deadline<'a> {
    s: &'a TcpStream,
    until: Instant,
}

impl Read for Deadline<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let left = self.until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(handshake_timed_out());
        }
        self.s.set_read_timeout(Some(left))?;
        let mut s = self.s;
        s.read(buf)
    }
}

impl Shared {
    /// Checks one AUTH. Checks are serialized and each failure pushes the next one back by
    /// `auth_delay`, so parallel connections together get no more guesses than one.
    fn check_auth(&self, id: u64, until: Instant, verify: impl FnOnce() -> bool) -> std::io::Result<bool> {
        loop {
            // A connection evicted from the pending budget stops waiting at once, so a flood
            // cannot pile up sleeping threads here.
            if !lock(&self.pending).iter().any(|(x, _)| *x == id) {
                return Err(std::io::Error::new(ErrorKind::ConnectionAborted, "hh-net: dropped from the pending budget"));
            }
            let mut gate = lock(&self.auth_gate);
            let now = Instant::now();
            if now >= *gate {
                let ok = verify();
                if !ok {
                    *gate = now + self.cfg.auth_delay;
                }
                return Ok(ok);
            }
            if *gate > until {
                return Err(handshake_timed_out());
            }
            let wait = (*gate - now).min(Duration::from_millis(50));
            drop(gate);
            std::thread::sleep(wait);
        }
    }

    /// Moves an authenticated connection from the pending budget to the main one.
    fn admit(&self, id: u64) -> bool {
        let mut p = lock(&self.pending);
        let Some(i) = p.iter().position(|(x, _)| *x == id) else {
            return false; // evicted meanwhile
        };
        let mut c = lock(&self.conns);
        if c.len() >= self.cfg.max_connections {
            return false;
        }
        if let Some((_, s)) = p.remove(i) {
            c.insert(id, s);
        }
        true
    }
}

/// Runs the handshake within `handshake_timeout`; Ok(false) means the client was refused
/// (already answered).
fn handshake(sh: &Shared, id: u64, s: &TcpStream) -> std::io::Result<bool> {
    let cfg = &sh.cfg;
    let until = Instant::now() + cfg.handshake_timeout;
    // Unbuffered: nothing past the handshake frames may be consumed here.
    let mut r = Deadline { s, until };
    let mut w = s;
    let hello = proto::read_frame(&mut r, proto::MAX_HANDSHAKE_FRAME)?;
    let mut d = Dec(&hello.body);
    let parsed = (|| -> Result<(u16, Vec<u8>)> {
        if hello.op != op::HELLO || d.take(proto::MAGIC.len())? != proto::MAGIC {
            return Err(Error::Parse("hh-net: not an hh-net client".into()));
        }
        let v = d.u16()?;
        let cn = d.take(proto::NONCE)?.to_vec();
        d.end()?;
        Ok((v, cn))
    })();
    let (version, cnonce) = parsed.map_err(io_err)?;
    if version != proto::VERSION {
        let e = Error::Unsupported("hh-net protocol version");
        proto::write_all(&mut w, &proto::error_frame(0, &e))?;
        return Ok(false);
    }
    let snonce = proto::nonce().map_err(io_err)?;
    proto::write_all(
        &mut w,
        &proto::frame(0, op::CHALLENGE, |e| {
            e.u16(proto::VERSION);
            e.0.extend_from_slice(&snonce);
        }),
    )?;
    let auth = proto::read_frame(&mut r, proto::MAX_HANDSHAKE_FRAME)?;
    let token = cfg.token.as_bytes();
    if !sh.check_auth(id, until, || auth.op == op::AUTH && proto::verify_client(token, &snonce, &cnonce, &auth.body))? {
        std::thread::sleep(cfg.auth_delay);
        let e = Error::Permission("hh-net: authentication failed".into());
        let _ = proto::write_all(&mut w, &proto::error_frame(0, &e));
        return Ok(false);
    }
    if !sh.admit(id) {
        let e = Error::Other(format!("hh-server: connection limit ({}) reached, try again later", cfg.max_connections));
        let _ = proto::write_all(&mut w, &proto::error_frame(0, &e));
        return Ok(false);
    }
    let proof = proto::server_proof(token, &snonce, &cnonce);
    proto::write_all(
        &mut w,
        &proto::frame(0, op::AUTH_OK, |e| {
            e.0.extend_from_slice(&proof);
            e.u32(cfg.max_read as u32);
        }),
    )?;
    Ok(true)
}

fn connection(sh: &Shared, id: u64, s: TcpStream) -> std::io::Result<()> {
    let cfg = &sh.cfg;
    s.set_nodelay(true)?;
    // A client that stops reading must not pin a worker forever.
    s.set_write_timeout(Some(Duration::from_secs(30)))?;
    if !handshake(sh, id, &s)? {
        return Ok(());
    }
    s.set_read_timeout(None)?;
    // Idle clients are fine, but a vanished peer (crash, cable, sleep) must not hold its
    // slot forever: keepalive probes after 60 s of silence find it within a few minutes.
    let ka = socket2::TcpKeepalive::new().with_time(Duration::from_secs(60)).with_interval(Duration::from_secs(10));
    let _ = socket2::SockRef::from(&s).set_tcp_keepalive(&ka);
    let w = s.try_clone()?;
    let mut r = BufReader::with_capacity(64 << 10, s);

    let conn = Conn {
        sh,
        handles: Mutex::default(),
        next_handle: AtomicU32::new(1),
        w: Mutex::new(w),
    };
    let max_frame = cfg.max_read + (1 << 20);
    let (tx, rx) = sync_channel::<(u32, Req)>(cfg.workers * 4);
    let rx = Mutex::new(rx);
    std::thread::scope(|scope| {
        for _ in 0..cfg.workers.max(1) {
            scope.spawn(|| conn.worker(&rx));
        }
        // Any framing or decoding error ends the connection.
        while let Ok(f) = proto::read_frame(&mut r, max_frame) {
            let Ok(req) = decode_request(&f) else { break };
            if tx.send((f.id, req)).is_err() {
                break;
            }
        }
        drop(tx);
        // Drops the peer and unblocks workers stuck writing to it.
        let _ = r.get_ref().shutdown(Shutdown::Both);
    });
    Ok(())
}

/// A decoded request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Req {
    List,
    Open(Pid),
    Close(u32),
    Read(u32, Vec<(Addr, u32)>),
    Write(u32, Addr, Vec<u8>),
    Regions(u32),
    Modules(u32),
    Threads(u32),
    IsAlive(u32),
    Alloc(u32, u64, Prot, Option<Addr>),
    Free(u32, Addr, u64),
    Protect(u32, Addr, u64, Prot),
    Suspend(u32),
    Resume(u32),
}

/// Decodes a post-handshake request frame. Errors mean the client is broken or hostile.
pub fn decode_request(f: &Frame) -> Result<Req> {
    let mut d = Dec(&f.body);
    let req = match f.op {
        op::LIST => Req::List,
        op::OPEN => Req::Open(d.u32()?),
        op::CLOSE => Req::Close(d.u32()?),
        op::READ => {
            let h = d.u32()?;
            let n = d.count(12)?;
            let mut v = Vec::with_capacity(n);
            for _ in 0..n {
                v.push((d.u64()?, d.u32()?));
            }
            Req::Read(h, v)
        }
        op::WRITE => Req::Write(d.u32()?, d.u64()?, d.bytes()?.to_vec()),
        op::REGIONS => Req::Regions(d.u32()?),
        op::MODULES => Req::Modules(d.u32()?),
        op::THREADS => Req::Threads(d.u32()?),
        op::IS_ALIVE => Req::IsAlive(d.u32()?),
        op::ALLOC => Req::Alloc(d.u32()?, d.u64()?, d.prot()?, d.opt_u64()?),
        op::FREE => Req::Free(d.u32()?, d.u64()?, d.u64()?),
        op::PROTECT => Req::Protect(d.u32()?, d.u64()?, d.u64()?, d.prot()?),
        op::SUSPEND => Req::Suspend(d.u32()?),
        op::RESUME => Req::Resume(d.u32()?),
        _ => return Err(Error::Parse(format!("hh-net: unknown opcode {}", f.op))),
    };
    d.end()?;
    Ok(req)
}

/// An open process on one connection. Dropping the last reference (CLOSE, disconnect,
/// server shutdown) undoes the client's outstanding suspends.
struct Handle {
    p: Arc<dyn Process>,
    /// Successful SUSPENDs not yet matched by a RESUME.
    suspends: AtomicUsize,
    /// The server-wide handle count, given back on drop.
    total: Arc<AtomicUsize>,
}

impl std::ops::Deref for Handle {
    type Target = dyn Process;
    fn deref(&self) -> &(dyn Process + 'static) {
        &*self.p
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        // A client that disconnects or crashes must not leave its target stopped.
        for _ in 0..*self.suspends.get_mut() {
            let _ = self.p.resume();
        }
        self.total.fetch_sub(1, Relaxed);
    }
}

struct Conn<'a> {
    sh: &'a Shared,
    handles: Mutex<HashMap<u32, Arc<Handle>>>,
    next_handle: AtomicU32,
    w: Mutex<TcpStream>,
}

impl Conn<'_> {
    fn worker(&self, rx: &Mutex<Receiver<(u32, Req)>>) {
        loop {
            let next = lock(rx).recv();
            let Ok((id, req)) = next else { return };
            // A panic in a backend becomes an error response instead of killing the worker.
            let resp = match catch_unwind(AssertUnwindSafe(|| self.exec(id, req))) {
                Ok(Ok(Some(f))) => f,
                Ok(Ok(None)) => continue,
                Ok(Err(e)) => proto::error_frame(id, &e),
                Err(_) => proto::error_frame(id, &Error::Other("hh-net: internal error while executing the request".into())),
            };
            let mut w = lock(&self.w);
            // Keep draining after a failed write so the reader never blocks on a full queue.
            if proto::write_all(&mut *w, &resp).is_err() {
                let _ = w.shutdown(Shutdown::Both);
            }
        }
    }

    fn get(&self, h: u32) -> Result<Arc<Handle>> {
        lock(&self.handles)
            .get(&h)
            .cloned()
            .ok_or_else(|| Error::Other(format!("hh-net: unknown process handle {h}")))
    }

    fn open(&self, pid: Pid) -> Result<(u32, u8)> {
        let too_many = || Error::Other("hh-net: too many open processes on this connection".into());
        if lock(&self.handles).len() >= self.sh.cfg.max_handles {
            return Err(too_many());
        }
        let total = &self.sh.open_handles;
        if total.fetch_add(1, Relaxed) >= self.sh.cfg.max_total_handles {
            total.fetch_sub(1, Relaxed);
            return Err(Error::Other("hh-net: too many open processes on this server".into()));
        }
        let p = match self.sh.backend.open(pid) {
            Ok(p) => p,
            Err(e) => {
                total.fetch_sub(1, Relaxed);
                return Err(e);
            }
        };
        let ps = p.pointer_size() as u8;
        // From here the Handle owns the count.
        let handle = Arc::new(Handle { p, suspends: AtomicUsize::new(0), total: total.clone() });
        let mut hs = lock(&self.handles);
        if hs.len() >= self.sh.cfg.max_handles {
            return Err(too_many());
        }
        let h = self.next_handle.fetch_add(1, Relaxed);
        hs.insert(h, handle);
        Ok((h, ps))
    }

    fn check_writable(&self) -> Result<()> {
        if self.sh.cfg.read_only {
            Err(Error::Permission("hh-server runs in read-only mode".into()))
        } else {
            Ok(())
        }
    }

    /// Executes one request; returns the full response frame, or None for CLOSE.
    fn exec(&self, id: u32, req: Req) -> Result<Option<Vec<u8>>> {
        let ok = |f: &dyn Fn(&mut Enc)| Ok(Some(proto::frame(id, proto::STATUS_OK, f)));
        if matches!(req, Req::Write(..) | Req::Alloc(..) | Req::Free(..) | Req::Protect(..) | Req::Suspend(_) | Req::Resume(_)) {
            self.check_writable()?;
        }
        let max_read = self.sh.cfg.max_read;
        match req {
            Req::List => {
                let l = self.sh.backend.list_processes()?;
                ok(&|e| proto::enc_list(e, &l, proto::enc_process))
            }
            Req::Open(pid) => {
                let (h, ps) = self.open(pid)?;
                ok(&|e| {
                    e.u32(h);
                    e.u8(ps);
                })
            }
            Req::Close(h) => {
                let gone = lock(&self.handles).remove(&h);
                drop(gone); // outside the lock: may resume the target
                Ok(None)
            }
            Req::Read(h, ranges) => {
                let p = self.get(h)?;
                let total: u64 = ranges.iter().map(|r| r.1 as u64).sum();
                if ranges.len() > proto::MAX_RANGES || total > max_read as u64 {
                    return Err(Error::Other(format!(
                        "hh-net: read batch ({} ranges, {total} bytes) exceeds the server limit ({} ranges, {max_read} bytes)",
                        ranges.len(),
                        proto::MAX_RANGES
                    )));
                }
                Ok(Some(read_batch(id, &*p.p, &ranges, total as usize)))
            }
            Req::Write(h, addr, data) => {
                if data.len() > max_read {
                    return Err(Error::Other(format!("hh-net: write of {} bytes exceeds the server limit {max_read}", data.len())));
                }
                self.get(h)?.write(addr, &data)?;
                ok(&|_| {})
            }
            Req::Regions(h) => {
                let l = self.get(h)?.regions()?;
                ok(&|e| proto::enc_list(e, &l, proto::enc_region))
            }
            Req::Modules(h) => {
                let l = self.get(h)?.modules()?;
                ok(&|e| proto::enc_list(e, &l, proto::enc_module))
            }
            Req::Threads(h) => {
                let l = self.get(h)?.threads()?;
                ok(&|e| proto::enc_list(e, &l, |e, t| e.u32(*t)))
            }
            Req::IsAlive(h) => {
                let a = self.get(h)?.is_alive();
                ok(&|e| e.u8(a as u8))
            }
            Req::Alloc(h, size, prot, near) => {
                let a = self.get(h)?.alloc(size, prot, near)?;
                ok(&|e| e.u64(a))
            }
            Req::Free(h, addr, size) => {
                self.get(h)?.free(addr, size)?;
                ok(&|_| {})
            }
            Req::Protect(h, addr, size, prot) => {
                let old = self.get(h)?.protect(addr, size, prot)?;
                ok(&|e| e.prot(old))
            }
            Req::Suspend(h) => {
                let h = self.get(h)?;
                h.p.suspend()?;
                h.suspends.fetch_add(1, Relaxed);
                ok(&|_| {})
            }
            Req::Resume(h) => {
                let h = self.get(h)?;
                h.p.resume()?;
                let _ = h.suspends.fetch_update(Relaxed, Relaxed, |n| n.checked_sub(1));
                ok(&|_| {})
            }
        }
    }
}

/// Reads every range straight into the response frame (no intermediate buffers).
fn read_batch(id: u32, p: &dyn Process, ranges: &[(Addr, u32)], total: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(9 + total + ranges.len() * 5);
    out.extend_from_slice(&[0; 4]);
    out.extend_from_slice(&id.to_le_bytes());
    out.push(proto::STATUS_OK);
    for &(addr, len) in ranges {
        let head = out.len();
        out.push(0);
        out.extend_from_slice(&[0; 4]);
        let start = out.len();
        out.resize(start + len as usize, 0);
        match p.read(addr, &mut out[start..]) {
            Ok(n) => {
                let n = n.min(len as usize);
                out.truncate(start + n);
                out[head + 1..start].copy_from_slice(&(n as u32).to_le_bytes());
            }
            Err(err) => {
                out.truncate(head);
                let mut e = Enc(std::mem::take(&mut out));
                e.u8(1);
                proto::enc_error(&mut e, &err);
                out = e.0;
            }
        }
    }
    let len = (out.len() - 4) as u32;
    out[..4].copy_from_slice(&len.to_le_bytes());
    out
}
