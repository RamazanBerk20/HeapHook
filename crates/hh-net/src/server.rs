//! The server side: serves `hh_core` processes to authenticated clients.
use std::collections::HashMap;
use std::io::BufReader;
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering::Relaxed};
use std::sync::mpsc::{Receiver, sync_channel};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

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
    pub max_connections: usize,
    /// Open process handles per connection.
    pub max_handles: usize,
    /// Threads executing requests per connection (pipelined requests run in parallel).
    pub workers: usize,
    /// Time an unauthenticated client gets to finish the handshake.
    pub handshake_timeout: Duration,
    /// Wait before answering a failed authentication.
    pub auth_delay: Duration,
}

impl ServerConfig {
    pub fn new(token: impl Into<String>) -> Self {
        ServerConfig {
            token: token.into(),
            read_only: false,
            max_read: proto::DEFAULT_MAX_READ,
            max_connections: 16,
            max_handles: 256,
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
    conns: Mutex<HashMap<u64, TcpStream>>,
    next_conn: AtomicU64,
}

pub struct Server {
    listener: TcpListener,
    shared: Arc<Shared>,
}

/// A running server; dropping it (or [`ServerHandle::shutdown`]) stops it and closes every
/// connection.
pub struct ServerHandle {
    addr: SocketAddr,
    shared: Arc<Shared>,
    thread: Option<JoinHandle<()>>,
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
                next_conn: AtomicU64::new(0),
            }),
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.listener.local_addr()?)
    }

    /// Accepts connections until stopped; each connection gets its own threads.
    pub fn run(self) -> Result<()> {
        for s in self.listener.incoming() {
            if self.shared.stop.load(Relaxed) {
                break;
            }
            let Ok(s) = s else { continue };
            let sh = self.shared.clone();
            let id = sh.next_conn.fetch_add(1, Relaxed);
            {
                let Ok(mut conns) = sh.conns.lock() else { break };
                if conns.len() >= sh.cfg.max_connections {
                    continue; // dropping `s` closes it
                }
                let Ok(c) = s.try_clone() else { continue };
                conns.insert(id, c);
            }
            let spawned = std::thread::Builder::new().name("hh-net conn".into()).spawn(move || {
                let _ = connection(&sh, s);
                if let Ok(mut c) = sh.conns.lock()
                    && let Some(s) = c.remove(&id)
                {
                    let _ = s.shutdown(Shutdown::Both);
                }
            });
            if spawned.is_err()
                && let Ok(mut c) = self.shared.conns.lock()
            {
                c.remove(&id);
            }
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
        if let Ok(c) = self.shared.conns.lock() {
            for s in c.values() {
                let _ = s.shutdown(Shutdown::Both);
            }
        }
    }
}

// ------------------------------------------------------------------ one connection

fn io_err(e: Error) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

/// Runs the handshake; Ok(false) means authentication failed (already answered).
fn handshake(cfg: &ServerConfig, r: &mut BufReader<TcpStream>, w: &mut TcpStream) -> std::io::Result<bool> {
    let hello = proto::read_frame(r, proto::MAX_HANDSHAKE_FRAME)?;
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
        proto::write_all(w, &proto::error_frame(0, &e))?;
        return Ok(false);
    }
    let snonce = proto::nonce().map_err(io_err)?;
    proto::write_all(
        w,
        &proto::frame(0, op::CHALLENGE, |e| {
            e.u16(proto::VERSION);
            e.0.extend_from_slice(&snonce);
        }),
    )?;
    let auth = proto::read_frame(r, proto::MAX_HANDSHAKE_FRAME)?;
    let token = cfg.token.as_bytes();
    if auth.op != op::AUTH || !proto::verify_client(token, &snonce, &cnonce, &auth.body) {
        std::thread::sleep(cfg.auth_delay);
        let e = Error::Permission("hh-net: authentication failed".into());
        let _ = proto::write_all(w, &proto::error_frame(0, &e));
        return Ok(false);
    }
    let proof = proto::server_proof(token, &snonce, &cnonce);
    proto::write_all(
        w,
        &proto::frame(0, op::AUTH_OK, |e| {
            e.0.extend_from_slice(&proof);
            e.u32(cfg.max_read as u32);
        }),
    )?;
    Ok(true)
}

fn connection(sh: &Shared, s: TcpStream) -> std::io::Result<()> {
    let cfg = &sh.cfg;
    s.set_nodelay(true)?;
    s.set_read_timeout(Some(cfg.handshake_timeout))?;
    // A client that stops reading must not pin a worker forever.
    s.set_write_timeout(Some(Duration::from_secs(30)))?;
    let mut w = s.try_clone()?;
    let mut r = BufReader::with_capacity(64 << 10, s);
    if !handshake(cfg, &mut r, &mut w)? {
        return Ok(());
    }
    r.get_ref().set_read_timeout(None)?;

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

struct Conn<'a> {
    sh: &'a Shared,
    handles: Mutex<HashMap<u32, Arc<dyn Process>>>,
    next_handle: AtomicU32,
    w: Mutex<TcpStream>,
}

fn poisoned<T>(_: T) -> Error {
    Error::Other("hh-net: internal lock poisoned".into())
}

impl Conn<'_> {
    fn worker(&self, rx: &Mutex<Receiver<(u32, Req)>>) {
        loop {
            let next = match rx.lock() {
                Ok(rx) => rx.recv(),
                Err(_) => return,
            };
            let Ok((id, req)) = next else { return };
            let resp = match self.exec(id, req) {
                Ok(Some(f)) => f,
                Ok(None) => continue,
                Err(e) => proto::error_frame(id, &e),
            };
            let Ok(mut w) = self.w.lock() else { return };
            // Keep draining after a failed write so the reader never blocks on a full queue.
            if proto::write_all(&mut *w, &resp).is_err() {
                let _ = w.shutdown(Shutdown::Both);
            }
        }
    }

    fn get(&self, h: u32) -> Result<Arc<dyn Process>> {
        self.handles
            .lock()
            .map_err(poisoned)?
            .get(&h)
            .cloned()
            .ok_or_else(|| Error::Other(format!("hh-net: unknown process handle {h}")))
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
                let p = self.sh.backend.open(pid)?;
                let ps = p.pointer_size() as u8;
                let mut hs = self.handles.lock().map_err(poisoned)?;
                if hs.len() >= self.sh.cfg.max_handles {
                    return Err(Error::Other("hh-net: too many open processes on this connection".into()));
                }
                let h = self.next_handle.fetch_add(1, Relaxed);
                hs.insert(h, p);
                ok(&|e| {
                    e.u32(h);
                    e.u8(ps);
                })
            }
            Req::Close(h) => {
                self.handles.lock().map_err(poisoned)?.remove(&h);
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
                Ok(Some(read_batch(id, &*p, &ranges, total as usize)))
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
                self.get(h)?.suspend()?;
                ok(&|_| {})
            }
            Req::Resume(h) => {
                self.get(h)?.resume()?;
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
