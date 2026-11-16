//! The client side: a remote machine's processes as `hh_core::Process` objects.
//!
//! One TCP connection is multiplexed: any number of threads send requests concurrently
//! (each frame is written whole under a lock), a reader thread routes responses back by id.
use std::collections::HashMap;
use std::io::{self, BufReader, ErrorKind};
use std::net::{Shutdown, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering::Relaxed};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, sync_channel};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hh_core::{Addr, Error, Memory, Module, Pid, Process, ProcessInfo, Prot, Region, Result};

use crate::proto::{self, Dec, Enc, Frame, op};

pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Default)]
struct Pending {
    map: HashMap<u32, SyncSender<Frame>>,
    /// Set once the connection is gone; why.
    dead: Option<String>,
}

struct Conn {
    w: Mutex<TcpStream>,
    pending: Mutex<Pending>,
    next_id: AtomicU32,
    timeout_ms: AtomicU64,
    max_read: usize,
}

fn lost(why: &str) -> Error {
    Error::Io(io::Error::new(ErrorKind::ConnectionAborted, format!("hh-net: connection to server lost: {why}")))
}

fn poisoned<T>(_: T) -> Error {
    Error::Other("hh-net: internal lock poisoned".into())
}

impl Conn {
    fn kill(&self, why: String) {
        if let Ok(mut p) = self.pending.lock() {
            p.dead.get_or_insert(why);
            p.map.clear(); // waiting callers see a disconnected channel
        }
        if let Ok(w) = self.w.lock() {
            let _ = w.shutdown(Shutdown::Both);
        }
    }

    fn reader(&self, mut r: BufReader<TcpStream>) {
        // shortcut: fixed slack for list/regions responses; raise if a target has >500k regions.
        let max = self.max_read + (64 << 20);
        loop {
            match proto::read_frame(&mut r, max) {
                Ok(f) => {
                    let tx = self.pending.lock().ok().and_then(|mut p| p.map.remove(&f.id));
                    if let Some(tx) = tx {
                        let _ = tx.try_send(f);
                    }
                }
                Err(e) => {
                    let why = if e.kind() == ErrorKind::UnexpectedEof { "server closed the connection".into() } else { e.to_string() };
                    return self.kill(why);
                }
            }
        }
    }

    fn write(&self, buf: &[u8]) -> Result<()> {
        let mut w = self.w.lock().map_err(poisoned)?;
        proto::write_all(&mut *w, buf).map_err(|e| {
            drop(w);
            let why = e.to_string();
            self.kill(why.clone());
            lost(&why)
        })
    }

    fn send(&self, op: u8, f: impl FnOnce(&mut Enc)) -> Result<(u32, Receiver<Frame>)> {
        let id = match self.next_id.fetch_add(1, Relaxed) {
            0 => self.next_id.fetch_add(1, Relaxed), // 0 is the handshake's
            id => id,
        };
        let (tx, rx) = sync_channel(1);
        {
            let mut p = self.pending.lock().map_err(poisoned)?;
            if let Some(why) = &p.dead {
                return Err(lost(why));
            }
            p.map.insert(id, tx);
        }
        self.write(&proto::frame(id, op, f))?;
        Ok((id, rx))
    }

    fn forget(&self, id: u32) {
        if let Ok(mut p) = self.pending.lock() {
            p.map.remove(&id);
        }
    }

    /// Waits for the response; returns the ok body or the remote error.
    fn wait(&self, id: u32, rx: Receiver<Frame>) -> Result<Vec<u8>> {
        let t = Duration::from_millis(self.timeout_ms.load(Relaxed));
        let f = match rx.recv_timeout(t) {
            Ok(f) => f,
            Err(RecvTimeoutError::Timeout) => {
                self.forget(id);
                return Err(Error::Io(io::Error::new(ErrorKind::TimedOut, "hh-net: server did not answer in time")));
            }
            Err(RecvTimeoutError::Disconnected) => {
                let why = self.pending.lock().ok().and_then(|p| p.dead.clone()).unwrap_or_default();
                return Err(lost(&why));
            }
        };
        match f.op {
            proto::STATUS_OK => Ok(f.body),
            proto::STATUS_ERR => Err(proto::dec_error(&mut Dec(&f.body))?),
            s => Err(Error::Parse(format!("hh-net: bad response status {s}"))),
        }
    }

    fn call(&self, op: u8, f: impl FnOnce(&mut Enc)) -> Result<Vec<u8>> {
        let (id, rx) = self.send(op, f)?;
        self.wait(id, rx)
    }
}

/// Owner side of the connection: closing the socket ends the reader thread.
struct Client(Arc<Conn>);

impl Drop for Client {
    fn drop(&mut self) {
        self.0.kill("client closed".into());
    }
}

/// A connection to an `hh-server`. Cheap to clone; safe to share between threads.
#[derive(Clone)]
pub struct RemoteHost {
    c: Arc<Client>,
}

fn expect_frame(f: &Frame, want: u8) -> Result<()> {
    if f.op == proto::STATUS_ERR {
        return Err(proto::dec_error(&mut Dec(&f.body))?);
    }
    if f.op != want {
        return Err(Error::Parse(format!("hh-net: unexpected handshake message {}", f.op)));
    }
    Ok(())
}

/// Connects and authenticates. `token` is the server's shared secret; it is not sent, only
/// proven (see [`crate::proto`]).
pub fn connect(addr: impl ToSocketAddrs, token: &str) -> Result<RemoteHost> {
    let mut last = io::Error::new(ErrorKind::InvalidInput, "hh-net: address resolved to nothing");
    let mut stream = None;
    for a in addr.to_socket_addrs()? {
        match TcpStream::connect_timeout(&a, Duration::from_secs(10)) {
            Ok(s) => {
                stream = Some(s);
                break;
            }
            Err(e) => last = e,
        }
    }
    let s = stream.ok_or(last)?;
    s.set_nodelay(true)?;
    s.set_read_timeout(Some(DEFAULT_TIMEOUT))?;
    s.set_write_timeout(Some(DEFAULT_TIMEOUT))?;
    let mut w = s.try_clone()?;
    let mut r = BufReader::with_capacity(256 << 10, s);

    let cnonce = proto::nonce()?;
    proto::write_all(
        &mut w,
        &proto::frame(0, op::HELLO, |e| {
            e.0.extend_from_slice(proto::MAGIC);
            e.u16(proto::VERSION);
            e.0.extend_from_slice(&cnonce);
        }),
    )?;
    let ch = proto::read_frame(&mut r, 1024)?;
    expect_frame(&ch, op::CHALLENGE)?;
    let mut d = Dec(&ch.body);
    if d.u16()? != proto::VERSION {
        return Err(Error::Unsupported("hh-net protocol version"));
    }
    let snonce = d.take(proto::NONCE)?.to_vec();
    let proof = proto::client_proof(token.as_bytes(), &snonce, &cnonce);
    proto::write_all(&mut w, &proto::frame(0, op::AUTH, |e| e.0.extend_from_slice(&proof)))?;
    let ok = proto::read_frame(&mut r, 1024).map_err(|e| {
        if e.kind() == ErrorKind::UnexpectedEof { Error::Permission("hh-net: authentication failed".into()) } else { e.into() }
    })?;
    expect_frame(&ok, op::AUTH_OK)?;
    let mut d = Dec(&ok.body);
    if !proto::verify_server(token.as_bytes(), &snonce, &cnonce, d.take(32)?) {
        return Err(Error::Permission("hh-net: server could not prove it knows the token".into()));
    }
    let max_read = (d.u32()? as usize).max(4096);
    r.get_ref().set_read_timeout(None)?;

    let conn = Arc::new(Conn {
        w: Mutex::new(w),
        pending: Mutex::default(),
        next_id: AtomicU32::new(1),
        timeout_ms: AtomicU64::new(DEFAULT_TIMEOUT.as_millis() as u64),
        max_read,
    });
    let c2 = conn.clone();
    std::thread::Builder::new().name("hh-net client".into()).spawn(move || c2.reader(r))?;
    Ok(RemoteHost { c: Arc::new(Client(conn)) })
}

impl RemoteHost {
    fn conn(&self) -> &Conn {
        &self.c.0
    }

    /// Per-request timeout (default 30 s). A timed-out request fails with `ErrorKind::TimedOut`;
    /// the connection stays usable.
    pub fn set_timeout(&self, t: Duration) {
        let ms = t.as_millis().clamp(1, u64::MAX as u128) as u64;
        self.conn().timeout_ms.store(ms, Relaxed);
        if let Ok(w) = self.conn().w.lock() {
            let _ = w.set_write_timeout(Some(t.max(Duration::from_millis(1))));
        }
    }

    /// Largest READ batch / WRITE the server accepts in one request.
    pub fn max_read(&self) -> usize {
        self.conn().max_read
    }

    pub fn list_processes(&self) -> Result<Vec<ProcessInfo>> {
        proto::dec_list(&self.conn().call(op::LIST, |_| {})?, 9, proto::dec_process)
    }

    pub fn open(&self, pid: Pid) -> Result<Arc<dyn Process>> {
        Ok(Arc::new(self.open_remote(pid)?))
    }

    /// Like [`RemoteHost::open`] but keeps the concrete type for [`RemoteProcess::read_batch`].
    pub fn open_remote(&self, pid: Pid) -> Result<RemoteProcess> {
        let b = self.conn().call(op::OPEN, |e| e.u32(pid))?;
        let mut d = Dec(&b);
        let (handle, ps) = (d.u32()?, d.u8()?);
        d.end()?;
        if ps != 4 && ps != 8 {
            return Err(Error::Parse(format!("hh-net: bad pointer size {ps}")));
        }
        Ok(RemoteProcess {
            c: self.c.clone(),
            handle,
            pid,
            ptr_size: ps as usize,
        })
    }
}

/// A process on the server. Implements `Process`, so scanners and tools work on it unchanged.
pub struct RemoteProcess {
    c: Arc<Client>,
    handle: u32,
    pid: Pid,
    ptr_size: usize,
}

impl Drop for RemoteProcess {
    fn drop(&mut self) {
        let h = self.handle;
        let _ = self.conn().write(&proto::frame(0, op::CLOSE, |e| e.u32(h)));
    }
}

impl RemoteProcess {
    fn conn(&self) -> &Conn {
        &self.c.0
    }

    fn call(&self, op: u8, f: impl FnOnce(&mut Enc)) -> Result<Vec<u8>> {
        let h = self.handle;
        self.conn().call(op, |e| {
            e.u32(h);
            f(e)
        })
    }

    fn call_empty(&self, op: u8, f: impl FnOnce(&mut Enc)) -> Result<()> {
        Dec(&self.call(op, f)?).end()
    }

    /// Reads many ranges in as few round trips as the server limits allow (requests are
    /// pipelined). `sink(i, result)` gets every range's `Memory::read` result in order.
    fn batch(&self, ranges: &[(Addr, usize)], mut sink: impl FnMut(usize, Result<&[u8]>)) -> Result<()> {
        let mr = self.conn().max_read;
        // Group boundaries: each group fits in one READ.
        let mut groups = Vec::new();
        let (mut start, mut bytes) = (0, 0);
        for (i, r) in ranges.iter().enumerate() {
            let len = r.1.min(mr);
            if i > start && (i - start == proto::MAX_RANGES || bytes + len > mr) {
                groups.push(start..i);
                (start, bytes) = (i, 0);
            }
            bytes += len;
        }
        if start < ranges.len() {
            groups.push(start..ranges.len());
        }
        let mut sent = Vec::with_capacity(groups.len());
        let mut res = Ok(());
        for g in &groups {
            let h = self.handle;
            let req = self.conn().send(op::READ, |e| {
                e.u32(h);
                e.u32(g.len() as u32);
                for &(a, l) in &ranges[g.clone()] {
                    e.u64(a);
                    e.u32(l.min(mr) as u32);
                }
            });
            match req {
                Ok(r) => sent.push(r),
                Err(e) => {
                    res = Err(e);
                    break;
                }
            }
        }
        let mut sent = sent.into_iter();
        for g in &groups {
            if res.is_err() {
                break;
            }
            let Some((id, rx)) = sent.next() else { break };
            res = self.conn().wait(id, rx).and_then(|body| {
                let mut d = Dec(&body);
                for i in g.clone() {
                    match d.u8()? {
                        proto::STATUS_OK => {
                            let b = d.bytes()?;
                            sink(i, Ok(&b[..b.len().min(ranges[i].1)]));
                        }
                        proto::STATUS_ERR => sink(i, Err(proto::dec_error(&mut d)?)),
                        _ => return Err(Error::Parse("hh-net: bad read result".into())),
                    }
                }
                d.end()
            });
        }
        for (id, _) in sent {
            self.conn().forget(id);
        }
        res
    }

    /// Reads many small ranges in one round trip. The outer error is a transport failure; the
    /// inner ones are per range (`Memory::read` semantics: a result may be shorter than asked,
    /// and a range longer than [`RemoteHost::max_read`] is read short).
    pub fn read_batch(&self, ranges: &[(Addr, usize)]) -> Result<Vec<Result<Vec<u8>>>> {
        let mut out = Vec::with_capacity(ranges.len());
        self.batch(ranges, |_, r| out.push(r.map(<[u8]>::to_vec)))?;
        Ok(out)
    }
}

impl Memory for RemoteProcess {
    fn read(&self, addr: Addr, buf: &mut [u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        // Large reads go out as pipelined chunks; stop at the first short or failed chunk.
        let mr = self.conn().max_read;
        let chunks: Vec<(Addr, usize)> = (0..buf.len()).step_by(mr).map(|o| (addr.wrapping_add(o as u64), mr.min(buf.len() - o))).collect();
        let (mut done, mut stop, mut first_err) = (0, false, None);
        self.batch(&chunks, |i, r| {
            if stop {
                return;
            }
            match r {
                Ok(b) => {
                    let o = i * mr;
                    buf[o..o + b.len()].copy_from_slice(b);
                    done += b.len();
                    stop = b.len() < chunks[i].1;
                }
                Err(e) => {
                    if i == 0 {
                        first_err = Some(e);
                    }
                    stop = true;
                }
            }
        })?;
        match first_err {
            Some(e) => Err(e),
            None => Ok(done),
        }
    }

    fn write(&self, addr: Addr, data: &[u8]) -> Result<()> {
        let mr = self.conn().max_read;
        // shortcut: writes above max_read go out as several requests, so they are not atomic.
        for (i, c) in data.chunks(mr).enumerate() {
            let a = addr.wrapping_add((i * mr) as u64);
            self.call_empty(op::WRITE, |e| {
                e.u64(a);
                e.bytes(c);
            })?;
        }
        Ok(())
    }

    fn pointer_size(&self) -> usize {
        self.ptr_size
    }
}

impl Process for RemoteProcess {
    fn pid(&self) -> Pid {
        self.pid
    }
    fn is_alive(&self) -> bool {
        self.call(op::IS_ALIVE, |_| {}).is_ok_and(|b| b == [1])
    }
    fn regions(&self) -> Result<Vec<Region>> {
        proto::dec_list(&self.call(op::REGIONS, |_| {})?, 20, proto::dec_region)
    }
    fn modules(&self) -> Result<Vec<Module>> {
        proto::dec_list(&self.call(op::MODULES, |_| {})?, 24, proto::dec_module)
    }
    fn threads(&self) -> Result<Vec<u32>> {
        proto::dec_list(&self.call(op::THREADS, |_| {})?, 4, |d| d.u32())
    }
    fn alloc(&self, size: u64, prot: Prot, near: Option<Addr>) -> Result<Addr> {
        let b = self.call(op::ALLOC, |e| {
            e.u64(size);
            e.prot(prot);
            match near {
                None => e.u8(0),
                Some(a) => {
                    e.u8(1);
                    e.u64(a);
                }
            }
        })?;
        let mut d = Dec(&b);
        let a = d.u64()?;
        d.end()?;
        Ok(a)
    }
    fn free(&self, addr: Addr, size: u64) -> Result<()> {
        self.call_empty(op::FREE, |e| {
            e.u64(addr);
            e.u64(size);
        })
    }
    fn protect(&self, addr: Addr, size: u64, prot: Prot) -> Result<Prot> {
        let b = self.call(op::PROTECT, |e| {
            e.u64(addr);
            e.u64(size);
            e.prot(prot);
        })?;
        let mut d = Dec(&b);
        let p = d.prot()?;
        d.end()?;
        Ok(p)
    }
    fn suspend(&self) -> Result<()> {
        self.call_empty(op::SUSPEND, |_| {})
    }
    fn resume(&self) -> Result<()> {
        self.call_empty(op::RESUME, |_| {})
    }
}
