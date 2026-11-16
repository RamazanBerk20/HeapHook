//! Protocol, security and concurrency tests against an in-process server on loopback.
use std::io::{self, ErrorKind, Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hh_core::{Addr, Error, Memory, MockProcess, Module, Pid, Process, ProcessInfo, Prot, Region, RegionKind, Result};
use hh_net::proto::{self, Dec, Enc, Frame, op};
use hh_net::server::{Req, decode_request};
use hh_net::{Backend, Server, ServerConfig, ServerHandle, connect};

const BASE: Addr = 0x10000;
/// An alloc of this size panics inside the backend.
const PANIC_SIZE: u64 = 0xDEAD;
/// Reads at ERR + k fail with error variant k.
const ERR: Addr = 0xE000_0000;

fn all_errors() -> Vec<Error> {
    vec![
        Error::Io(io::Error::new(ErrorKind::BrokenPipe, "pipe broke")),
        Error::NoAccess { addr: 0xdead_beef_0000 },
        Error::Permission("nope".into()),
        Error::ProcessGone,
        Error::Parse("bad text".into()),
        Error::Unsupported("threads"),
        Error::Other("other thing".into()),
    ]
}

fn same(a: &Error, b: &Error) -> bool {
    std::mem::discriminant(a) == std::mem::discriminant(b) && a.to_string() == b.to_string()
}

struct TestProc {
    mock: MockProcess,
    delay_ms: AtomicU64,
    suspends: AtomicU32,
    resumes: AtomicU32,
}

impl Memory for TestProc {
    fn read(&self, addr: Addr, buf: &mut [u8]) -> Result<usize> {
        let d = self.delay_ms.load(Relaxed);
        if d > 0 {
            std::thread::sleep(Duration::from_millis(d));
        }
        if let Some(k) = addr.checked_sub(ERR).filter(|k| *k < 7) {
            return Err(all_errors().swap_remove(k as usize));
        }
        self.mock.read(addr, buf)
    }
    fn write(&self, addr: Addr, data: &[u8]) -> Result<()> {
        self.mock.write(addr, data)
    }
}

impl Process for TestProc {
    fn pid(&self) -> Pid {
        42
    }
    fn regions(&self) -> Result<Vec<Region>> {
        let mut r = self.mock.regions()?;
        r.push(Region {
            start: 0x7000_0000,
            size: 0x1000,
            prot: Prot { r: true, w: false, x: true },
            kind: RegionKind::Image,
            shared: true,
            path: Some("/usr/lib/libé.so".into()),
        });
        Ok(r)
    }
    fn modules(&self) -> Result<Vec<Module>> {
        Ok(vec![Module { name: "game".into(), path: "/g/game".into(), base: 0x400000, size: 0x2000 }])
    }
    fn threads(&self) -> Result<Vec<u32>> {
        Ok(vec![42, 43])
    }
    fn alloc(&self, size: u64, _prot: Prot, near: Option<Addr>) -> Result<Addr> {
        assert!(size != PANIC_SIZE, "backend bug");
        Ok(near.unwrap_or(0x5000_0000) + size)
    }
    fn free(&self, _addr: Addr, _size: u64) -> Result<()> {
        Ok(())
    }
    fn protect(&self, _addr: Addr, _size: u64, _prot: Prot) -> Result<Prot> {
        Ok(Prot { r: true, w: true, x: false })
    }
    fn suspend(&self) -> Result<()> {
        self.suspends.fetch_add(1, Relaxed);
        Ok(())
    }
    fn resume(&self) -> Result<()> {
        self.resumes.fetch_add(1, Relaxed);
        Ok(())
    }
}

struct TestBackend(Arc<TestProc>);

impl Backend for TestBackend {
    fn list_processes(&self) -> Result<Vec<ProcessInfo>> {
        Ok(vec![
            ProcessInfo { pid: 42, name: "game".into(), exe: Some("/g/game".into()) },
            ProcessInfo { pid: 7, name: "init".into(), exe: None },
        ])
    }
    fn open(&self, pid: Pid) -> Result<Arc<dyn Process>> {
        match pid {
            42 => Ok(self.0.clone()),
            _ => Err(Error::Permission(format!("cannot open {pid}"))),
        }
    }
}

const TOKEN: &str = "s3cret-token";

fn start_with(mem: usize, f: impl FnOnce(&mut ServerConfig)) -> (ServerHandle, Arc<TestProc>) {
    let data: Vec<u8> = (0..mem).map(|i| (i * 7 + i / 4096) as u8).collect();
    let p = Arc::new(TestProc { mock: MockProcess::new(BASE, data), delay_ms: AtomicU64::new(0), suspends: AtomicU32::new(0), resumes: AtomicU32::new(0) });
    let mut cfg = ServerConfig::new(TOKEN);
    cfg.auth_delay = Duration::from_millis(100);
    f(&mut cfg);
    let s = Server::bind("127.0.0.1:0", cfg, Arc::new(TestBackend(p.clone()))).unwrap().spawn().unwrap();
    (s, p)
}

fn start() -> (ServerHandle, Arc<TestProc>) {
    start_with(1 << 20, |_| {})
}

// ------------------------------------------------------------------ codec

#[test]
fn error_roundtrip_every_variant() {
    for err in all_errors() {
        let f = proto::error_frame(9, &err);
        let fr = proto::read_frame(&mut &f[..], 1 << 10).unwrap();
        assert_eq!((fr.id, fr.op), (9, proto::STATUS_ERR));
        let mut d = Dec(&fr.body);
        let back = proto::dec_error(&mut d).unwrap();
        d.end().unwrap();
        assert!(same(&err, &back), "{err:?} -> {back:?}");
        if let (Error::Io(a), Error::Io(b)) = (&err, &back) {
            assert_eq!(a.kind(), b.kind());
        }
    }
}

#[test]
fn types_roundtrip() {
    let p = ProcessInfo { pid: 5, name: "a".into(), exe: None };
    let r = Region { start: 1, size: 2, prot: Prot { r: true, w: false, x: true }, kind: RegionKind::Mapped, shared: true, path: Some("[heap]".into()) };
    let m = Module { name: "n".into(), path: "p".into(), base: 3, size: 4 };
    let mut e = Enc(Vec::new());
    proto::enc_list(&mut e, &[p.clone(), p], proto::enc_process);
    let l = proto::dec_list(&e.0, 9, proto::dec_process).unwrap();
    assert_eq!((l.len(), l[0].pid, l[0].exe.as_deref()), (2, 5, None));
    let mut e = Enc(Vec::new());
    proto::enc_list(&mut e, std::slice::from_ref(&r), proto::enc_region);
    let l = proto::dec_list(&e.0, 20, proto::dec_region).unwrap();
    assert_eq!((l[0].start, l[0].size, l[0].prot, l[0].kind, l[0].shared, l[0].path.as_deref()), (1, 2, r.prot, RegionKind::Mapped, true, Some("[heap]")));
    let mut e = Enc(Vec::new());
    proto::enc_list(&mut e, std::slice::from_ref(&m), proto::enc_module);
    let l = proto::dec_list(&e.0, 24, proto::dec_module).unwrap();
    assert_eq!((l[0].name.as_str(), l[0].path.as_str(), l[0].base, l[0].size), ("n", "p", 3, 4));
}

#[test]
fn request_decoding() {
    let f = |op, b: &dyn Fn(&mut Enc)| {
        let v = proto::frame(1, op, b);
        decode_request(&proto::read_frame(&mut &v[..], 1 << 10).unwrap())
    };
    assert_eq!(f(op::LIST, &|_| {}).unwrap(), Req::List);
    assert_eq!(
        f(op::READ, &|e| {
            e.u32(3);
            e.u32(2);
            e.u64(10);
            e.u32(4);
            e.u64(20);
            e.u32(8);
        })
        .unwrap(),
        Req::Read(3, vec![(10, 4), (20, 8)])
    );
    assert_eq!(
        f(op::ALLOC, &|e| {
            e.u32(1);
            e.u64(4096);
            e.prot(Prot { r: true, w: true, x: true });
            e.u8(1);
            e.u64(0x400000);
        })
        .unwrap(),
        Req::Alloc(1, 4096, Prot { r: true, w: true, x: true }, Some(0x400000))
    );
    // Trailing bytes, truncation, bad prot, unknown opcode, absurd counts.
    assert!(f(op::LIST, &|e| e.u8(0)).is_err());
    assert!(f(op::OPEN, &|e| e.u8(0)).is_err());
    assert!(f(op::PROTECT, &|e| {
        e.u32(1);
        e.u64(0);
        e.u64(0);
        e.u8(9);
    })
    .is_err());
    assert!(f(77, &|_| {}).is_err());
    assert!(f(op::READ, &|e| {
        e.u32(1);
        e.u32(u32::MAX);
    })
    .is_err());
}

/// Tiny deterministic PRNG for the fuzz tests.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

#[test]
fn fuzz_decoders() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let ops = [op::LIST, op::OPEN, op::CLOSE, op::READ, op::WRITE, op::REGIONS, op::MODULES, op::THREADS, op::IS_ALIVE, op::ALLOC, op::FREE, op::PROTECT, op::SUSPEND, op::RESUME, 0, 255];
    for i in 0..200_000 {
        let n = (rng.next() % 64) as usize;
        let body = rng.bytes(n);
        let f = Frame { id: 1, op: ops[i % ops.len()], body: body.clone() };
        let _ = decode_request(&f);
        let _ = proto::dec_error(&mut Dec(&body));
        let _ = proto::dec_list(&body, 20, proto::dec_region);
        let _ = proto::dec_list(&body, 24, proto::dec_module);
        let _ = proto::dec_list(&body, 9, proto::dec_process);
        // Random streams through the framer, with a small limit.
        let _ = proto::read_frame(&mut &body[..], 32);
    }
    // A huge declared length is rejected before allocating.
    let e = proto::read_frame(&mut &[0xff, 0xff, 0xff, 0xff, 0, 0][..], 1 << 20).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidData);
    // Valid frames, truncated at every position, never decode wrongly or panic.
    let v = proto::frame(5, op::WRITE, |e| {
        e.u32(1);
        e.u64(BASE);
        e.bytes(b"hello");
    });
    for cut in 0..v.len() {
        assert!(proto::read_frame(&mut &v[..cut], 1 << 10).is_err());
    }
}

// ------------------------------------------------------------------ raw sockets

fn raw(h: &ServerHandle) -> TcpStream {
    let s = TcpStream::connect(h.addr()).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s
}

/// Hello + challenge; returns the server nonce and the client nonce used.
fn hello(s: &mut TcpStream) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let cn = vec![7u8; 32];
    s.write_all(&proto::frame(0, op::HELLO, |e| {
        e.0.extend_from_slice(proto::MAGIC);
        e.u16(proto::VERSION);
        e.0.extend_from_slice(&cn);
    }))?;
    let f = proto::read_frame(s, 1024)?;
    assert_eq!(f.op, op::CHALLENGE);
    Ok((f.body[2..].to_vec(), cn))
}

fn send_auth(s: &mut TcpStream, proof: &[u8]) -> Frame {
    s.write_all(&proto::frame(0, op::AUTH, |e| e.0.extend_from_slice(proof))).unwrap();
    proto::read_frame(s, 1024).unwrap()
}

/// A raw socket past the handshake.
fn authed(h: &ServerHandle) -> TcpStream {
    let mut s = raw(h);
    let (sn, cn) = hello(&mut s).unwrap();
    let f = send_auth(&mut s, &proto::client_proof(TOKEN.as_bytes(), &sn, &cn));
    assert_eq!(f.op, op::AUTH_OK);
    s
}

/// True if the server closed the connection (EOF or reset) without answering.
fn closed(s: &mut TcpStream) -> bool {
    let mut b = [0u8; 64];
    loop {
        match s.read(&mut b) {
            Ok(0) => return true,
            Ok(_) => continue, // e.g. a pending error frame
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => return false,
            Err(_) => return true,
        }
    }
}

fn still_serves(h: &ServerHandle) {
    let c = connect(h.addr(), TOKEN).unwrap();
    assert_eq!(c.list_processes().unwrap().len(), 2);
}

#[test]
fn garbage_drops_connection() {
    let (h, _) = start();
    let mut rng = Rng(12345);
    for i in 0..60 {
        // Before auth: random bytes, or a request without the handshake.
        let mut s = raw(&h);
        if i % 3 == 0 {
            let _ = s.write_all(&proto::frame(1, op::LIST, |_| {}));
        } else {
            let n = 1 + (rng.next() % 300) as usize;
            let _ = s.write_all(&rng.bytes(n));
        }
        let _ = s.shutdown(std::net::Shutdown::Write);
        assert!(closed(&mut s), "pre-auth garbage {i}");
    }
    for i in 0..60 {
        // After auth: random frames with plausible lengths, or random raw bytes.
        let mut s = authed(&h);
        if i % 2 == 0 {
            let n = (rng.next() % 200) as usize;
            let body = rng.bytes(n);
            let _ = s.write_all(&proto::frame(1, 15 + (rng.next() % 80) as u8, |e| e.0.extend_from_slice(&body)));
        } else {
            let n = 1 + (rng.next() % 300) as usize;
            let mut b = rng.bytes(n);
            b[..4.min(n)].fill(0xff); // implausible length prefix
            let _ = s.write_all(&b);
        }
        assert!(closed(&mut s), "post-auth garbage {i}");
    }
    // Oversized frame header: the server must not try to allocate it.
    let mut s = authed(&h);
    s.write_all(&u32::MAX.to_le_bytes()).unwrap();
    assert!(closed(&mut s));
    // Truncated frame followed by an abrupt disconnect.
    let mut s = authed(&h);
    s.write_all(&proto::frame(1, op::LIST, |_| {})[..6]).unwrap();
    drop(s);
    still_serves(&h);
}

// ------------------------------------------------------------------ auth

#[test]
fn wrong_token_rejected() {
    let (h, _) = start();
    let t = Instant::now();
    let e = connect(h.addr(), "s3cret-tokem").err().unwrap();
    assert!(matches!(e, Error::Permission(_)), "{e:?}");
    assert!(t.elapsed() >= Duration::from_millis(100), "failed auth must be delayed");
    assert!(matches!(connect(h.addr(), "").err().unwrap(), Error::Permission(_)));
    // The server closes after one failed attempt.
    let mut s = raw(&h);
    let (sn, cn) = hello(&mut s).unwrap();
    let f = send_auth(&mut s, &proto::client_proof(b"wrong", &sn, &cn));
    assert_eq!(f.op, proto::STATUS_ERR);
    assert!(closed(&mut s));
    still_serves(&h);
}

#[test]
fn empty_server_token_refused() {
    assert!(Server::bind("127.0.0.1:0", ServerConfig::new(""), Arc::new(TestBackend(Arc::new(TestProc { mock: MockProcess::new(0, vec![]), delay_ms: AtomicU64::new(0), suspends: AtomicU32::new(0), resumes: AtomicU32::new(0) })))).is_err());
}

#[test]
fn replayed_handshake_rejected() {
    let (h, _) = start();
    // Record a valid exchange...
    let mut s = raw(&h);
    let (sn, cn) = hello(&mut s).unwrap();
    let proof = proto::client_proof(TOKEN.as_bytes(), &sn, &cn);
    assert_eq!(send_auth(&mut s, &proof).op, op::AUTH_OK);
    // ...and replay it on a new connection: the fresh server nonce makes it invalid.
    let mut s2 = raw(&h);
    let (sn2, _) = hello(&mut s2).unwrap();
    assert_ne!(sn, sn2);
    assert_eq!(send_auth(&mut s2, &proof).op, proto::STATUS_ERR);
    assert!(closed(&mut s2));
}

#[test]
fn wrong_version_and_magic() {
    let (h, _) = start();
    let mut s = raw(&h);
    s.write_all(&proto::frame(0, op::HELLO, |e| {
        e.0.extend_from_slice(proto::MAGIC);
        e.u16(99);
        e.0.extend_from_slice(&[0; 32]);
    }))
    .unwrap();
    let f = proto::read_frame(&mut s, 1024).unwrap();
    assert!(matches!(proto::dec_error(&mut Dec(&f.body)).unwrap(), Error::Unsupported(_)));
    let mut s = raw(&h);
    s.write_all(&proto::frame(0, op::HELLO, |e| e.0.extend_from_slice(&[b'X'; 40]))).unwrap();
    assert!(closed(&mut s));
}

#[test]
fn idle_unauthenticated_client_dropped() {
    let (h, _) = start_with(4096, |c| c.handshake_timeout = Duration::from_millis(200));
    let mut s = raw(&h);
    assert!(closed(&mut s));
}

// ------------------------------------------------------------------ operations

#[test]
fn every_operation() {
    let (h, tp) = start();
    let c = connect(h.addr(), TOKEN).unwrap();
    let l = c.list_processes().unwrap();
    assert_eq!((l[0].pid, l[0].exe.as_deref(), l[1].exe.as_deref()), (42, Some("/g/game"), None));
    assert!(matches!(c.open(1).err().unwrap(), Error::Permission(s) if s == "cannot open 1"));
    let p = c.open(42).unwrap();
    assert_eq!((p.pid(), p.pointer_size()), (42, 8));
    assert!(p.is_alive());
    p.write(BASE + 8, &0x1122_3344_5566_7788u64.to_le_bytes()).unwrap();
    assert_eq!(p.read_ptr(BASE + 8).unwrap(), 0x1122_3344_5566_7788);
    // Short read at the end of memory, error past it.
    let mut b = vec![0u8; 64];
    assert_eq!(p.read(BASE + (1 << 20) - 16, &mut b).unwrap(), 16);
    assert!(matches!(p.read(BASE + (1 << 20), &mut b), Err(Error::NoAccess { addr }) if addr == BASE + (1 << 20)));
    assert!(matches!(p.read_exact(BASE + (1 << 20) - 16, &mut b), Err(Error::NoAccess { addr }) if addr == BASE + (1 << 20)));
    // Each error variant survives the trip.
    for (k, want) in all_errors().iter().enumerate() {
        let got = p.read(ERR + k as u64, &mut b).unwrap_err();
        assert!(same(want, &got), "{want:?} vs {got:?}");
    }
    let r = p.regions().unwrap();
    assert_eq!(r.len(), 2);
    assert_eq!((r[1].path.as_deref(), r[1].shared, r[1].kind), (Some("/usr/lib/libé.so"), true, RegionKind::Image));
    assert_eq!(p.modules().unwrap()[0].base, 0x400000);
    assert_eq!(p.threads().unwrap(), [42, 43]);
    assert_eq!(p.alloc(0x100, Prot::default(), Some(0x1000)).unwrap(), 0x1100);
    assert_eq!(p.alloc(0x100, Prot::default(), None).unwrap(), 0x5000_0100);
    p.free(0x1100, 0x100).unwrap();
    assert_eq!(p.protect(0x1000, 1, Prot::default()).unwrap(), Prot { r: true, w: true, x: false });
    p.suspend().unwrap();
    p.resume().unwrap();
    assert_eq!(tp.suspends.load(Relaxed), 1);
}

#[test]
fn batched_and_chunked_reads() {
    let (h, tp) = start_with(1 << 20, |c| c.max_read = 64 << 10);
    let c = connect(h.addr(), TOKEN).unwrap();
    assert_eq!(c.max_read(), 64 << 10);
    let p = c.open_remote(42).unwrap();
    let want = tp.mock.mem.read().unwrap().clone();
    // A 1 MiB read becomes 16 pipelined chunks.
    let mut b = vec![0u8; 1 << 20];
    assert_eq!(p.read(BASE, &mut b).unwrap(), 1 << 20);
    assert_eq!(b, want);
    // Ending past memory: short.
    assert_eq!(p.read(BASE + 0x1000, &mut b).unwrap(), (1 << 20) - 0x1000);
    // 3000 small ranges (spanning several requests), with failures mixed in.
    let ranges: Vec<(Addr, usize)> = (0..3000).map(|i| if i % 100 == 99 { (ERR + 1, 8) } else { (BASE + i as u64 * 333, 40) }).collect();
    let res = p.read_batch(&ranges).unwrap();
    assert_eq!(res.len(), 3000);
    for (i, r) in res.iter().enumerate() {
        match r {
            Ok(v) => assert_eq!(v[..], want[i * 333..i * 333 + 40]),
            Err(e) => assert!(i % 100 == 99 && matches!(e, Error::NoAccess { .. })),
        }
    }
    // Writes larger than max_read are split.
    let data: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    p.write(BASE, &data).unwrap();
    assert_eq!(tp.mock.mem.read().unwrap()[..200_000], data[..]);
}

#[test]
fn read_only_mode() {
    let (h, tp) = start_with(4096, |c| c.read_only = true);
    let c = connect(h.addr(), TOKEN).unwrap();
    let p = c.open(42).unwrap();
    let ro = |r: Result<()>| assert!(matches!(r, Err(Error::Permission(_))), "{r:?}");
    ro(p.write(BASE, &[1]));
    ro(p.alloc(1, Prot::default(), None).map(drop));
    ro(p.free(1, 1));
    ro(p.protect(1, 1, Prot::default()).map(drop));
    ro(p.suspend());
    ro(p.resume());
    assert_eq!(tp.suspends.load(Relaxed), 0);
    assert_eq!(tp.mock.mem.read().unwrap()[0], 0);
    let mut b = [0u8; 4];
    p.read_exact(BASE, &mut b).unwrap();
    assert!(p.regions().is_ok());
}

#[test]
fn concurrent_threads() {
    let (h, tp) = start();
    let c = connect(h.addr(), TOKEN).unwrap();
    let p = c.open(42).unwrap();
    std::thread::scope(|s| {
        for t in 0..8u64 {
            let p = p.clone();
            s.spawn(move || {
                let base = BASE + t * 0x10000;
                for i in 0..300u64 {
                    let v = (t << 32 | i).to_le_bytes();
                    let a = base + (i % 64) * 8;
                    p.write(a, &v).unwrap();
                    assert_eq!(p.read_ptr(a).unwrap(), t << 32 | i);
                    let mut big = vec![0u8; 0x8000];
                    assert_eq!(p.read(base + 0x1000, &mut big).unwrap(), 0x8000);
                }
            });
        }
    });
    let m = tp.mock.mem.read().unwrap();
    for t in 0..8u64 {
        let o = (t * 0x10000) as usize;
        // Last write to slot k was i = 256 + k (k < 44) or 192 + k.
        let k = 3;
        assert_eq!(u64::from_le_bytes(m[o + k * 8..o + k * 8 + 8].try_into().unwrap()), t << 32 | (256 + k as u64));
    }
}

#[test]
fn timeout_and_server_gone() {
    let (h, tp) = start();
    let c = connect(h.addr(), TOKEN).unwrap();
    let p = c.open(42).unwrap();
    tp.delay_ms.store(1500, Relaxed);
    c.set_timeout(Duration::from_millis(200));
    let mut b = [0u8; 8];
    let t = Instant::now();
    let e = p.read(BASE, &mut b).unwrap_err();
    assert!(matches!(&e, Error::Io(io) if io.kind() == ErrorKind::TimedOut), "{e:?}");
    assert!(t.elapsed() < Duration::from_millis(1000));

    // Server goes away mid-request: the caller gets a clear error, not a hang.
    c.set_timeout(Duration::from_secs(30));
    let p2 = p.clone();
    let waiter = std::thread::spawn(move || {
        let mut b = [0u8; 8];
        let t = Instant::now();
        (p2.read(BASE, &mut b), t.elapsed())
    });
    std::thread::sleep(Duration::from_millis(200));
    h.shutdown();
    let (r, dt) = waiter.join().unwrap();
    let e = r.unwrap_err();
    assert!(matches!(&e, Error::Io(io) if io.kind() == ErrorKind::ConnectionAborted), "{e:?}");
    assert!(dt < Duration::from_secs(5), "{dt:?}");
    // Later calls fail fast too.
    assert!(matches!(c.list_processes(), Err(Error::Io(io)) if io.kind() == ErrorKind::ConnectionAborted));
    assert!(!p.is_alive());
}

#[test]
fn connection_limit() {
    let (h, _) = start_with(4096, |c| c.max_connections = 2);
    let a = connect(h.addr(), TOKEN).unwrap();
    let b = connect(h.addr(), TOKEN).unwrap();
    let e = connect(h.addr(), TOKEN).err().unwrap();
    assert!(e.to_string().contains("connection limit (2) reached"), "{e}");
    drop((a, b));
    // Slots free up once the server notices the disconnects.
    let t = Instant::now();
    while connect(h.addr(), TOKEN).is_err() {
        assert!(t.elapsed() < Duration::from_secs(5));
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn oversized_requests_get_errors_not_crashes() {
    let (h, _) = start_with(4096, |c| c.max_read = 4096);
    let mut s = authed(&h);
    s.write_all(&proto::frame(1, op::OPEN, |e| e.u32(42))).unwrap();
    let f = proto::read_frame(&mut s, 1 << 20).unwrap();
    let hd = u32::from_le_bytes(f.body[..4].try_into().unwrap());
    // Batch above the byte budget: an error response, the connection stays.
    s.write_all(&proto::frame(2, op::READ, |e| {
        e.u32(hd);
        e.u32(2);
        e.u64(BASE);
        e.u32(4096);
        e.u64(BASE);
        e.u32(1);
    }))
    .unwrap();
    let f = proto::read_frame(&mut s, 1 << 20).unwrap();
    assert_eq!((f.id, f.op), (2, proto::STATUS_ERR));
    // Unknown handle.
    s.write_all(&proto::frame(3, op::REGIONS, |e| e.u32(999))).unwrap();
    let f = proto::read_frame(&mut s, 1 << 20).unwrap();
    assert_eq!((f.id, f.op), (3, proto::STATUS_ERR));
}

// ------------------------------------------------------------------ release audit regressions

/// Waits up to 5 s for `f`.
fn eventually(what: &str, f: impl Fn() -> bool) {
    let t = Instant::now();
    while !f() {
        assert!(t.elapsed() < Duration::from_secs(5), "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn idle_unauthenticated_connections_cannot_lock_out_clients() {
    let (h, _) = start_with(4096, |c| {
        c.max_connections = 2;
        c.max_pending = 4;
        c.handshake_timeout = Duration::from_secs(60);
    });
    // Far more idle sockets than either budget: the oldest pending ones get dropped.
    let idle: Vec<TcpStream> = (0..40).map(|_| raw(&h)).collect();
    let a = connect(h.addr(), TOKEN).unwrap();
    let b = connect(h.addr(), TOKEN).unwrap();
    assert_eq!(a.list_processes().unwrap().len(), 2);
    assert_eq!(b.list_processes().unwrap().len(), 2);
    drop(idle);
}

#[test]
fn trickling_handshake_gets_one_deadline() {
    let (h, _) = start_with(4096, |c| c.handshake_timeout = Duration::from_millis(400));
    let mut s = raw(&h);
    let mut r = s.try_clone().unwrap();
    let t = Instant::now();
    let reader = std::thread::spawn(move || {
        let mut b = [0u8; 64];
        // Returns when the server closes (EOF or reset), not on our 5 s read timeout.
        while let Ok(n) = r.read(&mut b) {
            if n == 0 {
                break;
            }
        }
        t.elapsed()
    });
    let hello = proto::frame(0, op::HELLO, |e| {
        e.0.extend_from_slice(proto::MAGIC);
        e.u16(proto::VERSION);
        e.0.extend_from_slice(&[7; 32]);
    });
    // One byte every 50 ms: every single read is fast, the whole frame takes 2.4 s.
    for b in hello {
        if reader.is_finished() || s.write_all(&[b]).is_err() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let closed_after = reader.join().unwrap();
    assert!(closed_after < Duration::from_millis(1500), "{closed_after:?}");
}

#[test]
fn disconnect_close_and_shutdown_resume_suspended_targets() {
    let (h, tp) = start();
    let resumes = || tp.resumes.load(Relaxed);
    // Disconnect with two outstanding suspends (three suspends, one resume).
    let c = connect(h.addr(), TOKEN).unwrap();
    let p = c.open(42).unwrap();
    for _ in 0..3 {
        p.suspend().unwrap();
    }
    p.resume().unwrap();
    assert_eq!(resumes(), 1);
    drop((p, c));
    eventually("resume after disconnect", || resumes() == 3);
    // CLOSE of the handle.
    let c = connect(h.addr(), TOKEN).unwrap();
    let p = c.open(42).unwrap();
    p.suspend().unwrap();
    drop(p);
    eventually("resume after close", || resumes() == 4);
    // Server shutdown: done by the time shutdown returns.
    let p = c.open(42).unwrap();
    p.suspend().unwrap();
    h.shutdown();
    assert_eq!(resumes(), 5);
}

#[test]
fn backend_panic_is_an_error_and_frees_the_slot() {
    let (h, _) = start_with(4096, |c| {
        c.max_connections = 1;
        c.workers = 2;
    });
    let c = connect(h.addr(), TOKEN).unwrap();
    let p = c.open(42).unwrap();
    for _ in 0..5 {
        let e = p.alloc(PANIC_SIZE, Prot::default(), None).unwrap_err();
        assert!(e.to_string().contains("internal error"), "{e}");
    }
    assert_eq!(p.threads().unwrap(), [42, 43]);
    drop((p, c));
    eventually("slot freed", || connect(h.addr(), TOKEN).is_ok());
}

#[test]
fn server_wide_handle_cap() {
    let (h, _) = start_with(4096, |c| c.max_total_handles = 3);
    let a = connect(h.addr(), TOKEN).unwrap();
    let b = connect(h.addr(), TOKEN).unwrap();
    let a1 = a.open(42).unwrap();
    let _a2 = a.open(42).unwrap();
    let _b1 = b.open(42).unwrap();
    let e = b.open(42).err().unwrap();
    assert!(e.to_string().contains("on this server"), "{e}");
    // A failed backend open does not use up the budget.
    drop(a1);
    eventually("handle freed", || b.open(42).is_ok());
    assert!(b.open(1).is_err());
}

#[test]
fn failed_auth_is_rate_limited_server_wide() {
    let (h, _) = start(); // auth_delay 100 ms
    let t = Instant::now();
    std::thread::scope(|s| {
        for _ in 0..6 {
            s.spawn(|| assert!(matches!(connect(h.addr(), "wrong-token-guess").err().unwrap(), Error::Permission(_))));
        }
    });
    // Per-connection delays would let all six finish after ~100 ms.
    assert!(t.elapsed() >= Duration::from_millis(550), "{:?}", t.elapsed());
    still_serves(&h);
}

#[test]
fn hh_server_refuses_short_tokens() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_hh-server"))
        .args(["--listen", "127.0.0.1:0", "--token", "short-token"])
        .env_remove("HH_SERVER_TOKEN")
        .output()
        .unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("at least 16 characters"), "{err}");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_hh-server")).args(["--listen", "127.0.0.1:0"]).env("HH_SERVER_TOKEN", "123456789012345").output().unwrap();
    assert!(!out.status.success());
}

// ------------------------------------------------------------------ benchmark

/// `cargo test -p hh-net --release -- --ignored --nocapture bench`
#[test]
#[ignore]
fn bench_throughput() {
    const MEM: usize = 256 << 20;
    const UNIT: usize = 4 << 20;
    let (h, _) = start_with(MEM, |_| {});
    let c = connect(h.addr(), TOKEN).unwrap();
    let p = c.open_remote(42).unwrap();
    let p = Arc::new(p);
    for threads in [1usize, 8] {
        let t = Instant::now();
        let total = Mutex::new(0usize);
        std::thread::scope(|s| {
            for k in 0..threads {
                let (p, total) = (&p, &total);
                s.spawn(move || {
                    let mut buf = vec![0u8; UNIT];
                    let mut n = 0;
                    for pass in 0..2 {
                        let _ = pass;
                        for u in (k..MEM / UNIT).step_by(threads) {
                            n += p.read(BASE + (u * UNIT) as u64, &mut buf).unwrap();
                        }
                    }
                    *total.lock().unwrap() += n;
                });
            }
        });
        let mib = *total.lock().unwrap() as f64 / (1 << 20) as f64;
        println!("sequential 4 MiB reads, {threads} thread(s): {:.0} MiB/s", mib / t.elapsed().as_secs_f64());
    }
    let ranges: Vec<(Addr, usize)> = (0..256).map(|i| (BASE + i * 4096 + 16, 8)).collect();
    let t = Instant::now();
    let mut n = 0;
    while t.elapsed() < Duration::from_secs(2) {
        assert_eq!(p.read_batch(&ranges).unwrap().len(), 256);
        n += 1;
    }
    println!("batches of 256 x 8-byte reads: {:.0} round trips/s", n as f64 / t.elapsed().as_secs_f64());
    let t = Instant::now();
    let mut n = 0;
    let mut b = [0u8; 8];
    while t.elapsed() < Duration::from_secs(1) {
        p.read(BASE, &mut b).unwrap();
        n += 1;
    }
    println!("single 8-byte reads: {:.0} round trips/s", n as f64 / t.elapsed().as_secs_f64());
}
