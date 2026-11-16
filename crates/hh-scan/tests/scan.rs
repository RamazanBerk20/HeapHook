// Hole lists with one range are deliberate.
#![allow(clippy::single_range_in_vec_init)]
use std::ops::Range;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use hh_core::{Addr, Error, Memory, MockProcess, Module, Pid, Process, Prot, Region, RegionKind, Result};
use hh_scan::*;

/// Several regions plus unreadable ranges that can be changed between scans.
struct Fake {
    regions: Vec<(Addr, RwLock<Vec<u8>>, Prot, RegionKind)>,
    holes: Mutex<Vec<Range<Addr>>>,
    suspends: AtomicU32,
    resumes: AtomicU32,
    read_delay: AtomicU64,
    /// Start addresses of regions reported as write-copy pages.
    cow: Vec<Addr>,
    pid: AtomicU32,
    modules: Mutex<Vec<Module>>,
}

const RW: Prot = Prot { r: true, w: true, x: false };
const RX: Prot = Prot { r: true, w: false, x: true };

impl Fake {
    fn new(regions: Vec<(Addr, usize, Prot, RegionKind)>) -> Self {
        Fake {
            regions: regions.into_iter().map(|(a, n, p, k)| (a, RwLock::new(vec![0; n]), p, k)).collect(),
            holes: Mutex::default(),
            suspends: AtomicU32::new(0),
            resumes: AtomicU32::new(0),
            read_delay: AtomicU64::new(0),
            cow: Vec::new(),
            pid: AtomicU32::new(1),
            modules: Mutex::default(),
        }
    }
    fn region(&self, addr: Addr) -> Result<(usize, usize)> {
        for (i, (a, m, _, _)) in self.regions.iter().enumerate() {
            let n = m.read().unwrap().len() as u64;
            if addr >= *a && addr - a < n {
                return Ok((i, (addr - a) as usize));
            }
        }
        Err(Error::NoAccess { addr })
    }
    fn put(&self, addr: Addr, b: &[u8]) {
        self.write(addr, b).unwrap();
    }
}

impl Memory for Fake {
    fn read(&self, addr: Addr, buf: &mut [u8]) -> Result<usize> {
        let d = self.read_delay.load(Relaxed);
        if d > 0 {
            std::thread::sleep(Duration::from_millis(d));
        }
        let holes = self.holes.lock().unwrap();
        if holes.iter().any(|h| h.contains(&addr)) {
            return Err(Error::NoAccess { addr });
        }
        let (i, o) = self.region(addr)?;
        let m = self.regions[i].1.read().unwrap();
        let mut n = buf.len().min(m.len() - o);
        for h in holes.iter().filter(|h| h.start > addr) {
            n = n.min((h.start - addr) as usize);
        }
        buf[..n].copy_from_slice(&m[o..o + n]);
        Ok(n)
    }
    fn write(&self, addr: Addr, data: &[u8]) -> Result<()> {
        let (i, o) = self.region(addr)?;
        let mut m = self.regions[i].1.write().unwrap();
        m.get_mut(o..o + data.len()).ok_or(Error::NoAccess { addr })?.copy_from_slice(data);
        Ok(())
    }
}

impl Process for Fake {
    fn pid(&self) -> Pid {
        self.pid.load(Relaxed)
    }
    fn regions(&self) -> Result<Vec<Region>> {
        Ok(self
            .regions
            .iter()
            .map(|(a, m, p, k)| Region { start: *a, size: m.read().unwrap().len() as u64, prot: *p, kind: *k, shared: false, cow: self.cow.contains(a), path: None })
            .collect())
    }
    fn modules(&self) -> Result<Vec<Module>> {
        Ok(self.modules.lock().unwrap().clone())
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

const A: Addr = 0x10000;
const B: Addr = 0x800000;
const C: Addr = 0x900000;

/// Two rw regions (64 KiB, 9 MiB so it spans several work units) and one rx region.
fn fake() -> Arc<Fake> {
    Arc::new(Fake::new(vec![
        (A, 0x10000, RW, RegionKind::Private),
        (B, 9 << 20, RW, RegionKind::Private),
        (0x2000000, 0x1000, RX, RegionKind::Image),
    ]))
}

fn first(vtype: VType, st: ScanType, v: &str) -> FirstScan {
    FirstScan { vtype, scan_type: st, value: Some(v.into()), value2: None, not: false, opts: ScanOptions::default() }
}

fn next(st: ScanType, v: Option<&str>) -> NextScan {
    NextScan { scan_type: st, value: v.map(Into::into), value2: None, not: false, percent: None }
}

fn addrs(s: &Scanner) -> Vec<Addr> {
    s.results(0, 1 << 20).unwrap().into_iter().map(|r| r.addr).collect()
}

fn scanner(p: &Arc<Fake>) -> Scanner {
    Scanner::new(p.clone())
}

#[test]
fn exact_every_numeric_type() {
    let cases: [(VType, &str, Vec<u8>); 7] = [
        (VType::Byte, "200", vec![200]),
        (VType::Byte, "-56", vec![200]),
        (VType::Bytes2, "-2", (-2i16).to_le_bytes().to_vec()),
        (VType::Bytes4, "123456789", 123456789u32.to_le_bytes().to_vec()),
        (VType::Bytes8, "0x1122334455667788", 0x1122334455667788u64.to_le_bytes().to_vec()),
        (VType::Float, "3.25", 3.25f32.to_le_bytes().to_vec()),
        (VType::Double, "-7.125", (-7.125f64).to_le_bytes().to_vec()),
    ];
    for (vt, v, bytes) in cases {
        let p = fake();
        let at = [A + 0x40, B + 0x10, B + (5 << 20) + 8, 0x2000000 + 0x80];
        for a in at {
            p.put(a, &bytes);
        }
        let s = scanner(&p);
        assert_eq!(s.first_scan(&first(vt, ScanType::Exact, v)).unwrap().count, 4, "{vt:?} {v}");
        assert_eq!(addrs(&s), at, "{vt:?}");
        let r = &s.results(0, 1).unwrap()[0];
        assert_eq!(r.vtype, vt);
        assert_eq!(r.value.as_deref(), Some(r.first.as_str()));
        // `not` inverts: everything aligned except the four hits.
        let mut f = first(vt, ScanType::Exact, v);
        f.not = true;
        f.opts.start = Some(A);
        f.opts.stop = Some(A + 0x100);
        let w = value_size(vt, &Fmt::default()).unwrap().min(4) as u64;
        assert_eq!(s.first_scan(&f).unwrap().count, 0x100 / w - 1, "{vt:?} not");
    }
}

#[test]
fn bigger_smaller_between_signedness_and_hex() {
    let p = fake();
    p.put(A, &[5, 0x80, 0xff, 0x10]);
    let mut f = first(VType::Byte, ScanType::Bigger, "100");
    f.opts.stop = Some(A + 4);
    let s = scanner(&p);
    // Signed (default): 0x80 = -128 and 0xff = -1 are not bigger than 100.
    assert_eq!(s.first_scan(&f).unwrap().count, 0);
    f.opts.signed = false;
    assert_eq!(s.first_scan(&f).unwrap().count, 2);
    f.scan_type = ScanType::Smaller;
    f.value = Some("16".into());
    assert_eq!(addrs(s.tap(|s| s.first_scan(&f).unwrap())), [A]);
    f.opts.hex = true; // "16" = 0x16
    assert_eq!(s.first_scan(&f).unwrap().count, 2);
    f = first(VType::Byte, ScanType::Between, "-1");
    f.value2 = Some("6".into());
    f.opts.stop = Some(A + 4);
    s.first_scan(&f).unwrap();
    assert_eq!(addrs(&s), [A, A + 2]);
    f.opts.signed = false;
    f.value = Some("6".into());
    f.value2 = Some("0".into());
    s.first_scan(&f).unwrap();
    assert_eq!(addrs(&s), [A]);

    p.put(A + 0x100, &2.5f32.to_le_bytes());
    p.put(A + 0x104, &(-2.5f32).to_le_bytes());
    let mut f = first(VType::Float, ScanType::Bigger, "2.4");
    f.opts.start = Some(A + 0x100);
    f.opts.stop = Some(A + 0x108);
    s.first_scan(&f).unwrap();
    assert_eq!(addrs(&s), [A + 0x100]);
    f.scan_type = ScanType::Between;
    f.value = Some("-3".into());
    f.value2 = Some("0".into());
    s.first_scan(&f).unwrap();
    assert_eq!(addrs(&s), [A + 0x104]);
    assert!(s.first_scan(&first(VType::Bytes4, ScanType::Bigger, "x")).is_err());
    assert!(s.first_scan(&first(VType::Bytes4, ScanType::Increased, "1")).is_err());
}

trait Tap: Sized {
    fn tap(&self, f: impl FnOnce(&Self) -> ScanCount) -> &Self {
        f(self);
        self
    }
}
impl Tap for Scanner {}

#[test]
fn float_rounding_modes() {
    let p = fake();
    let vals = [1.44f32, 1.45, 1.5, 1.549, 1.551, 1.41, 1.59, 1.6, 1.39];
    for (i, v) in vals.iter().enumerate() {
        p.put(A + 4 * i as u64, &v.to_le_bytes());
    }
    let s = scanner(&p);
    let mut f = first(VType::Float, ScanType::Exact, "1.5");
    f.opts.stop = Some(A + 4 * vals.len() as u64);
    let found = |s: &Scanner| s.results(0, 100).unwrap().iter().map(|r| r.first.parse::<f32>().unwrap()).collect::<Vec<_>>();
    s.first_scan(&f).unwrap();
    assert_eq!(found(&s), [1.45, 1.5, 1.549]);
    f.opts.rounding = Rounding::Extreme;
    s.first_scan(&f).unwrap();
    assert_eq!(found(&s), [1.44, 1.45, 1.5, 1.549, 1.551, 1.41, 1.59]);
    f.opts.rounding = Rounding::Truncated;
    s.first_scan(&f).unwrap();
    assert_eq!(found(&s), [1.5, 1.549, 1.551, 1.59]);
    f.value = Some("1".into()); // no decimals: rounded = [0.5, 1.5)
    f.opts.rounding = Rounding::Rounded;
    s.first_scan(&f).unwrap();
    assert_eq!(found(&s), [1.44, 1.45, 1.41, 1.39]);
}

#[test]
fn unknown_then_compare_scans_with_undo() {
    let p = fake();
    let a = |i: u64| A + 4 * i;
    for i in 0..8 {
        p.put(a(i), &100i32.to_le_bytes());
    }
    let s = scanner(&p);
    let mut f = first(VType::Bytes4, ScanType::Unknown, "");
    f.value = None;
    f.opts.stop = Some(a(8));
    assert_eq!(s.first_scan(&f).unwrap().count, 8);
    // 0: +5  1: -5  2: +10%  3: -10%  4: same  5: 7  6: -1 (signed decrease)  7: same
    for (i, v) in [(0, 105i32), (1, 95), (2, 110), (3, 90), (5, 7), (6, -1)] {
        p.put(a(i), &v.to_le_bytes());
    }
    let mut n = next(ScanType::Changed, None);
    assert_eq!(s.next_scan(&n).unwrap().count, 6);
    s.undo().unwrap();
    assert_eq!(s.count(), 8);
    assert!(s.undo().is_err(), "one level only");
    n.scan_type = ScanType::Unchanged;
    s.next_scan(&n).unwrap();
    assert_eq!(addrs(&s), [a(4), a(7)]);
    s.undo().unwrap();
    s.next_scan(&next(ScanType::Increased, None)).unwrap();
    assert_eq!(addrs(&s), [a(0), a(2)]);
    s.undo().unwrap();
    s.next_scan(&next(ScanType::Decreased, None)).unwrap();
    assert_eq!(addrs(&s), [a(1), a(3), a(5), a(6)]);
    s.undo().unwrap();
    s.next_scan(&next(ScanType::IncreasedBy, Some("5"))).unwrap();
    assert_eq!(addrs(&s), [a(0)]);
    s.undo().unwrap();
    s.next_scan(&next(ScanType::DecreasedBy, Some("93"))).unwrap();
    assert_eq!(addrs(&s), [a(5)]);
    s.undo().unwrap();
    let mut pct = next(ScanType::IncreasedBy, Some("10"));
    pct.percent = Some(true);
    s.next_scan(&pct).unwrap();
    assert_eq!(addrs(&s), [a(2)]);
    s.undo().unwrap();
    pct.scan_type = ScanType::DecreasedBy;
    s.next_scan(&pct).unwrap();
    assert_eq!(addrs(&s), [a(3)]);
    s.undo().unwrap();
    let mut btw = next(ScanType::Between, Some("90"));
    btw.value2 = Some("105".into());
    btw.percent = Some(true);
    s.next_scan(&btw).unwrap();
    assert_eq!(addrs(&s), [a(0), a(1), a(3), a(4), a(7)]);
    s.undo().unwrap();
    let mut ex = next(ScanType::Exact, Some("100"));
    ex.not = true;
    s.next_scan(&ex).unwrap();
    assert_eq!(addrs(&s), [a(0), a(1), a(2), a(3), a(5), a(6)]);

    // Chain: previous follows each scan, first stays.
    s.new_scan();
    assert_eq!(s.count(), 0);
    p.put(a(0), &100i32.to_le_bytes());
    s.first_scan(&f).unwrap();
    p.put(a(0), &200i32.to_le_bytes());
    s.next_scan(&next(ScanType::Changed, None)).unwrap();
    p.put(a(0), &100i32.to_le_bytes());
    s.next_scan(&next(ScanType::Changed, None)).unwrap();
    let r = &s.results(0, 1).unwrap()[0];
    assert_eq!((r.value.as_deref(), r.previous.as_str(), r.first.as_str()), (Some("100"), "100", "100"));
    s.next_scan(&next(ScanType::SameAsFirst, None)).unwrap();
    assert_eq!(addrs(&s), [a(0)]);
}

#[test]
fn float_next_scans() {
    let p = fake();
    p.put(A, &10.0f64.to_le_bytes());
    p.put(A + 8, &10.0f64.to_le_bytes());
    let s = scanner(&p);
    let mut f = first(VType::Double, ScanType::Unknown, "");
    f.opts.stop = Some(A + 16);
    f.opts.alignment = Some(8);
    s.first_scan(&f).unwrap();
    p.put(A, &12.5f64.to_le_bytes());
    p.put(A + 8, &9.0f64.to_le_bytes());
    s.next_scan(&next(ScanType::IncreasedBy, Some("2.5"))).unwrap();
    assert_eq!(addrs(&s), [A]);
    s.undo().unwrap();
    s.next_scan(&next(ScanType::Decreased, None)).unwrap();
    assert_eq!(addrs(&s), [A + 8]);
    s.undo().unwrap();
    let mut pct = next(ScanType::IncreasedBy, Some("25"));
    pct.percent = Some(true);
    s.next_scan(&pct).unwrap();
    assert_eq!(addrs(&s), [A]);
}

#[test]
fn strings_aob_binary() {
    let p = fake();
    p.put(A + 3, b"Hello world");
    p.put(B + (4 << 20) - 2, b"HELLO"); // spans a work-unit boundary
    p.put(A + 0x200, &[b'h', 0, b'E', 0, b'l', 0, b'L', 0, b'o', 0]);
    let s = scanner(&p);
    s.first_scan(&first(VType::String, ScanType::Exact, "hello")).unwrap();
    assert_eq!(addrs(&s), [A + 3, B + (4 << 20) - 2]);
    assert_eq!(s.results(0, 1).unwrap()[0].value.as_deref(), Some("Hello"));
    let mut f = first(VType::String, ScanType::Exact, "Hello");
    f.opts.case_sensitive = true;
    s.first_scan(&f).unwrap();
    assert_eq!(addrs(&s), [A + 3]);
    f.opts.case_sensitive = false;
    f.opts.utf16 = true;
    s.first_scan(&f).unwrap();
    assert_eq!(addrs(&s), [A + 0x200]);
    assert_eq!(s.results(0, 1).unwrap()[0].value.as_deref(), Some("hElLo"));

    p.put(A + 0x300, &[0xde, 0xad, 0xbe, 0xef]);
    p.put(A + 0x400, &[0xde, 0x11, 0xb0, 0xef]);
    s.first_scan(&first(VType::Aob, ScanType::Exact, "DE ?? B? EF")).unwrap();
    assert_eq!(addrs(&s), [A + 0x300, A + 0x400]);
    assert_eq!(s.results(0, 1).unwrap()[0].value.as_deref(), Some("DE AD BE EF"));
    p.put(A + 0x401, &[0x12]);
    s.next_scan(&next(ScanType::Changed, None)).unwrap();
    assert_eq!(addrs(&s), [A + 0x400]);
    s.undo().unwrap();
    s.next_scan(&next(ScanType::Exact, Some("DE AD ?? ??"))).unwrap();
    assert_eq!(addrs(&s), [A + 0x300]);
    // A value of another length is allowed; it becomes the entries' width.
    s.next_scan(&next(ScanType::Exact, Some("DE"))).unwrap();
    assert_eq!(s.results(0, 1).unwrap()[0].value.as_deref(), Some("DE"));
    assert!(s.next_scan(&next(ScanType::Increased, None)).is_err());

    p.put(A + 0x500, &[0b1011_0110]);
    let mut f = first(VType::Binary, ScanType::Exact, "1?11 0?10");
    f.opts.start = Some(A + 0x4f0);
    f.opts.stop = Some(A + 0x510);
    s.first_scan(&f).unwrap();
    assert_eq!(addrs(&s), [A + 0x500]);
    assert_eq!(s.results(0, 1).unwrap()[0].value.as_deref(), Some("10110110"));
    assert!(s.first_scan(&first(VType::String, ScanType::Unknown, "")).is_err());
}

#[test]
fn all_types_at_once() {
    let p = fake();
    p.put(A + 0x10, &100u32.to_le_bytes());
    p.put(A + 0x20, &100.0f32.to_le_bytes());
    p.put(A + 0x30, &100.25f64.to_le_bytes());
    let s = scanner(&p);
    let mut f = first(VType::All, ScanType::Exact, "100");
    f.opts.stop = Some(A + 0x40);
    s.first_scan(&f).unwrap();
    let rows = s.results(0, 100).unwrap();
    let got: Vec<(Addr, VType)> = rows.iter().map(|r| (r.addr, r.vtype)).collect();
    assert_eq!(got, [(A + 0x10, VType::Bytes4), (A + 0x20, VType::Float), (A + 0x30, VType::Double)]);
    assert_eq!(rows[2].value.as_deref(), Some("100.25"));
    // Next scan per type: only the float changes to 101.
    p.put(A + 0x20, &101.0f32.to_le_bytes());
    s.next_scan(&next(ScanType::Increased, None)).unwrap();
    assert_eq!(addrs(&s), [A + 0x20]);
    s.undo().unwrap();
    s.next_scan(&next(ScanType::Exact, Some("1.5"))).unwrap();
    assert_eq!(s.count(), 0);
    // Unknown initial value for "all".
    f.scan_type = ScanType::Unknown;
    f.opts.alignment = Some(4);
    f.opts.stop = Some(A + 0x10);
    assert_eq!(s.first_scan(&f).unwrap().count, 4);
    p.put(A + 4, &[1]);
    s.next_scan(&next(ScanType::Changed, None)).unwrap();
    let rows = s.results(0, 10).unwrap();
    let got: Vec<_> = rows.iter().map(|r| (r.addr, r.vtype, r.value.as_deref())).collect();
    // The 8-byte value at A covers A+4 too.
    assert_eq!(got, [(A, VType::Bytes8, Some("4294967296")), (A + 4, VType::Bytes4, Some("1"))]);
}

#[test]
fn grouped_scans() {
    let p = fake();
    let put = |a: Addr| {
        p.put(a, &100u32.to_le_bytes());
        p.put(a + 4, &2.5f32.to_le_bytes());
        p.put(a + 12, &8u16.to_le_bytes());
    };
    put(A + 0x100);
    put(B + 0x2000);
    let s = scanner(&p);
    s.first_scan(&first(VType::Grouped, ScanType::Exact, "4:100 f:2.5 w:4 2:8")).unwrap();
    assert_eq!(addrs(&s), [A + 0x100, B + 0x2000]);
    p.put(B + 0x2004, &2.0f32.to_le_bytes());
    s.next_scan(&next(ScanType::Exact, Some("4:100 f:2.5 w:4 2:8"))).unwrap();
    assert_eq!(addrs(&s), [A + 0x100]);
    // Out of order: the first element starts the block, the rest anywhere in it.
    let mut f = first(VType::Grouped, ScanType::Exact, "OOO BS:16 4:100 2:8 f:2.5");
    f.opts.alignment = Some(2);
    f.opts.stop = Some(B);
    s.first_scan(&f).unwrap();
    assert_eq!(addrs(&s), [A + 0x100]);
    assert!(s.first_scan(&first(VType::Grouped, ScanType::Exact, "q:1")).is_err());
}

#[test]
fn holes_and_memory_vanishing_mid_session() {
    let p = fake();
    let at = [B + 0x1000, B + 0x5000, B + 0x9000];
    for a in at {
        p.put(a, &0x5151u32.to_le_bytes());
    }
    *p.holes.lock().unwrap() = vec![(B + 0x4000..B + 0x6000)];
    let s = scanner(&p);
    s.first_scan(&first(VType::Bytes4, ScanType::Exact, "20817")).unwrap();
    assert_eq!(addrs(&s), [at[0], at[2]]);
    // Readable again but the first match vanishes: it drops out, value is null meanwhile.
    *p.holes.lock().unwrap() = vec![(B..B + 0x2000)];
    let r = s.results(0, 10).unwrap();
    assert_eq!((r[0].value.as_deref(), r[1].value.as_deref()), (None, Some("20817")));
    s.next_scan(&next(ScanType::Unchanged, None)).unwrap();
    assert_eq!(addrs(&s), [at[2]]);
    // Unknown scan over a region that loses pages before the next scan.
    *p.holes.lock().unwrap() = vec![];
    let mut f = first(VType::Bytes4, ScanType::Unknown, "");
    f.opts.start = Some(A);
    f.opts.stop = Some(A + 0x10000);
    assert_eq!(s.first_scan(&f).unwrap().count, 0x4000);
    *p.holes.lock().unwrap() = vec![(A + 0x8000..A + 0x9000)];
    assert_eq!(s.next_scan(&next(ScanType::Unchanged, None)).unwrap().count, 0x4000 - 0x400);
}

#[test]
fn ranges_filters_alignment() {
    let p = fake();
    for a in [A + 1, A + 0x10, A + 0x1a8, B + 0x2a8, 0x2000000] {
        p.put(a, &[0x77]);
    }
    let s = scanner(&p);
    let mut f = first(VType::Byte, ScanType::Exact, "119");
    assert_eq!(s.first_scan(&f).unwrap().count, 5);
    f.opts.writable = Tri::No;
    assert_eq!(addrs(s.tap(|s| s.first_scan(&f).unwrap())), [0x2000000]);
    f.opts.writable = Tri::Any;
    f.opts.executable = Tri::No;
    assert_eq!(s.first_scan(&f).unwrap().count, 4);
    f.opts.copy_on_write = Tri::Yes; // only the image region would qualify, and it is not writable
    assert_eq!(s.first_scan(&f).unwrap().count, 0);
    f.opts.copy_on_write = Tri::Any;
    // Only write-copy pages are copy-on-write; writable private image data (.data/.bss) is not.
    let mut fk = Fake::new(vec![
        (A, 0x1000, RW, RegionKind::Image),
        (B, 0x1000, RW, RegionKind::Mapped),
        (C, 0x1000, RW, RegionKind::Private),
    ]);
    fk.cow = vec![B];
    let fk = Arc::new(fk);
    for a in [A, B, C] {
        fk.put(a, &[0x77]);
    }
    let mut g = first(VType::Byte, ScanType::Exact, "119");
    g.opts.copy_on_write = Tri::Yes;
    assert_eq!(addrs(scanner(&fk).tap(|s| s.first_scan(&g).unwrap())), [B]);
    g.opts.copy_on_write = Tri::No;
    assert_eq!(addrs(scanner(&fk).tap(|s| s.first_scan(&g).unwrap())), [A, C]);
    g.opts.copy_on_write = Tri::Any;
    assert_eq!(addrs(scanner(&fk).tap(|s| s.first_scan(&g).unwrap())), [A, B, C]);
    f.opts.alignment = Some(8);
    assert_eq!(addrs(s.tap(|s| s.first_scan(&f).unwrap())), [A + 0x10, A + 0x1a8, B + 0x2a8]);
    f.opts.last_digits = Some("A8".into());
    assert_eq!(addrs(s.tap(|s| s.first_scan(&f).unwrap())), [A + 0x1a8, B + 0x2a8]);
    f.opts.last_digits = None;
    f.opts.alignment = None;
    f.opts.start = Some(A + 2);
    f.opts.stop = Some(B + 0x2a8);
    assert_eq!(addrs(s.tap(|s| s.first_scan(&f).unwrap())), [A + 0x10, A + 0x1a8]);
    f.opts.pause_while_scanning = true;
    s.first_scan(&f).unwrap();
    assert_eq!((p.suspends.load(Relaxed), p.resumes.load(Relaxed)), (1, 1));
}

#[test]
fn paging_and_spill_to_disk() {
    let p = fake();
    let s = scanner(&p);
    s.set_memory_limit(0);
    let mut f = first(VType::Bytes4, ScanType::Unknown, "");
    f.value = None;
    assert_eq!(s.first_scan(&f).unwrap().count, (0x10000 + (9 << 20) + 0x1000) / 4);
    assert!(s.spilled_bytes() > 9 << 20);
    let page = s.results(0x4000 - 2, 4).unwrap();
    assert_eq!(page.iter().map(|r| r.addr).collect::<Vec<_>>(), [A + 0xfff8, A + 0xfffc, B, B + 4]);
    p.put(B + 0x123450, &9i32.to_le_bytes());
    p.put(B + 0x823450, &9i32.to_le_bytes());
    assert_eq!(s.next_scan(&next(ScanType::Changed, None)).unwrap().count, 2);
    let r = s.results(1, 10).unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!((r[0].addr, r[0].value.as_deref(), r[0].previous.as_str(), r[0].first.as_str()), (B + 0x823450, Some("9"), "9", "0"));
    assert!(s.results(5, 10).unwrap().is_empty());
}

#[test]
fn cancel_from_another_thread() {
    let p = fake();
    p.put(A, &1u32.to_le_bytes());
    let s = Arc::new(scanner(&p));
    s.first_scan(&first(VType::Bytes4, ScanType::Exact, "1")).unwrap();
    p.read_delay.store(200, Relaxed);
    let s2 = s.clone();
    let t = std::thread::spawn(move || s2.first_scan(&first(VType::Bytes4, ScanType::Exact, "7")));
    let t0 = Instant::now();
    while !s.progress().running {
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(addrs(&s), [A], "results show the last completed scan while scanning");
    s.cancel();
    let r = t.join().unwrap();
    assert!(r.is_err(), "cancelled scan must fail");
    assert!(t0.elapsed() < Duration::from_secs(2));
    assert!(!s.progress().running);
    p.read_delay.store(0, Relaxed);
    assert_eq!(addrs(&s), [A], "previous results survive a cancelled scan");
}

#[test]
fn progress_counts() {
    let p = fake();
    p.put(B + 4, &[1]);
    let s = scanner(&p);
    s.first_scan(&first(VType::Byte, ScanType::Exact, "1")).unwrap();
    let pr = s.progress();
    assert_eq!((pr.done, pr.total, pr.found, pr.running), (pr.total, 0x10000 + (9 << 20) + 0x1000, 1, false));
}

#[test]
fn freezer_modes() {
    let p = Arc::new(MockProcess::new(0x1000, vec![0; 64]));
    let fz = Freezer::new(p.clone()).unwrap();
    fz.set_interval(Duration::from_millis(5));
    let e = |addr: Addr, v: &str, mode| FrozenEntry { addr, vtype: VType::Bytes4, value: v.into(), mode, fmt: Fmt { signed: true, ..Fmt::default() } };
    fz.set(&[e(0x1000, "50", FreezeMode::Exact), e(0x1004, "50", FreezeMode::AllowIncrease), e(0x1008, "50", FreezeMode::AllowDecrease)]).unwrap();
    let rd = |a: Addr| {
        let mut b = [0u8; 4];
        p.read_exact(a, &mut b).unwrap();
        i32::from_le_bytes(b)
    };
    let settle = || std::thread::sleep(Duration::from_millis(60));
    settle();
    assert_eq!((rd(0x1000), rd(0x1004), rd(0x1008)), (50, 50, 50));
    for a in [0x1000, 0x1004, 0x1008] {
        p.write(a, &60i32.to_le_bytes()).unwrap();
    }
    settle();
    assert_eq!((rd(0x1000), rd(0x1004), rd(0x1008)), (50, 60, 50));
    for a in [0x1000, 0x1004, 0x1008] {
        p.write(a, &40i32.to_le_bytes()).unwrap();
    }
    settle();
    assert_eq!((rd(0x1000), rd(0x1004), rd(0x1008)), (50, 60, 40));
    // Re-sending the same entry keeps its grown value instead of rewriting 50.
    fz.set(&[e(0x1004, "50", FreezeMode::AllowIncrease)]).unwrap();
    settle();
    assert_eq!(rd(0x1004), 60);
    assert!(fz.set(&[e(0x1000, "nope", FreezeMode::Exact)]).is_err());
    fz.set(&[]).unwrap();
    p.write(0x1000, &1i32.to_le_bytes()).unwrap();
    settle();
    assert_eq!(rd(0x1000), 1);
    drop(fz); // joins the thread
}

#[test]
fn read_write_values() {
    let p = MockProcess::new(0x1000, vec![0; 32]);
    write_value(&p, 0x1000, VType::Bytes4, "-2", &Fmt::default()).unwrap();
    write_value(&p, 0x1008, VType::String, "abc", &Fmt::default()).unwrap();
    let refs: Vec<ValueRef> = serde_json::from_str(
        r#"[{"addr":"0x1000","vtype":"4bytes","signed":true},{"addr":"0x1000","vtype":"4bytes","hex":true},
            {"addr":"0x1008","vtype":"string","len":3},{"addr":"0x101e","vtype":"4bytes"},
            {"addr":"0x101e","vtype":"string","len":8},{"addr":"0x1000","vtype":"aob","len":2}]"#,
    )
    .unwrap();
    let v = read_values(&p, &refs);
    assert_eq!(v, [Some("-2".into()), Some("FFFFFFFE".into()), Some("abc".into()), None, Some("".into()), Some("FE FF".into())]);
    assert!(write_value(&p, 0x1000, VType::Byte, "300", &Fmt::default()).is_err());
}

#[test]
fn serde_names_match_contract() {
    let f: FirstScan = serde_json::from_str(
        r#"{"vtype":"2bytes","scan_type":"same_as_first","value":"1","not":true,
            "opts":{"start":"0x1000","stop":4096,"writable":"yes","executable":"no","copy_on_write":"any",
                    "alignment":4,"hex":true,"case_sensitive":false,"utf16":true,"rounding":"extreme",
                    "percent":true,"pause_while_scanning":true}}"#,
    )
    .unwrap();
    assert_eq!((f.vtype, f.scan_type, f.opts.start, f.opts.stop, f.opts.writable), (VType::Bytes2, ScanType::SameAsFirst, Some(0x1000), Some(4096), Tri::Yes));
    assert!(f.opts.signed, "signed defaults on");
    let n: NextScan = serde_json::from_str(r#"{"scan_type":"increased_by","value":"5"}"#).unwrap();
    assert_eq!(n.scan_type, ScanType::IncreasedBy);
    let row = ResultRow { addr: 0x7ffd12340000, vtype: VType::Float, value: None, previous: "1".into(), first: "2".into(), bit: None };
    assert_eq!(
        serde_json::to_string(&row).unwrap(),
        r#"{"addr":"0x7ffd12340000","vtype":"float","value":null,"previous":"1","first":"2"}"#
    );
    let e: FrozenEntry = serde_json::from_str(r#"{"addr":"0x10","vtype":"double","value":"1.5","mode":"allow_decrease"}"#).unwrap();
    assert_eq!(e.mode, FreezeMode::AllowDecrease);
    assert_eq!(serde_json::to_string(&ScanProgress::default()).unwrap(), r#"{"done":0,"total":0,"found":0,"running":false}"#);
    for (v, s) in [(VType::Bytes8, "\"8bytes\""), (VType::Aob, "\"aob\""), (VType::Grouped, "\"grouped\"")] {
        assert_eq!(serde_json::to_string(&v).unwrap(), s);
    }
}

/// `cargo test -p hh-scan --release -- --ignored --nocapture throughput`
/// (prefix `RAYON_NUM_THREADS=1` for per-core numbers; many threads hit memory bandwidth).
#[test]
#[ignore]
fn throughput() {
    const GIB: usize = 1 << 30;
    let mut mem = vec![0u8; GIB];
    let mut x = 0x9e3779b97f4a7c15u64;
    for c in mem.chunks_exact_mut(8) {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        c.copy_from_slice(&x.to_le_bytes());
    }
    mem[0x1234_5678..0x1234_567c].copy_from_slice(&0xdeadbeefu32.to_le_bytes());
    let p = Arc::new(MockProcess::new(0x10000, mem));
    let s = Scanner::new(p);
    let threads = rayon::current_num_threads();
    for (name, f) in [
        ("exact 4-byte aligned", first(VType::Bytes4, ScanType::Exact, "3735928559")),
        ("exact 4-byte unaligned", FirstScan { opts: ScanOptions { alignment: Some(1), ..ScanOptions::default() }, ..first(VType::Bytes4, ScanType::Exact, "3735928559") }),
        ("exact float", first(VType::Float, ScanType::Exact, "1.5")),
        ("aob", first(VType::Aob, ScanType::Exact, "EF BE AD DE")),
        ("unknown 4-byte", first(VType::Bytes4, ScanType::Unknown, "")),
    ] {
        let t = Instant::now();
        let n = s.first_scan(&f).unwrap().count;
        let dt = t.elapsed().as_secs_f64();
        println!("{name:24} {n:>10} hits  {dt:.3}s  {:.2} GiB/s on {threads} threads", 1.0 / dt);
        if name == "unknown 4-byte" {
            let t = Instant::now();
            let n = s.next_scan(&next(ScanType::Unchanged, None)).unwrap().count;
            println!("{:24} {n:>10} hits  {:.3}s  spilled {} MiB", "next unchanged", t.elapsed().as_secs_f64(), s.spilled_bytes() >> 20);
        }
    }
}

fn next_vs(st: ScanType, v: Option<&str>, vs: &str) -> NextScanEx {
    NextScanEx { scan: next(st, v), compare_to: Some(vs.into()) }
}

fn rows(s: &Scanner) -> Vec<(Addr, Option<String>, String, String)> {
    s.results(0, 1 << 20).unwrap().into_iter().map(|r| (r.addr, r.value, r.previous, r.first)).collect()
}

#[test]
fn dense_results_stay_small_and_correct() {
    let p = fake();
    let s = scanner(&p);
    s.set_memory_limit(0); // everything on disk
    let mut f = first(VType::Bytes4, ScanType::Unknown, "");
    f.value = None;
    let total = (0x10000 + (9 << 20) + 0x1000) / 4;
    assert_eq!(s.first_scan(&f).unwrap().count, total);
    let snap = s.spilled_bytes();
    // Unchanged keeps the snapshot: only bitmaps are added.
    p.put(B + 0x100, &5u32.to_le_bytes());
    assert_eq!(s.next_scan(&next(ScanType::Unchanged, None)).unwrap().count, total - 1);
    assert!(s.spilled_bytes() < snap + snap / 16, "{} vs {snap}", s.spilled_bytes());
    // A changed scan of a dense set where most values change stays dense (copy + bitmap).
    for i in 0..0x4000u64 {
        p.put(A + 4 * i, &(i as u32 + 1).to_le_bytes());
    }
    p.put(A + 0x40, &0u32.to_le_bytes()); // back to its first value
    assert_eq!(s.next_scan(&next(ScanType::Changed, None)).unwrap().count, 0x4000 - 1);
    let r = s.results(0x10, 2).unwrap();
    assert_eq!((r[0].addr, r[0].value.as_deref(), r[0].previous.as_str(), r[0].first.as_str()), (A + 0x44, Some("18"), "18", "0"));
    assert_eq!(r[1].addr, A + 0x48);
    // Paging over the bitmap, then a sparse result packs.
    assert_eq!(s.results(0x3ffe, 5).unwrap().iter().map(|r| r.addr).collect::<Vec<_>>(), [A + 0xfffc]);
    p.put(A + 0x80, &77u32.to_le_bytes());
    s.next_scan(&next(ScanType::Changed, None)).unwrap();
    assert_eq!(rows(&s), [(A + 0x80, Some("77".into()), "77".into(), "0".into())]);
    s.undo().unwrap();
    assert_eq!(s.count(), 0x4000 - 1);
    // Same as first on a dense chunk compares with the shared first snapshot.
    s.next_scan(&next(ScanType::SameAsFirst, None)).unwrap();
    assert_eq!(s.count(), 0);

    // "All" sets keep a type mask byte per position.
    let mut f = first(VType::All, ScanType::Unknown, "");
    f.opts.alignment = Some(4);
    f.opts.stop = Some(A + 0x100);
    f.opts.all_types = vec![VType::Bytes8, VType::Bytes2];
    assert_eq!(s.first_scan(&f).unwrap().count, 0x40);
    p.put(A + 0x10, &1u8.to_le_bytes());
    assert_eq!(s.next_scan(&next(ScanType::Unchanged, None)).unwrap().count, 0x40 - 1);
    let r = s.results(0, 100).unwrap();
    assert_eq!((r[2].addr, r[2].vtype), (A + 8, VType::Bytes8));
    assert_eq!((r[3].addr, r[3].vtype), (A + 0xc, VType::Bytes2), "A+0xc lost its 8-byte bit");
    assert_eq!((r[4].addr, r[4].vtype), (A + 0x14, VType::Bytes8));
}

#[test]
fn saved_scans() {
    let p = fake();
    let a = |i: u64| A + 4 * i;
    for i in 0..4 {
        p.put(a(i), &100u32.to_le_bytes());
    }
    let s = scanner(&p);
    let mut f = first(VType::Bytes4, ScanType::Unknown, "");
    f.opts.stop = Some(a(4));
    s.first_scan(&f).unwrap();
    assert!(s.save_scan("first").is_err() && s.save_scan(" ").is_err());
    s.save_scan("start").unwrap();
    p.put(a(0), &150u32.to_le_bytes());
    p.put(a(1), &50u32.to_le_bytes());
    s.next_scan(&next(ScanType::Changed, None)).unwrap();
    s.save_scan("hp").unwrap();
    assert_eq!(s.saved_scans(), ["hp", "start"]);
    p.put(a(0), &160u32.to_le_bytes());
    p.put(a(1), &100u32.to_le_bytes());
    // Against the previous scan both changed; against "start", a(1) is back where it was.
    assert_eq!(s.next_scan_ex(&next_vs(ScanType::Unchanged, None, "start")).unwrap().count, 1);
    assert_eq!(addrs(&s), [a(1)]);
    s.undo().unwrap();
    s.next_scan_ex(&next_vs(ScanType::IncreasedBy, Some("60"), "start")).unwrap();
    assert_eq!(addrs(&s), [a(0)]);
    s.undo().unwrap();
    s.next_scan_ex(&next_vs(ScanType::Increased, None, "hp")).unwrap();
    assert_eq!(addrs(&s), [a(0), a(1)]);
    s.undo().unwrap();
    s.next_scan_ex(&next_vs(ScanType::Decreased, None, "first")).unwrap();
    assert_eq!(addrs(&s), [] as [Addr; 0]);
    s.undo().unwrap();
    // Entries missing from the saved scan drop out.
    s.next_scan(&next(ScanType::Changed, None)).unwrap(); // previous was 150/50: both changed
    s.next_scan(&next(ScanType::Exact, Some("160"))).unwrap();
    s.save_scan("one").unwrap();
    s.undo().unwrap();
    assert_eq!(s.next_scan_ex(&next_vs(ScanType::Unchanged, None, "one")).unwrap().count, 1);
    assert!(s.next_scan_ex(&next_vs(ScanType::Changed, None, "nope")).is_err());
    s.delete_saved_scan("hp").unwrap();
    assert!(s.delete_saved_scan("hp").is_err());
    // A saved scan of another type cannot be compared against.
    s.save_scan("ints").unwrap();
    let mut g = first(VType::Float, ScanType::Unknown, "");
    g.opts.stop = Some(a(4));
    s.first_scan(&g).unwrap();
    assert!(s.saved_scans().is_empty(), "a first scan drops saved scans");
    s.save_scan("floats").unwrap();
    s.new_scan();
    assert!(s.saved_scans().is_empty());
    let n: NextScanEx = serde_json::from_str(r#"{"scan_type":"unchanged","compare_to":"x"}"#).unwrap();
    assert_eq!((n.scan.scan_type, n.compare_to.as_deref()), (ScanType::Unchanged, Some("x")));
    let n: NextScanEx = serde_json::from_str(r#"{"scan_type":"exact","value":"1"}"#).unwrap();
    assert_eq!((n.scan.value.as_deref(), n.compare_to), (Some("1"), None));
}

#[test]
fn byte_like_next_scans() {
    let p = fake();
    p.put(A + 0x10, b"hello world");
    p.put(A + 0x40, b"hello there");
    let s = scanner(&p);
    s.first_scan(&first(VType::String, ScanType::Exact, "hello")).unwrap();
    s.save_scan("hello").unwrap();
    p.put(A + 0x40, b"Jello");
    s.next_scan(&next(ScanType::Changed, None)).unwrap();
    assert_eq!(rows(&s), [(A + 0x40, Some("Jello".into()), "Jello".into(), "hello".into())]);
    s.undo().unwrap();
    s.next_scan(&next(ScanType::Unchanged, None)).unwrap();
    assert_eq!(addrs(&s), [A + 0x10]);
    s.undo().unwrap();
    p.put(A + 0x40, b"hello");
    s.next_scan(&next(ScanType::SameAsFirst, None)).unwrap();
    assert_eq!(addrs(&s), [A + 0x10, A + 0x40]);
    // A longer exact value, then changed/unchanged on the new length.
    s.next_scan(&next(ScanType::Exact, Some("hello world"))).unwrap();
    assert_eq!(addrs(&s), [A + 0x10]);
    p.put(A + 0x1a, b"D");
    s.next_scan(&next(ScanType::Changed, None)).unwrap();
    assert_eq!(addrs(&s), [A + 0x10]);
    s.undo().unwrap();
    s.undo().unwrap_err();
    assert!(s.next_scan(&next(ScanType::Increased, None)).is_err());
    let mut n = next(ScanType::Exact, Some("HELLO"));
    n.not = true;
    s.next_scan(&n).unwrap();
    assert_eq!(s.count(), 0);

    // Groups: changed / unchanged over the whole group.
    let put = |a: Addr, v: u32| {
        p.put(a, &v.to_le_bytes());
        p.put(a + 4, &2.5f32.to_le_bytes());
    };
    put(A + 0x100, 7);
    put(A + 0x200, 7);
    s.first_scan(&first(VType::Grouped, ScanType::Exact, "4:7 f:2.5")).unwrap();
    p.put(A + 0x204, &3.5f32.to_le_bytes());
    s.next_scan(&next(ScanType::Unchanged, None)).unwrap();
    assert_eq!(addrs(&s), [A + 0x100]);
    s.undo().unwrap();
    s.next_scan(&next(ScanType::Changed, None)).unwrap();
    assert_eq!(addrs(&s), [A + 0x200]);
    s.undo().unwrap();
    s.next_scan(&next(ScanType::Exact, Some("4:7 f:3.5"))).unwrap();
    assert_eq!(addrs(&s), [A + 0x200]);
    assert!(s.next_scan(&next(ScanType::Decreased, None)).is_err());
}

#[test]
fn binary_bits_and_decimal() {
    let p = fake();
    p.put(A + 0x20, &[0b1011_0000, 0b0000_0001]); // "1 1011" at bit 4 of A+0x20
    let s = scanner(&p);
    let mut f = first(VType::Binary, ScanType::Exact, "11011");
    f.opts.start = Some(A);
    f.opts.stop = Some(A + 0x100);
    s.first_scan(&f).unwrap();
    let r = s.results(0, 10).unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!((r[0].addr, r[0].bit, r[0].value.as_deref()), (A + 0x20, Some(4), Some("11011")));
    assert_eq!(serde_json::to_value(&r[0]).unwrap()["bit"], 4);
    // Decimal entry: 27 = 11011.
    f.opts.binary_decimal = true;
    f.value = Some("27".into());
    assert_eq!(addrs(s.tap(|s| s.first_scan(&f).unwrap())), [A + 0x20]);
    // A fixed start bit, and zero-extension to a bit length (leading zeros must match).
    f.opts.bit_start = Some(3);
    assert_eq!(s.first_scan(&f).unwrap().count, 0);
    f.opts.bit_start = Some(4);
    assert_eq!(s.first_scan(&f).unwrap().count, 1);
    f.opts.bit_len = Some(8); // 00011011 at bit 4 spans into A+0x21, whose bits 1..3 are 0
    assert_eq!(addrs(s.tap(|s| s.first_scan(&f).unwrap())), [A + 0x20]);
    assert_eq!(s.results(0, 1).unwrap()[0].value.as_deref(), Some("00011011"));
    f.opts.bit_len = Some(3);
    assert!(s.first_scan(&f).is_err(), "27 does not fit in 3 bits");
    // Next scans per bit field.
    f.opts.bit_len = None;
    f.opts.bit_start = None;
    s.first_scan(&f).unwrap();
    p.put(A + 0x20, &[0b0000_0000]); // other bits change: still unchanged? no, the field lost bits
    s.next_scan(&next(ScanType::Changed, None)).unwrap();
    assert_eq!(s.count(), 1);
    s.undo().unwrap();
    p.put(A + 0x20, &[0b1011_1111]); // only bits outside the field (0..3) changed
    s.next_scan(&next(ScanType::Unchanged, None)).unwrap();
    assert_eq!(s.count(), 1);
    s.next_scan(&next(ScanType::Exact, Some("27"))).unwrap();
    assert_eq!(s.count(), 1);
}

#[test]
fn custom_types() {
    let p = fake();
    let be4 = CustomType::preset("4 Byte Big Endian").unwrap();
    p.put(A + 0x10, &1000u32.to_be_bytes());
    p.put(A + 0x20, &[0x40, 0x42, 0x0f]); // 3-byte LE 1000000
    p.put(A + 0x30, &1234i32.to_le_bytes()); // fixed point 12.34
    p.put(A + 0x40, &(1.5f32).to_be_bytes());
    let s = scanner(&p);
    let scan = |ct: CustomType, st: ScanType, v: &str| {
        let mut f = first(VType::Bytes4, st, v);
        f.opts.custom = Some(ct);
        f.opts.stop = Some(A + 0x100);
        f.opts.alignment = Some(1);
        s.first_scan(&f).unwrap();
        addrs(&s)
    };
    assert_eq!(scan(be4, ScanType::Exact, "1000"), [A + 0x10]);
    assert_eq!(s.results(0, 1).unwrap()[0].value.as_deref(), Some("1000"));
    assert_eq!(scan(CustomType::int(3, false), ScanType::Exact, "1000000"), [A + 0x20]);
    let fixed = CustomType { scale: 0.01, signed: true, ..CustomType::int(4, true) };
    assert_eq!(scan(fixed, ScanType::Exact, "12.34"), [A + 0x30]);
    assert_eq!(s.results(0, 1).unwrap()[0].value.as_deref(), Some("12.34"));
    let mut f = first(VType::Float, ScanType::Bigger, "1.4");
    f.opts.custom = CustomType::preset("float big endian");
    f.opts.alignment = Some(16);
    f.opts.stop = Some(A + 0x100);
    s.first_scan(&f).unwrap();
    assert_eq!(addrs(&s), [A + 0x20, A + 0x40], "40 42 0F 00 is 3.03 as a big-endian float");
    let mut f = first(VType::Float, ScanType::Exact, "1.5");
    f.opts.custom = CustomType::preset("float big endian");
    f.opts.stop = Some(A + 0x100);
    s.first_scan(&f).unwrap();
    assert_eq!(addrs(&s), [A + 0x40]);
    // Unknown + next scans with a custom type.
    let mut u = first(VType::Bytes4, ScanType::Unknown, "");
    u.opts.custom = Some(fixed);
    u.opts.stop = Some(A + 0x40);
    s.first_scan(&u).unwrap();
    p.put(A + 0x30, &1300i32.to_le_bytes());
    s.next_scan(&next(ScanType::IncreasedBy, Some("0.66"))).unwrap();
    assert_eq!(rows(&s), [(A + 0x30, Some("13".into()), "13".into(), "12.34".into())]);

    // read / write / freeze, bit fields keep their neighbours.
    let m = MockProcess::new(0x1000, vec![0xff; 16]);
    let nib = CustomType { bit_start: 4, bit_len: 4, ..CustomType::int(1, false) };
    write_custom(&m, 0x1000, &nib, "3", &Fmt::default()).unwrap();
    write_custom(&m, 0x1004, &be4, "0x01020304", &Fmt::default()).unwrap();
    assert!(write_custom(&m, 0x1000, &nib, "16", &Fmt::default()).is_err());
    let refs: Vec<ValueRefEx> = serde_json::from_str(
        r#"[{"addr":"0x1000","vtype":"byte"},{"addr":"0x1000","vtype":"byte","custom":{"size":1,"bit_start":4,"bit_len":4}},
            {"addr":"0x1004","vtype":"4bytes","hex":true,"custom":{"size":4,"big_endian":true}},
            {"addr":"0x1000","vtype":"byte","custom":{"size":1,"bit_start":4,"bit_len":4,"binary":true}}]"#,
    )
    .unwrap();
    assert_eq!(read_values_ex(&m, &refs), [Some("63".into()), Some("3".into()), Some("1020304".into()), Some("0011".into())]);
    assert!(serde_json::from_str::<CustomType>(r#"{"size":9}"#).unwrap().validate().is_err());
    assert_eq!(serde_json::from_str::<CustomType>(r#"{"size":2}"#).unwrap(), CustomType::int(2, false));
    let m = Arc::new(m);
    let fz = Freezer::new(m.clone()).unwrap();
    fz.set_interval(Duration::from_millis(5));
    let e: FrozenEntryEx = serde_json::from_str(
        r#"{"addr":"0x1000","vtype":"byte","value":"5","mode":"allow_increase","custom":{"size":1,"bit_start":4,"bit_len":4}}"#,
    )
    .unwrap();
    fz.set_ex(&[e]).unwrap();
    std::thread::sleep(Duration::from_millis(60));
    let rd = || {
        let mut b = [0u8; 1];
        m.read_exact(0x1000, &mut b).unwrap();
        b[0]
    };
    assert_eq!(rd(), 0x5f);
    m.write(0x1000, &[0x20]).unwrap(); // field dropped to 2, low bits cleared
    std::thread::sleep(Duration::from_millis(60));
    assert_eq!(rd(), 0x50, "field restored, other bits kept");
    m.write(0x1000, &[0x93]).unwrap(); // field grew to 9: allowed
    std::thread::sleep(Duration::from_millis(60));
    assert_eq!(rd(), 0x93);
}

#[test]
fn all_type_selection_and_strings() {
    let p = fake();
    p.put(A + 0x10, &100u32.to_le_bytes());
    p.put(A + 0x20, &100.0f32.to_le_bytes());
    p.put(A + 0x30, b"100");
    let s = scanner(&p);
    let mut f = first(VType::All, ScanType::Exact, "100");
    f.opts.stop = Some(A + 0x40);
    f.opts.all_types = vec![VType::Float, VType::String];
    s.first_scan(&f).unwrap();
    let got: Vec<(Addr, VType, Option<String>)> = s.results(0, 10).unwrap().into_iter().map(|r| (r.addr, r.vtype, r.value)).collect();
    assert_eq!(got, [(A + 0x20, VType::Float, Some("100".into())), (A + 0x30, VType::String, Some("100".into()))]);
    p.put(A + 0x30, b"101");
    s.next_scan(&next(ScanType::Changed, None)).unwrap();
    assert_eq!(addrs(&s), [A + 0x30]);
    s.undo().unwrap();
    s.next_scan(&next(ScanType::Exact, Some("101"))).unwrap();
    assert_eq!(addrs(&s), [A + 0x30]);
    // Only bytes: the 4-byte 100 shows up as a byte.
    f.opts.all_types = vec![VType::Byte];
    s.first_scan(&f).unwrap();
    assert_eq!(s.results(0, 10).unwrap().iter().map(|r| (r.addr, r.vtype)).collect::<Vec<_>>(), [(A + 0x10, VType::Byte)]);
    f.scan_type = ScanType::Unknown;
    f.opts.all_types = vec![VType::Bytes2];
    f.opts.stop = Some(A + 8);
    f.opts.alignment = Some(2);
    s.first_scan(&f).unwrap();
    assert!(s.results(0, 10).unwrap().iter().all(|r| r.vtype == VType::Bytes2));
    f.opts.all_types = vec![VType::String];
    assert!(s.first_scan(&f).is_err(), "unknown needs a numeric type");
}

#[test]
fn threads_priority_pause_and_fine_cancel() {
    let p = fake();
    p.put(B + 0x123458, &0x77u32.to_le_bytes());
    let s = Arc::new(scanner(&p));
    let mut f = first(VType::Bytes4, ScanType::Exact, "119");
    f.opts.threads = Some(2);
    f.opts.priority = Priority::Low;
    assert_eq!(addrs(s.tap(|s| s.first_scan(&f).unwrap())), [B + 0x123458]);
    f.opts.threads = Some(0);
    assert!(s.first_scan(&f).is_err());
    f.opts.threads = Some(1);
    f.opts.priority = Priority::Idle;
    s.first_scan(&f).unwrap();
    s.next_scan(&next(ScanType::Unchanged, None)).unwrap();
    assert_eq!(s.count(), 1);

    // A slow predicate (out-of-order group over a big block) inside one 4 MiB unit.
    let slow = || {
        let mut g = first(VType::Grouped, ScanType::Exact, "OOO BS:256 4:0 4:2");
        g.opts.start = Some(B);
        g.opts.stop = Some(B + (4 << 20));
        g.opts.threads = Some(1);
        g
    };
    let run = |s: &Arc<Scanner>| {
        let s2 = s.clone();
        let t = std::thread::spawn(move || s2.first_scan(&slow()));
        while !(s.progress().running && s.progress().done > 0) {
            std::thread::sleep(Duration::from_millis(1));
        }
        t
    };
    let t = run(&s);
    assert_eq!(addrs(&s), [B + 0x123458], "results show the previous set meanwhile");
    s.pause();
    assert!(s.progress().paused && s.progress().running);
    // The one in-flight unit may still finish (well over 400 ms on a loaded CI runner).
    let d0 = s.progress().done;
    let t0 = Instant::now();
    while s.progress().done == d0 && t0.elapsed() < Duration::from_secs(3) {
        std::thread::sleep(Duration::from_millis(5));
    }
    let d = s.progress().done;
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(s.progress().done, d, "paused");
    s.resume();
    let t0 = Instant::now();
    while s.progress().done == d {
        std::thread::sleep(Duration::from_millis(1));
        assert!(t0.elapsed() < Duration::from_secs(5));
    }
    let t0 = Instant::now();
    s.cancel();
    assert!(t.join().unwrap().is_err());
    assert!(t0.elapsed() < Duration::from_secs(2), "cancel inside a unit: {:?}", t0.elapsed());
    // Cancel also ends a paused scan.
    let t = run(&s);
    s.pause();
    s.cancel();
    assert!(t.join().unwrap().is_err());
    assert!(!s.progress().running && !s.progress().paused);
    assert_eq!(addrs(&s), [B + 0x123458]);
    assert!(!serde_json::to_string(&s.progress()).unwrap().contains("paused"));
}

#[test]
fn percent_semantics() {
    let p = fake();
    let a = |i: u64| A + 4 * i;
    let start = [100i32, -100, 15, 15, 100, 100];
    for (i, v) in start.iter().enumerate() {
        p.put(a(i as u64), &v.to_le_bytes());
    }
    let s = scanner(&p);
    let mut f = first(VType::Bytes4, ScanType::Unknown, "");
    f.opts.stop = Some(a(start.len() as u64));
    s.first_scan(&f).unwrap();
    // -100 increased by 10% is -90; 15 + 10% rounds to 16 or 17; 109 is not 110.
    for (i, v) in [(0, 110i32), (1, -90), (2, 16), (3, 17), (4, 109), (5, 111)] {
        p.put(a(i), &v.to_le_bytes());
    }
    let mut n = next(ScanType::IncreasedBy, Some("10"));
    n.percent = Some(true);
    s.next_scan(&n).unwrap();
    assert_eq!(addrs(&s), [a(0), a(1), a(2), a(3)]);
    s.undo().unwrap();
    n.value2 = Some("11".into()); // range 10%..11%: inclusive, no rounding
    s.next_scan(&n).unwrap();
    assert_eq!(addrs(&s), [a(0), a(1), a(5)]);
    // Floats: the typed percentage is rounded like an exact float value.
    let mut g = first(VType::Double, ScanType::Unknown, "");
    g.opts.alignment = Some(8);
    g.opts.stop = Some(A + 24);
    for (i, v) in [10.0f64, -10.0, 10.0].iter().enumerate() {
        p.put(A + 8 * i as u64, &v.to_le_bytes());
    }
    s.first_scan(&g).unwrap();
    for (i, v) in [12.54f64, -7.5, 12.56].iter().enumerate() {
        p.put(A + 8 * i as u64, &v.to_le_bytes());
    }
    let mut n = next(ScanType::IncreasedBy, Some("25"));
    n.percent = Some(true);
    s.next_scan(&n).unwrap();
    assert_eq!(addrs(&s), [A, A + 8]);
    s.undo().unwrap();
    n.scan_type = ScanType::DecreasedBy;
    s.next_scan(&n).unwrap();
    assert_eq!(s.count(), 0);
}

#[test]
fn unicode_case_and_codepages() {
    let p = fake();
    p.put(A + 0x10, "ÉCOLE".as_bytes());
    p.put(A + 0x40, "ΟΔΟΣ".as_bytes());
    let w: Vec<u8> = "привет".encode_utf16().flat_map(u16::to_le_bytes).collect();
    p.put(A + 0x80, &w);
    p.put(A + 0xc0, &[b'c', 0xe9, b'l', 0x80]); // "cél€" in code page 1252
    let s = scanner(&p);
    let find = |v: &str, utf16: bool, cp: Option<u32>| {
        let mut f = first(VType::String, ScanType::Exact, v);
        f.opts.utf16 = utf16;
        f.opts.codepage = cp;
        f.opts.stop = Some(A + 0x100);
        s.first_scan(&f).map(|_| addrs(&s))
    };
    assert_eq!(find("école", false, None).unwrap(), [A + 0x10]);
    assert_eq!(find("οδος", false, None).unwrap(), [A + 0x40]);
    assert_eq!(find("οδος", false, None).unwrap(), find("ΟΔΟς", false, None).unwrap(), "final sigma folds");
    assert_eq!(find("ПРИВЕТ", true, None).unwrap(), [A + 0x80]);
    assert_eq!(find("CÉL€", false, Some(1252)).unwrap(), [A + 0xc0]);
    assert_eq!(s.results(0, 1).unwrap()[0].value.as_deref(), Some("cél€"));
    assert_eq!(find("CÉL", false, Some(28591)).unwrap(), [A + 0xc0]);
    assert!(find("x", false, Some(932)).is_err());
    assert!(find("€", false, Some(28591)).is_err());
}

// ---------------------------------------------------------------- hostile input (release audit)

#[test]
fn table_value_lengths_are_capped() {
    let p = fake();
    let huge = Fmt { len: Some(1 << 40), ..Fmt::default() };
    assert!(value_size(VType::String, &huge).is_err());
    assert!(value_size(VType::Aob, &huge).is_err());
    assert!(value_size(VType::String, &Fmt { len: Some(usize::MAX), utf16: true, ..Fmt::default() }).is_err());
    assert_eq!(value_size(VType::Aob, &Fmt { len: Some(MAX_VALUE_LEN), ..Fmt::default() }).unwrap(), MAX_VALUE_LEN);
    let refs = [ValueRef { addr: A, vtype: VType::String, fmt: huge }, ValueRef { addr: A, vtype: VType::Byte, fmt: Fmt::default() }];
    assert_eq!(read_values(&*p, &refs), [None, Some("0".into())]);
    let ex = [ValueRefEx { r: refs[0].clone(), custom: None }];
    assert_eq!(read_values_ex(&*p, &ex), [None]);
}

#[test]
fn bigger_than_max_and_smaller_than_min_match_nothing() {
    let p = fake();
    let s = scanner(&p);
    for (st, v) in [(ScanType::Bigger, i128::MAX.to_string()), (ScanType::Smaller, i128::MIN.to_string())] {
        for vt in [VType::Byte, VType::Bytes4, VType::Bytes8] {
            let mut f = first(vt, st, &v);
            f.opts.signed = true;
            assert_eq!(s.first_scan(&f).map(|c| c.count).unwrap_or(0), 0, "{st:?} {vt:?}");
        }
    }
}

#[test]
fn bad_alignments_and_group_spans_are_rejected() {
    let p = fake();
    let s = scanner(&p);
    for a in [0, u64::MAX, (1 << 32) + 1] {
        let mut f = first(VType::Bytes4, ScanType::Exact, "1");
        f.opts.alignment = Some(a);
        assert!(s.first_scan(&f).is_err(), "{a:#x}");
    }
    let mut f = first(VType::Bytes4, ScanType::Exact, "1");
    f.opts.alignment = Some(1 << 32);
    assert!(s.first_scan(&f).is_ok());
    for g in ["w:FFFFFFFFFFFFFFFF 1:0", "w:18446744073709551615 1:0", "w:900000 w:900000 1:0", "BS:99999999 OOO 1:0", "BA:0 1:0"] {
        assert!(s.first_scan(&first(VType::Grouped, ScanType::Exact, g)).is_err(), "{g}");
    }
}

#[cfg(target_os = "linux")]
#[test]
fn pause_leaves_an_already_stopped_target_stopped() {
    use std::process::Command;
    let mut child = Command::new("sleep").arg("30").spawn().unwrap();
    let pid = child.id();
    Command::new("kill").args(["-STOP", &pid.to_string()]).status().unwrap();
    let stat = || std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
    for _ in 0..200 {
        if stat().rsplit_once(')').is_some_and(|(_, r)| r.trim_start().starts_with(['T', 't'])) {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let p = fake();
    p.pid.store(pid, Relaxed);
    let s = scanner(&p);
    let mut f = first(VType::Bytes4, ScanType::Exact, "1");
    f.opts.pause_while_scanning = true;
    s.first_scan(&f).unwrap();
    let counts = (p.suspends.load(Relaxed), p.resumes.load(Relaxed));
    // A remote target with the same pid: this machine's /proc says nothing about it.
    s.set_local(false);
    s.first_scan(&f).unwrap();
    let remote = (p.suspends.load(Relaxed), p.resumes.load(Relaxed));
    let _ = child.kill();
    let _ = child.wait();
    assert_eq!(counts, (0, 0));
    assert_eq!(remote, (1, 1));
}

// ---------------------------------------------------------------- 1.0 feature gaps

fn module(name: &str, base: Addr, size: u64) -> Module {
    Module { name: name.into(), path: format!("/x/{name}"), base, size }
}

fn opts_in(start: Addr, stop: Addr) -> ScanOptions {
    ScanOptions { start: Some(start), stop: Some(stop), ..ScanOptions::default() }
}

#[test]
fn saved_values_by_address() {
    let p = fake();
    p.put(A + 0x10, &5u32.to_le_bytes());
    p.put(B + 0x100, &5u32.to_le_bytes());
    let s = scanner(&p);
    s.first_scan(&first(VType::Bytes4, ScanType::Exact, "5")).unwrap();
    s.save_scan("five").unwrap();
    p.put(A + 0x10, &6u32.to_le_bytes());
    s.next_scan(&next(ScanType::Changed, None)).unwrap();
    assert_eq!(addrs(&s), [A + 0x10]);
    let some = |v: &str| Some(v.to_string());
    assert_eq!(s.saved_values("five", &[B + 0x100, A + 0x10, A + 0x14, 0]).unwrap(), [some("5"), some("5"), None, None]);
    // "first": the first-scan value of the current results only.
    assert_eq!(s.saved_values("first", &[A + 0x10, B + 0x100]).unwrap(), [some("5"), None]);
    assert!(s.saved_values("nope", &[A]).is_err());

    // Dense (unknown initial value) sets, plain and masked.
    p.put(A + 3, &[7]);
    for vt in [VType::Byte, VType::All] {
        let f = FirstScan { opts: opts_in(A, A + 0x100), ..first(vt, ScanType::Unknown, "") };
        s.first_scan(&f).unwrap();
        s.save_scan("u").unwrap();
        assert_eq!(s.saved_values("u", &[A + 0x200, A + 4, A + 3]).unwrap()[1..], [some("0"), some("7")], "{vt:?}");
        assert_eq!(s.saved_values("u", &[A + 0x200]).unwrap(), [None]);
    }
}

#[test]
fn spill_dir_is_public() {
    let dir = tempfile::tempdir_in(".").unwrap();
    let s = scanner(&fake());
    s.set_spill_dir(Some(dir.path().to_path_buf()));
    assert_eq!(s.effective_spill_dir(), dir.path());
    assert_eq!(spill_dir(Some(dir.path())), dir.path());
    s.set_spill_dir(None);
    assert_eq!(s.effective_spill_dir(), spill_dir(None));
}

#[test]
fn custom_number_helpers() {
    let p = MockProcess::new(0x1000, vec![0; 16]);
    let fmt = Fmt::default();
    let fixed = CustomType { scale: 0.01, ..CustomType::int(2, true) };
    write_custom(&p, 0x1000, &fixed, "12.34", &fmt).unwrap();
    assert_eq!(read_custom(&p, 0x1000, &fixed).unwrap(), CustomNumber::Float(12.34));
    assert_eq!(add_custom(&p, 0x1000, &fixed, 1.5).unwrap(), CustomNumber::Float(13.84));
    assert_eq!(fixed.format(&p.mem.read().unwrap()[..2], &fmt), "13.84");

    let be = CustomType::preset("4 Byte Big Endian").unwrap();
    write_custom_number(&p, 0x1004, &be, CustomNumber::Int(258)).unwrap();
    assert_eq!(p.mem.read().unwrap()[4..8], [0, 0, 1, 2]);
    assert_eq!(add_custom(&p, 0x1004, &be, -8.0).unwrap(), CustomNumber::Int(250));
    assert_eq!(add_custom(&p, 0x1004, &be, 0.5).unwrap_err().to_string(), "parse error: 250.5 is not an integer");
    assert!(be.encode_number(CustomNumber::Float(3.0)).is_ok());

    // Bit field: bits 4..6 of a byte; the other bits stay.
    let bits = CustomType { bit_start: 4, bit_len: 3, ..CustomType::int(1, false) };
    p.write(0x1008, &[0xff]).unwrap();
    assert_eq!(read_custom(&p, 0x1008, &bits).unwrap(), CustomNumber::Int(7));
    write_custom_number(&p, 0x1008, &bits, CustomNumber::Int(2)).unwrap();
    assert_eq!(p.mem.read().unwrap()[8], 0xaf);
    assert_eq!(add_custom(&p, 0x1008, &bits, 1.0).unwrap(), CustomNumber::Int(3));
    assert!(add_custom(&p, 0x1008, &bits, 10.0).is_err());
    assert_eq!(p.mem.read().unwrap()[8], 0xbf, "a failed add writes nothing");

    let bin = CustomType { binary: true, ..CustomType::int(1, false) };
    assert_eq!(bin.encode_number(CustomNumber::Int(5)).unwrap(), [5]);
    let fl = CustomType::preset("Float Big Endian").unwrap();
    write_custom_number(&p, 0x100c, &fl, CustomNumber::Float(2.5)).unwrap();
    assert_eq!(add_custom(&p, 0x100c, &fl, -1.0).unwrap(), CustomNumber::Float(1.5));
    assert_eq!(fl.number(&[0x3f, 0xc0, 0, 0]), Some(CustomNumber::Float(1.5)));
    assert_eq!(fl.number(&[0x3f]), None);
    assert!(read_custom(&p, 0x2000, &fl).is_err());
}

#[test]
fn region_kind_module_range_and_size_filters() {
    let p = Arc::new(Fake::new(vec![
        (0x10000, 0x1000, RW, RegionKind::Image),
        (0x20000, 0x1000, RW, RegionKind::Image),
        (0x30000, 0x1000, RW, RegionKind::Private),
        (0x40000, 0x2000, RW, RegionKind::Mapped),
    ]));
    *p.modules.lock().unwrap() = vec![module("game.exe", 0x10000, 0x1000), module("lib.so", 0x20000, 0x1000)];
    for a in [0x10010, 0x20010, 0x30010, 0x40010] {
        p.put(a, &9u32.to_le_bytes());
    }
    let s = scanner(&p);
    let scan = |o: ScanOptions| -> Result<Vec<Addr>> {
        s.first_scan(&FirstScan { opts: o, ..first(VType::Bytes4, ScanType::Exact, "9") })?;
        Ok(addrs(&s))
    };
    let d = ScanOptions::default;
    let r = |start, end| AddrRange { start, end };
    assert_eq!(scan(d()).unwrap(), [0x10010, 0x20010, 0x30010, 0x40010]);
    assert_eq!(scan(ScanOptions { kinds: vec![RegionKind::Private], ..d() }).unwrap(), [0x30010]);
    assert_eq!(scan(ScanOptions { kinds: vec![RegionKind::Image, RegionKind::Mapped], ..d() }).unwrap(), [0x10010, 0x20010, 0x40010]);
    assert_eq!(scan(ScanOptions { modules: vec!["GAME.EXE".into()], ..d() }).unwrap(), [0x10010]);
    let ex = ScanOptions { exclude_modules: vec!["game.exe".into(), "not-loaded.dll".into()], ..d() };
    assert_eq!(scan(ex).unwrap(), [0x20010, 0x30010, 0x40010]);
    assert!(scan(ScanOptions { modules: vec!["nope".into()], ..d() }).unwrap_err().to_string().contains("no module named"));
    // A range only has to hold the value's start.
    let rg = ScanOptions { ranges: vec![r(0x40000, 0x40100), r(0x20000, 0x20011)], ..d() };
    assert_eq!(scan(rg.clone()).unwrap(), [0x20010, 0x40010]);
    assert!(scan(ScanOptions { modules: vec!["game.exe".into()], ..rg }).unwrap().is_empty());
    assert_eq!(scan(ScanOptions { min_region_size: Some(0x2000), ..d() }).unwrap(), [0x40010]);
    assert_eq!(scan(ScanOptions { max_region_size: Some(0x1000), ..d() }).unwrap(), [0x10010, 0x20010, 0x30010]);
    assert!(scan(ScanOptions { ranges: vec![r(5, 5)], ..d() }).is_err());
    assert!(scan(ScanOptions { ranges: vec![r(0, 1); 5000], ..d() }).is_err());
    // Excluding part of a region splits it.
    *p.modules.lock().unwrap() = vec![module("mid", 0x40008, 0x10)];
    p.put(0x40020, &9u32.to_le_bytes());
    assert_eq!(scan(ScanOptions { exclude_modules: vec!["mid".into()], kinds: vec![RegionKind::Mapped], ..d() }).unwrap(), [0x40020]);
    // JSON names.
    let o: ScanOptions = serde_json::from_str(r#"{"kinds":["Image"],"modules":["a"],"exclude_modules":["b"],"ranges":[{"start":"0x10","end":"0x20"}],"min_region_size":1,"simple_values":true}"#).unwrap();
    assert_eq!((o.kinds, o.ranges, o.simple_values), (vec![RegionKind::Image], vec![r(0x10, 0x20)], true));
}

#[test]
fn freezer_per_entry_operations() {
    let p = Arc::new(MockProcess::new(0x1000, vec![0; 64]));
    let fz = Freezer::new(p.clone()).unwrap();
    fz.set_interval(Duration::from_secs(3600));
    let fast = Some(Duration::from_millis(5));
    let ex = |addr: Addr, v: &str, mode, vtype| FrozenEntryEx { entry: FrozenEntry { addr, vtype, value: v.into(), mode, fmt: Fmt::default() }, custom: None };
    let int = |addr, v| ex(addr, v, FreezeMode::Exact, VType::Bytes4);
    let rd = |a: Addr| {
        let mut b = [0u8; 4];
        p.read_exact(a, &mut b).unwrap();
        b
    };
    let num = |a| u32::from_le_bytes(rd(a));
    let settle = || std::thread::sleep(Duration::from_millis(60));

    fz.put(&int(0x1000, "7"), fast).unwrap();
    settle();
    assert_eq!(num(0x1000), 7);
    p.write(0x1000, &1u32.to_le_bytes()).unwrap();
    settle();
    assert_eq!(num(0x1000), 7, "own 5 ms interval, not the freezer's hour");
    fz.put(&int(0x1004, "3"), fast).unwrap();
    fz.put(&int(0x1000, "8"), fast).unwrap();
    settle();
    assert_eq!((num(0x1000), num(0x1004), fz.len()), (8, 3, 2));
    assert!(fz.remove(0x1000) && !fz.remove(0x1000));
    p.write(0x1000, &1u32.to_le_bytes()).unwrap();
    settle();
    assert_eq!((num(0x1000), num(0x1004)), (1, 3));

    fz.freeze_many(&[0x1010, 0x1014, 0x1018], &int(0, "42"), fast).unwrap();
    assert!(fz.freeze_many(&[0x1020], &int(0, "x"), fast).is_err());
    settle();
    assert_eq!(([num(0x1010), num(0x1014), num(0x1018)], fz.len()), ([42; 3], 4));

    // The freezer's own (hour-long) interval: written once, then left alone.
    fz.put(&int(0x1020, "5"), None).unwrap();
    settle();
    assert_eq!(num(0x1020), 5);
    p.write(0x1020, &1u32.to_le_bytes()).unwrap();
    settle();
    assert_eq!(num(0x1020), 1);

    // Unwritable addresses are reported, and the report clears with the entry.
    assert!(fz.failures().is_empty());
    fz.put(&int(0x9000, "1"), fast).unwrap();
    settle();
    let f = fz.failures();
    assert_eq!((f.len(), f[0].addr), (1, 0x9000));
    fz.remove(0x9000);
    assert!(fz.failures().is_empty());

    // Allow increase on a float, allow decrease on a custom type.
    fz.put(&ex(0x1028, "1.5", FreezeMode::AllowIncrease, VType::Float), fast).unwrap();
    let be2 = CustomType::preset("2 Byte Big Endian").unwrap();
    let mut e = ex(0x1030, "100", FreezeMode::AllowDecrease, VType::Bytes2);
    e.custom = Some(be2);
    fz.put(&e, fast).unwrap();
    settle();
    let fl = || f32::from_le_bytes(rd(0x1028));
    let be = || u16::from_be_bytes(rd(0x1030)[..2].try_into().unwrap());
    assert_eq!((fl(), be()), (1.5, 100));
    p.write(0x1028, &2.5f32.to_le_bytes()).unwrap();
    p.write(0x1030, &50u16.to_be_bytes()).unwrap();
    settle();
    assert_eq!((fl(), be()), (2.5, 50));
    p.write(0x1028, &0.5f32.to_le_bytes()).unwrap();
    p.write(0x1030, &200u16.to_be_bytes()).unwrap();
    settle();
    assert_eq!((fl(), be()), (2.5, 50));
}

#[test]
fn sort_remove_export_and_stats() {
    let p = fake();
    for (a, v) in [(A + 0x40, 30u32), (A + 0x10, 10), (B + 0x100, 20), (B + (5 << 20), 40)] {
        p.put(a, &v.to_le_bytes());
    }
    let s = scanner(&p);
    s.first_scan(&first(VType::Bytes4, ScanType::Bigger, "5")).unwrap();
    let natural = [A + 0x10, A + 0x40, B + 0x100, B + (5 << 20)];
    assert_eq!(addrs(&s), natural);
    s.sort(SortKey::Value, false).unwrap();
    assert_eq!(addrs(&s), [A + 0x10, B + 0x100, A + 0x40, B + (5 << 20)]);
    s.sort(SortKey::Value, true).unwrap();
    let page: Vec<Addr> = s.results(1, 2).unwrap().iter().map(|r| r.addr).collect();
    assert_eq!(page, [A + 0x40, B + 0x100]);
    assert_eq!(s.results(1, 1).unwrap()[0].value.as_deref(), Some("30"));
    s.sort(SortKey::Address, true).unwrap();
    assert_eq!(addrs(&s), natural.iter().rev().copied().collect::<Vec<_>>());
    s.sort(SortKey::Address, false).unwrap();
    assert_eq!(addrs(&s), natural);

    // Remove (the order resets to addresses), undo brings them back.
    s.sort(SortKey::Value, false).unwrap();
    assert_eq!(s.remove(&[A + 0x40, A + 0x44, A + 0x40]).unwrap(), 1);
    assert_eq!(addrs(&s), [A + 0x10, B + 0x100, B + (5 << 20)]);
    assert_eq!(s.remove(&[A + 0x44]).unwrap(), 0);
    s.undo().unwrap();
    assert_eq!(addrs(&s), natural);
    // Next scans work on a set with removals.
    s.remove(&[B + 0x100]).unwrap();
    assert_eq!(s.next_scan(&next(ScanType::Unchanged, None)).unwrap().count, 3);

    let mut out = Vec::new();
    assert_eq!(s.export_addresses(&mut out).unwrap(), 3);
    assert_eq!(String::from_utf8(out).unwrap(), format!("{:X}\n{:X}\n{:X}\n", A + 0x10, A + 0x40, B + (5 << 20)));

    let st = s.result_stats().unwrap();
    assert_eq!(st.iter().map(|x| (x.start, x.count)).collect::<Vec<_>>(), [(A, 2), (B, 1)]);
    assert_eq!((st[0].size, st[0].kind), (0x10000, Some(RegionKind::Private)));

    // Dense sets, plain and masked ("all").
    for vt in [VType::Byte, VType::All] {
        s.first_scan(&FirstScan { opts: opts_in(A, A + 0x100), ..first(vt, ScanType::Unknown, "") }).unwrap();
        let n = s.count();
        assert_eq!(s.remove(&[A + 5, A + 0xc8, A + 0x1000]).unwrap(), 2, "{vt:?}");
        assert_eq!(s.count(), n - 2);
        let got = addrs(&s);
        assert!(!got.contains(&(A + 5)) && !got.contains(&(A + 0xc8)) && got.contains(&(A + 6)));
        assert_eq!(s.saved_values("first", &[A + 5, A + 6]).unwrap()[0], None);
        s.undo().unwrap();
        assert_eq!(s.count(), n);
        s.sort(SortKey::Value, true).unwrap();
        // Bytes: the 30 is the largest; "all" rows read 4 bytes, so 30 << 24 at A+0x3d is.
        let top = if vt == VType::Byte { A + 0x40 } else { A + 0x3d };
        assert_eq!(s.results(0, 1).unwrap()[0].addr, top, "{vt:?}");
    }
}

#[test]
fn sort_refuses_huge_result_sets() {
    let p = Arc::new(Fake::new(vec![(A, MAX_SORT as usize + 16, RW, RegionKind::Private)]));
    let s = scanner(&p);
    assert_eq!(s.first_scan(&first(VType::Byte, ScanType::Unknown, "")).unwrap().count, MAX_SORT + 16);
    let e = s.sort(SortKey::Value, false).unwrap_err().to_string();
    assert!(e.contains("too many to sort"), "{e}");
    s.sort(SortKey::Address, false).unwrap();
    assert!(scanner(&fake()).sort(SortKey::Value, false).is_err(), "no results yet");
}

#[test]
fn simple_float_values() {
    let p = fake();
    for (i, v) in [1e-30f32, 1.5, 1e20, f32::NAN, 0.0001].into_iter().enumerate() {
        p.put(A + 8 * i as u64, &v.to_le_bytes());
    }
    p.put(A + 0x80, &1e-30f64.to_le_bytes());
    p.put(A + 0x88, &2.25f64.to_le_bytes());
    let s = scanner(&p);
    let scan = |vt, simple, all_types: Vec<VType>| {
        let o = ScanOptions { simple_values: simple, all_types, ..opts_in(A, A + 0x40) };
        s.first_scan(&FirstScan { opts: o, ..first(vt, ScanType::Bigger, "0") }).unwrap();
        addrs(&s)
    };
    assert_eq!(scan(VType::Float, false, vec![]), [A, A + 8, A + 16, A + 32]);
    assert_eq!(scan(VType::Float, true, vec![]), [A + 8, A + 32]);
    assert_eq!(scan(VType::All, true, vec![VType::Float]), [A + 8, A + 32]);
    // Next scans keep the filter.
    s.first_scan(&FirstScan { opts: ScanOptions { simple_values: true, ..opts_in(A + 0x80, A + 0x90) }, ..first(VType::Double, ScanType::Unknown, "") }).unwrap();
    s.next_scan(&next(ScanType::Unchanged, None)).unwrap();
    assert_eq!(addrs(&s), [A + 0x88]);
}

#[test]
fn pointer_type_scan() {
    let p = fake();
    *p.modules.lock().unwrap() = vec![module("img", 0x2000000, 0x1000)];
    for (i, v) in [A + 0x100, B + 0x10, 0x2000008, 0xdead].into_iter().enumerate() {
        p.put(A + 8 * i as u64, &v.to_le_bytes());
    }
    let s = scanner(&p);
    let scan = |modules: Vec<String>, ranges: Vec<AddrRange>| {
        s.pointer_scan(&PointerScan { opts: opts_in(A, A + 0x100), modules, ranges }).unwrap();
        addrs(&s)
    };
    assert_eq!(scan(vec![], vec![]), [A, A + 8, A + 16]);
    assert_eq!(scan(vec!["img".into()], vec![]), [A + 16]);
    assert_eq!(scan(vec![], vec![AddrRange { start: B, end: B + 0x100 }]), [A + 8]);
    assert!(s.pointer_scan(&PointerScan { modules: vec!["nope".into()], ..PointerScan::default() }).is_err());
    // Results are 8-byte entries: next scans and rows work as for that type.
    scan(vec![], vec![]);
    p.put(A, &(A + 0x200).to_le_bytes());
    assert_eq!(s.next_scan(&next(ScanType::Changed, None)).unwrap().count, 1);
    assert_eq!(s.results(0, 1).unwrap()[0].vtype, VType::Bytes8);
}

#[test]
fn hostile_region_lists_scan_cleanly() {
    // Unsorted, overlapping, empty and wrapping regions (a hostile remote server).
    let p = Arc::new(Fake::new(vec![
        (A + 0x8000, 0x10000, RW, RegionKind::Private),
        (A, 0x10000, RW, RegionKind::Private),
        (A + 0x2000, 0x1000, RW, RegionKind::Private),
        (A + 0x40000, 0, RW, RegionKind::Private),
        (u64::MAX - 0xfff, 0x2000, RW, RegionKind::Private),
    ]));
    // Reads go to the first listed region holding the address.
    p.put(A + 0x11000, &777777u32.to_le_bytes());
    p.put(A + 0x100, &777777u32.to_le_bytes());
    let s = scanner(&p);
    assert_eq!(s.first_scan(&first(VType::Bytes4, ScanType::Exact, "777777")).unwrap().count, 2);
    assert_eq!(addrs(&s), [A + 0x100, A + 0x11000]);
    assert_eq!(s.next_scan(&next(ScanType::Unchanged, None)).unwrap().count, 2);
    let mut f = first(VType::Bytes4, ScanType::Unknown, "");
    f.value = None;
    let n = s.first_scan(&f).unwrap().count;
    assert_eq!(n, (0x18000 / 4) as u64, "every aligned slot once");
    assert_eq!(s.next_scan(&next(ScanType::Unchanged, None)).unwrap().count, n);
}
