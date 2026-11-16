//! Read-call counts of next scans and result pages (each read is a round trip on a remote
//! target). Prints `reads:` lines; run with `--nocapture` to see them.
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

use hh_core::{Addr, Error, Memory, Pid, Process, Prot, Region, RegionKind, Result};
use hh_scan::*;

/// Regions of bytes; like Linux `process_vm_readv`, a read continues across adjacent
/// regions and stops at the first unmapped byte. Counts read calls and bytes asked for.
struct Counting {
    regions: Vec<(Addr, Vec<u8>)>,
    reads: AtomicU64,
    bytes: AtomicU64,
}

impl Counting {
    fn new(regions: Vec<(Addr, usize)>) -> Self {
        Counting { regions: regions.into_iter().map(|(a, n)| (a, vec![0; n])).collect(), reads: AtomicU64::new(0), bytes: AtomicU64::new(0) }
    }
    fn put(&mut self, addr: Addr, b: &[u8]) {
        let (a, m) = self.regions.iter_mut().find(|(a, m)| addr >= *a && addr < a + m.len() as u64).unwrap();
        let o = (addr - *a) as usize;
        m[o..o + b.len()].copy_from_slice(b);
    }
    fn reset(&self) -> (u64, u64) {
        (self.reads.swap(0, Relaxed), self.bytes.swap(0, Relaxed))
    }
}

impl Memory for Counting {
    fn read(&self, addr: Addr, buf: &mut [u8]) -> Result<usize> {
        self.reads.fetch_add(1, Relaxed);
        self.bytes.fetch_add(buf.len() as u64, Relaxed);
        let mut n = 0;
        while n < buf.len() {
            let a = addr + n as u64;
            let Some((s, m)) = self.regions.iter().find(|(s, m)| a >= *s && a < s + m.len() as u64) else { break };
            let o = (a - s) as usize;
            let k = (buf.len() - n).min(m.len() - o);
            buf[n..n + k].copy_from_slice(&m[o..o + k]);
            n += k;
        }
        if n == 0 { Err(Error::NoAccess { addr }) } else { Ok(n) }
    }
    fn write(&self, addr: Addr, _: &[u8]) -> Result<()> {
        Err(Error::NoAccess { addr })
    }
}

impl Process for Counting {
    fn pid(&self) -> Pid {
        1
    }
    fn regions(&self) -> Result<Vec<Region>> {
        let rw = Prot { r: true, w: true, x: false };
        Ok(self.regions.iter().map(|(a, m)| Region { start: *a, size: m.len() as u64, prot: rw, kind: RegionKind::Private, shared: false, cow: false, path: None }).collect())
    }
}

fn exact(v: &str) -> FirstScan {
    FirstScan { vtype: VType::Bytes4, scan_type: ScanType::Exact, value: Some(v.into()), value2: None, not: false, opts: ScanOptions { threads: Some(1), ..ScanOptions::default() } }
}

/// (next-scan reads, bytes, first result page reads)
fn measure(name: &str, p: Counting, hits: u64) -> (u64, u64, u64) {
    let p = Arc::new(p);
    let s = Scanner::new(p.clone());
    assert_eq!(s.first_scan(&exact("777777")).unwrap().count, hits, "{name}");
    p.reset();
    let next = NextScan { scan_type: ScanType::Exact, value: Some("777777".into()), value2: None, not: false, percent: None };
    assert_eq!(s.next_scan(&next).unwrap().count, hits, "{name}");
    let (reads, bytes) = p.reset();
    assert_eq!(s.results(0, 100).unwrap().len() as u64, hits.min(100));
    let (rows, _) = p.reset();
    eprintln!("reads: {name:28} next scan {reads:>4} reads {bytes:>9} bytes; 100-row page {rows:>4} reads");
    (reads, bytes, rows)
}

#[test]
fn next_scans_and_pages_coalesce_reads() {
    let v = 777777u32.to_le_bytes();
    // 1. 200 adjacent 64 KiB regions (one result chunk each), one hit per region.
    let mut p = Counting::new((0..200).map(|i| (0x1000_0000 + i * 0x10000, 0x10000)).collect());
    (0..200).for_each(|i| p.put(0x1000_0000 + i * 0x10000 + 0x100, &v));
    // Before coalescing: 200 reads (one per chunk), page 100 reads (one per row).
    assert_eq!(measure("adjacent regions", p, 200), (2, 12976136, 1));
    // 2. One 9 MiB region, a hit every 48 KiB (sparse, near each other).
    let mut p = Counting::new(vec![(0x2000_0000, 9 << 20)]);
    let n = (9 << 20) / 0xC000;
    (0..n).for_each(|i| p.put(0x2000_0000 + i * 0xC000, &v));
    // Before: 3 reads / 9289740 bytes, page 100 reads.
    assert_eq!(measure("one region, hit per 48 KiB", p, n), (2, 9338888, 1));
    // 3. One 9 MiB region, a hit every 1 MiB (far apart).
    let mut p = Counting::new(vec![(0x3000_0000, 9 << 20)]);
    (0..9).for_each(|i| p.put(0x3000_0000 + i * 0x10_0000 + 8, &v));
    // Before: 3 reads of whole 4 MiB units (6291468 bytes); now one small read per hit.
    assert_eq!(measure("one region, hit per 1 MiB", p, 9), (9, 36, 9));
    // 4. 64 separate regions with unmapped gaps, 4 hits each.
    let mut p = Counting::new((0..64).map(|i| (0x4000_0000 + i * 0x20000, 0x10000)).collect());
    (0..64).for_each(|i| (0..4).for_each(|j| p.put(0x4000_0000 + i * 0x20000 + j * 0x400, &v)));
    // Before: 64 reads / 196864 bytes, page 100 reads. Unmapped gaps need a call each.
    assert_eq!(measure("separate regions", p, 256), (64, 196864, 25));
}
