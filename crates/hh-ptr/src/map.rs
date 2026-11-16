//! Pointer map: every pointer-looking value in the target's readable memory.
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;
use std::sync::OnceLock;

use hh_core::{Addr, Error, Module, Process, Region, RegionKind, Result};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::path::{Bases, PointerPath, region_stacks, thread_stacks, walk};
use crate::{Progress, cancelled};

const MAGIC: &[u8; 8] = b"HHPMAP01";
const CHUNK: u64 = 1 << 20;
const PAGE: u64 = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Entry {
    pub value: u64,
    pub addr: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CollectOptions {
    /// Pointer slot alignment in bytes (1 = unaligned, 4 = "32-bit aligned");
    /// 0 means the target's pointer size.
    pub alignment: u64,
    /// Skip read-only regions as pointer sources.
    pub writable_only: bool,
}

#[derive(Serialize, Deserialize)]
struct MapHeader {
    pointer_size: usize,
    regions: Vec<Region>,
    modules: Vec<Module>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    stacks: Vec<(Addr, Addr)>,
}

/// A snapshot of all pointers of one process.
#[derive(Debug)]
pub struct PointerMap {
    pub pointer_size: usize,
    /// Readable regions at collection time, sorted by address.
    pub regions: Vec<Region>,
    pub modules: Vec<Module>,
    /// Thread stack ranges in `THREADSTACK<n>` order (see [`crate::thread_stacks`]); empty
    /// = the regions tagged as stacks (maps saved before per-thread stacks).
    pub stacks: Vec<(Addr, Addr)>,
    /// Sorted by (value, addr).
    pub(crate) entries: Vec<Entry>,
    by_addr: OnceLock<Vec<Entry>>,
}

/// Sorted, merged [start, end) ranges of `regions`.
fn ranges(regions: &[Region]) -> Vec<(u64, u64)> {
    let mut out: Vec<(u64, u64)> = Vec::new();
    for r in regions {
        let end = r.start.saturating_add(r.size);
        match out.last_mut() {
            Some(last) if last.1 >= r.start => last.1 = last.1.max(end),
            _ => out.push((r.start, end)),
        }
    }
    out
}

fn in_ranges(ranges: &[(u64, u64)], v: u64) -> bool {
    let i = ranges.partition_point(|r| r.0 <= v);
    i > 0 && v < ranges[i - 1].1
}

/// Linux maps a module's .bss as an anonymous region right after its image: count it in.
fn extend_bss(modules: &mut [Module], regions: &[Region]) {
    for m in modules {
        let end = m.base + m.size;
        if let Some(r) = regions
            .iter()
            .find(|r| r.start == end && r.kind == RegionKind::Private && r.path.is_none())
        {
            m.size += r.size;
        }
    }
}

fn scan_chunk(
    p: &dyn Process,
    start: u64,
    len: u64,
    ps: usize,
    align: u64,
    valid: &[(u64, u64)],
) -> Vec<Entry> {
    let (lo, hi) = (valid[0].0, valid[valid.len() - 1].1);
    let mut buf = vec![0u8; len as usize + ps - 1];
    let mut out = Vec::new();
    let mut pos = 0u64;
    while pos < len {
        let addr = start + pos;
        match p.read(addr, &mut buf[pos as usize..]) {
            Ok(n) if n > 0 => {
                let seg = &buf[pos as usize..pos as usize + n];
                let first = addr.next_multiple_of(align) - addr;
                let mut o = first;
                while o + ps as u64 <= n as u64 && addr + o < start + len {
                    let b = &seg[o as usize..o as usize + ps];
                    let v = if ps == 8 {
                        u64::from_le_bytes(b.try_into().unwrap_or_default())
                    } else {
                        u32::from_le_bytes(b.try_into().unwrap_or_default()) as u64
                    };
                    if v >= lo && v < hi && in_ranges(valid, v) {
                        out.push(Entry {
                            value: v,
                            addr: addr + o,
                        });
                    }
                    o += align;
                }
                pos += n as u64;
            }
            // Unreadable page in the middle of a region: skip to the next page.
            _ => pos = (addr / PAGE + 1) * PAGE - start,
        }
    }
    out
}

impl PointerMap {
    /// One pass over the process's readable memory, in parallel. Thread stacks are the
    /// regions tagged as stacks; see [`PointerMap::collect_ex`].
    pub fn collect(p: &dyn Process, opts: &CollectOptions, progress: &Progress) -> Result<Self> {
        Self::collect_ex(p, opts, false, progress)
    }

    /// [`PointerMap::collect`]; `local`: `p` runs on this machine, so every thread's stack
    /// is found (`THREADSTACK1`... for the other threads; see [`crate::thread_stacks`]).
    pub fn collect_ex(p: &dyn Process, opts: &CollectOptions, local: bool, progress: &Progress) -> Result<Self> {
        let ps = p.pointer_size();
        if ps != 4 && ps != 8 {
            return Err(Error::Unsupported("pointer size other than 4 or 8"));
        }
        let align = match opts.alignment {
            0 => ps as u64,
            a if a <= 8 => a,
            _ => return Err(Error::Other("alignment must be 0..=8".into())),
        };
        let mut regions: Vec<Region> = p
            .regions()?
            .into_iter()
            .filter(|r| r.prot.r && r.size > 0)
            .collect();
        regions.sort_by_key(|r| r.start);
        let mut modules = p.modules()?;
        extend_bss(&mut modules, &regions);
        let stacks = if local { thread_stacks(p, true)? } else { region_stacks(&regions) };
        let valid = ranges(&regions);
        let mut chunks = Vec::new();
        for r in regions.iter().filter(|r| !opts.writable_only || r.prot.w) {
            let mut s = r.start;
            let end = r.start.saturating_add(r.size);
            while s < end {
                let n = CHUNK.min(end - s);
                chunks.push((s, n));
                s += n;
            }
        }
        progress.start(chunks.iter().map(|c| c.1).sum());
        let entries: Vec<Entry> = if valid.is_empty() {
            Vec::new()
        } else {
            chunks
                .par_iter()
                .flat_map_iter(|&(s, n)| {
                    progress.wait_if_paused();
                    if progress.is_cancelled() {
                        return Vec::new();
                    }
                    let v = scan_chunk(p, s, n, ps, align, &valid);
                    progress
                        .done
                        .fetch_add(n, std::sync::atomic::Ordering::Relaxed);
                    progress
                        .found
                        .fetch_add(v.len() as u64, std::sync::atomic::Ordering::Relaxed);
                    v
                })
                .collect()
        };
        if progress.is_cancelled() {
            return Err(cancelled());
        }
        Ok(Self::from_entries(ps, regions, modules, stacks, entries))
    }

    fn from_entries(
        pointer_size: usize,
        regions: Vec<Region>,
        modules: Vec<Module>,
        stacks: Vec<(Addr, Addr)>,
        mut entries: Vec<Entry>,
    ) -> Self {
        entries.par_sort_unstable_by_key(|e| (e.value, e.addr));
        PointerMap {
            pointer_size,
            regions,
            modules,
            stacks,
            entries,
            by_addr: OnceLock::new(),
        }
    }

    /// Thread stack ranges in `THREADSTACK<n>` order.
    pub fn stack_ranges(&self) -> Vec<(Addr, Addr)> {
        if self.stacks.is_empty() { region_stacks(&self.regions) } else { self.stacks.clone() }
    }

    /// Number of pointers.
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The pointer stored at `addr` when the map was taken.
    pub fn read_ptr(&self, addr: Addr) -> Option<Addr> {
        let by_addr = self.by_addr.get_or_init(|| {
            let mut v = self.entries.clone();
            v.par_sort_unstable_by_key(|e| e.addr);
            v
        });
        by_addr
            .binary_search_by_key(&addr, |e| e.addr)
            .ok()
            .map(|i| by_addr[i].value)
    }

    pub(crate) fn bases(&self) -> Bases {
        Bases::new(&self.modules, &self.stack_ranges())
    }

    /// Where `path` led in this snapshot.
    pub fn resolve(&self, path: &PointerPath) -> Option<Addr> {
        let base = self
            .bases()
            .addr_of(path.module.as_deref())?
            .wrapping_add_signed(path.base_offset);
        walk(base, &path.offsets, |a| self.read_ptr(a))
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let mut w = BufWriter::with_capacity(1 << 20, File::create(path)?);
        let header = serde_json::to_vec(&MapHeader {
            pointer_size: self.pointer_size,
            regions: self.regions.clone(),
            modules: self.modules.clone(),
            stacks: self.stacks.clone(),
        })
        .map_err(|e| Error::Other(e.to_string()))?;
        w.write_all(MAGIC)?;
        w.write_all(&(header.len() as u32).to_le_bytes())?;
        w.write_all(&header)?;
        w.write_all(&(self.entries.len() as u64).to_le_bytes())?;
        for e in &self.entries {
            w.write_all(&e.value.to_le_bytes())?;
            w.write_all(&e.addr.to_le_bytes())?;
        }
        w.flush()?;
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self> {
        let f = File::open(path)?;
        let file_len = f.metadata()?.len();
        let mut r = BufReader::with_capacity(1 << 20, f);
        let bad = || Error::Parse("not a HeapHook pointer map".into());
        let mut magic = [0u8; 8];
        r.read_exact(&mut magic)?;
        if &magic != MAGIC {
            return Err(bad());
        }
        let mut n4 = [0u8; 4];
        r.read_exact(&mut n4)?;
        let hlen = u32::from_le_bytes(n4) as u64;
        if hlen > file_len {
            return Err(bad());
        }
        let mut hbuf = vec![0u8; hlen as usize];
        r.read_exact(&mut hbuf)?;
        let h: MapHeader = serde_json::from_slice(&hbuf).map_err(|_| bad())?;
        if h.pointer_size != 4 && h.pointer_size != 8 {
            return Err(bad());
        }
        let mut n8 = [0u8; 8];
        r.read_exact(&mut n8)?;
        let count = u64::from_le_bytes(n8);
        if count.checked_mul(16) != file_len.checked_sub(20 + hlen) {
            return Err(bad());
        }
        let mut entries = Vec::with_capacity(count as usize);
        let mut b = [0u8; 16];
        for _ in 0..count {
            r.read_exact(&mut b)?;
            let (v, a) = b.split_at(8);
            entries.push(Entry {
                value: u64::from_le_bytes(v.try_into().unwrap_or_default()),
                addr: u64::from_le_bytes(a.try_into().unwrap_or_default()),
            });
        }
        let mut regions = h.regions;
        regions.sort_by_key(|r| r.start);
        // Re-sorting is cheap on sorted input and keeps range lookups correct on odd files.
        Ok(Self::from_entries(
            h.pointer_size,
            regions,
            h.modules,
            h.stacks,
            entries,
        ))
    }
}
