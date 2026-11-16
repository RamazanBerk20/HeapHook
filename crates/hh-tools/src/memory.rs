//! Memory utilities: the region view, saving memory to a file and loading it back, fill,
//! copy, snapshots and their diffs, and "find what points to this address".
//!
//! # `.hhmem` file format (HeapHook's take on Cheat Engine's `.CEM`)
//! All integers little-endian:
//! ```text
//! magic   8 bytes  "HHMEM\x01\0\0"
//! count   u32      number of blocks
//! flags   u32      0 (reserved)
//! count times:
//!   addr  u64      address the bytes were read from
//!   len   u64      byte count
//!   data  len bytes
//! ```
//! Unreadable pages are left out, so one requested range can become several blocks.
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;

use hh_asm::module_offset;
use hh_core::{Addr, Error, Process, Prot, RegionKind, Result};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::{Progress, check_len, hexaddr, hexbytes};

// --------------------------------------------------------------------------- region view

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegionTag {
    /// Part of a loaded module.
    Image,
    /// `[heap]` (Linux brk heap).
    Heap,
    /// `[stack]` / `[stack:tid]`.
    Stack,
    /// File mapping that is not a module.
    Mapped,
    /// Anonymous private memory (allocations, thread stacks the OS does not name).
    Private,
    /// Kernel-provided pages: `[vdso]`, `[vvar]`, `[vsyscall]`, ...
    Special,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegionInfo {
    #[serde(with = "hexaddr")]
    pub start: Addr,
    pub size: u64,
    pub prot: Prot,
    /// `rwxp` style: `-` for missing rights, `s` shared / `p` private.
    pub prot_text: String,
    pub kind: RegionKind,
    pub shared: bool,
    pub path: Option<String>,
    /// Module containing the region start.
    pub module: Option<String>,
    pub tag: RegionTag,
}

/// Cheat Engine's memory-region view, with heap / stack annotation where the OS tags
/// regions (`Region.path` such as `[heap]`, `[stack]` on Linux).
pub fn regions(p: &dyn Process) -> Result<Vec<RegionInfo>> {
    let mods = p.modules().unwrap_or_default();
    Ok(p.regions()?
        .into_iter()
        .map(|r| {
            let module = mods
                .iter()
                .find(|m| r.start >= m.base && r.start - m.base < m.size)
                .map(|m| m.name.clone());
            let path = r.path.as_deref().unwrap_or("");
            let tag = if path == "[heap]" {
                RegionTag::Heap
            } else if path.starts_with("[stack") {
                RegionTag::Stack
            } else if path.starts_with('[') && !path.starts_with("[anon") {
                RegionTag::Special
            } else if module.is_some() || r.kind == RegionKind::Image {
                RegionTag::Image
            } else if r.kind == RegionKind::Mapped {
                RegionTag::Mapped
            } else {
                RegionTag::Private
            };
            let f = |b: bool, c: char| if b { c } else { '-' };
            RegionInfo {
                start: r.start,
                size: r.size,
                prot: r.prot,
                prot_text: [f(r.prot.r, 'r'), f(r.prot.w, 'w'), f(r.prot.x, 'x'), if r.shared { 's' } else { 'p' }]
                    .iter()
                    .collect(),
                kind: r.kind,
                shared: r.shared,
                path: r.path,
                module,
                tag,
            }
        })
        .collect())
}

// ------------------------------------------------------------------------- blocks / files

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Range {
    #[serde(with = "hexaddr")]
    pub start: Addr,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    pub addr: Addr,
    pub data: Vec<u8>,
}

/// Memory contents at one moment, as readable blocks sorted by address.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub blocks: Vec<Block>,
}

impl Snapshot {
    pub fn bytes(&self) -> u64 {
        self.blocks.iter().map(|b| b.data.len() as u64).sum()
    }
}

const CHUNK: u64 = 16 << 20;
const PAGE: u64 = 0x1000;

/// Calls `f` with every readable piece of `ranges` (split where reads fail).
fn read_ranges(
    p: &dyn Process,
    ranges: &[Range],
    progress: &Progress,
    mut f: impl FnMut(Addr, Vec<u8>) -> Result<()>,
) -> Result<()> {
    progress.start(ranges.iter().map(|r| r.size).sum());
    for r in ranges {
        let end = r.start.saturating_add(r.size);
        let mut a = r.start;
        let mut cur: Option<(Addr, Vec<u8>)> = None;
        while a < end {
            progress.check()?;
            let want = (end - a).min(CHUNK);
            let mut buf = vec![0u8; want as usize];
            let n = p.read(a, &mut buf).unwrap_or(0) as u64;
            if n > 0 {
                buf.truncate(n as usize);
                match &mut cur {
                    Some((s, d)) if *s + d.len() as u64 == a => d.extend_from_slice(&buf),
                    _ => {
                        if let Some((s, d)) = cur.take() {
                            f(s, d)?;
                        }
                        cur = Some((a, buf));
                    }
                }
                a += n;
                progress.add(n);
            } else {
                // Skip to the next page.
                let next = ((a / PAGE) + 1).saturating_mul(PAGE).min(end);
                progress.add(next - a);
                a = next;
            }
            // Keep blocks bounded so a streaming save does not hold a whole region set.
            if let Some((_, d)) = &cur
                && d.len() as u64 >= CHUNK
            {
                let (s, d) = cur.take().unwrap_or_default();
                f(s, d)?;
            }
        }
        if let Some((s, d)) = cur {
            f(s, d)?;
        }
    }
    Ok(())
}

/// Reads `ranges` into memory.
pub fn snapshot(p: &dyn Process, ranges: &[Range], progress: &Progress) -> Result<Snapshot> {
    let mut blocks = Vec::new();
    read_ranges(p, ranges, progress, |addr, data| {
        blocks.push(Block { addr, data });
        Ok(())
    })?;
    blocks.sort_by_key(|b| b.addr);
    Ok(Snapshot { blocks })
}

/// Every readable region (optionally only writable ones) as ranges.
pub fn readable_ranges(p: &dyn Process, writable_only: bool) -> Result<Vec<Range>> {
    Ok(p.regions()?
        .into_iter()
        .filter(|r| r.prot.r && (r.prot.w || !writable_only))
        .map(|r| Range { start: r.start, size: r.size })
        .collect())
}

const MAGIC: &[u8; 8] = b"HHMEM\x01\0\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileSummary {
    pub blocks: u64,
    pub bytes: u64,
}

fn write_header(w: &mut impl Write, count: u32) -> std::io::Result<()> {
    w.write_all(MAGIC)?;
    w.write_all(&count.to_le_bytes())?;
    w.write_all(&0u32.to_le_bytes())
}

fn write_block(w: &mut impl Write, addr: Addr, data: &[u8]) -> std::io::Result<()> {
    w.write_all(&addr.to_le_bytes())?;
    w.write_all(&(data.len() as u64).to_le_bytes())?;
    w.write_all(data)
}

/// Saves the readable parts of `ranges` to an `.hhmem` file, streaming.
pub fn save_memory(
    p: &dyn Process,
    ranges: &[Range],
    path: &Path,
    progress: &Progress,
) -> Result<FileSummary> {
    let mut w = BufWriter::new(std::fs::File::create(path)?);
    write_header(&mut w, 0)?;
    let mut s = FileSummary { blocks: 0, bytes: 0 };
    read_ranges(p, ranges, progress, |addr, data| {
        write_block(&mut w, addr, &data)?;
        s.blocks += 1;
        s.bytes += data.len() as u64;
        Ok(())
    })?;
    let count = u32::try_from(s.blocks).map_err(|_| Error::Other("too many blocks".into()))?;
    let mut f = w.into_inner().map_err(|e| Error::Io(e.into_error()))?;
    f.seek(SeekFrom::Start(8))?;
    f.write_all(&count.to_le_bytes())?;
    Ok(s)
}

/// Writes a snapshot as an `.hhmem` file.
pub fn save_snapshot(snap: &Snapshot, path: &Path) -> Result<FileSummary> {
    let mut w = BufWriter::new(std::fs::File::create(path)?);
    let count = u32::try_from(snap.blocks.len()).map_err(|_| Error::Other("too many blocks".into()))?;
    write_header(&mut w, count)?;
    for b in &snap.blocks {
        write_block(&mut w, b.addr, &b.data)?;
    }
    w.flush()?;
    Ok(FileSummary { blocks: count as u64, bytes: snap.bytes() })
}

/// Reads an `.hhmem` file.
pub fn load_snapshot(path: &Path) -> Result<Snapshot> {
    let f = std::fs::File::open(path)?;
    let mut left = f.metadata()?.len();
    let mut r = BufReader::new(f);
    let mut head = [0u8; 16];
    r.read_exact(&mut head)?;
    if &head[..8] != MAGIC {
        return Err(Error::Parse("not a HeapHook memory file".into()));
    }
    left = left.saturating_sub(16);
    let count = u32::from_le_bytes(head[8..12].try_into().unwrap_or_default());
    let mut blocks = Vec::new();
    for _ in 0..count {
        let mut h = [0u8; 16];
        r.read_exact(&mut h)?;
        let addr = u64::from_le_bytes(h[..8].try_into().unwrap_or_default());
        let len = u64::from_le_bytes(h[8..].try_into().unwrap_or_default());
        left = left.saturating_sub(16);
        if len > left {
            return Err(Error::Parse("memory file truncated".into()));
        }
        if addr.checked_add(len).is_none() {
            return Err(Error::Parse(format!("memory file block at {addr:#x} wraps the address space")));
        }
        let mut data = vec![0u8; check_len(len)?];
        r.read_exact(&mut data)?;
        left -= len;
        blocks.push(Block { addr, data });
    }
    blocks.sort_by_key(|b| b.addr);
    Ok(Snapshot { blocks })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreSummary {
    pub blocks: u64,
    pub bytes: u64,
    /// Blocks that could not be written (target address after relocation).
    #[serde(with = "crate::hexvec")]
    pub failed: Vec<Addr>,
}

/// Writes a snapshot back into the process. `relocate_to` moves the first block there and
/// every other block by the same distance. Protection is lifted temporarily if needed.
pub fn restore(p: &dyn Process, snap: &Snapshot, relocate_to: Option<Addr>) -> Result<RestoreSummary> {
    let delta = match (relocate_to, snap.blocks.first()) {
        (Some(t), Some(b)) => t.wrapping_sub(b.addr),
        _ => 0,
    };
    let mut s = RestoreSummary { blocks: 0, bytes: 0, failed: Vec::new() };
    for b in &snap.blocks {
        let a = b.addr.wrapping_add(delta);
        match hh_asm::write_code(p, a, &b.data) {
            Ok(()) => {
                s.blocks += 1;
                s.bytes += b.data.len() as u64;
            }
            Err(_) => s.failed.push(a),
        }
    }
    Ok(s)
}

/// `load_snapshot` + `restore`: Cheat Engine's "load memory region".
pub fn load_memory(p: &dyn Process, path: &Path, relocate_to: Option<Addr>) -> Result<RestoreSummary> {
    restore(p, &load_snapshot(path)?, relocate_to)
}

// ---------------------------------------------------------------------------- fill / copy

fn end_of(addr: Addr, len: u64) -> Result<Addr> {
    addr.checked_add(len).ok_or_else(|| Error::Other(format!("range {addr:#x}+{len:#x} wraps the address space")))
}

/// Fills `[addr, addr+len)` with `pattern` repeated.
pub fn fill(p: &dyn Process, addr: Addr, len: u64, pattern: &[u8]) -> Result<()> {
    if pattern.is_empty() {
        return Err(Error::Other("empty fill pattern".into()));
    }
    check_len(len)?;
    end_of(addr, len)?;
    let chunk = (1u64 << 20).min(len) as usize;
    // A whole number of patterns per chunk keeps the phase across chunks.
    let chunk = (chunk / pattern.len()).max(1) * pattern.len();
    let buf: Vec<u8> = pattern.iter().copied().cycle().take(chunk).collect();
    let mut off = 0u64;
    while off < len {
        let n = (len - off).min(buf.len() as u64) as usize;
        hh_asm::write_code(p, addr + off, &buf[..n])?;
        off += n as u64;
    }
    Ok(())
}

/// Copies `len` bytes from `src` to `dst` (overlapping ranges are handled like memmove).
pub fn copy(p: &dyn Process, src: Addr, dst: Addr, len: u64) -> Result<()> {
    check_len(len)?;
    end_of(src, len)?;
    end_of(dst, len)?;
    const C: u64 = 1 << 20;
    let mut buf = vec![0u8; C.min(len) as usize];
    let n_chunks = len.div_ceil(C.max(1));
    let backwards = dst > src && dst < src.saturating_add(len);
    for i in 0..n_chunks {
        let i = if backwards { n_chunks - 1 - i } else { i };
        let off = i * C;
        let n = (len - off).min(C) as usize;
        p.read_exact(src + off, &mut buf[..n])?;
        hh_asm::write_code(p, dst + off, &buf[..n])?;
    }
    Ok(())
}

// --------------------------------------------------------------------------------- diffs

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffRange {
    #[serde(with = "hexaddr")]
    pub addr: Addr,
    pub len: u64,
    #[serde(with = "hexbytes")]
    pub old: Vec<u8>,
    /// Empty when the memory became unreadable.
    #[serde(with = "hexbytes")]
    pub new: Vec<u8>,
}

/// Longest run reported as one diff entry (longer runs are split).
const MAX_RUN: usize = 256;

fn diff_bytes(addr: Addr, a: &[u8], b: &[u8], max: usize, out: &mut Vec<DiffRange>) {
    let n = a.len().min(b.len());
    let mut i = 0;
    while i < n && out.len() < max {
        // Skip equal 8-byte words fast.
        if i + 8 <= n && a[i..i + 8] == b[i..i + 8] {
            i += 8;
            continue;
        }
        if a[i] == b[i] {
            i += 1;
            continue;
        }
        let s = i;
        while i < n && i - s < MAX_RUN && a[i] != b[i] {
            i += 1;
        }
        out.push(DiffRange {
            addr: addr + s as u64,
            len: (i - s) as u64,
            old: a[s..i].to_vec(),
            new: b[s..i].to_vec(),
        });
    }
}

/// Differences between two snapshots where they overlap (at most `max` entries).
pub fn diff_snapshots(old: &Snapshot, new: &Snapshot, max: usize) -> Vec<DiffRange> {
    let mut out = Vec::new();
    for a in &old.blocks {
        let a_end = a.addr + a.data.len() as u64;
        let first = new.blocks.partition_point(|b| b.addr + (b.data.len() as u64) <= a.addr);
        for b in new.blocks[first..].iter().take_while(|b| b.addr < a_end) {
            let lo = a.addr.max(b.addr);
            let hi = a_end.min(b.addr + b.data.len() as u64);
            if lo >= hi {
                continue;
            }
            let sa = &a.data[(lo - a.addr) as usize..(hi - a.addr) as usize];
            let sb = &b.data[(lo - b.addr) as usize..(hi - b.addr) as usize];
            diff_bytes(lo, sa, sb, max, &mut out);
            if out.len() >= max {
                return out;
            }
        }
    }
    out
}

/// Differences between a snapshot and live memory. Parts that became unreadable are
/// reported with an empty `new`.
pub fn diff_live(p: &dyn Process, old: &Snapshot, max: usize, progress: &Progress) -> Result<Vec<DiffRange>> {
    let ranges: Vec<Range> = old
        .blocks
        .iter()
        .map(|b| Range { start: b.addr, size: b.data.len() as u64 })
        .collect();
    let now = snapshot(p, &ranges, progress)?;
    let mut out = diff_snapshots(old, &now, max);
    // Unreadable now: whatever of `old` no block of `now` covers.
    for b in &old.blocks {
        let mut a = b.addr;
        let end = b.addr + b.data.len() as u64;
        for c in now.blocks.iter().filter(|c| c.addr < end && c.addr + c.data.len() as u64 > b.addr) {
            if c.addr > a && out.len() < max {
                out.push(DiffRange { addr: a, len: c.addr - a, old: b.data[(a - b.addr) as usize..(c.addr - b.addr) as usize].to_vec(), new: Vec::new() });
            }
            a = a.max(c.addr + c.data.len() as u64);
        }
        if a < end && out.len() < max {
            out.push(DiffRange { addr: a, len: end - a, old: b.data[(a - b.addr) as usize..].to_vec(), new: Vec::new() });
        }
    }
    out.sort_by_key(|d| d.addr);
    Ok(out)
}

// ------------------------------------------------------------------------- pointers to X

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PointerQuery {
    #[serde(with = "hexaddr")]
    pub target: Addr,
    /// Accept pointers to `[target - max_offset, target]` (structure base + offset).
    pub max_offset: u64,
    /// Only pointers stored inside modules (static addresses).
    pub static_only: bool,
    pub writable_only: bool,
    pub max_results: usize,
}

impl Default for PointerQuery {
    fn default() -> Self {
        PointerQuery { target: 0, max_offset: 0, static_only: false, writable_only: false, max_results: 100_000 }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PointerHit {
    /// Where the pointer is stored.
    #[serde(with = "hexaddr")]
    pub addr: Addr,
    #[serde(with = "hexaddr")]
    pub value: Addr,
    /// `target - value`.
    pub offset: u64,
    /// `module+offset` of `addr` for static pointers.
    pub module: Option<String>,
}

/// "Find out what addresses point to this": pointer-aligned values in readable memory that
/// point to `target` (or up to `max_offset` below it). Parallel; sorted by address.
pub fn find_pointers(p: &dyn Process, q: &PointerQuery, progress: &Progress) -> Result<Vec<PointerHit>> {
    let ps = p.pointer_size();
    let mods = p.modules().unwrap_or_default();
    let in_mod = |a: Addr| mods.iter().any(|m| a >= m.base && a - m.base < m.size);
    let mut chunks: Vec<(Addr, u64)> = p
        .regions()?
        .into_iter()
        .filter(|r| r.prot.r && (r.prot.w || !q.writable_only))
        .filter(|r| !q.static_only || in_mod(r.start))
        .flat_map(|r| {
            let end = r.start.saturating_add(r.size);
            (0..r.size.div_ceil(CHUNK)).map(move |i| {
                let s = r.start + i * CHUNK;
                (s, (end - s).min(CHUNK))
            })
        })
        .collect();
    progress.start(chunks.iter().map(|c| c.1).sum());
    let lo = q.target.saturating_sub(q.max_offset);
    // Batches in address order, so scanning stops as soon as the lowest `max_results` hits
    // are known instead of collecting every hit first.
    chunks.sort_unstable();
    let mut hits: Vec<PointerHit> = Vec::new();
    for batch in chunks.chunks(rayon::current_num_threads().max(1) * 4) {
        if hits.len() >= q.max_results {
            break;
        }
        let found: Vec<Vec<PointerHit>> = batch
            .par_iter()
            .map(|&(s, n)| {
                progress.check()?;
                let b = crate::read_some(p, s, n as usize);
                let mut out = Vec::new();
                let skew = ((ps as u64 - s % ps as u64) % ps as u64) as usize;
                for (i, w) in b.get(skew..).unwrap_or_default().chunks_exact(ps).enumerate() {
                    let mut v = [0u8; 8];
                    v[..ps].copy_from_slice(w);
                    let v = u64::from_le_bytes(v);
                    if v != 0 && v >= lo && v <= q.target {
                        let addr = s + (skew + i * ps) as u64;
                        out.push(PointerHit { addr, value: v, offset: q.target - v, module: None });
                        if out.len() >= q.max_results {
                            break;
                        }
                    }
                }
                progress.add(n);
                progress.add_found(out.len() as u64);
                Ok(out)
            })
            .collect::<Result<_>>()?;
        hits.extend(found.into_iter().flatten());
    }
    hits.sort_by_key(|h| h.addr);
    hits.truncate(q.max_results);
    for h in &mut hits {
        h.module = module_offset(&mods, h.addr);
    }
    Ok(hits)
}
