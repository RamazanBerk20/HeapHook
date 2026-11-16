//! On-disk result files: paging, rescan, sort/merge.
use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use hh_core::{Addr, Error, Process, Result};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::map::PointerMap;
use crate::path::{Bases, PointerPath, walk};
use crate::{MAX_LEVEL, Progress};

/// Fixed-size records (read only; written by HeapHook before 1.0).
const MAGIC_V1: &[u8; 8] = b"HHPTRS01";
/// Variable-length records, an index and a trailer.
const MAGIC_V2: &[u8; 8] = b"HHPTRS02";
/// Base index meaning "absolute address".
pub(crate) const ABS: u32 = u32::MAX;
/// Records per read batch.
const BATCH: usize = 1 << 16;
/// The v2 index holds the byte offset of every `INDEX_STEP`-th record.
const INDEX_STEP: u64 = 4096;
/// Smallest v2 record: base, base offset and level, one byte each.
const MIN_REC: u64 = 3;
/// Records sorted in memory per run of the external merge sort (~150 bytes each).
const RUN: usize = 1 << 18;
/// Most runs merged at once (open files).
const FAN: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResultHeader {
    pub pointer_size: usize,
    pub max_level: usize,
    /// The address the paths lead to.
    pub target: Addr,
    /// Base names records refer to by index.
    pub bases: Vec<String>,
}

fn rec_size(max_level: usize) -> usize {
    13 + 4 * max_level
}

fn put_var(buf: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        buf.push(v as u8 | 0x80);
        v >>= 7;
    }
    buf.push(v as u8);
}

fn zigzag(v: i64) -> u64 {
    ((v << 1) ^ (v >> 63)) as u64
}

fn unzigzag(u: u64) -> i64 {
    (u >> 1) as i64 ^ -((u & 1) as i64)
}

/// Appends one v2 record: varint base (0 = absolute, else index + 1), zigzag varint base
/// offset, u8 level, zigzag varint offsets.
pub(crate) fn encode(buf: &mut Vec<u8>, base: u32, base_off: i64, offs: impl ExactSizeIterator<Item = i64>) {
    put_var(buf, if base == ABS { 0 } else { base as u64 + 1 });
    put_var(buf, zigzag(base_off));
    buf.push(offs.len() as u8);
    for o in offs {
        put_var(buf, zigzag(o));
    }
}

fn corrupt() -> Error {
    Error::Parse("corrupt pointer result record".into())
}

/// One decoded record, without allocating.
#[derive(Clone, Copy)]
pub(crate) struct Rec {
    base: u32,
    base_off: i64,
    n: usize,
    offs: [i64; MAX_LEVEL],
}

impl Rec {
    fn offsets(&self) -> &[i64] {
        &self.offs[..self.n]
    }
}

fn decode_v1(r: &[u8], max_level: usize, nbases: usize) -> Result<Rec> {
    let base = u32::from_le_bytes(r[0..4].try_into().map_err(|_| corrupt())?);
    let base_off = i64::from_le_bytes(r[4..12].try_into().map_err(|_| corrupt())?);
    let n = r[12] as usize;
    if n > max_level || (base != ABS && base as usize >= nbases) {
        return Err(corrupt());
    }
    let mut offs = [0i64; MAX_LEVEL];
    for (i, o) in offs.iter_mut().take(n).enumerate() {
        let p = 13 + 4 * i;
        *o = i32::from_le_bytes(r[p..p + 4].try_into().map_err(|_| corrupt())?) as i64;
    }
    Ok(Rec { base, base_off, n, offs })
}

/// Decodes a v2 record from `next_byte`; at most 10 bytes per varint.
fn decode_v2(mut next_byte: impl FnMut() -> Result<u8>, max_level: usize, nbases: usize) -> Result<Rec> {
    fn var(next_byte: &mut impl FnMut() -> Result<u8>) -> Result<u64> {
        let mut v = 0u64;
        for i in 0..10 {
            let x = next_byte()?;
            v |= u64::from(x & 0x7f) << (7 * i);
            if x & 0x80 == 0 {
                return Ok(v);
            }
        }
        Err(corrupt())
    }
    let mut var = || var(&mut next_byte);
    let base = match var()? {
        0 => ABS,
        b if b <= nbases as u64 => (b - 1) as u32,
        _ => return Err(corrupt()),
    };
    let base_off = unzigzag(var()?);
    let n = var()? as usize;
    if n > max_level {
        return Err(corrupt());
    }
    let mut offs = [0i64; MAX_LEVEL];
    for o in offs.iter_mut().take(n) {
        *o = unzigzag(var()?);
    }
    Ok(Rec { base, base_off, n, offs })
}

/// Length of the v2 record at the start of `b`.
fn rec_len(b: &[u8]) -> Result<usize> {
    let mut p = 0;
    decode_v2(
        || {
            let x = *b.get(p).ok_or_else(corrupt)?;
            p += 1;
            Ok(x)
        },
        MAX_LEVEL,
        u32::MAX as usize - 1,
    )?;
    Ok(p)
}

/// Writes a v2 result file.
pub(crate) struct Writer {
    w: BufWriter<File>,
    /// Bytes of records written.
    pos: u64,
    count: u64,
    index: Vec<u64>,
    scratch: Vec<u8>,
}

impl Writer {
    pub fn create(path: &Path, h: &ResultHeader) -> Result<Self> {
        let json = serde_json::to_vec(h).map_err(|e| Error::Other(e.to_string()))?;
        let mut w = BufWriter::with_capacity(1 << 20, File::create(path)?);
        w.write_all(MAGIC_V2)?;
        w.write_all(&(json.len() as u32).to_le_bytes())?;
        w.write_all(&json)?;
        Ok(Writer { w, pos: 0, count: 0, index: Vec::new(), scratch: Vec::new() })
    }

    /// `bytes` holds whole records made by [`encode`].
    pub fn write_encoded(&mut self, bytes: &[u8]) -> Result<()> {
        let mut p = 0;
        while p < bytes.len() {
            if self.count.is_multiple_of(INDEX_STEP) {
                self.index.push(self.pos + p as u64);
            }
            p += rec_len(&bytes[p..])?;
            self.count += 1;
        }
        self.w.write_all(bytes)?;
        self.pos += bytes.len() as u64;
        Ok(())
    }

    fn push(&mut self, base: u32, base_off: i64, offs: &[i64]) -> Result<()> {
        let mut s = std::mem::take(&mut self.scratch);
        s.clear();
        encode(&mut s, base, base_off, offs.iter().copied());
        let r = self.write_encoded(&s);
        self.scratch = s;
        r
    }

    /// Writes the index and trailer (u64 count, u64 index offset); returns the count.
    pub fn finish(mut self) -> Result<u64> {
        for o in &self.index {
            self.w.write_all(&o.to_le_bytes())?;
        }
        self.w.write_all(&self.count.to_le_bytes())?;
        self.w.write_all(&self.pos.to_le_bytes())?;
        self.w.flush()?;
        Ok(self.count)
    }
}

/// A result file on disk; reads go to the file, nothing is cached but the v2 index
/// (8 bytes per 4096 paths).
#[derive(Debug, Clone)]
pub struct ResultFile {
    path: PathBuf,
    pub header: ResultHeader,
    data_start: u64,
    count: u64,
    /// v2 files: byte offsets of every [`INDEX_STEP`]-th record; `None` = v1.
    index: Option<Vec<u64>>,
}

/// One row of the results table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResultRow {
    pub path: PointerPath,
    /// CE-style text, e.g. `[["game.exe"+001A2B3C]+10]+8`.
    pub text: String,
    /// Where the path leads now; `None` if a hop is unreadable.
    pub address: Option<Addr>,
    /// Pointer-sized value at `address`.
    pub value: Option<u64>,
}

/// What a rescan resolves paths against.
#[derive(Clone, Copy)]
pub enum Source<'a> {
    /// A process; `THREADSTACK<n>` beyond the main thread's tagged stack is not resolved.
    Process(&'a dyn Process),
    Map(&'a PointerMap),
    /// A process on this machine: every thread's stack resolves (see [`crate::thread_stacks`]).
    LocalProcess(&'a dyn Process),
}

/// Filters for a rescan. Paths that do not fully resolve in the source are always dropped.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RescanOptions {
    /// The path must lead here (e.g. the value's new address after a restart).
    pub target: Option<Addr>,
    /// The bytes at the end of the path must equal these (needs a process source).
    pub value: Option<Vec<u8>>,
    /// The resolved base address must be in `[start, end)`.
    pub base_range: Option<(Addr, Addr)>,
    /// The path must start / end with exactly these offsets.
    pub starts_with: Vec<i64>,
    pub ends_with: Vec<i64>,
    /// Drop paths longer than this; 0 = any.
    pub max_level: usize,
}

/// Reads records in file order from some record on.
struct Reader {
    r: BufReader<File>,
    v2: bool,
    max_level: usize,
    nbases: usize,
    left: u64,
    buf: Vec<u8>,
}

impl Reader {
    fn next(&mut self) -> Result<Option<Rec>> {
        if self.left == 0 {
            return Ok(None);
        }
        self.left -= 1;
        let eof = |e: std::io::Error| if e.kind() == std::io::ErrorKind::UnexpectedEof { corrupt() } else { e.into() };
        if !self.v2 {
            self.buf.resize(rec_size(self.max_level), 0);
            self.r.read_exact(&mut self.buf).map_err(eof)?;
            return decode_v1(&self.buf, self.max_level, self.nbases).map(Some);
        }
        let r = &mut self.r;
        let byte = || -> Result<u8> {
            let mut b = [0u8];
            r.read_exact(&mut b).map_err(eof)?;
            Ok(b[0])
        };
        decode_v2(byte, self.max_level, self.nbases).map(Some)
    }

    /// Up to `n` records.
    fn take(&mut self, n: usize) -> Result<Vec<Rec>> {
        let mut v = Vec::with_capacity(n.min(BATCH).min(self.left as usize));
        while v.len() < n {
            match self.next()? {
                Some(r) => v.push(r),
                None => break,
            }
        }
        Ok(v)
    }
}

impl ResultFile {
    /// Opens a result file of either format.
    pub fn open(path: &Path) -> Result<Self> {
        let mut f = File::open(path)?;
        let len = f.metadata()?.len();
        let bad = || Error::Parse("not a HeapHook pointer result file".into());
        let mut head = [0u8; 12];
        f.read_exact(&mut head)?;
        let v2 = match &head[..8] {
            m if m == MAGIC_V1 => false,
            m if m == MAGIC_V2 => true,
            _ => return Err(bad()),
        };
        let hlen = u32::from_le_bytes([head[8], head[9], head[10], head[11]]) as u64;
        if 12 + hlen > len {
            return Err(bad());
        }
        let mut json = vec![0u8; hlen as usize];
        f.read_exact(&mut json)?;
        let header: ResultHeader = serde_json::from_slice(&json).map_err(|_| bad())?;
        if header.max_level == 0 || header.max_level > MAX_LEVEL || header.bases.len() >= ABS as usize {
            return Err(bad());
        }
        let data_start = 12 + hlen;
        let truncated = || Error::Parse("truncated pointer result file".into());
        if !v2 {
            let rec = rec_size(header.max_level) as u64;
            if !(len - data_start).is_multiple_of(rec) {
                return Err(truncated());
            }
            return Ok(ResultFile { path: path.to_owned(), header, data_start, count: (len - data_start) / rec, index: None });
        }
        let body = len.checked_sub(data_start + 16).ok_or_else(truncated)?;
        let mut t = [0u8; 16];
        f.seek(SeekFrom::Start(len - 16))?;
        f.read_exact(&mut t)?;
        let count = u64::from_le_bytes(t[..8].try_into().unwrap_or_default());
        let index_off = u64::from_le_bytes(t[8..].try_into().unwrap_or_default());
        let entries = count.div_ceil(INDEX_STEP);
        if index_off > body || count > index_off / MIN_REC || Some(body - index_off) != entries.checked_mul(8) {
            return Err(truncated());
        }
        let mut raw = vec![0u8; (entries * 8) as usize];
        f.seek(SeekFrom::Start(data_start + index_off))?;
        f.read_exact(&mut raw)?;
        let index: Vec<u64> = raw.chunks_exact(8).map(|c| u64::from_le_bytes(c.try_into().unwrap_or_default())).collect();
        if index.first().is_some_and(|&x| x != 0) || index.windows(2).any(|w| w[0] >= w[1]) || index.last().is_some_and(|&x| x >= index_off) {
            return Err(bad());
        }
        Ok(ResultFile { path: path.to_owned(), header, data_start, count, index: Some(index) })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
    /// Number of paths.
    pub fn len(&self) -> u64 {
        self.count
    }
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
    /// True for files in the compact (v2) format, which every new file uses.
    pub fn is_compact(&self) -> bool {
        self.index.is_some()
    }

    fn to_path(&self, r: &Rec) -> PointerPath {
        PointerPath {
            module: (r.base != ABS).then(|| self.header.bases[r.base as usize].clone()),
            base_offset: r.base_off,
            offsets: r.offsets().to_vec(),
        }
    }

    /// A reader positioned at record `offset` (clamped to the end).
    fn reader_at(&self, offset: u64) -> Result<Reader> {
        let offset = offset.min(self.count);
        let mut f = File::open(&self.path)?;
        let (pos, skip) = match &self.index {
            None => (offset * rec_size(self.header.max_level) as u64, 0),
            Some(ix) => match ix.get((offset / INDEX_STEP) as usize) {
                Some(&p) => (p, offset % INDEX_STEP),
                None => (0, 0),
            },
        };
        f.seek(SeekFrom::Start(self.data_start + pos))?;
        let mut r = Reader {
            r: BufReader::with_capacity(64 << 10, f),
            v2: self.index.is_some(),
            max_level: self.header.max_level,
            nbases: self.header.bases.len(),
            left: self.count - offset + skip,
            buf: Vec::new(),
        };
        for _ in 0..skip {
            r.next()?;
        }
        Ok(r)
    }

    /// Paths `[offset, offset + limit)`.
    pub fn read(&self, offset: u64, limit: usize) -> Result<Vec<PointerPath>> {
        Ok(self.reader_at(offset)?.take(limit)?.iter().map(|r| self.to_path(r)).collect())
    }

    /// A page of rows, resolved against `process` when given.
    pub fn results(&self, offset: u64, limit: usize, process: Option<&dyn Process>) -> Result<Vec<ResultRow>> {
        self.results_ex(offset, limit, process, false)
    }

    /// [`ResultFile::results`]; `local`: the process runs on this machine, so every
    /// thread's stack resolves (see [`crate::thread_stacks`]).
    pub fn results_ex(&self, offset: u64, limit: usize, process: Option<&dyn Process>, local: bool) -> Result<Vec<ResultRow>> {
        let paths = self.read(offset, limit)?;
        let bases = process.map(|p| Bases::of_process_ex(p, local)).transpose()?;
        Ok(paths
            .into_iter()
            .map(|path| {
                let address = process.zip(bases.as_ref()).and_then(|(p, b)| {
                    let base = b.addr_of(path.module.as_deref())?;
                    walk(base.wrapping_add_signed(path.base_offset), &path.offsets, |a| p.read_ptr(a).ok())
                });
                let value = process.zip(address).and_then(|(p, a)| p.read_ptr(a).ok());
                ResultRow { text: path.to_string(), path, address, value }
            })
            .collect())
    }

    /// Calls `f` with batches of records, in file order; honours pause and cancel.
    fn batches(&self, progress: &Progress, mut f: impl FnMut(&[Rec]) -> Result<()>) -> Result<()> {
        let mut r = self.reader_at(0)?;
        let mut done = 0;
        while done < self.count {
            progress.wait_if_paused();
            if progress.is_cancelled() {
                break;
            }
            let recs = r.take(BATCH)?;
            if recs.is_empty() {
                return Err(corrupt());
            }
            f(&recs)?;
            done += recs.len() as u64;
            progress.done.store(done, std::sync::atomic::Ordering::Relaxed);
        }
        Ok(())
    }

    /// Writes the paths that pass `o` in `source` to `out`. On cancel the paths checked
    /// so far are kept.
    pub fn rescan(&self, source: Source<'_>, o: &RescanOptions, out: &Path, progress: &Progress) -> Result<ResultFile> {
        let bases = match source {
            Source::Process(p) => Bases::of_process(p)?,
            Source::LocalProcess(p) => Bases::of_process_ex(p, true)?,
            Source::Map(m) => m.bases(),
        };
        if let (Some(_), Source::Map(_)) = (&o.value, source) {
            return Err(Error::Unsupported("value filter needs a live process"));
        }
        let h = &self.header;
        let addrs: Vec<Option<Addr>> = h.bases.iter().map(|n| bases.addr_of(Some(n))).collect();
        let read = |a: Addr| match source {
            Source::Process(p) | Source::LocalProcess(p) => p.read_ptr(a).ok(),
            Source::Map(m) => m.read_ptr(a),
        };
        let keep = |r: &Rec| -> bool {
            let offs = r.offsets();
            if (o.max_level > 0 && r.n > o.max_level) || !offs.starts_with(&o.starts_with) || !offs.ends_with(&o.ends_with) {
                return false;
            }
            let base = if r.base == ABS { Some(0) } else { addrs[r.base as usize] };
            let Some(base) = base.map(|b| b.wrapping_add_signed(r.base_off)) else {
                return false;
            };
            if o.base_range.is_some_and(|(s, e)| base < s || base >= e) {
                return false;
            }
            let Some(end) = walk(base, offs, read) else {
                return false;
            };
            if o.target.is_some_and(|t| t != end) {
                return false;
            }
            match (&o.value, source) {
                (Some(v), Source::Process(p) | Source::LocalProcess(p)) => {
                    let mut b = vec![0u8; v.len()];
                    p.read_exact(end, &mut b).is_ok() && b == *v
                }
                _ => true,
            }
        };
        let mut header = h.clone();
        header.target = o.target.unwrap_or(h.target);
        let mut w = Writer::create(out, &header)?;
        progress.start(self.count);
        self.batches(progress, |recs| {
            let kept: Vec<&Rec> = recs.par_iter().filter(|r| keep(r)).collect();
            progress.found.fetch_add(kept.len() as u64, std::sync::atomic::Ordering::Relaxed);
            kept.iter().try_for_each(|r| w.push(r.base, r.base_off, r.offsets()))
        })?;
        w.finish()?;
        ResultFile::open(out)
    }

    /// This file sorted by level, base name, base offset, offsets; duplicates removed.
    pub fn sorted(&self, out: &Path) -> Result<ResultFile> {
        merge(&[self], out)
    }
}

/// Sort key: level, base (index into sorted names), base offset, offsets (zero padded).
type Key = (u8, u32, i64, [i64; MAX_LEVEL]);

/// Run files of an external sort, removed when dropped.
struct Runs(Vec<PathBuf>);

impl Drop for Runs {
    fn drop(&mut self) {
        for p in &self.0 {
            let _ = std::fs::remove_file(p);
        }
    }
}

/// Merges result files into one sorted, de-duplicated file. All inputs must have the same
/// pointer size; the target of the first one is kept. External merge sort: memory stays
/// bounded (runs of 2^18 paths sorted in RAM, written next to `out`, then merged), so
/// `out` may be one of the inputs.
pub fn merge(inputs: &[&ResultFile], out: &Path) -> Result<ResultFile> {
    merge_runs(inputs, out, RUN)
}

pub(crate) fn merge_runs(inputs: &[&ResultFile], out: &Path, run: usize) -> Result<ResultFile> {
    let first = inputs.first().ok_or_else(|| Error::Other("nothing to merge".into()))?;
    if inputs.iter().any(|f| f.header.pointer_size != first.header.pointer_size) {
        return Err(Error::Other("pointer sizes differ".into()));
    }
    let mut names: Vec<String> = inputs.iter().flat_map(|f| f.header.bases.iter().cloned()).collect();
    names.sort();
    names.dedup();
    let max_level = inputs.iter().map(|f| f.header.max_level).max().unwrap_or(1);
    let header = ResultHeader { pointer_size: first.header.pointer_size, max_level, target: first.header.target, bases: names };
    let stem = out.file_name().ok_or_else(|| Error::Other("bad output path".into()))?.to_string_lossy().into_owned();
    let mut runs = Runs(Vec::new());
    let mut n_runs = 0;
    let mut next_run = || {
        n_runs += 1;
        out.with_file_name(format!("{stem}.run{n_runs}"))
    };
    let write = |path: &Path, keys: &mut dyn Iterator<Item = Key>| -> Result<()> {
        let mut w = Writer::create(path, &header)?;
        let mut last: Option<Key> = None;
        for k in keys {
            if last != Some(k) {
                w.push(k.1, k.2, &k.3[..k.0 as usize])?;
                last = Some(k);
            }
        }
        w.finish().map(drop)
    };
    // Phase 1: sorted runs; every input is fully read before `out` is created.
    let mut buf: Vec<Key> = Vec::new();
    for f in inputs {
        let map: Vec<u32> = f.header.bases.iter().map(|n| header.bases.binary_search(n).map(|i| i as u32).unwrap_or(ABS)).collect();
        f.batches(&Progress::new(), |recs| {
            for r in recs {
                let base = if r.base == ABS { ABS } else { map[r.base as usize] };
                buf.push((r.n as u8, base, r.base_off, r.offs));
                if buf.len() >= run {
                    buf.par_sort_unstable();
                    let p = next_run();
                    runs.0.push(p.clone());
                    write(&p, &mut buf.drain(..))?;
                }
            }
            Ok(())
        })?;
    }
    if runs.0.is_empty() {
        // Everything fit in memory: no run files.
        buf.par_sort_unstable();
        write(out, &mut buf.drain(..))?;
        return ResultFile::open(out);
    }
    if !buf.is_empty() {
        buf.par_sort_unstable();
        let p = next_run();
        runs.0.push(p.clone());
        write(&p, &mut buf.drain(..))?;
    }
    drop(buf);
    // Phase 2: k-way merges, at most FAN files at a time.
    while runs.0.len() > 1 {
        let group = Runs(runs.0.drain(..runs.0.len().min(FAN)).collect());
        let dst = if runs.0.is_empty() { out.to_path_buf() } else { next_run() };
        let files = group.0.iter().map(|p| ResultFile::open(p)).collect::<Result<Vec<_>>>()?;
        let mut readers = files.iter().map(|f| f.reader_at(0)).collect::<Result<Vec<_>>>()?;
        let mut heap = BinaryHeap::new();
        for (i, r) in readers.iter_mut().enumerate() {
            if let Some(x) = r.next()? {
                heap.push(Reverse((key(&x), i)));
            }
        }
        let mut err = None;
        let mut it = std::iter::from_fn(|| {
            let Reverse((k, i)) = heap.pop()?;
            match readers[i].next() {
                Ok(Some(x)) => heap.push(Reverse((key(&x), i))),
                Ok(None) => {}
                Err(e) => {
                    err = Some(e);
                    heap.clear();
                }
            }
            Some(k)
        });
        let written = write(&dst, &mut it);
        if let Some(e) = err {
            return Err(e);
        }
        written?;
        // Close the runs before deleting them (Windows cannot delete open files).
        drop((readers, files, group));
        if dst != out {
            runs.0.push(dst);
        }
    }
    if let Some(p) = runs.0.pop() {
        std::fs::rename(&p, out)?;
    }
    ResultFile::open(out)
}

/// Key of a record already in merged-header base numbering.
fn key(r: &Rec) -> Key {
    (r.n as u8, r.base, r.base_off, r.offs)
}
