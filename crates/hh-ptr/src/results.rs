//! On-disk result files: paging, rescan, sort/merge.
use std::fs::File;
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use hh_core::{Addr, Error, Process, Result};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::map::PointerMap;
use crate::path::{Bases, PointerPath, walk};
use crate::{MAX_LEVEL, Progress};

const MAGIC: &[u8; 8] = b"HHPTRS01";
/// Base index meaning "absolute address".
pub(crate) const ABS: u32 = u32::MAX;
/// Records per read batch.
const BATCH: u64 = 1 << 16;

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

pub(crate) fn encode(
    buf: &mut Vec<u8>,
    max_level: usize,
    base: u32,
    base_off: i64,
    offs: impl ExactSizeIterator<Item = i64>,
) {
    buf.extend_from_slice(&base.to_le_bytes());
    buf.extend_from_slice(&base_off.to_le_bytes());
    buf.push(offs.len() as u8);
    let n = offs.len();
    for o in offs {
        buf.extend_from_slice(&(o as i32).to_le_bytes());
    }
    buf.resize(buf.len() + 4 * (max_level - n), 0);
}

/// One decoded record, without allocating.
#[derive(Clone, Copy)]
struct Rec {
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

fn decode(r: &[u8], max_level: usize, nbases: usize) -> Result<Rec> {
    let bad = || Error::Parse("corrupt pointer result record".into());
    let base = u32::from_le_bytes(r[0..4].try_into().map_err(|_| bad())?);
    let base_off = i64::from_le_bytes(r[4..12].try_into().map_err(|_| bad())?);
    let n = r[12] as usize;
    if n > max_level || (base != ABS && base as usize >= nbases) {
        return Err(bad());
    }
    let mut offs = [0i64; MAX_LEVEL];
    for (i, o) in offs.iter_mut().take(n).enumerate() {
        let p = 13 + 4 * i;
        *o = i32::from_le_bytes(r[p..p + 4].try_into().map_err(|_| bad())?) as i64;
    }
    Ok(Rec {
        base,
        base_off,
        n,
        offs,
    })
}

pub(crate) struct Writer {
    w: BufWriter<File>,
    rec: usize,
    count: u64,
}

impl Writer {
    pub fn create(path: &Path, h: &ResultHeader) -> Result<Self> {
        let json = serde_json::to_vec(h).map_err(|e| Error::Other(e.to_string()))?;
        let mut w = BufWriter::with_capacity(1 << 20, File::create(path)?);
        w.write_all(MAGIC)?;
        w.write_all(&(json.len() as u32).to_le_bytes())?;
        w.write_all(&json)?;
        Ok(Writer {
            w,
            rec: rec_size(h.max_level),
            count: 0,
        })
    }
    /// `bytes` holds whole records.
    pub fn write_raw(&mut self, bytes: &[u8]) -> Result<()> {
        self.w.write_all(bytes)?;
        self.count += (bytes.len() / self.rec) as u64;
        Ok(())
    }
    /// Returns the record count.
    pub fn finish(mut self) -> Result<u64> {
        self.w.flush()?;
        Ok(self.count)
    }
}

/// A result file on disk; reads go to the file, nothing is cached.
#[derive(Debug, Clone)]
pub struct ResultFile {
    path: PathBuf,
    pub header: ResultHeader,
    data_start: u64,
    count: u64,
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
    Process(&'a dyn Process),
    Map(&'a PointerMap),
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

impl ResultFile {
    pub fn open(path: &Path) -> Result<Self> {
        let mut f = File::open(path)?;
        let len = f.metadata()?.len();
        let bad = || Error::Parse("not a HeapHook pointer result file".into());
        let mut head = [0u8; 12];
        f.read_exact(&mut head)?;
        if &head[..8] != MAGIC {
            return Err(bad());
        }
        let hlen = u32::from_le_bytes([head[8], head[9], head[10], head[11]]) as u64;
        if 12 + hlen > len {
            return Err(bad());
        }
        let mut json = vec![0u8; hlen as usize];
        f.read_exact(&mut json)?;
        let header: ResultHeader = serde_json::from_slice(&json).map_err(|_| bad())?;
        if header.max_level == 0 || header.max_level > MAX_LEVEL {
            return Err(bad());
        }
        let data_start = 12 + hlen;
        let rec = rec_size(header.max_level) as u64;
        if !(len - data_start).is_multiple_of(rec) {
            return Err(Error::Parse("truncated pointer result file".into()));
        }
        Ok(ResultFile {
            path: path.to_owned(),
            header,
            data_start,
            count: (len - data_start) / rec,
        })
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

    fn rec(&self) -> usize {
        rec_size(self.header.max_level)
    }

    fn to_path(&self, r: &Rec) -> PointerPath {
        PointerPath {
            module: (r.base != ABS).then(|| self.header.bases[r.base as usize].clone()),
            base_offset: r.base_off,
            offsets: r.offsets().to_vec(),
        }
    }

    /// Raw records `[offset, offset + limit)`, clamped to the file.
    fn raw(&self, f: &mut File, offset: u64, limit: u64) -> Result<Vec<u8>> {
        let n = limit.min(self.count.saturating_sub(offset));
        if n == 0 {
            return Ok(Vec::new());
        }
        let mut buf = vec![0u8; n as usize * self.rec()];
        f.seek(SeekFrom::Start(
            self.data_start + offset * self.rec() as u64,
        ))?;
        f.read_exact(&mut buf)?;
        Ok(buf)
    }

    /// Paths `[offset, offset + limit)`.
    pub fn read(&self, offset: u64, limit: usize) -> Result<Vec<PointerPath>> {
        let buf = self.raw(&mut File::open(&self.path)?, offset, limit as u64)?;
        buf.chunks_exact(self.rec())
            .map(|r| Ok(self.to_path(&decode(r, self.header.max_level, self.header.bases.len())?)))
            .collect()
    }

    /// A page of rows, resolved against `process` when given.
    pub fn results(
        &self,
        offset: u64,
        limit: usize,
        process: Option<&dyn Process>,
    ) -> Result<Vec<ResultRow>> {
        let paths = self.read(offset, limit)?;
        let bases = process.map(Bases::of_process).transpose()?;
        Ok(paths
            .into_iter()
            .map(|path| {
                let address = process.zip(bases.as_ref()).and_then(|(p, b)| {
                    let base = b.addr_of(path.module.as_deref())?;
                    walk(
                        base.wrapping_add_signed(path.base_offset),
                        &path.offsets,
                        |a| p.read_ptr(a).ok(),
                    )
                });
                let value = process.zip(address).and_then(|(p, a)| p.read_ptr(a).ok());
                ResultRow {
                    text: path.to_string(),
                    path,
                    address,
                    value,
                }
            })
            .collect())
    }

    /// Calls `f` with batches of raw records, in file order.
    fn batches(&self, progress: &Progress, mut f: impl FnMut(&[u8]) -> Result<()>) -> Result<()> {
        let mut file = File::open(&self.path)?;
        let mut off = 0;
        while off < self.count && !progress.is_cancelled() {
            f(&self.raw(&mut file, off, BATCH)?)?;
            off += BATCH;
            progress
                .done
                .store(off.min(self.count), std::sync::atomic::Ordering::Relaxed);
        }
        Ok(())
    }

    /// Writes the paths that pass `o` in `source` to `out`. On cancel the paths checked
    /// so far are kept.
    pub fn rescan(
        &self,
        source: Source<'_>,
        o: &RescanOptions,
        out: &Path,
        progress: &Progress,
    ) -> Result<ResultFile> {
        let bases = match source {
            Source::Process(p) => Bases::of_process(p)?,
            Source::Map(m) => m.bases(),
        };
        if let (Some(_), Source::Map(_)) = (&o.value, source) {
            return Err(Error::Unsupported("value filter needs a live process"));
        }
        let h = &self.header;
        let addrs: Vec<Option<Addr>> = h.bases.iter().map(|n| bases.addr_of(Some(n))).collect();
        let read = |a: Addr| match source {
            Source::Process(p) => p.read_ptr(a).ok(),
            Source::Map(m) => m.read_ptr(a),
        };
        let keep = |r: &Rec| -> bool {
            let offs = r.offsets();
            if (o.max_level > 0 && r.n > o.max_level)
                || !offs.starts_with(&o.starts_with)
                || !offs.ends_with(&o.ends_with)
            {
                return false;
            }
            let base = if r.base == ABS {
                Some(0)
            } else {
                addrs[r.base as usize]
            };
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
                (Some(v), Source::Process(p)) => {
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
        let (rec, ml, nb) = (self.rec(), h.max_level, h.bases.len());
        self.batches(progress, |buf| {
            let kept: Vec<&[u8]> = buf
                .par_chunks_exact(rec)
                .filter(|r| decode(r, ml, nb).is_ok_and(|d| keep(&d)))
                .collect();
            progress
                .found
                .fetch_add(kept.len() as u64, std::sync::atomic::Ordering::Relaxed);
            kept.iter().try_for_each(|r| w.write_raw(r))
        })?;
        w.finish()?;
        ResultFile::open(out)
    }

    /// This file sorted by level, base name, base offset, offsets; duplicates removed.
    pub fn sorted(&self, out: &Path) -> Result<ResultFile> {
        merge(&[self], out)
    }
}

/// Merges result files into one sorted, de-duplicated file. All inputs must have the same
/// pointer size; the target of the first one is kept.
// shortcut: sorts in RAM (~90 bytes per path); switch to an external merge sort if files
// with hundreds of millions of paths need sorting.
pub fn merge(inputs: &[&ResultFile], out: &Path) -> Result<ResultFile> {
    let first = inputs
        .first()
        .ok_or_else(|| Error::Other("nothing to merge".into()))?;
    if inputs
        .iter()
        .any(|f| f.header.pointer_size != first.header.pointer_size)
    {
        return Err(Error::Other("pointer sizes differ".into()));
    }
    let mut names: Vec<String> = inputs
        .iter()
        .flat_map(|f| f.header.bases.iter().cloned())
        .collect();
    names.sort();
    names.dedup();
    let max_level = inputs.iter().map(|f| f.header.max_level).max().unwrap_or(1);
    let mut all: Vec<(u8, u32, i64, [i32; MAX_LEVEL])> = Vec::new();
    for f in inputs {
        let map: Vec<u32> = f
            .header
            .bases
            .iter()
            .map(|n| names.binary_search(n).map(|i| i as u32).unwrap_or(ABS))
            .collect();
        let (rec, ml, nb) = (f.rec(), f.header.max_level, f.header.bases.len());
        f.batches(&Progress::new(), |buf| {
            for r in buf.chunks_exact(rec) {
                let d = decode(r, ml, nb)?;
                let mut offs = [0i32; MAX_LEVEL];
                for (o, &x) in offs.iter_mut().zip(d.offsets()) {
                    *o = x as i32;
                }
                let base = if d.base == ABS {
                    ABS
                } else {
                    map[d.base as usize]
                };
                all.push((d.n as u8, base, d.base_off, offs));
            }
            Ok(())
        })?;
    }
    all.par_sort_unstable();
    all.dedup();
    let header = ResultHeader {
        pointer_size: first.header.pointer_size,
        max_level,
        target: first.header.target,
        bases: names,
    };
    let mut w = Writer::create(out, &header)?;
    let mut buf = Vec::new();
    for (n, base, off, offs) in &all {
        encode(
            &mut buf,
            max_level,
            *base,
            *off,
            offs[..*n as usize].iter().map(|&o| o as i64),
        );
        if buf.len() >= 1 << 20 {
            w.write_raw(&buf)?;
            buf.clear();
        }
    }
    w.write_raw(&buf)?;
    w.finish()?;
    ResultFile::open(out)
}
