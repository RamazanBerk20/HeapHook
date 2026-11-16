//! Result storage. A result set is a list of chunks, one per scanned work unit (<= a few MiB
//! of address space), each either
//! - `Dense`: a memory copy where the results are positions `p0 + k * align`, all of them
//!   (unknown initial value) or those marked in a bitmap (one bit per position, or one
//!   type-mask byte per position for masked sets). Previous values are read from the copy,
//!   first values from the first scan's copy, which every later dense chunk shares. A next
//!   scan over a dense chunk stays dense while that is smaller than packing the survivors,
//!   and an `unchanged` scan even reuses the previous copy, so "unknown, then compare,
//!   compare, ..." costs about one snapshot plus bitmaps.
//! - `Packed`: columns `[u32 offset; n] [u8 type mask; n if masked] [prev; n*W] [first; n*W]`.
//!
//! Payloads are reference counted (`Blob` is cheap to clone), so undo, saved scans and dense
//! chunks share them. Payloads move to an anonymous temp file once the set holds more than
//! its memory limit, so result counts are bounded by disk, not RAM.
use std::borrow::Cow;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use hh_core::{Addr, Error, Result};

#[derive(Clone)]
pub(crate) enum Blob {
    Mem(Arc<Vec<u8>>),
    Disk { file: Arc<File>, off: u64, len: usize },
}

impl Blob {
    pub fn load(&self) -> Result<Cow<'_, [u8]>> {
        match self {
            Blob::Mem(v) => Ok(Cow::Borrowed(v)),
            Blob::Disk { file, off, len } => {
                let mut v = vec![0; *len];
                read_at(file, &mut v, *off)?;
                Ok(Cow::Owned(v))
            }
        }
    }
}

pub(crate) struct Spill {
    file: OnceLock<Arc<File>>,
    next: AtomicU64,
    used: AtomicU64,
    limit: u64,
    /// Explicit spill directory (`Scanner::set_spill_dir`); `None` = [`spill_dir`]'s choice.
    dir: Option<PathBuf>,
}

impl Spill {
    pub fn new(limit: u64) -> Self {
        Spill { file: OnceLock::new(), next: AtomicU64::new(0), used: AtomicU64::new(0), limit, dir: None }
    }
    pub fn in_dir(self, dir: Option<PathBuf>) -> Self {
        Spill { dir, ..self }
    }

    fn file(&self) -> Result<&Arc<File>> {
        if self.file.get().is_none() {
            // Anonymous (unlinked) file: nothing is left behind, even after a crash.
            let _ = self.file.set(Arc::new(tempfile::tempfile_in(spill_dir(self.dir.as_deref()))?));
        }
        self.file.get().ok_or_else(|| Error::Other("spill file".into()))
    }

    pub fn put(&self, v: Vec<u8>) -> Result<Blob> {
        let len = v.len() as u64;
        if self.used.fetch_add(len, Ordering::Relaxed) + len <= self.limit {
            return Ok(Blob::Mem(Arc::new(v)));
        }
        self.used.fetch_sub(len, Ordering::Relaxed);
        let off = self.next.fetch_add(len, Ordering::Relaxed);
        let file = self.file()?.clone();
        write_at(&file, &v, off)?;
        Ok(Blob::Disk { file, off, len: v.len() })
    }

    /// Bytes this set wrote to its temp file (shared payloads count where they were written).
    pub fn on_disk(&self) -> u64 {
        self.next.load(Ordering::Relaxed)
    }
}

/// Where spill files go: `explicit`, else `$HEAPHOOK_TMPDIR`, else the system temp dir unless
/// it is RAM-backed (tmpfs, the default /tmp on most Linux desktops, where "spilling" would
/// consume the very memory it should save): then `/var/tmp` or `~/.cache/heaphook`.
pub(crate) fn spill_dir(explicit: Option<&Path>) -> PathBuf {
    if let Some(d) = explicit {
        return d.to_path_buf();
    }
    if let Some(d) = std::env::var_os("HEAPHOOK_TMPDIR").filter(|d| !d.is_empty()) {
        return d.into();
    }
    let tmp = std::env::temp_dir();
    let Ok(mounts) = std::fs::read_to_string("/proc/self/mountinfo") else { return tmp };
    if !on_tmpfs(&mounts, &tmp) {
        return tmp;
    }
    let cache = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| Path::new(&h).join(".cache")))
        .map(|c| c.join("heaphook"));
    for d in [Some(PathBuf::from("/var/tmp")), cache].into_iter().flatten() {
        if std::fs::create_dir_all(&d).is_ok() && !on_tmpfs(&mounts, &d) && tempfile::tempfile_in(&d).is_ok() {
            return d;
        }
    }
    tmp
}

/// True if `path` lies on a tmpfs/ramfs mount according to `/proc/self/mountinfo` text.
fn on_tmpfs(mountinfo: &str, path: &Path) -> bool {
    let path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    // Longest mount point containing the path wins. Fields: id parent dev root mountpoint
    // options... - fstype source superoptions (mount points escape spaces as \040).
    mountinfo
        .lines()
        .filter_map(|l| {
            let (pre, post) = l.split_once(" - ")?;
            let mp = pre.split(' ').nth(4)?.replace("\\040", " ");
            Some((mp, post.split(' ').next()?.to_string()))
        })
        .filter(|(mp, _)| path.starts_with(mp))
        .max_by_key(|(mp, _)| mp.len())
        .is_some_and(|(_, fs)| fs == "tmpfs" || fs == "ramfs")
}

#[cfg(unix)]
fn write_at(f: &File, buf: &[u8], off: u64) -> std::io::Result<()> {
    std::os::unix::fs::FileExt::write_all_at(f, buf, off)
}
#[cfg(unix)]
fn read_at(f: &File, buf: &mut [u8], off: u64) -> std::io::Result<()> {
    std::os::unix::fs::FileExt::read_exact_at(f, buf, off)
}
#[cfg(windows)]
fn write_at(f: &File, mut buf: &[u8], mut off: u64) -> std::io::Result<()> {
    use std::os::windows::fs::FileExt;
    while !buf.is_empty() {
        let n = f.seek_write(buf, off)?;
        if n == 0 {
            return Err(std::io::ErrorKind::WriteZero.into());
        }
        buf = &buf[n..];
        off += n as u64;
    }
    Ok(())
}
#[cfg(windows)]
fn read_at(f: &File, mut buf: &mut [u8], mut off: u64) -> std::io::Result<()> {
    use std::os::windows::fs::FileExt;
    while !buf.is_empty() {
        let n = f.seek_read(buf, off)?;
        if n == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        buf = &mut buf[n..];
        off += n as u64;
    }
    Ok(())
}

#[derive(Clone)]
pub(crate) struct Dense {
    /// Memory copy (previous values); byte 0 is at chunk offset `cur_off`.
    pub cur: Blob,
    pub cur_off: usize,
    /// First-scan copy and its chunk offset; `None` = `cur` is the first scan.
    pub first: Option<(Blob, usize)>,
    /// `None` = every position is a result.
    pub bits: Option<Blob>,
    pub p0: usize,
    pub align: usize,
    pub npos: usize,
}

#[derive(Clone)]
pub(crate) enum ChunkKind {
    Dense(Dense),
    Packed { blob: Blob, shared_first: bool },
}

#[derive(Clone)]
pub(crate) struct Chunk {
    pub base: Addr,
    /// Exclusive end address of the chunk's entries.
    pub end: Addr,
    pub count: u64,
    pub kind: ChunkKind,
}

pub(crate) struct ResultSet {
    pub chunks: Vec<Chunk>,
    /// Global index of each chunk's first entry.
    pub starts: Vec<u64>,
    pub count: u64,
    /// Bytes stored per entry for previous/first values.
    pub width: usize,
    /// Entries carry a type mask ("all") or bit-offset mask (binary).
    pub masked: bool,
    /// Mask of an entry of a full dense chunk (every allowed type).
    pub full_mask: u8,
    pub spill: Spill,
}

/// The payloads of one chunk, loaded.
pub(crate) struct Loaded<'a> {
    a: Cow<'a, [u8]>,
    first: Option<Cow<'a, [u8]>>,
    bits: Option<Cow<'a, [u8]>>,
}

impl ResultSet {
    pub fn new(chunks: Vec<Chunk>, width: usize, masked: bool, full_mask: u8, spill: Spill) -> Self {
        let mut starts = Vec::with_capacity(chunks.len());
        let mut count = 0;
        for c in &chunks {
            starts.push(count);
            count += c.count;
        }
        ResultSet { chunks, starts, count, width, masked, full_mask, spill }
    }

    pub fn load<'a>(&self, c: &'a Chunk) -> Result<Loaded<'a>> {
        Ok(match &c.kind {
            ChunkKind::Dense(d) => Loaded {
                a: d.cur.load()?,
                first: d.first.as_ref().map(|(b, _)| b.load()).transpose()?,
                bits: d.bits.as_ref().map(Blob::load).transpose()?,
            },
            ChunkKind::Packed { blob, .. } => Loaded { a: blob.load()?, first: None, bits: None },
        })
    }

    pub fn view<'a>(&self, c: &Chunk, l: &'a Loaded<'_>) -> View<'a> {
        let n = c.count as usize;
        let (w, masked) = (self.width, self.masked);
        match &c.kind {
            ChunkKind::Dense(d) => View {
                bytes: &l.a,
                n,
                w,
                masked,
                full_mask: self.full_mask,
                dense: Some(DenseView {
                    p0: d.p0,
                    align: d.align,
                    npos: d.npos,
                    cur_off: d.cur_off,
                    first: l.first.as_deref().map(|f| (f, d.first.as_ref().map_or(0, |x| x.1))),
                    bits: l.bits.as_deref(),
                }),
                prev: 0,
                first: 0,
            },
            ChunkKind::Packed { shared_first, .. } => {
                let prev = 4 * n + if masked { n } else { 0 };
                let first = if *shared_first { prev } else { prev + w * n };
                View { bytes: &l.a, n, w, masked, full_mask: self.full_mask, dense: None, prev, first }
            }
        }
    }
}

struct DenseView<'a> {
    p0: usize,
    align: usize,
    npos: usize,
    cur_off: usize,
    first: Option<(&'a [u8], usize)>,
    bits: Option<&'a [u8]>,
}

/// A dense chunk's copies (each with the chunk offset of its byte 0) and bitmap.
pub(crate) struct DenseArrays<'a> {
    pub cur: (&'a [u8], usize),
    pub first: (&'a [u8], usize),
    pub bits: Option<&'a [u8]>,
    pub p0: usize,
    pub align: usize,
}

/// Decoded accessors over one loaded chunk. Entries are addressed by slot: the entry index
/// for packed chunks, the position index for dense ones (see [`View::slots`]).
pub(crate) struct View<'a> {
    bytes: &'a [u8],
    pub n: usize,
    w: usize,
    masked: bool,
    full_mask: u8,
    dense: Option<DenseView<'a>>,
    prev: usize,
    first: usize,
}

impl<'a> View<'a> {
    /// Slots of the chunk's entries in address order.
    pub fn slots(&self) -> Box<dyn Iterator<Item = usize> + 'a> {
        match &self.dense {
            None => Box::new(0..self.n),
            Some(DenseView { bits: None, npos, .. }) => Box::new(0..*npos),
            Some(DenseView { bits: Some(b), npos, .. }) if self.masked => {
                let b: &'a [u8] = b;
                Box::new((0..*npos).filter(move |&k| b[k] != 0))
            }
            Some(DenseView { bits: Some(b), .. }) => {
                let b: &'a [u8] = b;
                Box::new(b.chunks(8).enumerate().flat_map(|(wi, c)| {
                    let mut x = [0u8; 8];
                    x[..c.len()].copy_from_slice(c);
                    let mut m = u64::from_le_bytes(x);
                    std::iter::from_fn(move || {
                        (m != 0).then(|| {
                            let j = m.trailing_zeros() as usize;
                            m &= m - 1;
                            wi * 64 + j
                        })
                    })
                }))
            }
        }
    }

    /// Slot of the last entry (`n` > 0).
    pub fn last_slot(&self) -> usize {
        match &self.dense {
            None => self.n - 1,
            Some(DenseView { bits: None, npos, .. }) => npos - 1,
            Some(DenseView { bits: Some(b), .. }) if self.masked => b.iter().rposition(|&x| x != 0).unwrap_or(0),
            Some(DenseView { bits: Some(b), .. }) => {
                let i = b.iter().rposition(|&x| x != 0).unwrap_or(0);
                i * 8 + 7 - b[i].leading_zeros() as usize
            }
        }
    }

    /// Raw arrays of a dense chunk.
    pub fn dense_arrays(&self) -> Option<DenseArrays<'a>> {
        let d = self.dense.as_ref().filter(|_| !self.masked)?;
        let cur = (self.bytes, d.cur_off);
        Some(DenseArrays { cur, first: d.first.unwrap_or(cur), bits: d.bits, p0: d.p0, align: d.align })
    }

    /// Whether this is a dense chunk (slots are positions `0..npos`).
    pub fn dense_geometry(&self) -> Option<(usize, usize, usize)> {
        self.dense.as_ref().map(|d| (d.p0, d.align, d.npos))
    }

    /// Entry offset from the chunk base.
    #[inline]
    pub fn off(&self, k: usize) -> usize {
        match &self.dense {
            Some(d) => d.p0 + k * d.align,
            None => u32::from_le_bytes(self.bytes[4 * k..4 * k + 4].try_into().unwrap_or_default()) as usize,
        }
    }
    /// Type / bit-offset mask; 1 for unmasked sets.
    #[inline]
    pub fn mask(&self, k: usize) -> u8 {
        if !self.masked {
            return 1;
        }
        match &self.dense {
            Some(DenseView { bits: Some(b), .. }) => b[k],
            Some(_) => self.full_mask,
            None => self.bytes[4 * self.n + k],
        }
    }
    /// Previous value (dense: everything from the position to the copy's end).
    #[inline]
    pub fn prev(&self, k: usize) -> &'a [u8] {
        match &self.dense {
            Some(d) => self.bytes.get(self.off(k) - d.cur_off..).unwrap_or_default(),
            None => &self.bytes[self.prev + self.w * k..][..self.w],
        }
    }
    #[inline]
    pub fn first(&self, k: usize) -> &'a [u8] {
        match &self.dense {
            Some(DenseView { first: Some((f, fo)), .. }) => f.get(self.off(k) - fo..).unwrap_or_default(),
            Some(_) => self.prev(k),
            None => &self.bytes[self.first + self.w * k..][..self.w],
        }
    }
}

/// Accumulates a `Packed` chunk.
pub(crate) struct Builder {
    w: usize,
    masked: bool,
    shared_first: bool,
    offs: Vec<u8>,
    masks: Vec<u8>,
    prev: Vec<u8>,
    first: Vec<u8>,
    last: usize,
}

impl Builder {
    pub fn new(w: usize, masked: bool, shared_first: bool) -> Self {
        Builder { w, masked, shared_first, offs: Vec::new(), masks: Vec::new(), prev: Vec::new(), first: Vec::new(), last: 0 }
    }

    fn put(dst: &mut Vec<u8>, src: &[u8], w: usize) {
        let n = src.len().min(w);
        dst.extend_from_slice(&src[..n]);
        dst.resize(dst.len() + (w - n), 0);
    }

    #[inline]
    pub fn push(&mut self, off: usize, mask: u8, prev: &[u8], first: &[u8]) {
        self.offs.extend_from_slice(&(off as u32).to_le_bytes());
        self.last = off;
        if self.masked {
            self.masks.push(mask);
        }
        Self::put(&mut self.prev, prev, self.w);
        if !self.shared_first {
            Self::put(&mut self.first, first, self.w);
        }
    }

    pub fn finish(self, base: Addr, spill: &Spill) -> Result<Option<Chunk>> {
        let n = self.offs.len() / 4;
        if n == 0 {
            return Ok(None);
        }
        let end = base + self.last as u64 + 1;
        let mut v = self.offs;
        v.extend(self.masks);
        v.extend(self.prev);
        v.extend(self.first);
        let blob = spill.put(v)?;
        Ok(Some(Chunk { base, end, count: n as u64, kind: ChunkKind::Packed { blob, shared_first: self.shared_first } }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dense_bitmap_slots() {
        let marks: Vec<u8> = (0..200).map(|k| u8::from(k % 7 == 0 || k == 199)).collect();
        let mut bits = vec![0u8; 25];
        marks.iter().enumerate().for_each(|(k, &m)| bits[k / 8] |= m << (k % 8));
        let sp = Spill::new(u64::MAX);
        let d = Dense { cur: sp.put(vec![9; 800]).unwrap(), cur_off: 0, first: None, bits: Some(sp.put(bits).unwrap()), p0: 0, align: 4, npos: 200 };
        let count = marks.iter().filter(|&&m| m != 0).count() as u64;
        let c = Chunk { base: 0, end: 800, count, kind: ChunkKind::Dense(d) };
        let set = ResultSet::new(vec![c.clone()], 4, false, 1, sp);
        let l = set.load(&c).unwrap();
        let v = set.view(&c, &l);
        let got: Vec<usize> = v.slots().collect();
        let want: Vec<usize> = (0..200).filter(|k| marks[*k] != 0).collect();
        assert_eq!(got, want);
        assert_eq!((v.off(7), v.mask(7), v.prev(199).len()), (28, 1, 4));
        // Spilled payloads load back identically.
        let sp = Spill::new(0);
        let b = sp.put(vec![1, 2, 3]).unwrap();
        assert!(matches!(b, Blob::Disk { .. }) && sp.on_disk() == 3);
        assert_eq!(&*b.clone().load().unwrap(), &[1, 2, 3]);
    }

    #[test]
    fn spill_files_are_anonymous_and_avoid_tmpfs() {
        let dir = tempfile::tempdir_in(".").unwrap();
        let sp = Spill::new(0).in_dir(Some(dir.path().to_path_buf()));
        let b = sp.put(vec![7; 4096]).unwrap();
        assert_eq!(&*b.load().unwrap(), &[7; 4096][..]);
        // The file is open but unlinked: nothing to clean up after a crash.
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
        assert_eq!(spill_dir(Some(dir.path())), dir.path());

        let mi = "22 1 0:21 / / rw - ext4 /dev/sda1 rw\n\
                  30 22 0:25 / /tmp rw,nosuid - tmpfs tmpfs rw\n\
                  31 22 0:26 / /tmp/my\\040disk rw - ext4 /dev/sdb1 rw\n";
        assert!(on_tmpfs(mi, Path::new("/tmp/x")));
        assert!(!on_tmpfs(mi, Path::new("/var/tmp")));
        assert!(!on_tmpfs(mi, Path::new("/tmp/my disk/y")));
        assert!(!on_tmpfs(mi, Path::new("/tmpfoo")));
        // Whatever this machine has, the default choice is not RAM-backed when avoidable.
        if let Ok(m) = std::fs::read_to_string("/proc/self/mountinfo")
            && std::env::var_os("HEAPHOOK_TMPDIR").is_none()
            && !on_tmpfs(&m, Path::new("/var/tmp"))
        {
            assert!(!on_tmpfs(&m, &spill_dir(None)));
        }
    }
}
