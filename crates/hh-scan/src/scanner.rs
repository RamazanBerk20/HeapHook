//! The scan session: parallel first/next scans, one-level undo, saved scans, progress,
//! pause/cancel, paged results.
use std::collections::BTreeMap;
use std::ops::Range;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use hh_core::{Addr, Error, Memory, Process, RegionKind, Result};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::hexaddr;
use crate::plan::{
    ALL_ORDER, ALL_STRING, Fast, FirstScan, Kind, NextScan, NextScanEx, NumCmp, Plan, PointerScan, Priority, ScanType, Test,
    compile_first, compile_next, eval,
};
use crate::store::{Builder, Chunk, ChunkKind, Dense, ResultSet, Spill, View};
use crate::value::{CustomType, Fmt, Num, Pattern, Prim, VType, Val, bit_string, format_value, with_num};

/// Address-space bytes per parallel work unit (and per result chunk).
const UNIT: u64 = 4 << 20;
/// Pause/cancel/priority checkpoint granularity: address-space bytes (first scans) ...
const BLOCK: usize = 256 << 10;
/// ... and entries (next scans).
const BLOCK_ENTRIES: usize = 1 << 14;
const PAGE: u64 = 4096;
const DEFAULT_MEM_LIMIT: u64 = 512 << 20;
/// Needed byte ranges closer than this are read with one call: on a remote target every read
/// is a network round trip, which costs about as much as transferring this many bytes.
const GAP: usize = 64 << 10;
/// Gaps up to this are not worth tracking separately.
const SMALL_GAP: usize = 256;
/// Largest span merged into one read call, and of a group of result chunks read together.
const MAX_READ: usize = 8 << 20;
/// Longest address-range / module lists a scan accepts.
const MAX_LIST: usize = 4096;
/// Most results [`Scanner::sort`] orders (about 16 bytes each while sorting).
pub const MAX_SORT: u64 = 5_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanCount {
    pub count: u64,
}

/// `done`/`total` are bytes (first scan) or entries (next scan).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ScanProgress {
    pub done: u64,
    pub total: u64,
    pub found: u64,
    pub running: bool,
    /// The running scan is paused ([`Scanner::pause`]); omitted when false.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub paused: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResultRow {
    #[serde(with = "hexaddr")]
    pub addr: Addr,
    /// Type of this entry (differs per entry in "all" scans).
    pub vtype: VType,
    /// Current value; `None` if no longer readable.
    pub value: Option<String>,
    pub previous: String,
    pub first: String,
    /// Binary scans: bit offset of the field within the byte at `addr` (Cheat Engine shows
    /// `addr^bit`); omitted otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bit: Option<u8>,
}

#[derive(Default)]
struct Progress {
    done: AtomicU64,
    total: AtomicU64,
    found: AtomicU64,
    running: AtomicBool,
    cancel: AtomicBool,
    paused: AtomicBool,
}

#[derive(Clone)]
struct Saved {
    kind: Kind,
    set: Arc<ResultSet>,
}

/// Result order of [`Scanner::sort`]: (chunk index, slot) per row, for one result set.
type Order = (Arc<ResultSet>, Arc<Vec<(u32, u32)>>);

#[derive(Default)]
struct State {
    kind: Option<Kind>,
    cur: Option<Arc<ResultSet>>,
    sorted: Option<Order>,
    undo: Option<Arc<ResultSet>>,
    saved: BTreeMap<String, Saved>,
    /// Bumped by `new_scan`/`undo`, so a scan that ran meanwhile does not install its result.
    generation: u64,
}

/// One scan session over a process. All methods take `&self`: run scans on a worker thread
/// and call `progress`/`cancel`/`pause`/`results` from any other.
pub struct Scanner {
    proc: Arc<dyn Process>,
    st: Mutex<State>,
    /// Held for a scan's whole run; scans run one at a time.
    busy: Mutex<()>,
    prog: Progress,
    mem_limit: AtomicU64,
    spill_dir: Mutex<Option<std::path::PathBuf>>,
}

struct Running<'a>(&'a Progress);
impl Drop for Running<'_> {
    fn drop(&mut self) {
        self.0.running.store(false, Relaxed);
        self.0.paused.store(false, Relaxed);
    }
}

struct Suspended<'a>(&'a dyn Process);
impl Drop for Suspended<'_> {
    fn drop(&mut self) {
        let _ = self.0.resume();
    }
}

/// True if the target is already stopped (Linux: state `T`/`t` in `/proc/<pid>/stat`), so a
/// "pause while scanning" must neither suspend nor resume it. Elsewhere: unknown, false.
fn already_stopped(p: &dyn Process) -> bool {
    #[cfg(target_os = "linux")]
    if let Ok(s) = std::fs::read_to_string(format!("/proc/{}/stat", p.pid())) {
        // The state follows the parenthesised command name, which may itself contain ')'.
        return s.rsplit_once(')').and_then(|(_, r)| r.trim_start().chars().next()).is_some_and(|c| matches!(c, 'T' | 't'));
    }
    let _ = p;
    false
}

fn suspend(p: &dyn Process, on: bool) -> Result<Option<Suspended<'_>>> {
    if !on || already_stopped(p) {
        return Ok(None);
    }
    match p.suspend() {
        Ok(()) => Ok(Some(Suspended(p))),
        Err(Error::Unsupported(_)) => Ok(None),
        Err(e) => Err(e),
    }
}

thread_local!(static SPARE: std::cell::Cell<Vec<u8>> = const { std::cell::Cell::new(Vec::new()) });

impl Drop for ReadBuf {
    fn drop(&mut self) {
        SPARE.set(std::mem::take(&mut self.data));
    }
}

/// Memory copy of `[addr, addr+len)` with the readable sub-ranges; unreadable pages are skipped.
struct ReadBuf {
    data: Vec<u8>,
    valid: Vec<Range<usize>>,
}

impl ReadBuf {
    fn read(mem: &dyn Memory, addr: Addr, len: usize) -> ReadBuf {
        Self::read_ranges(mem, addr, len, std::iter::once(0..len))
    }

    /// Reads the byte ranges `want` (ascending starts, relative to `addr`, cut at `len`) into
    /// a `len`-byte buffer. Ranges less than [`GAP`] apart are read with one call (up to
    /// [`MAX_READ`]); after an unreadable page or a short read the next call starts at the
    /// next wanted byte, so holes between wanted ranges cost no calls.
    fn read_ranges(mem: &dyn Memory, addr: Addr, len: usize, want: impl IntoIterator<Item = Range<usize>>) -> ReadBuf {
        // Reusing a per-thread buffer avoids page-faulting a fresh allocation for every unit.
        let mut data = SPARE.take();
        data.resize(len, 0);
        let mut segs: Vec<Range<usize>> = Vec::new();
        for r in want {
            let r = r.start.min(len)..r.end.min(len);
            match segs.last_mut() {
                _ if r.is_empty() => {}
                Some(l) if r.start <= l.end + SMALL_GAP => l.end = l.end.max(r.end),
                _ => segs.push(r),
            }
        }
        let mut valid: Vec<Range<usize>> = Vec::new();
        let mut i = 0;
        while i < segs.len() {
            let s = segs[i].start;
            let mut j = i + 1;
            while j < segs.len() && segs[j].start <= segs[j - 1].end + GAP && segs[j].end - s <= MAX_READ {
                j += 1;
            }
            let e = segs[j - 1].end;
            let (mut pos, mut k) = (s, i);
            while pos < e {
                match mem.read(addr + pos as u64, &mut data[pos..e]) {
                    Ok(n) if n > 0 => {
                        match valid.last_mut() {
                            Some(r) if r.end == pos => r.end += n,
                            _ => valid.push(pos..pos + n),
                        }
                        pos += n;
                    }
                    _ => {
                        let a = addr + pos as u64;
                        // Skip to the next page; the last page of the address space ends the read.
                        pos = ((a / PAGE + 1).checked_mul(PAGE)).map_or(e, |n| ((n - addr) as usize).min(e));
                    }
                }
                // Go on inside the wanted segment holding `pos`, else at the next one.
                while k < j && segs[k].end <= pos {
                    k += 1;
                }
                match segs[i..j].get(k - i) {
                    Some(r) => pos = pos.max(r.start),
                    None => break,
                }
            }
            i = j;
        }
        ReadBuf { data, valid }
    }

    /// Bytes from `off` up to `max` long, cut at the end of the readable range.
    #[inline]
    fn slice(&self, off: usize, max: usize) -> Option<&[u8]> {
        let r = match self.valid.as_slice() {
            [r] => r,
            v => v.get(v.partition_point(|r| r.end <= off))?,
        };
        (r.start <= off && off < r.end).then(|| &self.data[off..r.end.min(off + max)])
    }
}

#[derive(Clone, Copy)]
struct Align {
    step: u64,
    off: u64,
}

impl Align {
    /// Distance from `a` to the next position at or after it.
    fn pad(self, a: Addr) -> u64 {
        let m = ((a % self.step) + self.step - (self.off % self.step)) % self.step;
        (self.step - m) % self.step
    }
}

struct Unit {
    start: Addr,
    end: Addr,
    read_end: Addr,
}

/// Where a next scan's "previous" value comes from.
enum Src {
    Prev,
    First,
    Saved(Arc<ResultSet>),
}

fn err_reset() -> Error {
    Error::Other("the results were reset or undone while the scan ran".into())
}

impl Scanner {
    pub fn new(proc: Arc<dyn Process>) -> Self {
        Scanner {
            proc,
            st: Mutex::default(),
            busy: Mutex::default(),
            prog: Progress::default(),
            mem_limit: AtomicU64::new(DEFAULT_MEM_LIMIT),
            spill_dir: Mutex::new(None),
        }
    }

    /// RAM a result set may use before chunks spill to a temp file.
    pub fn set_memory_limit(&self, bytes: u64) {
        self.mem_limit.store(bytes, Relaxed);
    }

    /// Directory for spill files (`None` = `$HEAPHOOK_TMPDIR`, else a disk-backed temp dir).
    pub fn set_spill_dir(&self, dir: Option<std::path::PathBuf>) {
        *self.spill_dir.lock().unwrap_or_else(|e| e.into_inner()) = dir;
    }

    fn spill(&self) -> Spill {
        Spill::new(self.mem_limit.load(Relaxed)).in_dir(self.spill_dir.lock().unwrap_or_else(|e| e.into_inner()).clone())
    }

    pub fn progress(&self) -> ScanProgress {
        let p = &self.prog;
        ScanProgress {
            done: p.done.load(Relaxed),
            total: p.total.load(Relaxed),
            found: p.found.load(Relaxed),
            running: p.running.load(Relaxed),
            paused: p.paused.load(Relaxed),
        }
    }

    /// Stops the running scan; it returns an error and the previous results stay.
    pub fn cancel(&self) {
        self.prog.cancel.store(true, Relaxed);
    }

    /// Pauses the running scan at its next checkpoint (every ~256 KiB / 16k entries per
    /// thread). A new scan starts unpaused; `cancel` also ends a paused scan.
    pub fn pause(&self) {
        if self.prog.running.load(Relaxed) {
            self.prog.paused.store(true, Relaxed);
        }
    }

    /// Continues a paused scan.
    pub fn resume(&self) {
        self.prog.paused.store(false, Relaxed);
    }

    pub fn count(&self) -> u64 {
        self.lock().cur.as_ref().map_or(0, |s| s.count)
    }

    /// Bytes of result data spilled to disk (current, undo and saved sets).
    pub fn spilled_bytes(&self) -> u64 {
        let st = self.lock();
        let mut sets: Vec<&Arc<ResultSet>> = st.cur.iter().chain(&st.undo).chain(st.saved.values().map(|s| &s.set)).collect();
        sets.sort_by_key(|s| Arc::as_ptr(s));
        sets.dedup_by(|a, b| Arc::ptr_eq(a, b));
        sets.iter().map(|s| s.spill.on_disk()).sum()
    }

    /// Clears results and saved scans.
    pub fn new_scan(&self) {
        let mut st = self.lock();
        let g = st.generation + 1;
        *st = State { generation: g, ..State::default() };
    }

    /// Restores the results from before the last next scan (one level).
    pub fn undo(&self) -> Result<()> {
        let mut st = self.lock();
        let u = st.undo.take().ok_or_else(|| Error::Other("nothing to undo".into()))?;
        st.cur = Some(u);
        st.generation += 1;
        Ok(())
    }

    /// Saves the current results under `name` (Cheat Engine's "save current scan results"),
    /// replacing a saved scan of that name. Saved scans share storage with the live set,
    /// live until `new_scan` or the next first scan, and are compared against with
    /// [`NextScanEx::compare_to`]. `"first"` is reserved for the first scan.
    pub fn save_scan(&self, name: &str) -> Result<()> {
        let name = name.trim();
        if name.is_empty() || name.eq_ignore_ascii_case("first") {
            return Err(Error::Parse(format!("bad saved scan name {name:?}")));
        }
        let mut st = self.lock();
        let (Some(kind), Some(set)) = (st.kind.clone(), st.cur.clone()) else {
            return Err(Error::Other("no scan to save".into()));
        };
        st.saved.insert(name.to_owned(), Saved { kind, set });
        Ok(())
    }

    /// Names of the saved scans, sorted.
    pub fn saved_scans(&self) -> Vec<String> {
        self.lock().saved.keys().cloned().collect()
    }

    pub fn delete_saved_scan(&self, name: &str) -> Result<()> {
        self.lock().saved.remove(name.trim()).map(|_| ()).ok_or_else(|| Error::Other(format!("no saved scan {name:?}")))
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.st.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn start(&self, total: u64) -> (MutexGuard<'_, ()>, Running<'_>) {
        let busy = self.busy.lock().unwrap_or_else(|e| e.into_inner());
        let p = &self.prog;
        p.cancel.store(false, Relaxed);
        p.paused.store(false, Relaxed);
        p.done.store(0, Relaxed);
        p.found.store(0, Relaxed);
        p.total.store(total, Relaxed);
        p.running.store(true, Relaxed);
        (busy, Running(p))
    }

    fn check_cancel(&self) -> Result<()> {
        if self.prog.cancel.load(Relaxed) {
            return Err(Error::Other("scan cancelled".into()));
        }
        Ok(())
    }

    /// Cancel, pause and priority point inside a scan.
    fn checkpoint(&self, prio: Priority) -> Result<()> {
        self.check_cancel()?;
        while self.prog.paused.load(Relaxed) {
            std::thread::sleep(Duration::from_millis(5));
            self.check_cancel()?;
        }
        match prio {
            Priority::Normal => {}
            Priority::Low => std::thread::yield_now(),
            Priority::Idle => std::thread::sleep(Duration::from_millis(1)),
        }
        Ok(())
    }

    /// Runs `f` on a pool of `threads` workers (`None` = the global pool).
    fn par<R: Send>(threads: Option<usize>, f: impl FnOnce() -> R + Send) -> Result<R> {
        match threads {
            None => Ok(f()),
            Some(n) => {
                let pool = rayon::ThreadPoolBuilder::new().num_threads(n.max(1)).build().map_err(|e| Error::Other(e.to_string()))?;
                Ok(pool.install(f))
            }
        }
    }

    pub fn first_scan(&self, req: &FirstScan) -> Result<ScanCount> {
        let (kind, plan) = compile_first(req)?;
        self.run_first(kind, plan)
    }

    /// Finds pointer-sized values that point into readable memory (or only into
    /// `req.modules` / `req.ranges`). Starts a new scan like [`Scanner::first_scan`]; the
    /// results are 4- or 8-byte entries, so next scans (changed, unchanged, exact...) apply.
    pub fn pointer_scan(&self, req: &PointerScan) -> Result<ScanCount> {
        let ps = self.proc.pointer_size();
        if ps != 4 && ps != 8 {
            return Err(Error::Unsupported("pointer size other than 4 or 8"));
        }
        if req.modules.len() > MAX_LIST || req.ranges.len() > MAX_LIST {
            return Err(Error::Parse(format!("at most {MAX_LIST} modules and ranges")));
        }
        let mut opts = req.opts.clone();
        opts.alignment = Some(opts.alignment.unwrap_or(ps as u64));
        opts.custom = None;
        let vtype = if ps == 4 { VType::Bytes4 } else { VType::Bytes8 };
        let first = FirstScan { vtype, scan_type: ScanType::Exact, value: Some("0".into()), value2: None, not: false, opts };
        let (kind, mut plan) = compile_first(&first)?;
        let readable = norm(self.proc.regions()?.iter().filter(|r| r.prot.r).map(|r| (r.start, r.start.saturating_add(r.size))).collect());
        let targets = if req.modules.is_empty() && req.ranges.is_empty() {
            readable
        } else {
            let mut want = module_ranges(&*self.proc, &req.modules, true)?;
            want.extend(req.ranges.iter().map(|r| (r.start, r.end)));
            let want = norm(want);
            readable.into_iter().flat_map(|(s, e)| clip(s, e, Some(&want), &[])).collect()
        };
        let (lo, hi) = (targets.first().map_or(1, |r| r.0), targets.last().map_or(0, |r| r.1));
        let pred = move |c: &[u8], _: &[u8], _: &[u8]| {
            let mut b = [0u8; 8];
            b[..ps].copy_from_slice(&c[..ps]);
            let v = u64::from_le_bytes(b);
            lo <= v && v < hi && in_ranges(&targets, v)
        };
        plan.tests = vec![Test { bit: 1, need: ps, need_prev: 0, pred: Box::new(pred), num: None }];
        plan.fast = Fast::None;
        self.run_first(kind, plan)
    }

    fn run_first(&self, kind: Kind, plan: Plan) -> Result<ScanCount> {
        let (_busy, run) = self.start(0);
        let generation = self.lock().generation;
        let _s = suspend(&*self.proc, kind.opts.pause_while_scanning)?;
        let units = self.units(&kind)?;
        self.prog.total.store(units.iter().map(|u| u.end - u.start).sum(), Relaxed);
        let spill = self.spill();
        let chunks: Vec<Vec<Chunk>> = Self::par(kind.opts.threads, || {
            units.par_iter().map(|u| self.first_unit(&kind, &plan, u, &spill)).collect::<Result<_>>()
        })??;
        self.check_cancel()?;
        let set = ResultSet::new(chunks.into_iter().flatten().collect(), kind.width, kind.masked, kind.full_mask, spill);
        let count = set.count;
        let mut st = self.lock();
        if st.generation != generation {
            return Err(err_reset());
        }
        *st = State { kind: Some(kind), cur: Some(Arc::new(set)), generation, ..State::default() };
        drop(run);
        Ok(ScanCount { count })
    }

    pub fn next_scan(&self, req: &NextScan) -> Result<ScanCount> {
        self.next_scan_ex(&req.clone().into())
    }

    /// A next scan, optionally comparing against a saved scan (see [`NextScanEx`]).
    pub fn next_scan_ex(&self, req: &NextScanEx) -> Result<ScanCount> {
        let (_busy, run) = self.start(0);
        let (kind, cur, generation, saved) = {
            let st = self.lock();
            let none = || Error::Other("no first scan".into());
            let saved = match req.compare_to.as_deref().map(str::trim) {
                None => None,
                Some(n) if n.eq_ignore_ascii_case("first") => None,
                Some(n) => Some(st.saved.get(n).cloned().ok_or_else(|| Error::Other(format!("no saved scan {n:?}")))?),
            };
            (st.kind.clone().ok_or_else(none)?, st.cur.clone().ok_or_else(none)?, st.generation, saved)
        };
        let (plan, width) = compile_next(&kind, &req.scan, cur.width)?;
        let src = match (&req.compare_to, saved) {
            (None, _) => Src::Prev,
            (Some(_), None) => Src::First,
            (Some(_), Some(s)) => {
                if s.kind.vtype != kind.vtype || s.kind.opts.custom != kind.opts.custom || s.kind.bits != kind.bits {
                    return Err(Error::Parse("the saved scan has a different value type".into()));
                }
                Src::Saved(s.set)
            }
        };
        let keep = plan.keeps_prev && matches!(src, Src::Prev);
        self.prog.total.store(cur.count, Relaxed);
        let _s = suspend(&*self.proc, kind.opts.pause_while_scanning)?;
        let spill = self.spill();
        let groups = read_groups(&cur.chunks);
        let chunks: Vec<Vec<Chunk>> = Self::par(kind.opts.threads, || {
            groups
                .par_iter()
                .map(|g| self.next_group(&kind, &plan, &cur, &cur.chunks[g.clone()], &spill, width, &src, keep))
                .collect::<Result<_>>()
        })??;
        self.check_cancel()?;
        let set = ResultSet::new(chunks.into_iter().flatten().collect(), width, kind.masked, kind.full_mask, spill);
        let count = set.count;
        let mut st = self.lock();
        if st.generation != generation {
            return Err(err_reset());
        }
        st.undo = st.cur.replace(Arc::new(set));
        st.sorted = None;
        drop(run);
        Ok(ScanCount { count })
    }

    fn units(&self, k: &Kind) -> Result<Vec<Unit>> {
        let o = &k.opts;
        if o.ranges.len() > MAX_LIST || o.modules.len() > MAX_LIST || o.exclude_modules.len() > MAX_LIST {
            return Err(Error::Parse(format!("at most {MAX_LIST} ranges and modules")));
        }
        if let Some(r) = o.ranges.iter().find(|r| r.start >= r.end) {
            return Err(Error::Parse(format!("empty address range {:#x}..{:#x}", r.start, r.end)));
        }
        let inc = (!o.modules.is_empty()).then(|| module_ranges(&*self.proc, &o.modules, true).map(norm)).transpose()?;
        let exc = if o.exclude_modules.is_empty() { Vec::new() } else { norm(module_ranges(&*self.proc, &o.exclude_modules, false)?) };
        let ranges = (!o.ranges.is_empty()).then(|| norm(o.ranges.iter().map(|r| (r.start, r.end)).collect()));
        let mut regs = self.proc.regions()?;
        regs.sort_by_key(|r| r.start);
        let mut out = Vec::new();
        for r in regs {
            let cow = r.cow;
            if !r.prot.r
                || !o.writable.ok(r.prot.w)
                || !o.executable.ok(r.prot.x)
                || !o.copy_on_write.ok(cow)
                || (!o.kinds.is_empty() && !o.kinds.contains(&r.kind))
                || o.min_region_size.is_some_and(|m| r.size < m)
                || o.max_region_size.is_some_and(|m| r.size > m)
            {
                continue;
            }
            let rend = r.start.saturating_add(r.size);
            let (lo, hi) = (r.start.max(o.start.unwrap_or(0)), rend.min(o.stop.unwrap_or(u64::MAX)));
            let mut parts = clip(lo, hi, inc.as_deref(), &exc);
            if let Some(rg) = &ranges {
                parts = parts.into_iter().flat_map(|(s, e)| clip(s, e, Some(rg), &[])).collect();
            }
            for (lo, hi) in parts {
                let mut s = lo;
                while s < hi {
                    let e = hi.min(s.saturating_add(UNIT));
                    out.push(Unit { start: s, end: e, read_end: rend.min(e.saturating_add(k.width as u64 - 1)) });
                    s = e;
                }
            }
        }
        Ok(out)
    }

    fn first_unit(&self, k: &Kind, plan: &Plan, u: &Unit, spill: &Spill) -> Result<Vec<Chunk>> {
        let prio = k.opts.priority;
        self.checkpoint(prio)?;
        let buf = ReadBuf::read(&*self.proc, u.start, (u.read_end - u.start) as usize);
        self.check_cancel()?;
        let lim = (u.end - u.start) as usize;
        let al = Align { step: k.align, off: k.align_off };
        let step = k.align as usize;
        let need = k.min_need;
        let mut out = Vec::new();
        let mut b = Builder::new(k.width, k.masked, true);
        let mut accounted = 0u64;
        for r in &buf.valid {
            if r.start >= lim || r.len() < need {
                continue;
            }
            let base = u.start + r.start as u64;
            let p0 = al.pad(base) as usize;
            let end = (lim - r.start).min(r.len() + 1 - need); // positions p < end in the slice
            if p0 >= end {
                continue;
            }
            let s = &buf.data[r.clone()];
            if plan.unknown {
                let npos = (end - 1 - p0) / step + 1;
                let cur = spill.put(s.to_vec())?;
                let dense = Dense { cur, cur_off: 0, first: None, bits: None, p0, align: step, npos };
                let end = base + (p0 + (npos - 1) * step) as u64 + 1;
                out.push(Chunk { base, end, count: npos as u64, kind: ChunkKind::Dense(dense) });
                continue;
            }
            let mut bs = p0;
            while bs < end {
                self.checkpoint(prio)?;
                let be = end.min(bs + BLOCK);
                scan_block(plan, al, s, base, bs, be, step, &mut |p, m| b.push(r.start + p, m, &s[p..], &[]));
                self.prog.done.fetch_add((be - bs) as u64, Relaxed);
                accounted += (be - bs) as u64;
                bs += (be - bs).div_ceil(step) * step;
            }
        }
        if let Some(c) = b.finish(u.start, spill)? {
            out.push(c);
        }
        self.prog.done.fetch_add((u.end - u.start).saturating_sub(accounted), Relaxed);
        self.prog.found.fetch_add(out.iter().map(|c| c.count).sum(), Relaxed);
        Ok(out)
    }

    /// Next scan over a group of chunks (see [`read_groups`]) with one read plan.
    #[allow(clippy::too_many_arguments)]
    fn next_group(&self, k: &Kind, plan: &Plan, set: &ResultSet, group: &[Chunk], spill: &Spill, width: usize, src: &Src, keep: bool) -> Result<Vec<Chunk>> {
        self.checkpoint(k.opts.priority)?;
        let loaded = group.iter().map(|c| set.load(c)).collect::<Result<Vec<_>>>()?;
        let views: Vec<(&Chunk, View<'_>)> = group.iter().zip(&loaded).map(|(c, l)| (c, set.view(c, l))).filter(|(_, v)| v.n > 0).collect();
        let (Some((c0, v0)), Some((c1, v1))) = (views.first(), views.last()) else { return Ok(Vec::new()) };
        let max_need = plan.tests.iter().map(|t| t.need).max().unwrap_or(0).max(width);
        // Byte 0 of the read buffer is the group's first entry.
        let gbase = c0.base + v0.off(v0.slots().next().unwrap_or(0)) as u64;
        let len = (c1.base + v1.off(v1.last_slot()) as u64 - gbase) as usize + max_need;
        let mut live = if v0.dense_geometry().is_some() {
            ReadBuf::read(&*self.proc, gbase, len)
        } else {
            let want = views.iter().flat_map(|(c, v)| {
                v.slots().map(move |s| {
                    let a = (c.base + v.off(s) as u64 - gbase) as usize;
                    a..a + max_need
                })
            });
            ReadBuf::read_ranges(&*self.proc, gbase, len, want)
        };
        self.check_cancel()?;
        let mut out = Vec::new();
        for (c, v) in &views {
            out.extend(self.next_chunk(k, plan, c, v, &mut live, gbase, max_need, spill, width, src, keep)?);
        }
        Ok(out)
    }

    /// `live` holds the memory from `gbase` on; a dense chunk is always alone in its group.
    #[allow(clippy::too_many_arguments)]
    fn next_chunk(
        &self,
        k: &Kind,
        plan: &Plan,
        c: &Chunk,
        v: &View<'_>,
        live: &mut ReadBuf,
        gbase: Addr,
        max_need: usize,
        spill: &Spill,
        width: usize,
        src: &Src,
        keep: bool,
    ) -> Result<Option<Chunk>> {
        let prio = k.opts.priority;
        let at = |o: usize| (c.base + o as u64 - gbase) as usize;
        // Chunk offset of the buffer's byte 0 (dense chunks, alone in their group).
        let lo = gbase.saturating_sub(c.base) as usize;
        // Saved scan entries over this chunk's address range, in address order.
        let saved: Vec<(&Chunk, crate::store::Loaded<'_>)> = match src {
            Src::Saved(s) => {
                let i = s.chunks.partition_point(|x| x.end <= c.base);
                s.chunks[i..].iter().take_while(|x| x.base < c.end).map(|x| Ok((x, s.load(x)?))).collect::<Result<_>>()?
            }
            _ => Vec::new(),
        };
        let views: Vec<_> = match src {
            Src::Saved(s) => saved.iter().map(|(x, ld)| (x.base, s.view(x, ld))).collect(),
            _ => Vec::new(),
        };
        let mut saved_it = views.iter().flat_map(|(b, sv)| sv.slots().map(move |q| (b + sv.off(q) as u64, sv.prev(q)))).peekable();

        let geom = v.dense_geometry();
        // Survivors of a dense chunk by position: a bitmap, or mask bytes for masked sets.
        let mut marks = geom.map(|(_, _, npos)| vec![0u8; if k.masked { npos } else { npos.div_ceil(8) }]);
        let mut b = Builder::new(width, k.masked, false);
        let (mut count, mut done) = (0u64, 0u64);
        // Tight loop for the common "numeric dense chunk vs previous/first" case.
        let whole = matches!(live.valid.as_slice(), [r] if r.start == 0 && r.end == live.data.len());
        if let (Some(mk), Some(arrays), [t], Src::Prev | Src::First, true, false) =
            (&mut marks, v.dense_arrays(), plan.tests.as_slice(), src, whole, k.masked)
            && let Some((prim, signed, cmp, not)) = t.num
        {
            let (p, f) = if matches!(src, Src::First) { (arrays.first, arrays.first) } else { (arrays.cur, arrays.first) };
            let (p0, align) = (arrays.p0, arrays.align);
            let live = (&live.data[..], lo);
            let mut check = || self.checkpoint(prio);
            let npos = geom.map_or(0, |g| g.2);
            count = with_num!(prim, signed, T => dense_kernel::<T>(&cmp, not, live, p, f, p0, align, npos, arrays.bits, mk, &mut check))?;
            done = c.count;
        }
        for (j, s) in v.slots().enumerate().take(if done > 0 { 0 } else { usize::MAX }) {
            if j % BLOCK_ENTRIES == BLOCK_ENTRIES - 1 {
                self.checkpoint(prio)?;
                self.prog.done.fetch_add(BLOCK_ENTRIES as u64, Relaxed);
                done += BLOCK_ENTRIES as u64;
            }
            let o = v.off(s);
            let Some(cur) = live.slice(at(o), max_need) else { continue };
            let first = v.first(s);
            let prev = match src {
                Src::Prev => v.prev(s),
                Src::First => first,
                Src::Saved(_) => {
                    let a = c.base + o as u64;
                    while saved_it.next_if(|(x, _)| *x < a).is_some() {}
                    match saved_it.peek() {
                        Some((x, p)) if *x == a => p,
                        _ => continue,
                    }
                }
            };
            let mask = v.mask(s);
            let mut m = 0;
            for t in &plan.tests {
                if mask & t.bit != 0
                    && cur.len() >= t.need
                    && prev.len() >= t.need_prev
                    && first.len() >= t.need_prev
                    && (t.pred)(cur, prev, first)
                {
                    m |= t.bit;
                }
            }
            if m != 0 {
                count += 1;
                match &mut marks {
                    Some(mk) if k.masked => mk[s] = m,
                    Some(mk) => mk[s / 8] |= 1 << (s % 8),
                    None => b.push(o, m, cur, first),
                }
            }
        }
        self.prog.done.fetch_add(c.count - done, Relaxed);
        self.prog.found.fetch_add(count, Relaxed);
        let (Some(marks), Some((p0, align, npos)), ChunkKind::Dense(d)) = (marks, geom, &c.kind) else {
            return b.finish(c.base, spill);
        };
        if count == 0 {
            return Ok(None);
        }
        // Stay dense while the copy + bitmap is smaller than packing the survivors.
        let masked = k.masked;
        let dense_cost = if keep { 0 } else { live.data.len() } + if masked { npos } else { npos / 8 };
        let packed_cost = count as usize * (4 + usize::from(masked) + 2 * width);
        if dense_cost < packed_cost {
            let (cur, cur_off) = if keep { (d.cur.clone(), d.cur_off) } else { (spill.put(std::mem::take(&mut live.data))?, lo) };
            let first = Some(d.first.clone().unwrap_or_else(|| (d.cur.clone(), d.cur_off)));
            let bits = Some(spill.put(marks)?);
            let dense = Dense { cur, cur_off, first, bits, p0, align, npos };
            return Ok(Some(Chunk { base: c.base, end: c.end, count, kind: ChunkKind::Dense(dense) }));
        }
        let survivors: Vec<(usize, u8)> = if masked {
            marks.iter().enumerate().filter(|(_, m)| **m != 0).map(|(s, &m)| (s, m)).collect()
        } else {
            (0..npos).filter(|s| marks[s / 8] >> (s % 8) & 1 != 0).map(|s| (s, 1)).collect()
        };
        for (s, m) in survivors {
            let o = v.off(s);
            b.push(o, m, live.slice(at(o), max_need).unwrap_or_default(), v.first(s));
        }
        b.finish(c.base, spill)
    }

    /// Results `[offset, offset+limit)` in address order (or [`Scanner::sort`]'s order), with
    /// live current values. While a scan runs this pages through the last completed result
    /// set. Current values are read with few calls (nearby rows share one read).
    pub fn results(&self, offset: u64, limit: usize) -> Result<Vec<ResultRow>> {
        let (k, set, order) = {
            let st = self.lock();
            let (Some(k), Some(set)) = (&st.kind, &st.cur) else { return Ok(Vec::new()) };
            let order = st.sorted.as_ref().filter(|(s, _)| Arc::ptr_eq(s, set)).map(|(_, o)| o.clone());
            (k.clone(), set.clone(), order)
        };
        let end = set.count.min(offset.saturating_add(limit as u64));
        if offset >= end {
            return Ok(Vec::new());
        }
        let picks: Vec<(usize, usize)> = match order {
            Some(o) => o[offset as usize..end as usize].iter().map(|&(c, s)| (c as usize, s as usize)).collect(),
            None => {
                let mut picks = Vec::new();
                let mut i = offset;
                while i < end {
                    let ci = set.starts.partition_point(|&s| s <= i) - 1;
                    let (c, cs) = (&set.chunks[ci], set.starts[ci]);
                    let l = set.load(c)?;
                    let v = set.view(c, &l);
                    let take = ((end - cs).min(c.count) - (i - cs)) as usize;
                    picks.extend(v.slots().skip((i - cs) as usize).take(take).map(|s| (ci, s)));
                    i = cs + c.count;
                }
                picks
            }
        };
        self.rows(&k, &set, &picks)
    }

    /// Rows for (chunk index, slot) picks, in the picks' order.
    fn rows(&self, k: &Kind, set: &ResultSet, picks: &[(usize, usize)]) -> Result<Vec<ResultRow>> {
        let mut by_chunk: Vec<usize> = (0..picks.len()).collect();
        by_chunk.sort_by_key(|&i| picks[i]);
        let mut pre: Vec<Option<(Addr, Shape, String, String)>> = vec![None; picks.len()];
        let mut i = 0;
        while i < by_chunk.len() {
            let ci = picks[by_chunk[i]].0;
            let c = &set.chunks[ci];
            let l = set.load(c)?;
            let v = set.view(c, &l);
            while let Some(&j) = by_chunk.get(i).filter(|&&j| picks[j].0 == ci) {
                let s = picks[j].1;
                let sh = shape(k, set.width, v.mask(s), v.prev(s).len());
                pre[j] = Some((c.base + v.off(s) as u64, sh.clone(), sh.show(k, v.prev(s)), sh.show(k, v.first(s))));
                i += 1;
            }
        }
        let pre: Vec<_> = pre.into_iter().flatten().collect();
        let cur = read_many(&*self.proc, &pre.iter().map(|p| (p.0, p.1.size)).collect::<Vec<_>>());
        Ok(pre
            .into_iter()
            .zip(cur)
            .map(|((addr, sh, previous, first), cur)| ResultRow { addr, vtype: sh.vtype, value: cur.map(|b| sh.show(k, &b)), previous, first, bit: sh.bit })
            .collect())
    }

    /// The values a saved scan holds at `addrs` (`"first"`: the first-scan values of the
    /// current results), formatted like a row's `previous`; `None` where it has no entry.
    /// For the results' "saved" column.
    pub fn saved_values(&self, name: &str, addrs: &[Addr]) -> Result<Vec<Option<String>>> {
        let (k, set, first) = {
            let st = self.lock();
            let n = name.trim();
            if n.eq_ignore_ascii_case("first") {
                let none = || Error::Other("no first scan".into());
                (st.kind.clone().ok_or_else(none)?, st.cur.clone().ok_or_else(none)?, true)
            } else {
                let sv = st.saved.get(n).ok_or_else(|| Error::Other(format!("no saved scan {n:?}")))?;
                (sv.kind.clone(), sv.set.clone(), false)
            }
        };
        let mut idx: Vec<usize> = (0..addrs.len()).collect();
        idx.sort_by_key(|&i| addrs[i]);
        let mut out = vec![None; addrs.len()];
        let mut i = 0;
        while i < idx.len() {
            let a = addrs[idx[i]];
            let ci = set.chunks.partition_point(|c| c.end <= a);
            let Some(c) = set.chunks.get(ci).filter(|c| c.base <= a) else {
                i += 1;
                continue;
            };
            let l = set.load(c)?;
            let v = set.view(c, &l);
            while let Some(&j) = idx.get(i).filter(|&&j| addrs[j] < c.end) {
                if let Some(s) = addrs[j].checked_sub(c.base).and_then(|o| v.find(o as usize)) {
                    let b = if first { v.first(s) } else { v.prev(s) };
                    out[j] = Some(shape(&k, set.width, v.mask(s), v.prev(s).len()).show(&k, b));
                }
                i += 1;
            }
        }
        Ok(out)
    }

    /// The directory spill files go to now: [`Scanner::set_spill_dir`]'s, else
    /// `$HEAPHOOK_TMPDIR`, else a disk-backed temp dir (see [`crate::spill_dir`]).
    pub fn effective_spill_dir(&self) -> std::path::PathBuf {
        crate::store::spill_dir(self.spill_dir.lock().unwrap_or_else(|e| e.into_inner()).as_deref())
    }

    /// Orders [`Scanner::results`] by address or by value (the value of the last scan, not
    /// a live read; numbers numerically, text and byte arrays by their first 8 bytes).
    /// Address ascending is the natural order and costs nothing. At most [`MAX_SORT`]
    /// results; more is an error. The order lasts until the results change.
    pub fn sort(&self, key: SortKey, desc: bool) -> Result<()> {
        let (k, set) = {
            let mut st = self.lock();
            let (Some(k), Some(set)) = (st.kind.clone(), st.cur.clone()) else { return Err(Error::Other("no scan results".into())) };
            if key == SortKey::Address && !desc {
                st.sorted = None;
                return Ok(());
            }
            (k, set)
        };
        if set.count > MAX_SORT {
            return Err(Error::Other(format!(
                "{} results are too many to sort (at most {MAX_SORT}); narrow them down with a next scan first",
                set.count
            )));
        }
        let mut keys: Vec<(f64, u32, u32)> = Vec::with_capacity(set.count as usize);
        for (ci, c) in set.chunks.iter().enumerate() {
            let l = set.load(c)?;
            let v = set.view(c, &l);
            for s in v.slots() {
                let x = if key == SortKey::Value { sort_value(&k, set.width, v.mask(s), v.prev(s)) } else { 0.0 };
                keys.push((x, ci as u32, s as u32));
            }
        }
        if key == SortKey::Value {
            keys.sort_by(|a, b| a.0.total_cmp(&b.0));
        }
        if desc {
            keys.reverse();
        }
        let order = Arc::new(keys.into_iter().map(|(_, c, s)| (c, s)).collect());
        let mut st = self.lock();
        if !st.cur.as_ref().is_some_and(|c| Arc::ptr_eq(c, &set)) {
            return Err(err_reset());
        }
        st.sorted = Some((set, order));
        Ok(())
    }

    /// Removes the results at `addrs` (Cheat Engine's "remove selected addresses"); undo
    /// brings them back. Returns how many were removed.
    pub fn remove(&self, addrs: &[Addr]) -> Result<u64> {
        let mut a = addrs.to_vec();
        a.sort_unstable();
        a.dedup();
        let (set, generation) = {
            let st = self.lock();
            (st.cur.clone().ok_or_else(|| Error::Other("no scan results".into()))?, st.generation)
        };
        let spill = self.spill();
        let mut chunks = Vec::with_capacity(set.chunks.len());
        let mut removed = 0u64;
        for c in &set.chunks {
            let mine = &a[a.partition_point(|&x| x < c.base)..a.partition_point(|&x| x < c.end)];
            if mine.is_empty() {
                chunks.push(c.clone());
                continue;
            }
            let l = set.load(c)?;
            let v = set.view(c, &l);
            let hits: Vec<usize> = mine.iter().filter_map(|&x| v.find((x - c.base) as usize)).collect();
            if hits.is_empty() {
                chunks.push(c.clone());
                continue;
            }
            removed += hits.len() as u64;
            let count = c.count - hits.len() as u64;
            match &c.kind {
                _ if count == 0 => {}
                ChunkKind::Dense(d) => {
                    let mut marks = match d.bits.as_ref().map(|b| b.load()).transpose()? {
                        Some(b) => b.into_owned(),
                        None if set.masked => vec![set.full_mask; d.npos],
                        None => {
                            let mut b = vec![0xffu8; d.npos.div_ceil(8)];
                            if d.npos % 8 != 0 {
                                b[d.npos / 8] = (1u8 << (d.npos % 8)) - 1;
                            }
                            b
                        }
                    };
                    for s in hits {
                        if set.masked { marks[s] = 0 } else { marks[s / 8] &= !(1 << (s % 8)) }
                    }
                    let dense = Dense { bits: Some(spill.put(marks)?), ..d.clone() };
                    chunks.push(Chunk { count, kind: ChunkKind::Dense(dense), ..c.clone() });
                }
                ChunkKind::Packed { .. } => {
                    let mut b = Builder::new(set.width, set.masked, false);
                    let mut gone = hits.iter().peekable();
                    for s in v.slots() {
                        if gone.next_if_eq(&&s).is_none() {
                            b.push(v.off(s), v.mask(s), v.prev(s), v.first(s));
                        }
                    }
                    chunks.extend(b.finish(c.base, &spill)?);
                }
            }
        }
        if removed == 0 {
            return Ok(0);
        }
        let new = ResultSet::new(chunks, set.width, set.masked, set.full_mask, spill);
        let mut st = self.lock();
        if st.generation != generation {
            return Err(err_reset());
        }
        st.undo = st.cur.replace(Arc::new(new));
        st.sorted = None;
        st.generation += 1;
        Ok(removed)
    }

    /// "Copy all addresses": writes every result's address (upper-case hex, one per line,
    /// in address order) to `w`; returns how many. Streams chunk by chunk.
    pub fn export_addresses(&self, w: &mut dyn std::io::Write) -> Result<u64> {
        let Some(set) = self.lock().cur.clone() else { return Ok(0) };
        let mut n = 0;
        for c in &set.chunks {
            let l = set.load(c)?;
            let v = set.view(c, &l);
            for s in v.slots() {
                writeln!(w, "{:X}", c.base + v.off(s) as u64)?;
                n += 1;
            }
        }
        Ok(n)
    }

    /// Result counts per memory region (with its module, if any), in address order, for a
    /// summary view. Results in memory that is no longer mapped share one row with `size`
    /// 0 and no `kind`.
    pub fn result_stats(&self) -> Result<Vec<ResultStat>> {
        let Some(set) = self.lock().cur.clone() else { return Ok(Vec::new()) };
        let mut regs = self.proc.regions()?;
        regs.sort_by_key(|r| r.start);
        let mods = self.proc.modules().unwrap_or_default();
        let mut per: BTreeMap<Option<usize>, u64> = BTreeMap::new();
        for c in &set.chunks {
            let i = regs.partition_point(|r| r.start <= c.base).checked_sub(1).filter(|&i| c.base < regs[i].start.saturating_add(regs[i].size));
            *per.entry(i).or_default() += c.count;
        }
        let mut out: Vec<ResultStat> = per
            .into_iter()
            .map(|(i, count)| match i {
                None => ResultStat { start: 0, size: 0, kind: None, path: None, module: None, count },
                Some(i) => {
                    let r = &regs[i];
                    let module = mods.iter().find(|m| r.start >= m.base && r.start - m.base < m.size).map(|m| m.name.clone());
                    ResultStat { start: r.start, size: r.size, kind: Some(r.kind), path: r.path.clone(), module, count }
                }
            })
            .collect();
        out.sort_by_key(|s| (s.kind.is_none(), s.start));
        Ok(out)
    }
}

/// Sort order of [`Scanner::results`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SortKey {
    Address,
    Value,
}

/// One row of [`Scanner::result_stats`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResultStat {
    #[serde(with = "hexaddr")]
    pub start: Addr,
    pub size: u64,
    pub kind: Option<RegionKind>,
    pub path: Option<String>,
    pub module: Option<String>,
    pub count: u64,
}

/// How an entry's bytes are shown.
#[derive(Clone)]
struct Shape {
    vtype: VType,
    /// Bytes to read for the current value.
    size: usize,
    bit: Option<u8>,
    how: How,
}

#[derive(Clone)]
enum How {
    Custom(CustomType, Fmt),
    /// Bit offset, field length.
    Bits(usize, usize),
    Plain(Fmt),
}

/// `have`: bytes stored for the entry ("all" scans show the first type that fits).
fn shape(k: &Kind, w: usize, mask: u8, have: usize) -> Shape {
    if let Some(ct) = k.opts.custom {
        return Shape { vtype: k.vtype, size: ct.size(), bit: None, how: How::Custom(ct, Fmt { hex: k.opts.hex, ..Fmt::default() }) };
    }
    if k.binary() {
        let shift = mask.trailing_zeros().min(7) as usize;
        return Shape { vtype: VType::Binary, size: (k.bits + shift).div_ceil(8), bit: Some(shift as u8), how: How::Bits(shift, k.bits) };
    }
    let (vtype, w) = if k.all() {
        let fits = |i: usize| match ALL_ORDER.get(i) {
            Some(p) => p.width() <= have,
            None => 1 << i == ALL_STRING && k.str_len > 0 && k.str_len <= have,
        };
        match (0..7).find(|&i| mask & (1 << i) != 0 && fits(i)) {
            Some(6) => (VType::String, k.str_len),
            Some(i) => (ALL_ORDER[i].vtype(), ALL_ORDER[i].width()),
            None => (Prim::B1.vtype(), 1),
        }
    } else {
        (k.vtype, w)
    };
    let int = Prim::of(vtype).is_some_and(|p| !p.is_float());
    Shape { vtype, size: w, bit: None, how: How::Plain(Fmt { len: None, signed: k.opts.signed, hex: k.opts.hex && int, utf16: k.opts.utf16 }) }
}

impl Shape {
    fn show(&self, k: &Kind, b: &[u8]) -> String {
        match &self.how {
            How::Custom(ct, f) => ct.format(b, f),
            How::Bits(shift, n) => bit_string(b, *shift, *n),
            How::Plain(f) => {
                let b = &b[..self.size.min(b.len())];
                match self.vtype {
                    VType::String => k.enc().decode(b),
                    vt => format_value(vt, b, f),
                }
            }
        }
    }
}

/// Sort key of a stored value: the number, or the first 8 bytes big-endian.
fn sort_value(k: &Kind, w: usize, mask: u8, b: &[u8]) -> f64 {
    let sh = shape(k, w, mask, b.len());
    match (&sh.how, Prim::of(sh.vtype)) {
        (How::Custom(ct, _), _) if b.len() >= ct.size() => ct.number(b).map_or(f64::NAN, |n| n.as_f64()),
        (How::Plain(_), Some(p)) if b.len() >= p.width() => with_num!(p, k.opts.signed, T => T::rd(b).f()),
        _ => {
            let mut x = [0u8; 8];
            let n = b.len().min(8).min(sh.size.max(1));
            x[..n].copy_from_slice(&b[..n]);
            u64::from_be_bytes(x) as f64
        }
    }
}

/// Reads `(address, length)` requests with few calls: nearby requests share one read plan.
/// `None` where a request is not fully readable.
fn read_many(mem: &dyn Memory, reqs: &[(Addr, usize)]) -> Vec<Option<Vec<u8>>> {
    let mut idx: Vec<usize> = (0..reqs.len()).collect();
    idx.sort_by_key(|&i| reqs[i].0);
    let mut out = vec![None; reqs.len()];
    let mut i = 0;
    while i < idx.len() {
        let base = reqs[idx[i]].0;
        let (mut j, mut end) = (i, base);
        while let Some(&x) = idx.get(j) {
            let (a, n) = reqs[x];
            let e = a.saturating_add(n as u64);
            if j > i && (a > end.saturating_add(GAP as u64) || e - base > MAX_READ as u64) {
                break;
            }
            end = end.max(e);
            j += 1;
        }
        let want = idx[i..j].iter().map(|&x| {
            let o = (reqs[x].0 - base) as usize;
            o..o + reqs[x].1
        });
        let buf = ReadBuf::read_ranges(mem, base, (end - base) as usize, want);
        for &x in &idx[i..j] {
            let (a, n) = reqs[x];
            out[x] = buf.slice((a - base) as usize, n).filter(|s| s.len() == n).map(<[u8]>::to_vec);
        }
        i = j;
    }
    out
}

/// Chunk groups a next scan reads together: consecutive packed chunks close to each other
/// (one read plan, so nearby entries share read calls); dense chunks (memory copies, read
/// whole) stay alone.
fn read_groups(chunks: &[Chunk]) -> Vec<Range<usize>> {
    let packed = |c: &Chunk| matches!(c.kind, ChunkKind::Packed { .. });
    let mut out: Vec<Range<usize>> = Vec::new();
    for (i, c) in chunks.iter().enumerate() {
        if let Some(g) = out.last_mut()
            && packed(c)
            && packed(&chunks[g.start])
            && c.base <= chunks[i - 1].end.saturating_add(GAP as u64)
            && c.end.saturating_sub(chunks[g.start].base) <= MAX_READ as u64
        {
            g.end = i + 1;
            continue;
        }
        out.push(i..i + 1);
    }
    out
}

/// Sorted, merged copy of `v` (empty ranges dropped).
fn norm(mut v: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
    v.retain(|r| r.0 < r.1);
    v.sort_unstable();
    let mut out: Vec<(u64, u64)> = Vec::with_capacity(v.len());
    for r in v {
        match out.last_mut() {
            Some(l) if r.0 <= l.1 => l.1 = l.1.max(r.1),
            _ => out.push(r),
        }
    }
    out
}

/// The parts of `[lo, hi)` inside `inc` (normalized; `None` = everywhere) and outside `exc`.
fn clip(lo: u64, hi: u64, inc: Option<&[(u64, u64)]>, exc: &[(u64, u64)]) -> Vec<(u64, u64)> {
    let mut v: Vec<(u64, u64)> = match inc {
        None => vec![(lo, hi)],
        Some(inc) => inc[inc.partition_point(|r| r.1 <= lo)..].iter().take_while(|r| r.0 < hi).map(|&(a, b)| (a.max(lo), b.min(hi))).collect(),
    };
    for &(a, b) in exc.iter().filter(|r| r.0 < hi && r.1 > lo) {
        v = v.into_iter().flat_map(|(s, e)| [(s, e.min(a)), (s.max(b), e)]).filter(|r| r.0 < r.1).collect();
    }
    v.retain(|r| r.0 < r.1);
    v
}

fn in_ranges(r: &[(u64, u64)], v: u64) -> bool {
    let i = r.partition_point(|x| x.0 <= v);
    i > 0 && v < r[i - 1].1
}

/// Address ranges of the named modules (case-insensitive); an unknown name is an error when
/// `strict`, skipped otherwise.
fn module_ranges(p: &dyn Process, names: &[String], strict: bool) -> Result<Vec<(u64, u64)>> {
    let mods = p.modules()?;
    let mut out = Vec::new();
    for n in names {
        match mods.iter().find(|m| m.name.eq_ignore_ascii_case(n.trim())) {
            Some(m) => out.push((m.base, m.base.saturating_add(m.size))),
            None if strict => return Err(Error::Parse(format!("no module named {n:?}"))),
            None => {}
        }
    }
    Ok(out)
}

/// Runs a first scan's predicate over positions `bs, bs+step, .. < be` of `s` (memory at
/// `base`); the caller guarantees every test's `need` fits for positions below `be`, except
/// longer binary patterns, which are cut at `s`'s end.
#[allow(clippy::too_many_arguments)]
fn scan_block(plan: &Plan, al: Align, s: &[u8], base: Addr, bs: usize, be: usize, step: usize, hit: &mut impl FnMut(usize, u8)) {
    let find = |pat: &Pattern, f: &mut dyn FnMut(usize)| {
        let hay = &s[bs..(be - 1 + pat.len()).min(s.len())];
        pat.find_all(hay, |p| {
            if al.pad(base + (bs + p) as u64) == 0 && bs + p < be {
                f(bs + p)
            }
        })
    };
    match &plan.fast {
        Fast::Num(prim, signed, c, not) => {
            with_num!(*prim, *signed, T => fast_num::<T>(s, bs, be, step, c, *not, &mut |p| hit(p, 1)))
        }
        Fast::Pat(pat) => find(pat, &mut |p| hit(p, 1)),
        Fast::Pats(pats) => {
            let mut hits: Vec<(usize, u8)> = Vec::new();
            for (bit, pat) in pats {
                find(pat, &mut |p| hits.push((p, *bit)));
            }
            hits.sort_unstable();
            let mut i = 0;
            while i < hits.len() {
                let (p, mut m) = hits[i];
                while i + 1 < hits.len() && hits[i + 1].0 == p {
                    i += 1;
                    m |= hits[i].1;
                }
                hit(p, m);
                i += 1;
            }
        }
        Fast::None => {
            for p in (bs..be).step_by(step) {
                let c = &s[p..];
                let m = plan.tests.iter().filter(|t| c.len() >= t.need && (t.pred)(c, c, c)).fold(0, |m, t| m | t.bit);
                if m != 0 {
                    hit(p, m)
                }
            }
        }
    }
}

/// Next scan over a dense chunk with one numeric test; sets survivors' bits in `marks` (a
/// bitmap over the `npos` positions) and returns their count. Slices come with the chunk
/// offset of their byte 0.
#[allow(clippy::too_many_arguments)]
fn dense_kernel<T: Num>(
    c: &NumCmp,
    not: bool,
    live: (&[u8], usize),
    prev: (&[u8], usize),
    first: (&[u8], usize),
    p0: usize,
    align: usize,
    npos: usize,
    bits: Option<&[u8]>,
    marks: &mut [u8],
    check: &mut dyn FnMut() -> Result<()>,
) -> Result<u64> {
    let w = T::W;
    let fits = |s: (&[u8], usize), o: usize| o >= s.1 && o - s.1 + w <= s.0.len();
    #[inline(always)]
    fn rd<T: Num>(s: (&[u8], usize), o: usize) -> T {
        T::rd(&s.0[o - s.1..])
    }
    let test = |o: usize| u64::from(eval(c, rd::<T>(live, o), rd::<T>(prev, o), rd::<T>(first, o)) != not);
    let mut count = 0;
    // Positions in 64-bit words; BLOCK_ENTRIES is a multiple of 64.
    for b0 in (0..npos.div_ceil(64)).step_by(BLOCK_ENTRIES / 64) {
        check()?;
        for wi in b0..npos.div_ceil(64).min(b0 + BLOCK_ENTRIES / 64) {
            let (k0, k1) = (wi * 64, npos.min(wi * 64 + 64));
            let (o0, o1) = (p0 + k0 * align, p0 + (k1 - 1) * align);
            let mut sel = match bits {
                None => u64::MAX >> (64 - (k1 - k0)),
                Some(bm) => {
                    let mut x = [0u8; 8];
                    let src = bm.get(wi * 8..bm.len().min(wi * 8 + 8)).unwrap_or_default();
                    x[..src.len()].copy_from_slice(src);
                    u64::from_le_bytes(x)
                }
            };
            let mut m = 0u64;
            if sel == u64::MAX && [live, prev, first].iter().all(|s| fits(*s, o0) && fits(*s, o1)) {
                // Every position of the word is a candidate and in bounds: branch-free.
                for j in 0..64 {
                    let o = o0 + j * align;
                    m |= u64::from(eval(c, rd::<T>(live, o), rd::<T>(prev, o), rd::<T>(first, o)) != not) << j;
                }
            } else {
                while sel != 0 {
                    let j = sel.trailing_zeros() as usize;
                    sel &= sel - 1;
                    let o = p0 + (k0 + j) * align;
                    if [live, prev, first].iter().all(|s| fits(*s, o)) {
                        m |= test(o) << j;
                    }
                }
            }
            count += u64::from(m.count_ones());
            let end = marks.len().min(wi * 8 + 8);
            let dst = &mut marks[wi * 8..end];
            let n = dst.len();
            dst.copy_from_slice(&m.to_le_bytes()[..n]);
        }
    }
    Ok(count)
}

/// Order-preserving map of a number's bits to `u64` (so a value range is a key range).
trait Key: Num {
    fn key(self) -> u64;
}
macro_rules! key_int {
    ($($t:ty => $sign:expr),*) => {$(
        impl Key for $t {
            #[inline(always)]
            fn key(self) -> u64 { self.bits() ^ $sign }
        }
    )*};
}
key_int!(u8 => 0, u16 => 0, u32 => 0, u64 => 0, i8 => 1 << 7, i16 => 1 << 15, i32 => 1 << 31, i64 => 1 << 63);
impl Key for f32 {
    #[inline(always)]
    fn key(self) -> u64 {
        let b = self.to_bits();
        (b ^ ((((b as i32) >> 31) as u32) | 0x8000_0000)) as u64
    }
}
impl Key for f64 {
    #[inline(always)]
    fn key(self) -> u64 {
        let b = self.to_bits();
        b ^ ((((b as i64) >> 63) as u64) | 1 << 63)
    }
}

/// Keys `[lo, hi]` of the values `c` accepts; `Some(None)` = none; `None` = not a range.
fn key_range<T: Key>(c: &NumCmp) -> Option<Option<(u64, u64)>> {
    let int_key = |v: i128| T::rd(&(v as u64).to_le_bytes()).key();
    Some(match *c {
        NumCmp::Bits(v) => Some((int_key(v as i128), int_key(v as i128))),
        NumCmp::I(lo, hi) if !T::FLOAT => {
            let bits = 8 * T::W as u32;
            let signed = T::rd(&[0xff; 8]).i() < 0;
            let (tmin, tmax) = if signed { (-(1i128 << (bits - 1)), (1i128 << (bits - 1)) - 1) } else { (0, (1i128 << bits) - 1) };
            let (lo, hi) = (lo.max(tmin), hi.min(tmax));
            (lo <= hi).then(|| (int_key(lo), int_key(hi)))
        }
        NumCmp::F(lo, hi) if T::FLOAT => {
            // Smallest / largest value of the type inside [lo, hi], as raw bits.
            let (a, b) = if T::W == 4 {
                let mut a = lo as f32;
                if (a as f64) < lo {
                    a = a.next_up();
                }
                let mut b = hi as f32;
                if (b as f64) > hi {
                    b = b.next_down();
                }
                // -0.0 == 0.0: a zero bound covers both zeros.
                (if a == 0.0 { -0.0f32 } else { a }.to_bits() as u64, if b == 0.0 { 0.0f32 } else { b }.to_bits() as u64)
            } else {
                (if lo == 0.0 { -0.0f64 } else { lo }.to_bits(), if hi == 0.0 { 0.0f64 } else { hi }.to_bits())
            };
            let (a, b) = (T::rd(&a.to_le_bytes()), T::rd(&b.to_le_bytes()));
            (a.f() <= b.f()).then(|| (a.key(), b.key()))
        }
        _ => return None,
    })
}

fn fast_num<T: Key>(s: &[u8], p0: usize, end: usize, step: usize, c: &NumCmp, not: bool, hit: &mut impl FnMut(usize)) {
    match key_range::<T>(c) {
        Some(Some((lo, hi))) => {
            let span = hi - lo;
            scan_loop::<T>(s, p0, end, step, |x| (x.key().wrapping_sub(lo) <= span) != not, hit)
        }
        Some(None) => scan_loop::<T>(s, p0, end, step, |_| not, hit),
        None => scan_loop::<T>(s, p0, end, step, |x| eval(c, x, x, x) != not, hit),
    }
}

/// Calls `hit(p)` for every `p` in `p0..end` stepping by `step` where `f` matches;
/// the caller guarantees `end - 1 + T::W <= s.len()`. Aligned scans test 64 values into a
/// bit mask before branching, which the compiler vectorizes.
#[inline(always)]
fn scan_loop<T: Num>(s: &[u8], p0: usize, end: usize, step: usize, f: impl Fn(T) -> bool, hit: &mut impl FnMut(usize)) {
    if step == T::W {
        let n = (end - p0).div_ceil(T::W);
        for (bi, blk) in s[p0..p0 + n * T::W].chunks(64 * T::W).enumerate() {
            let mut m = 0u64;
            if let Some(full) = blk.get(..64 * T::W) {
                // Fixed trip count and hoisted bounds checks let this loop vectorize.
                for j in 0..64 {
                    m |= u64::from(f(T::rd(&full[j * T::W..(j + 1) * T::W]))) << j;
                }
            } else {
                for (j, b) in blk.chunks_exact(T::W).enumerate() {
                    m |= u64::from(f(T::rd(b))) << j;
                }
            }
            while m != 0 {
                let j = m.trailing_zeros() as usize;
                m &= m - 1;
                hit(p0 + (bi * 64 + j) * T::W);
            }
        }
    } else {
        for p in (p0..end).step_by(step) {
            if f(T::rd(&s[p..])) {
                hit(p);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_ranges_match_eval() {
        let vals = [0.0f32, -0.0, 1.5, -1.5, 1.45, 1.55, f32::INFINITY, f32::NEG_INFINITY, f32::NAN, 1e-40, -1e-40, f32::MAX];
        for c in [NumCmp::F(1.45, 1.55), NumCmp::F(-2.0, 0.0), NumCmp::F(f64::NEG_INFINITY, -0.5), NumCmp::F(0.1f64.next_up(), f64::INFINITY), NumCmp::F(5.0, 4.0), NumCmp::F(0.0, 1.0)] {
            let r = key_range::<f32>(&c).unwrap();
            for v in vals {
                let by_key = r.is_some_and(|(lo, hi)| (lo..=hi).contains(&v.key()));
                assert_eq!(by_key, eval(&c, v, v, v), "{c:?} {v}");
            }
        }
        for c in [NumCmp::I(-5, 300), NumCmp::I(200, i128::MAX), NumCmp::I(i128::MIN, -129), NumCmp::Bits(0x80)] {
            for v in [-128i8, -5, -1, 0, 5, 127] {
                let r = key_range::<i8>(&c).unwrap();
                assert_eq!(r.is_some_and(|(lo, hi)| (lo..=hi).contains(&v.key())), eval(&c, v, v, v), "{c:?} {v}");
            }
            for v in [0u8, 5, 200, 255] {
                let r = key_range::<u8>(&c).unwrap();
                assert_eq!(r.is_some_and(|(lo, hi)| (lo..=hi).contains(&v.key())), eval(&c, v, v, v), "{c:?} {v}");
            }
        }
    }
}
