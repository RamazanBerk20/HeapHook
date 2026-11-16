//! Reverse pointer search from a target address over a [`PointerMap`].
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::time::{Duration, Instant};

use hh_core::{Addr, Error, Result};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::map::{Entry, PointerMap};
use crate::path::{is_stack, walk};
use crate::results::{ABS, ResultFile, ResultHeader, Writer, encode};
use crate::{MAX_LEVEL, Progress};

/// Cheat Engine's pointer scan dialog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ScanOptions {
    /// Maximum number of offsets in a path (1..=16).
    pub max_level: usize,
    /// Maximum offset per level ("structure size").
    pub max_offset: u64,
    /// Also allow offsets down to `-max_offset`.
    pub allow_negative: bool,
    /// Bases must be static (module images, and thread stacks if enabled). When false,
    /// every node is a base (absolute address) unless it is static.
    pub static_only: bool,
    /// Only these modules count as static bases (case-insensitive names); empty = all.
    pub base_modules: Vec<String>,
    /// Base address must be in `[start, end)`.
    pub base_range: Option<(Addr, Addr)>,
    /// Treat the top `stack_max` bytes of each thread stack as static (`THREADSTACK<n>`).
    pub thread_stacks: bool,
    pub stack_max: u64,
    /// A path never passes the same address twice.
    pub no_loops: bool,
    /// Follow at most this many pointers into each node, closest first ("max different
    /// offsets per node"); 0 = all.
    pub max_children: usize,
    /// The last offset must be one of these; empty = any.
    pub last_offsets: Vec<i64>,
    /// The path must end with exactly these offsets (in path order).
    pub ends_with: Vec<i64>,
    /// Intermediate nodes must be in private non-stack memory (heap).
    pub heap_only: bool,
    /// Stop after this many paths; 0 = unlimited.
    pub max_results: u64,
    /// Worker threads; 0 = all cores.
    pub threads: usize,
    /// The path must start with exactly these offsets (the ones applied first, from the
    /// base); Cheat Engine's "must start with offsets".
    pub starts_with: Vec<i64>,
    /// Every offset must be one of these; empty = any ("same offsets only").
    pub allowed_offsets: Vec<i64>,
    /// Do not search further back from a node that is already a static base (shorter
    /// paths only through it).
    pub stop_at_static: bool,
    /// Stop after this many seconds, keeping what was found (time paused does not count);
    /// 0 = no limit.
    pub time_limit_secs: u64,
}

impl Default for ScanOptions {
    fn default() -> Self {
        ScanOptions {
            max_level: 5,
            max_offset: 0x1000,
            allow_negative: false,
            static_only: true,
            base_modules: Vec::new(),
            base_range: None,
            thread_stacks: true,
            stack_max: 0x1000,
            no_loops: true,
            max_children: 0,
            last_offsets: Vec::new(),
            ends_with: Vec::new(),
            heap_only: false,
            max_results: 0,
            threads: 0,
            starts_with: Vec::new(),
            allowed_offsets: Vec::new(),
            stop_at_static: false,
            time_limit_secs: 0,
        }
    }
}

/// Levels below this depth fan out across threads.
const PAR_DEPTH: usize = 2;
const FLUSH: usize = 1 << 16;

struct Static {
    start: u64,
    end: u64,
    base: u32,
    origin: u64,
}

struct Ctx<'a> {
    map: &'a PointerMap,
    o: &'a ScanOptions,
    statics: Vec<Static>,
    heap: Vec<(u64, u64)>,
    compare: Vec<(&'a PointerMap, Vec<Option<Addr>>, Addr)>,
    out: Mutex<(Writer, Option<Error>)>,
    progress: &'a Progress,
    stop: AtomicBool,
    deadline: Option<Instant>,
}

impl Ctx<'_> {
    fn candidates(&self, target: u64) -> &[Entry] {
        let lo = target.saturating_sub(self.o.max_offset);
        let hi = if self.o.allow_negative {
            target.saturating_add(self.o.max_offset)
        } else {
            target
        };
        let e = &self.map.entries;
        let i0 = e.partition_point(|x| x.value < lo);
        let i1 = e.partition_point(|x| x.value <= hi);
        &e[i0..i1.max(i0)]
    }

    /// `k` = position counted from the end of the path (0 = last offset).
    fn offset_ok(&self, k: usize, off: i64) -> bool {
        let ew = &self.o.ends_with;
        (k != 0 || self.o.last_offsets.is_empty() || self.o.last_offsets.contains(&off))
            && (k >= ew.len() || ew[ew.len() - 1 - k] == off)
            && (self.o.allowed_offsets.is_empty() || self.o.allowed_offsets.contains(&off))
    }

    fn children(&self, target: u64, k: usize) -> impl Iterator<Item = (u64, i64)> + '_ {
        // Highest value first = smallest positive offset first.
        self.candidates(target)
            .iter()
            .rev()
            .map(move |e| (e.addr, target.wrapping_sub(e.value) as i64))
            .filter(move |&(_, off)| self.offset_ok(k, off))
    }

    fn base_of(&self, a: u64) -> Option<(u32, i64)> {
        let in_range = self.o.base_range.is_none_or(|(s, e)| s <= a && a < e);
        let i = self.statics.partition_point(|s| s.start <= a);
        match self.statics[..i].last() {
            Some(s) if a < s.end && in_range => Some((s.base, a.wrapping_sub(s.origin) as i64)),
            _ if !self.o.static_only && in_range => Some((ABS, a as i64)),
            _ => None,
        }
    }

    fn node_ok(&self, a: u64) -> bool {
        if !self.o.heap_only {
            return true;
        }
        let i = self.heap.partition_point(|r| r.0 <= a);
        i > 0 && a < self.heap[i - 1].1
    }

    fn dfs(&self, target: u64, rev: &mut Vec<i64>, nodes: &mut Vec<u64>, buf: &mut Vec<u8>) {
        self.progress.wait_if_paused();
        // The pause total (a lock) is only looked at once the plain deadline has passed.
        if self.deadline.is_some_and(|d| {
            let now = Instant::now();
            now > d && now > d + self.progress.paused_for()
        }) {
            self.stop.store(true, Relaxed);
        }
        if self.stop.load(Relaxed) || self.progress.is_cancelled() {
            return;
        }
        let k = rev.len();
        if k >= PAR_DEPTH && self.o.max_children == 0 {
            for (a, off) in self.children(target, k) {
                self.visit(a, off, rev, nodes, buf);
            }
            return;
        }
        let mut kids: Vec<(u64, i64)> = self
            .children(target, k)
            .filter(|(a, _)| !(self.o.no_loops && nodes.contains(a)))
            .collect();
        if self.o.max_children > 0 {
            kids.sort_by_key(|&(_, o)| o.unsigned_abs());
            kids.truncate(self.o.max_children);
        }
        if k >= PAR_DEPTH {
            for (a, off) in kids {
                self.visit(a, off, rev, nodes, buf);
            }
            return;
        }
        if k == 0 {
            self.progress.start(kids.len() as u64);
        }
        let (rev0, nodes0): (&Vec<i64>, &Vec<u64>) = (rev, nodes);
        kids.par_iter().for_each(|&(a, off)| {
            let (mut r, mut n, mut b) = (rev0.clone(), nodes0.clone(), Vec::new());
            self.visit(a, off, &mut r, &mut n, &mut b);
            self.flush(&mut b);
            if k == 0 {
                self.progress.done.fetch_add(1, Relaxed);
            }
        });
    }

    fn visit(&self, a: u64, off: i64, rev: &mut Vec<i64>, nodes: &mut Vec<u64>, buf: &mut Vec<u8>) {
        if self.o.no_loops && nodes.contains(&a) {
            return;
        }
        rev.push(off);
        let base = self.base_of(a);
        if rev.len() >= self.o.ends_with.len()
            && let Some((b, bo)) = base
        {
            self.emit(b, bo, rev, buf);
        }
        let at_static = self.o.stop_at_static && base.is_some_and(|(b, _)| b != ABS);
        if rev.len() < self.o.max_level && self.node_ok(a) && !at_static {
            nodes.push(a);
            self.dfs(a, rev, nodes, buf);
            nodes.pop();
        }
        rev.pop();
    }

    fn emit(&self, base: u32, bo: i64, rev: &[i64], buf: &mut Vec<u8>) {
        let sw = &self.o.starts_with;
        if rev.len() < sw.len() || !rev.iter().rev().zip(sw).all(|(a, b)| a == b) {
            return;
        }
        if !self.compare.is_empty() {
            let offs: Vec<i64> = rev.iter().rev().copied().collect();
            let ok = self.compare.iter().all(|(m, addrs, tgt)| {
                let b = if base == ABS {
                    Some(0)
                } else {
                    addrs[base as usize]
                };
                b.and_then(|b| walk(b.wrapping_add_signed(bo), &offs, |a| m.read_ptr(a)))
                    == Some(*tgt)
            });
            if !ok {
                return;
            }
        }
        let prev = self.progress.found.fetch_add(1, Relaxed);
        if self.o.max_results > 0 && prev >= self.o.max_results {
            self.stop.store(true, Relaxed);
            return;
        }
        encode(buf, base, bo, rev.iter().rev().copied());
        if buf.len() >= FLUSH {
            self.flush(buf);
        }
    }

    fn flush(&self, buf: &mut Vec<u8>) {
        if buf.is_empty() {
            return;
        }
        let mut out = self.out.lock().unwrap_or_else(|e| e.into_inner());
        if out.1.is_none()
            && let Err(e) = out.0.write_encoded(buf)
        {
            out.1 = Some(e);
            self.stop.store(true, Relaxed);
        }
        buf.clear();
    }
}

impl PointerMap {
    /// Finds every path to `target` and writes them to `out`. Each `(map, target)` in
    /// `compare` must also resolve the path to its own target ("compare with other saved
    /// pointermaps"). On cancel the paths found so far are kept.
    pub fn scan(
        &self,
        target: Addr,
        o: &ScanOptions,
        compare: &[(&PointerMap, Addr)],
        out: &Path,
        progress: &Progress,
    ) -> Result<ResultFile> {
        if o.max_level == 0 || o.max_level > MAX_LEVEL {
            return Err(Error::Other(format!("max level must be 1..={MAX_LEVEL}")));
        }
        if o.max_offset > i32::MAX as u64 {
            return Err(Error::Other("max offset too large".into()));
        }
        let bad_offs = |v: &[i64]| v.len() > o.max_level || v.iter().any(|&x| i32::try_from(x).is_err());
        if bad_offs(&o.ends_with) || bad_offs(&o.starts_with) {
            return Err(Error::Other("bad ends_with / starts_with offsets".into()));
        }
        let mut names: Vec<String> = self.modules.iter().map(|m| m.name.clone()).collect();
        let wanted = |n: &str| {
            o.base_modules.is_empty() || o.base_modules.iter().any(|b| b.eq_ignore_ascii_case(n))
        };
        let mut statics: Vec<Static> = self
            .modules
            .iter()
            .enumerate()
            .filter(|(_, m)| wanted(&m.name))
            .map(|(i, m)| Static {
                start: m.base,
                end: m.base.saturating_add(m.size),
                base: i as u32,
                origin: m.base,
            })
            .collect();
        let stacks = self.stack_ranges();
        for (j, &(start, top)) in stacks.iter().enumerate() {
            if o.thread_stacks {
                statics.push(Static {
                    start: top.saturating_sub(o.stack_max).max(start),
                    end: top,
                    base: names.len() as u32,
                    origin: top,
                });
            }
            names.push(format!("THREADSTACK{j}"));
        }
        statics.sort_by_key(|s| s.start);
        let heap = self
            .regions
            .iter()
            .filter(|r| r.kind == hh_core::RegionKind::Private && !is_stack(r))
            .filter(|r| !stacks.iter().any(|s| s.0 < r.start.saturating_add(r.size) && r.start < s.1))
            .map(|r| (r.start, r.start.saturating_add(r.size)))
            .collect();
        let compare: Vec<_> = compare
            .iter()
            .map(|&(m, t)| {
                let b = m.bases();
                let addrs = names.iter().map(|n| b.addr_of(Some(n))).collect();
                (m, addrs, t)
            })
            .collect();
        let header = ResultHeader {
            pointer_size: self.pointer_size,
            max_level: o.max_level,
            target,
            bases: names,
        };
        let ctx = Ctx {
            map: self,
            o,
            statics,
            heap,
            compare,
            out: Mutex::new((Writer::create(out, &header)?, None)),
            progress,
            stop: AtomicBool::new(false),
            deadline: (o.time_limit_secs > 0).then(|| Instant::now().checked_add(Duration::from_secs(o.time_limit_secs))).flatten(),
        };
        let run = || {
            let mut buf = Vec::new();
            ctx.dfs(target, &mut Vec::new(), &mut vec![target], &mut buf);
            ctx.flush(&mut buf);
        };
        if o.threads > 0 {
            rayon::ThreadPoolBuilder::new()
                .num_threads(o.threads)
                .build()
                .map_err(|e| Error::Other(e.to_string()))?
                .install(run);
        } else {
            run();
        }
        let (w, err) = ctx.out.into_inner().unwrap_or_else(|e| e.into_inner());
        if let Some(e) = err {
            return Err(e);
        }
        let n = w.finish()?;
        progress.found.store(n, Relaxed);
        ResultFile::open(out)
    }
}
