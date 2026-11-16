//! Pointer scanner commands over hh-ptr. Result files live in a per-session temp directory
//! (removed with the session) unless the user saves them elsewhere.
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};

use hh_ptr::{CollectOptions, PointerMap, PointerPath, Progress, RescanOptions, ResultFile, ScanOptions, Source};
use hh_scan::{Fmt, VType, ValueRef};
use serde::{Deserialize, Serialize};

use crate::commands::{App, R, hex_addr, lock, parse_addr, s};

pub struct Ptr {
    /// Private (0700, unpredictable name) scratch directory, removed on drop.
    dir: std::sync::OnceLock<tempfile::TempDir>,
    seq: AtomicU64,
    running: AtomicBool,
    cancel: AtomicBool,
    /// Paused by the user; carried over to the next phase's progress.
    paused: AtomicBool,
    phase: Mutex<&'static str>,
    progress: Mutex<Arc<Progress>>,
    map: Mutex<Option<Arc<PointerMap>>>,
    file: Mutex<Option<Arc<ResultFile>>>,
    /// The current results in a user-chosen order (column sort); `None` = file order.
    order: Mutex<Option<Arc<Vec<PointerPath>>>>,
}

/// Most paths a column sort loads into memory (~100 bytes each).
const MAX_SORT: u64 = 2_000_000;

impl Ptr {
    pub(crate) fn new() -> Self {
        Ptr {
            dir: std::sync::OnceLock::new(),
            seq: AtomicU64::new(0),
            running: AtomicBool::new(false),
            cancel: AtomicBool::new(false),
            paused: AtomicBool::new(false),
            phase: Mutex::new(""),
            progress: Mutex::default(),
            map: Mutex::default(),
            file: Mutex::default(),
            order: Mutex::default(),
        }
    }

    fn temp(&self, ext: &str) -> R<PathBuf> {
        let dir = match self.dir.get() {
            Some(d) => d,
            None => {
                let mut b = tempfile::Builder::new();
                b.prefix("heaphook-ptr-");
                #[cfg(unix)]
                b.permissions(std::os::unix::fs::PermissionsExt::from_mode(0o700));
                let d = b.tempdir().map_err(s)?;
                let _ = self.dir.set(d);
                self.dir.get().expect("set above")
            }
        };
        Ok(dir.path().join(format!("{}.{ext}", self.seq.fetch_add(1, Relaxed))))
    }

    /// Marks an operation as running until the guard drops.
    fn start(&self) -> R<RunGuard<'_>> {
        if self.running.swap(true, Relaxed) {
            return Err("a pointer scan is already running".into());
        }
        self.cancel.store(false, Relaxed);
        self.paused.store(false, Relaxed);
        Ok(RunGuard(self))
    }

    /// A fresh progress for the next phase; errors if the user cancelled in between.
    fn phase(&self, name: &'static str) -> R<Arc<Progress>> {
        if self.cancel.load(Relaxed) {
            return Err("cancelled".into());
        }
        *lock(&self.phase) = name;
        let p = Arc::new(Progress::new());
        if self.paused.load(Relaxed) {
            p.pause();
        }
        *lock(&self.progress) = p.clone();
        Ok(p)
    }

    fn set_file(&self, f: ResultFile) -> PtrInfo {
        let info = PtrInfo::of(&f);
        *lock(&self.order) = None;
        if let Some(old) = lock(&self.file).replace(Arc::new(f))
            && self.dir.get().is_some_and(|d| old.path().starts_with(d.path()))
        {
            let _ = std::fs::remove_file(old.path());
        }
        info
    }

    fn file(&self) -> R<Arc<ResultFile>> {
        lock(&self.file).clone().ok_or_else(|| "no pointer scan results".into())
    }
}

struct RunGuard<'a>(&'a Ptr);
impl Drop for RunGuard<'_> {
    fn drop(&mut self) {
        *lock(&self.0.phase) = "";
        self.0.paused.store(false, Relaxed);
        self.0.running.store(false, Relaxed);
    }
}

/// Another process's saved pointer map and where the value lived in it.
#[derive(Debug, Clone, Deserialize)]
pub struct CompareIn {
    pub path: String,
    pub target: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct PtrScanReq {
    pub target: String,
    /// hh-ptr `ScanOptions`; `base_range` comes as hex strings below.
    pub opts: ScanOptions,
    pub base_start: Option<String>,
    pub base_end: Option<String>,
    /// Pointer map collection: slot alignment (0 = pointer size) and writable-only sources.
    pub alignment: u64,
    pub writable_only: bool,
    /// Scan this saved map instead of collecting one from the process.
    pub map_path: Option<String>,
    pub compare: Vec<CompareIn>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct PtrRescanReq {
    /// Paths must lead to this address.
    pub target: Option<String>,
    /// The value at the end of the path must equal this (`vtype`/`fmt` say how to parse it).
    pub value: Option<String>,
    pub vtype: Option<VType>,
    pub fmt: Fmt,
    pub base_start: Option<String>,
    pub base_end: Option<String>,
    pub starts_with: Vec<i64>,
    pub ends_with: Vec<i64>,
    pub max_level: usize,
    /// Resolve against this saved map instead of the live process.
    pub map_path: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PtrInfo {
    pub count: u64,
    pub max_level: usize,
    pub target: String,
    /// The compact (1.0) file format; `false` for a result file from before 1.0.
    pub compact: bool,
}

impl PtrInfo {
    fn of(f: &ResultFile) -> Self {
        PtrInfo { count: f.len(), max_level: f.header.max_level, target: hex_addr(f.header.target), compact: f.is_compact() }
    }
}

/// A file the user picked must be a regular file (a FIFO or device would block the loader).
pub(crate) fn regular_file(path: &str) -> R<&Path> {
    let m = std::fs::metadata(path).map_err(|e| format!("{path}: {e}"))?;
    if !m.is_file() {
        return Err(format!("{path}: not a regular file"));
    }
    Ok(Path::new(path))
}

#[derive(Debug, Clone, Serialize)]
pub struct PtrProgress {
    pub running: bool,
    /// `collect` (pointer map), `scan`, `rescan` or empty.
    pub phase: &'static str,
    pub done: u64,
    pub total: u64,
    pub found: u64,
    /// Held by `ptr_pause` (cancel still ends it).
    pub paused: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct PtrRow {
    /// `"game.exe"+1A2B3C`, `THREADSTACK0-128` or an absolute hex address.
    pub base: String,
    /// Signed hex, in the order they are applied.
    pub offsets: Vec<String>,
    /// The whole path in CE notation (accepted by `resolve_address`).
    pub text: String,
    pub address: Option<String>,
    pub value: Option<String>,
}

fn signed_hex(o: i64) -> String {
    if o < 0 { format!("-{:X}", o.unsigned_abs()) } else { format!("{o:X}") }
}

fn range(a: &Option<String>, b: &Option<String>) -> R<Option<(u64, u64)>> {
    match (a.as_deref().filter(|x| !x.trim().is_empty()), b.as_deref().filter(|x| !x.trim().is_empty())) {
        (None, None) => Ok(None),
        (a, b) => Ok(Some((a.map(parse_addr).transpose()?.unwrap_or(0), b.map(parse_addr).transpose()?.unwrap_or(u64::MAX)))),
    }
}

impl App {
    /// The target runs on this machine: every thread's stack counts (`THREADSTACK1`...).
    fn ptr_local(&self) -> bool {
        self.session().is_ok_and(|s| s.info.remote.is_none())
    }

    /// Collects a pointer map (or loads `map_path`) and finds every path to `target`.
    /// Blocks until done; poll `ptr_progress`, stop with `ptr_cancel` (keeps what was found).
    pub fn ptr_scan(&self, req: &PtrScanReq) -> R<PtrInfo> {
        let sess = self.session()?;
        let pt = &sess.ptr;
        let _run = pt.start()?;
        let target = parse_addr(&req.target)?;
        let mut o = req.opts.clone();
        o.base_range = range(&req.base_start, &req.base_end)?;
        let compare = req
            .compare
            .iter()
            .map(|c| Ok((PointerMap::load(regular_file(&c.path)?).map_err(|e| format!("{}: {e}", c.path))?, parse_addr(&c.target)?)))
            .collect::<R<Vec<_>>>()?;
        let prog = pt.phase("collect")?;
        let map = match &req.map_path {
            Some(p) => PointerMap::load(regular_file(p)?),
            None => PointerMap::collect_ex(&*sess.proc, &CollectOptions { alignment: req.alignment, writable_only: req.writable_only }, sess.info.remote.is_none(), &prog),
        }
        .map_err(s)?;
        let map = Arc::new(map);
        *lock(&pt.map) = Some(map.clone());
        let prog = pt.phase("scan")?;
        let cmp: Vec<(&PointerMap, u64)> = compare.iter().map(|(m, a)| (m, *a)).collect();
        let f = map.scan(target, &o, &cmp, &pt.temp("ptr")?, &prog).map_err(s)?;
        Ok(pt.set_file(f))
    }

    /// Filters the current results into a new result set.
    pub fn ptr_rescan(&self, req: &PtrRescanReq) -> R<PtrInfo> {
        let sess = self.session()?;
        let pt = &sess.ptr;
        let _run = pt.start()?;
        let file = pt.file()?;
        let value = match (&req.value, req.vtype) {
            (Some(v), Some(t)) if !v.trim().is_empty() => Some(hh_scan::parse_value(t, v, &req.fmt).map_err(s)?),
            (Some(v), None) if !v.trim().is_empty() => return Err("a value filter needs a value type".into()),
            _ => None,
        };
        let o = RescanOptions {
            target: req.target.as_deref().filter(|t| !t.trim().is_empty()).map(parse_addr).transpose()?,
            value,
            base_range: range(&req.base_start, &req.base_end)?,
            starts_with: req.starts_with.clone(),
            ends_with: req.ends_with.clone(),
            max_level: req.max_level,
        };
        let map = req.map_path.as_deref().map(|p| PointerMap::load(regular_file(p)?).map_err(s)).transpose()?;
        let src = match &map {
            Some(m) => Source::Map(m),
            None if sess.info.remote.is_none() => Source::LocalProcess(&*sess.proc),
            None => Source::Process(&*sess.proc),
        };
        let prog = pt.phase("rescan")?;
        let f = file.rescan(src, &o, &pt.temp("ptr")?, &prog).map_err(s)?;
        Ok(pt.set_file(f))
    }

    pub fn ptr_progress(&self) -> R<PtrProgress> {
        let Ok(sess) = self.session() else {
            return Ok(PtrProgress { running: false, phase: "", done: 0, total: 0, found: 0, paused: false });
        };
        let p = lock(&sess.ptr.progress).snapshot();
        Ok(PtrProgress {
            running: sess.ptr.running.load(Relaxed),
            phase: *lock(&sess.ptr.phase),
            done: p.done,
            total: p.total,
            found: p.found,
            paused: sess.ptr.paused.load(Relaxed),
        })
    }

    /// Holds (`true`) or resumes the running pointer scan, rescan or map collection.
    pub fn ptr_pause(&self, pause: bool) -> R<()> {
        let sess = self.session()?;
        if !sess.ptr.running.load(Relaxed) {
            return Err("no pointer scan is running".into());
        }
        sess.ptr.paused.store(pause, Relaxed);
        let p = lock(&sess.ptr.progress).clone();
        if pause { p.pause() } else { p.resume() }
        Ok(())
    }

    pub fn ptr_cancel(&self) -> R<()> {
        if let Ok(sess) = self.session() {
            sess.ptr.cancel.store(true, Relaxed);
            sess.ptr.paused.store(false, Relaxed);
            let p = lock(&sess.ptr.progress).clone();
            p.cancel();
            p.resume();
        }
        Ok(())
    }

    /// Rows `[offset, offset + limit)` resolved now, with the value at the end of each path
    /// formatted as `vtype`.
    pub fn ptr_results(&self, offset: u64, limit: usize, vtype: VType, fmt: &Fmt) -> R<Vec<PtrRow>> {
        let sess = self.session()?;
        let local = self.ptr_local();
        let order = lock(&sess.ptr.order).clone();
        let rows = match order {
            Some(o) => o
                .iter()
                .skip(offset as usize)
                .take(limit.min(10_000))
                .map(|p| {
                    let address = hh_ptr::resolve_ex(&*sess.proc, p, local).ok();
                    hh_ptr::ResultRow { text: p.to_string(), path: p.clone(), address, value: None }
                })
                .collect(),
            None => sess.ptr.file()?.results_ex(offset, limit.min(10_000), Some(&*sess.proc), local).map_err(s)?,
        };
        let reqs: Vec<ValueRef> = rows.iter().map(|r| ValueRef { addr: r.address.unwrap_or(0), vtype, fmt: *fmt }).collect();
        let vals = hh_scan::read_values(&*sess.proc, &reqs);
        Ok(rows
            .into_iter()
            .zip(vals)
            .map(|(r, v)| PtrRow {
                base: r.path.base_text(),
                offsets: r.path.offsets.iter().map(|&o| signed_hex(o)).collect(),
                text: r.text,
                value: r.address.and(v),
                address: r.address.map(hex_addr),
            })
            .collect())
    }

    /// A cheat-table entry (docs/CONTRACT.md shape) for row `index`.
    pub fn ptr_entry(&self, index: u64, vtype: &str, description: &str) -> R<serde_json::Value> {
        let sess = self.session()?;
        let order = lock(&sess.ptr.order).clone();
        let path = match order {
            Some(o) => o.get(index as usize).cloned(),
            None => sess.ptr.file()?.read(index, 1).map_err(s)?.pop(),
        }
        .ok_or("no such row")?;
        Ok(hh_ptr::to_table_entry(&path, 0, description, vtype))
    }

    /// Saves the pointer map of the last scan, or collects one now when there is none.
    pub fn ptr_save_map(&self, path: &str) -> R<()> {
        let sess = self.session()?;
        let pt = &sess.ptr;
        let map = lock(&pt.map).clone();
        let map = match map {
            Some(m) => m,
            None => {
                let _run = pt.start()?;
                let m = Arc::new(PointerMap::collect_ex(&*sess.proc, &CollectOptions::default(), sess.info.remote.is_none(), &*pt.phase("collect")?).map_err(s)?);
                *lock(&pt.map) = Some(m.clone());
                m
            }
        };
        map.save(Path::new(path)).map_err(s)
    }

    /// Orders the results by `key`: `base` (hh-ptr's sorted file: level, module, offset,
    /// offsets), `offset` (offset number `column`, paths without one first) or `value` (the
    /// value at the end, numeric when it parses). `desc` reverses.
    pub fn ptr_sort(&self, key: &str, column: usize, desc: bool, vtype: VType, fmt: &Fmt) -> R<PtrInfo> {
        let sess = self.session()?;
        let pt = &sess.ptr;
        let _run = pt.start()?;
        if key == "base" {
            let sorted = pt.file()?.sorted(&pt.temp("ptr")?).map_err(s)?;
            let info = pt.set_file(sorted);
            if !desc {
                return Ok(info);
            }
        }
        let file = pt.file()?;
        if file.len() > MAX_SORT {
            return Err(format!("{} paths are too many to sort by this column; rescan to narrow them down first", file.len()));
        }
        let mut paths = file.read(0, file.len() as usize).map_err(s)?;
        match key {
            "base" => {}
            "offset" => paths.sort_by_key(|p| p.offsets.get(column).copied()),
            "value" => {
                let local = sess.info.remote.is_none();
                let reqs: Vec<ValueRef> = paths.iter().map(|p| ValueRef { addr: hh_ptr::resolve_ex(&*sess.proc, p, local).unwrap_or(0), vtype, fmt: *fmt }).collect();
                let vals = hh_scan::read_values(&*sess.proc, &reqs);
                let key = |v: &Option<String>| (v.is_some(), v.as_deref().and_then(|x| x.trim().parse::<f64>().ok()).unwrap_or(f64::NAN), v.clone().unwrap_or_default());
                let mut kv: Vec<_> = paths.into_iter().zip(vals.iter().map(key)).collect();
                kv.sort_by(|a, b| a.1.0.cmp(&b.1.0).then(a.1.1.total_cmp(&b.1.1)).then_with(|| a.1.2.cmp(&b.1.2)));
                paths = kv.into_iter().map(|x| x.0).collect();
            }
            k => return Err(format!("unknown sort key {k:?}")),
        }
        if desc {
            paths.reverse();
        }
        *lock(&pt.order) = Some(Arc::new(paths));
        Ok(PtrInfo::of(&file))
    }

    pub fn ptr_save_results(&self, path: &str) -> R<()> {
        let f = self.session()?.ptr.file()?;
        // Saving onto the open result file itself would truncate it before copying.
        if std::fs::canonicalize(path).ok().is_some_and(|p| std::fs::canonicalize(f.path()).ok() == Some(p)) {
            return Ok(());
        }
        std::fs::copy(f.path(), path).map(drop).map_err(s)
    }

    pub fn ptr_open_results(&self, path: &str) -> R<PtrInfo> {
        let f = ResultFile::open(regular_file(path)?).map_err(s)?;
        Ok(self.session()?.ptr.set_file(f))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    #[cfg(unix)]
    fn scratch_dir_is_private_and_unpredictable() {
        use std::os::unix::fs::PermissionsExt;
        let (a, b) = (super::Ptr::new(), super::Ptr::new());
        let (pa, pb) = (a.temp("x").unwrap(), b.temp("x").unwrap());
        let da = pa.parent().unwrap();
        assert_ne!(da, pb.parent().unwrap());
        assert_eq!(std::fs::metadata(da).unwrap().permissions().mode() & 0o777, 0o700);
        assert!(!da.file_name().unwrap().to_string_lossy().contains(&std::process::id().to_string()));
        drop(a);
        assert!(!da.exists(), "scratch dir left behind");
    }
}
