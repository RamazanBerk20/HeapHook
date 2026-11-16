//! Plain functions and a background-job handle for driving pointer scans from a script
//! engine (Lua): start a scan, poll, pause/resume/cancel, then page the [`ResultFile`]
//! with [`ResultFile::len`], [`ResultFile::read`] and [`ResultFile::results`].
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use hh_core::{Addr, Error, Process, Result};

use crate::{CollectOptions, PointerMap, Progress, ProgressSnapshot, ResultFile, ScanOptions};

/// Collects a pointer map of `p` and scans it for `target`, writing the paths to `out`
/// (blocking). `local`: `p` runs on this machine (per-thread stacks, see
/// [`crate::thread_stacks`]).
pub fn scan_process(
    p: &dyn Process,
    target: Addr,
    opts: &ScanOptions,
    collect: &CollectOptions,
    local: bool,
    out: &std::path::Path,
    progress: &Progress,
) -> Result<ResultFile> {
    let map = PointerMap::collect_ex(p, collect, local, progress)?;
    map.scan(target, opts, &[], out, progress)
}

/// A pointer scan running on its own thread ([`scan_process`]).
pub struct PointerScanJob {
    progress: Arc<Progress>,
    thread: Mutex<Option<JoinHandle<Result<ResultFile>>>>,
    result: Mutex<Option<std::result::Result<ResultFile, String>>>,
}

impl PointerScanJob {
    pub fn start(
        p: Arc<dyn Process>,
        target: Addr,
        opts: ScanOptions,
        collect: CollectOptions,
        local: bool,
        out: PathBuf,
    ) -> Result<Self> {
        let progress = Arc::new(Progress::new());
        let pr = progress.clone();
        let th = std::thread::Builder::new()
            .name("hh-ptr-scan".into())
            .spawn(move || scan_process(&*p, target, &opts, &collect, local, &out, &pr))?;
        Ok(PointerScanJob { progress, thread: Mutex::new(Some(th)), result: Mutex::new(None) })
    }

    pub fn progress(&self) -> ProgressSnapshot {
        self.progress.snapshot()
    }
    pub fn pause(&self) {
        self.progress.pause()
    }
    pub fn resume(&self) {
        self.progress.resume()
    }
    /// Stops the scan; [`PointerScanJob::wait`] then gives the paths found so far (a
    /// cancel while the pointer map is still being collected is an error).
    pub fn cancel(&self) {
        self.progress.cancel()
    }
    pub fn is_done(&self) -> bool {
        self.result.lock().unwrap_or_else(|e| e.into_inner()).is_some()
            || self.thread.lock().unwrap_or_else(|e| e.into_inner()).as_ref().is_none_or(|t| t.is_finished())
    }

    /// Waits for the scan to end and returns its result file (the same on every call).
    pub fn wait(&self) -> Result<ResultFile> {
        let mut res = self.result.lock().unwrap_or_else(|e| e.into_inner());
        if res.is_none() {
            let th = self.thread.lock().unwrap_or_else(|e| e.into_inner()).take();
            *res = Some(match th.map(JoinHandle::join) {
                Some(Ok(r)) => r.map_err(|e| e.to_string()),
                Some(Err(_)) => Err("pointer scan thread panicked".into()),
                None => Err("pointer scan already collected".into()),
            });
        }
        res.clone().unwrap_or_else(|| Err("no result".into())).map_err(Error::Other)
    }
}

impl Drop for PointerScanJob {
    fn drop(&mut self) {
        self.progress.cancel();
        if let Some(t) = self.thread.lock().unwrap_or_else(|e| e.into_inner()).take() {
            let _ = t.join();
        }
    }
}
