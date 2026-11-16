//! HeapHook's own Lua pointer scan (`hhCreatePointerScan`, see the prelude): background
//! `hh_ptr::PointerScanJob`s, their results in a temporary file deleted with the job.
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hh_ptr::{CollectOptions, PointerScanJob, ScanOptions};
use mlua::{Table, Value};

use crate::State;
use crate::api::{B, addr, int_of, need_proc, rt, truthy};

type LR<T> = mlua::Result<T>;

/// Most paths one job keeps (`maxResults`; 0 asks for this many).
pub(crate) const MAX_PATHS: u64 = 10_000_000;
/// Most rows one `getResults` page returns.
const MAX_PAGE: usize = 10_000;
/// Most jobs alive at once.
const MAX_JOBS: usize = 16;

struct Job {
    job: Option<Arc<PointerScanJob>>,
    path: PathBuf,
}

impl Drop for Job {
    fn drop(&mut self) {
        // Cancel and join (PointerScanJob's own drop) before the file goes.
        if let Some(j) = self.job.take() {
            j.cancel();
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

#[derive(Default)]
pub(crate) struct Jobs(Mutex<HashMap<i64, Job>>);

pub(crate) fn clear(st: &State) {
    let all = std::mem::take(&mut *st.ext.ptr_jobs.0.lock().unwrap());
    drop(all);
}

fn job(st: &State, id: i64) -> LR<Arc<PointerScanJob>> {
    st.ext.ptr_jobs.0.lock().unwrap().get(&id).and_then(|j| j.job.clone()).ok_or_else(|| mlua::Error::runtime("pointer scan was destroyed"))
}

fn offsets(t: &Table, k: &str) -> LR<Vec<i64>> {
    Ok(match t.get::<Value>(k)? {
        Value::Table(l) => l.sequence_values::<Value>().map(|v| v.map(|v| int_of(&v).unwrap_or(0))).collect::<LR<_>>()?,
        _ => Vec::new(),
    })
}

fn options(st: &State, t: &Table) -> LR<(u64, ScanOptions, CollectOptions)> {
    let g = |k: &str| t.get::<Value>(k).unwrap_or(Value::Nil);
    let target = match g("target") {
        Value::Nil => return Err(mlua::Error::runtime("hhCreatePointerScan: options.target is required")),
        v => addr(st, &v, false).map_err(rt)?,
    };
    let d = ScanOptions::default();
    let num = |k: &str, def: u64| int_of(&g(k)).map_or(def, |v| v.max(0) as u64);
    let flag = |k: &str, def: bool| if g(k).is_nil() { def } else { truthy(&g(k)) };
    let max_results = num("maxResults", 100_000);
    let o = ScanOptions {
        max_level: num("maxLevel", d.max_level as u64).clamp(1, hh_ptr::MAX_LEVEL as u64) as usize,
        max_offset: num("maxOffset", d.max_offset),
        allow_negative: flag("allowNegative", d.allow_negative),
        static_only: flag("staticOnly", d.static_only),
        base_modules: match g("baseModules") {
            Value::Table(l) => l.sequence_values::<String>().collect::<LR<_>>()?,
            _ => Vec::new(),
        },
        thread_stacks: flag("threadStacks", d.thread_stacks),
        stack_max: num("stackMax", d.stack_max),
        no_loops: flag("noLoops", d.no_loops),
        max_children: num("maxChildren", 0) as usize,
        last_offsets: offsets(t, "lastOffsets")?,
        ends_with: offsets(t, "endsWith")?,
        starts_with: offsets(t, "startsWith")?,
        allowed_offsets: offsets(t, "allowedOffsets")?,
        heap_only: flag("heapOnly", d.heap_only),
        max_results: if max_results == 0 { MAX_PATHS } else { max_results.min(MAX_PATHS) },
        threads: num("threads", 0) as usize,
        stop_at_static: flag("stopAtStatic", d.stop_at_static),
        time_limit_secs: num("timeLimit", 0),
        ..d
    };
    let c = CollectOptions { alignment: num("alignment", 0), writable_only: flag("writableOnly", false) };
    Ok((target, o, c))
}

pub(crate) fn install(h: &B) -> LR<()> {
    h.f("ps_start", |_, st, t: Table| {
        let p = need_proc(st, false)?;
        let (target, o, c) = options(st, &t)?;
        let mut jobs = st.ext.ptr_jobs.0.lock().unwrap();
        if jobs.len() >= MAX_JOBS {
            return Err(mlua::Error::runtime(format!("more than {MAX_JOBS} pointer scans; destroy finished ones")));
        }
        let id = st.next_id.fetch_add(1, Ordering::SeqCst);
        let dir = hh_scan::spill_dir(None);
        std::fs::create_dir_all(&dir).map_err(|e| mlua::Error::runtime(format!("{}: {e}", dir.display())))?;
        let path = dir.join(format!("heaphook-lua-ptr-{}-{id}.hhptr", std::process::id()));
        let j = PointerScanJob::start(p, target, o, c, false, path.clone()).map_err(rt)?;
        jobs.insert(id, Job { job: Some(Arc::new(j)), path });
        Ok(id)
    })?;
    h.f("ps_progress", |lua, st, id: i64| {
        let j = job(st, id)?;
        let s = j.progress();
        let t = lua.create_table()?;
        t.set("Done", s.done as i64)?;
        t.set("Total", s.total as i64)?;
        t.set("Found", s.found as i64)?;
        t.set("Paused", s.paused)?;
        t.set("Cancelled", s.cancelled)?;
        t.set("Finished", j.is_done())?;
        Ok(t)
    })?;
    h.f("ps_pause", |_, st, id: i64| {
        job(st, id)?.pause();
        Ok(())
    })?;
    h.f("ps_resume", |_, st, id: i64| {
        job(st, id)?.resume();
        Ok(())
    })?;
    h.f("ps_cancel", |_, st, id: i64| {
        job(st, id)?.cancel();
        Ok(())
    })?;
    h.f("ps_done", |_, st, id: i64| Ok(job(st, id)?.is_done()))?;
    // (id, timeout ms OPTIONAL) -> number of paths, or nil on timeout. Waiting counts against
    // the script's budget; an error of the scan is raised.
    h.f("ps_wait", |_, st, (id, ms): (i64, Option<f64>)| {
        let j = job(st, id)?;
        let end = ms.filter(|m| m.is_finite() && *m >= 0.0).and_then(|m| Instant::now().checked_add(Duration::from_secs_f64(m / 1000.0)));
        while !j.is_done() {
            st.check()?;
            if end.is_some_and(|e| Instant::now() >= e) {
                return Ok(None);
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        Ok(Some(j.wait().map_err(rt)?.len() as i64))
    })?;
    // (id, offset, limit) -> {{Base, BaseOffset, Offsets, Text, Address, Value}} of a finished scan
    h.f("ps_results", |lua, st, (id, offset, limit): (i64, Option<i64>, Option<i64>)| {
        let j = job(st, id)?;
        if !j.is_done() {
            return Err(mlua::Error::runtime("pointer scan is still running; wait for it first"));
        }
        let rf = j.wait().map_err(rt)?;
        let limit = limit.unwrap_or(100).clamp(0, MAX_PAGE as i64) as usize;
        let p = st.proc();
        let rows = rf.results(offset.unwrap_or(0).max(0) as u64, limit, p.as_deref()).map_err(rt)?;
        let t = lua.create_table()?;
        for r in rows {
            let e = lua.create_table()?;
            e.set("Base", r.path.module)?;
            e.set("BaseOffset", r.path.base_offset)?;
            e.set("Offsets", lua.create_sequence_from(r.path.offsets)?)?;
            e.set("Text", r.text)?;
            e.set("Address", r.address.map(|a| a as i64))?;
            e.set("Value", r.value.map(|v| v as i64))?;
            t.push(e)?;
        }
        Ok(t)
    })?;
    h.f("ps_free", |_, st, id: i64| {
        let j = st.ext.ptr_jobs.0.lock().unwrap().remove(&id);
        drop(j);
        Ok(())
    })?;
    Ok(())
}
