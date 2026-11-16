//! Analysis-tool commands over hh-tools: structure dissector, "Dissect code", memory tools
//! (regions, save/load, fill, copy, snapshots, pointers to X), module headers, AOB
//! signatures and the code list.
//!
//! Structure definitions and the code list belong to the cheat table (they are saved with
//! it), so they live in [`crate::cheat::Live`]; dissections, snapshots and the running job
//! belong to the session.
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};

use hh_core::{Addr, Process, Prot};
use hh_tools::Progress;
use hh_tools::codelist::{CodeList, CodeStatus};
use hh_tools::dissect::{self, Cave, DissectOptions, DissectSummary, Dissection, Function, RefKind, StringRef};
use hh_tools::headers::HeaderSummary;
use hh_tools::memory::{self, ChangeMap, DiffRange, FileSummary, LoadPlan, PlanBlock, PointerHit, PointerQuery, Range, RegionInfo, RegionStats, RestoreSummary, Snapshot};
use hh_tools::signature::{self, SigOptions, Signature};
use hh_tools::structure::{self, FieldValue, GuessOptions, SpiderHit, SpiderOptions, Structure};
use serde::{Deserialize, Serialize};

use crate::commands::{App, R, hex_addr, lock, parse_addr, s};
use crate::table::{CodeEntry, Entry};

/// Per-session tool state.
#[derive(Default)]
pub struct Tools {
    /// The running long operation (one at a time) and its name.
    job: Mutex<Option<(&'static str, Arc<Progress>)>>,
    dissection: Mutex<Option<Arc<Dissection>>>,
    snaps: Mutex<Vec<Snap>>,
    snap_seq: AtomicU64,
    /// Structure views by `name@addr`: the locked copy and the last evaluation.
    views: Mutex<HashMap<String, View>>,
    /// Code filter: executed-instruction sets recorded with the debugger's coverage.
    filter: Mutex<CodeFilter>,
    /// Cancels a running assembly scan (`tools_cancel`).
    asm_cancel: AtomicBool,
}

#[derive(Default)]
struct View {
    locked: Option<Arc<Snapshot>>,
    last: Vec<FieldValue>,
}

/// Most structure views remembered (one per open address column).
const MAX_VIEWS: usize = 256;

#[derive(Default)]
struct CodeFilter {
    ran: Vec<Vec<Addr>>,
    not_ran: Vec<Vec<Addr>>,
    /// Function entries armed by the running recording (0 = not recording).
    armed: usize,
    /// Executed entries of the last recording.
    last: usize,
}

/// Code filter state for the UI.
#[derive(Debug, Clone, Serialize)]
pub struct FilterState {
    /// A recording is running (coverage armed on `armed` function entries).
    pub recording: bool,
    pub armed: usize,
    /// Recorded "ran" and "did not run" sets.
    pub ran_sets: usize,
    pub not_ran_sets: usize,
    /// Executed entries of the last recording.
    pub last_hits: usize,
    /// Functions in every ran set and in no did-not-run set.
    pub matches: usize,
}

/// One structure view (`struct_view`).
#[derive(Debug, Clone, Serialize)]
pub struct StructView {
    pub fields: Vec<FieldValue>,
    /// Leaf indexes (`hh_tools::structure::leaves` order) that differ: from the previous
    /// view of this column, or, while locked, between the locked copy (shown) and live memory.
    pub changed: Vec<usize>,
    pub locked: bool,
    /// C++ class of the object at the address (RTTI), when detected.
    pub class: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct FileSearchReq {
    pub path: String,
    /// Bytes with `??` wildcards (`48 8B ?? 05`); or empty and `vtype` + `value`.
    pub pattern: String,
    pub vtype: Option<hh_scan::VType>,
    pub value: String,
    pub fmt: hh_scan::Fmt,
    pub max: usize,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct AsmScanReq {
    pub start: String,
    pub end: String,
    pub pattern: String,
    pub max: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct AsmHitOut {
    pub addr: String,
    pub text: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AsmPageOut {
    pub hits: Vec<AsmHitOut>,
    /// Continue here (as `start`) for more; `None` = done.
    pub next: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SymbolOut {
    pub name: String,
    pub module: String,
    pub addr: String,
    pub size: u64,
    pub user: bool,
}

struct Snap {
    id: u64,
    label: String,
    snap: Arc<Snapshot>,
}

#[derive(Debug, Clone, Serialize)]
pub struct JobProgress {
    pub running: bool,
    /// `dissect`, `spider`, `snapshot`, `diff`, `pointers`, `save` or empty.
    pub job: &'static str,
    pub done: u64,
    pub total: u64,
    pub found: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Page<T> {
    pub total: usize,
    pub rows: Vec<T>,
}

#[derive(Debug, Clone, Serialize)]
pub struct XRefOut {
    pub from: String,
    pub to: String,
    pub kind: RefKind,
    /// The referencing instruction.
    pub text: String,
    /// `module+offset` of the function holding `from`, if the dissection knows one.
    pub func: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SnapInfo {
    pub id: u64,
    pub label: String,
    pub blocks: usize,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SigOut {
    #[serde(flatten)]
    pub sig: Signature,
    /// Where the pattern matches in its module now (verified with hh-asm's AOB scan).
    pub found: Vec<String>,
}

/// A code-list row: the entry, where it resolves now and what memory holds there.
#[derive(Debug, Clone, Serialize)]
pub struct CodeRow {
    #[serde(flatten)]
    pub entry: CodeEntry,
    #[serde(flatten)]
    pub status: CodeStatus,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct EvalReq {
    pub name: String,
    pub addr: String,
}

/// Disassembler annotation from the dissection.
#[derive(Debug, Clone, Default, Serialize)]
pub struct XRefCounts {
    pub calls: usize,
    pub jumps: usize,
    pub data: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct FuncOut {
    pub start: String,
    pub name: Option<String>,
    /// `dissection` or `heuristic`.
    pub source: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetRow {
    pub from: String,
    pub to: String,
    /// `call`, `jump` or `cond_jump`.
    pub kind: &'static str,
    pub text: String,
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Targets {
    pub start: String,
    pub end: String,
    pub source: &'static str,
    pub rows: Vec<TargetRow>,
}

/// Largest memory dump / snapshot file loaded (it is read into memory whole).
const MAX_DUMP: u64 = 2 << 30;

/// A dump file must be a regular file within [`MAX_DUMP`] (a FIFO or device has no real size).
fn dump_file(path: &str) -> R<()> {
    let m = std::fs::metadata(path).map_err(|e| format!("{path}: {e}"))?;
    if !m.is_file() {
        return Err(format!("{path}: not a regular file"));
    }
    if m.len() > MAX_DUMP {
        return Err(format!("{path}: {} MiB is too big for a memory file (limit {} MiB)", m.len() >> 20, MAX_DUMP >> 20));
    }
    Ok(())
}

/// A user-picked file the crate's loader opens itself: regular, at most `max` bytes.
fn user_file(path: &str, max: u64) -> R<&Path> {
    let p = crate::ptr::regular_file(path)?;
    let n = std::fs::metadata(p).map_err(|e| format!("{path}: {e}"))?.len();
    if n > max {
        return Err(format!("{path}: {} MiB is too big (limit {} MiB)", n >> 20, max >> 20));
    }
    Ok(p)
}

/// Largest dissection file loaded.
const MAX_DISSECTION: u64 = 4 << 30;

fn is_xml(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    p.ends_with(".xml") || p.ends_with(".ct")
}

const MAX_PAGE: usize = 10_000;

fn guard<T>(r: hh_core::Result<T>) -> R<T> {
    r.map_err(s)
}

/// App code entry <-> hh-tools code entry (the app's keeps CE's before/after context).
fn code_list(codes: &[CodeEntry]) -> CodeList {
    CodeList {
        entries: codes
            .iter()
            .map(|c| hh_tools::codelist::CodeEntry {
                description: c.description.clone(),
                addr: c.address.clone(),
                original: hh_tools::hexbytes::parse(&c.bytes).unwrap_or_default(),
            })
            .collect(),
    }
}

impl App {
    /// Runs `f` as the session's job: one at a time, progress visible to `tools_progress`.
    fn job<T>(&self, name: &'static str, f: impl FnOnce(&dyn Process, &Progress) -> hh_core::Result<T>) -> R<T> {
        let sess = self.session()?;
        let prog = Arc::new(Progress::new());
        {
            let mut j = lock(&sess.tools.job);
            if let Some((n, _)) = &*j {
                return Err(format!("another operation ({n}) is running"));
            }
            *j = Some((name, prog.clone()));
        }
        let r = f(&*sess.proc, &prog);
        *lock(&sess.tools.job) = None;
        r.map_err(s)
    }

    pub fn tools_progress(&self) -> R<JobProgress> {
        let j = self.session().ok().and_then(|s| lock(&s.tools.job).clone());
        Ok(match j {
            Some((job, p)) => {
                let x = p.snapshot();
                JobProgress { running: true, job, done: x.done, total: x.total, found: x.found }
            }
            None => JobProgress { running: false, job: "", done: 0, total: 0, found: 0 },
        })
    }

    pub fn tools_cancel(&self) -> R<()> {
        if let Ok(sess) = self.session() {
            sess.tools.asm_cancel.store(true, Relaxed);
            if let Some((_, p)) = lock(&sess.tools.job).clone() {
                p.cancel();
            }
        }
        Ok(())
    }

    // ------------------------------------------------------------------ structures

    /// Writes structures (`names` empty = all) to their own file: JSON `{structures}`, or
    /// CE `<Structures>` XML for `.xml`/`.ct`.
    pub fn struct_export(&self, path: &str, names: &[String]) -> R<()> {
        let all = self.x.live.state().table.structures;
        let list: Vec<Structure> = all.into_iter().filter(|st| names.is_empty() || names.contains(&st.name)).collect();
        if list.is_empty() {
            return Err("no structure to export".into());
        }
        let text = if is_xml(path) {
            let ps = self.session().map_or(8, |s| s.proc.pointer_size());
            structure::to_ct_xml(&list, ps)
        } else {
            serde_json::to_string_pretty(&serde_json::json!({ "structures": list })).map_err(s)?
        };
        std::fs::write(path, text).map_err(|e| format!("{path}: {e}"))
    }

    /// Adds the file's structures, replacing those of the same name; returns their names.
    pub fn struct_import(&self, path: &str) -> R<Vec<String>> {
        let text = String::from_utf8(crate::table::read_capped(Path::new(path), crate::table::MAX_FILE)?).map_err(|e| format!("{path}: {e}"))?;
        let add: Vec<Structure> = if is_xml(path) || text.trim_start().starts_with('<') {
            guard(structure::from_ct_xml(text.trim_start_matches('\u{feff}')))?
        } else {
            #[derive(Deserialize)]
            #[serde(untagged)]
            enum F {
                Wrapped { structures: Vec<Structure> },
                Bare(Vec<Structure>),
            }
            match serde_json::from_str::<F>(&text).map_err(|e| format!("{path}: {e}"))? {
                F::Wrapped { structures } | F::Bare(structures) => structures,
            }
        };
        if add.is_empty() {
            return Err(format!("{path}: no structures in the file"));
        }
        let mut cur = self.x.live.state().table.structures;
        cur.retain(|c| !add.iter().any(|a| a.name == c.name));
        let names = add.iter().map(|a| a.name.clone()).collect();
        cur.extend(add);
        self.struct_set(cur)?;
        Ok(names)
    }

    pub fn struct_get(&self) -> R<Vec<Structure>> {
        Ok(self.x.live.state().table.structures)
    }

    /// Replaces every definition (the UI edits elements, names, sizes locally).
    pub fn struct_set(&self, structs: Vec<Structure>) -> R<()> {
        guard(structure::validate_structures(&structs))?;
        let mut seen = std::collections::HashSet::new();
        for st in &structs {
            if st.name.trim().is_empty() || !seen.insert(st.name.as_str()) {
                return Err(format!("structure names must be unique and not empty ({:?})", st.name));
            }
        }
        self.x.live.set_structures(structs);
        Ok(())
    }

    /// Auto-guesses `size` bytes at `addr` into structure `name` (replacing one of that name).
    pub fn struct_guess(&self, name: &str, addr: &str, size: usize) -> R<Structure> {
        let sess = self.session()?;
        let a = parse_addr(&self.resolve_address(addr)?)?;
        // An empty name becomes the object's C++ class name (RTTI) when there is one.
        let ov = |a: Addr, n: usize| self.x.lua.engine.structure_override(a, n);
        let ov: Option<&structure::StructOverride> = if self.lua_hooks_ok() { Some(&ov) } else { None };
        let st = guard(structure::guess_structure_with(&*sess.proc, name, a, size.clamp(1, 0x10000), &self.guess_options(), ov))?;
        let name = st.name.as_str();
        let mut all = self.struct_get()?;
        match all.iter_mut().find(|x| x.name == name) {
            Some(x) => *x = st.clone(),
            None => all.push(st.clone()),
        }
        self.x.live.set_structures(all);
        Ok(st)
    }

    /// Evaluates each `{name, addr}`; one result (fields or error text) per request.
    pub fn struct_eval(&self, reqs: &[EvalReq]) -> R<Vec<Result<Vec<FieldValue>, String>>> {
        let sess = self.session()?;
        let structs = self.struct_get()?;
        Ok(reqs
            .iter()
            .map(|q| {
                let a = parse_addr(&q.addr)?;
                structure::evaluate(&*sess.proc, &structs, &q.name, a).map_err(s)
            })
            .collect())
    }

    /// Expands pointer element `index` of `owner` whose field is at `field_addr`: guesses a
    /// child structure when it has none. Returns `{name, addr}` of the child.
    pub fn struct_expand(&self, owner: &str, index: usize, field_addr: &str, size: usize) -> R<EvalReq> {
        let sess = self.session()?;
        let mut all = self.struct_get()?;
        let before = all.clone();
        let ov = |a: Addr, n: usize| self.x.lua.engine.structure_override(a, n);
        let ov: Option<&structure::StructOverride> = if self.lua_hooks_ok() { Some(&ov) } else { None };
        let (name, a) = guard(structure::expand_pointer_with(&*sess.proc, &mut all, owner, index, parse_addr(field_addr)?, size.clamp(8, 0x10000), &self.guess_options(), ov))?;
        if all != before {
            self.x.live.set_structures(all);
        }
        Ok(EvalReq { name, addr: hex_addr(a) })
    }

    /// Table entries for fields of `name`. The structure is reached from address expression
    /// `root` through the pointer fields at `path` (offsets in successive structures, empty =
    /// the structure is at `root`); `only` = top-level element indexes.
    pub fn struct_entries(&self, name: &str, root: &str, path: &[u64], only: Option<Vec<usize>>) -> R<Vec<Entry>> {
        let ptr = self.session().map(|s| s.proc.pointer_size()).unwrap_or(8);
        let structs = self.struct_get()?;
        // [root+p0] is the first hop: CE offsets apply after a dereference.
        let (addr, offs) = match path.split_first() {
            None => (root.trim().to_string(), Vec::new()),
            Some((p0, rest)) => (format!("{}+{p0:X}", root.trim()), rest.iter().copied().chain([0]).collect()),
        };
        let es = guard(structure::to_entries(&structs, name, &addr, &offs, ptr, only.as_deref(), 1))?;
        serde_json::from_value(serde_json::to_value(es).map_err(s)?).map_err(s)
    }

    /// RTTI / symbol naming; module files are read from this disk only for a local target.
    fn guess_options(&self) -> GuessOptions {
        GuessOptions { local_files: self.session().is_ok_and(|s| s.info.remote.is_none()), ..GuessOptions::default() }
    }

    /// Evaluates each `{name, addr}` for the dissector: live (or the locked copy), the leaves
    /// that changed, and the object's C++ class.
    pub fn struct_view(&self, reqs: &[EvalReq]) -> R<Vec<Result<StructView, String>>> {
        let sess = self.session()?;
        let structs = self.struct_get()?;
        let ps = sess.proc.pointer_size();
        let mut views = lock(&sess.tools.views);
        Ok(reqs
            .iter()
            .map(|q| {
                let a = parse_addr(&q.addr)?;
                let live = structure::evaluate(&*sess.proc, &structs, &q.name, a).map_err(s)?;
                let key = format!("{}@{a:x}", q.name);
                if views.len() >= MAX_VIEWS && !views.contains_key(&key) {
                    views.clear();
                }
                let v = views.entry(key).or_default();
                let (fields, changed) = match &v.locked {
                    Some(snap) => {
                        let f = structure::evaluate_locked(snap, &structs, &q.name, a, ps).map_err(s)?;
                        let c = structure::changed_fields(&f, &live);
                        (f, c)
                    }
                    None => {
                        let c = if v.last.is_empty() { Vec::new() } else { structure::changed_fields(&v.last, &live) };
                        (live.clone(), c)
                    }
                };
                v.last = live;
                Ok(StructView { fields, changed, locked: v.locked.is_some(), class: structure::rtti_class_name(&*sess.proc, a) })
            })
            .collect())
    }

    /// Locks (a frozen copy of the memory the view reads) or unlocks the view `name@addr`.
    pub fn struct_lock(&self, name: &str, addr: &str, on: bool) -> R<()> {
        let sess = self.session()?;
        let a = parse_addr(addr)?;
        let key = format!("{name}@{a:x}");
        let snap = if on { Some(Arc::new(guard(structure::lock_structure(&*sess.proc, &self.struct_get()?, name, a))?)) } else { None };
        let mut views = lock(&sess.tools.views);
        if views.len() >= MAX_VIEWS && !views.contains_key(&key) {
            views.clear();
        }
        views.entry(key).or_default().locked = snap;
        Ok(())
    }

    /// Writes `value` to leaf `leaf` (`leaves` order) of structure `name` at `addr`.
    pub fn struct_write(&self, name: &str, addr: &str, leaf: usize, value: &str) -> R<()> {
        let sess = self.session()?;
        let structs = self.struct_get()?;
        let fields = guard(structure::evaluate(&*sess.proc, &structs, name, parse_addr(addr)?))?;
        let f = *structure::leaves(&fields).get(leaf).ok_or_else(|| format!("{name} has no field {leaf}"))?;
        guard(structure::write_field(&*sess.proc, &structs, f, value))
    }

    /// C (`c`) or C# (`csharp`) definitions of the structures `names` (empty = all).
    pub fn struct_code(&self, names: &[String], lang: &str) -> R<String> {
        let all = self.struct_get()?;
        let list: Vec<Structure> = if names.is_empty() { all } else {
            // Children the named ones use come along (the generators emit them first).
            let mut want: Vec<String> = names.to_vec();
            let mut i = 0;
            while i < want.len() {
                if let Some(st) = all.iter().find(|x| x.name == want[i]) {
                    for c in st.elements.iter().filter_map(|e| e.child.clone()) {
                        if !want.contains(&c) {
                            want.push(c);
                        }
                    }
                }
                i += 1;
            }
            all.into_iter().filter(|x| want.contains(&x.name)).collect()
        };
        if list.is_empty() {
            return Err("no structure to export".into());
        }
        let ps = self.session().map_or(8, |s| s.proc.pointer_size());
        match lang {
            "c" => Ok(structure::to_c(&list, ps)),
            "csharp" | "cs" => Ok(structure::to_csharp(&list, ps)),
            l => Err(format!("unknown language {l:?}")),
        }
    }

    /// A table entry for one field of `name` at address expression `root`, reached through
    /// `path` (element indexes; an array element is followed by its item index, a pointer or
    /// nested element by the path inside its child). Pointer hops become entry offsets.
    pub fn struct_field_entry(&self, name: &str, root: &str, path: &[usize]) -> R<Entry> {
        let ps = self.session().map_or(8, |s| s.proc.pointer_size());
        let e = guard(structure::field_entry(&self.struct_get()?, name, root.trim(), &[], path, ps, 1))?;
        serde_json::from_value(serde_json::to_value(e).map_err(s)?).map_err(s)
    }

    /// Structure spider over address groups (hex strings); see `hh_tools::structure::spider`.
    pub fn struct_spider(&self, groups: &[Vec<String>], opts: &SpiderOptions) -> R<Vec<SpiderHit>> {
        let g: Vec<Vec<Addr>> = groups.iter().map(|g| g.iter().map(|a| parse_addr(a)).collect::<R<_>>()).collect::<R<_>>()?;
        self.job("spider", |p, prog| structure::spider(p, &g, opts, prog))
    }

    // --------------------------------------------------------------------- dissect

    /// Dissects the named modules (all when empty); keeps the result for the queries below.
    pub fn dissect_run(&self, modules: &[String], opts: &DissectOptions) -> R<DissectSummary> {
        let all = self.session()?.proc.modules().map_err(s)?;
        let mods: Vec<_> = all.into_iter().filter(|m| modules.is_empty() || modules.iter().any(|n| n.eq_ignore_ascii_case(&m.name))).collect();
        if mods.is_empty() {
            return Err("no such module".into());
        }
        let opts = self.dissect_opts(opts);
        let d = self.job("dissect", |p, prog| dissect::dissect(p, &mods, &opts, prog))?;
        let sum = d.summary();
        let sess = self.session()?;
        *lock(&sess.tools.dissection) = Some(Arc::new(d));
        *lock(&sess.tools.filter) = CodeFilter::default();
        Ok(sum)
    }

    /// Module files are read from this disk only for a local target.
    fn dissect_opts(&self, opts: &DissectOptions) -> DissectOptions {
        DissectOptions { local_files: opts.local_files && self.session().is_ok_and(|s| s.info.remote.is_none()), ..opts.clone() }
    }

    /// Dissects the named modules not dissected yet and merges them into the current
    /// dissection (a new one when there is none).
    pub fn dissect_add(&self, modules: &[String], opts: &DissectOptions) -> R<DissectSummary> {
        let all = self.session()?.proc.modules().map_err(s)?;
        let mods: Vec<_> = all.into_iter().filter(|m| modules.iter().any(|n| n.eq_ignore_ascii_case(&m.name))).collect();
        if mods.is_empty() {
            return Err("no such module".into());
        }
        let opts = self.dissect_opts(opts);
        let cur = lock(&self.session()?.tools.dissection).clone();
        let d = self.job("dissect", |p, prog| match cur {
            Some(c) => {
                let mut d = (*c).clone();
                d.add_modules(p, &mods, &opts, prog)?;
                Ok(d)
            }
            None => dissect::dissect(p, &mods, &opts, prog),
        })?;
        let sum = d.summary();
        *lock(&self.session()?.tools.dissection) = Some(Arc::new(d));
        Ok(sum)
    }

    /// Writes the current dissection to an `.hhdis` file.
    pub fn dissect_save(&self, path: &str) -> R<()> {
        let d = self.dissection()?;
        self.job("save", |_, prog| d.save(Path::new(path), prog))
    }

    /// Loads an `.hhdis` file (validated) as the current dissection.
    pub fn dissect_load(&self, path: &str) -> R<DissectSummary> {
        let p = user_file(path, MAX_DISSECTION)?;
        let d = self.job("load", |_, prog| Dissection::load(p, prog))?;
        let sum = d.summary();
        let sess = self.session()?;
        *lock(&sess.tools.dissection) = Some(Arc::new(d));
        *lock(&sess.tools.filter) = CodeFilter::default();
        Ok(sum)
    }

    // ------------------------------------------------------------------ code filter

    fn filter_state(&self, f: &CodeFilter) -> FilterState {
        let last_hits = f.last;
        let matches = self.dissection().map_or(0, |d| d.code_filter(&f.ran, &f.not_ran).len());
        FilterState { recording: f.armed > 0, armed: f.armed, ran_sets: f.ran.len(), not_ran_sets: f.not_ran.len(), last_hits, matches }
    }

    /// Starts recording which functions of the current dissection run: a one-shot int3 on
    /// every internal function entry (only addresses the dissection found; nothing else is
    /// ever armed). Needs the debugger attached. Returns how many were armed.
    pub fn code_filter_start(&self) -> R<FilterState> {
        let d = self.dissection()?;
        let entries: Vec<Addr> = d.functions(0, usize::MAX).into_iter().filter(|f| f.internal).map(|f| f.addr).take(hh_debug::MAX_COVERAGE).collect();
        if entries.is_empty() {
            return Err("the dissection has no functions to watch".into());
        }
        let armed = self.coverage_start(entries)?;
        let sess = self.session()?;
        let mut f = lock(&sess.tools.filter);
        f.armed = armed.max(1);
        Ok(self.filter_state(&f))
    }

    /// Ends the recording; its executed entries become a "ran" (`ran` true) or a "did not
    /// run" set.
    pub fn code_filter_stop(&self, ran: bool) -> R<FilterState> {
        let hits = self.coverage_stop()?;
        let sess = self.session()?;
        let mut f = lock(&sess.tools.filter);
        f.armed = 0;
        f.last = hits.len();
        if ran { f.ran.push(hits) } else { f.not_ran.push(hits) }
        Ok(self.filter_state(&f))
    }

    pub fn code_filter_state(&self) -> R<FilterState> {
        let sess = self.session()?;
        let f = lock(&sess.tools.filter);
        Ok(self.filter_state(&f))
    }

    /// Forgets the recorded sets (a running recording is stopped and dropped).
    pub fn code_filter_reset(&self) -> R<()> {
        let sess = self.session()?;
        if lock(&sess.tools.filter).armed > 0 {
            let _ = self.coverage_stop();
        }
        *lock(&sess.tools.filter) = CodeFilter::default();
        Ok(())
    }

    /// The functions in every ran set and in no did-not-run set.
    pub fn code_filter_list(&self, offset: usize, limit: usize) -> R<Page<Function>> {
        let sess = self.session()?;
        let d = self.dissection()?;
        let f = lock(&sess.tools.filter);
        let all = d.code_filter(&f.ran, &f.not_ran);
        let rows = all
            .iter()
            .skip(offset)
            .take(limit.min(MAX_PAGE))
            .cloned()
            .map(|mut x| {
                x.name = x.name.map(|n| hh_asm::demangle(&n).unwrap_or(n));
                x
            })
            .collect();
        Ok(Page { total: all.len(), rows })
    }

    // ------------------------------------------------------------- code search, symbols

    /// Cheat Engine's assembly scan over executable memory in `[start, end)`.
    pub fn asm_scan(&self, req: &AsmScanReq) -> R<AsmPageOut> {
        let start = parse_addr(&req.start)?;
        let end = match req.end.trim() { "" => u64::MAX, e => parse_addr(e)? };
        let sess = self.session()?;
        sess.tools.asm_cancel.store(false, Relaxed);
        let max = if req.max == 0 { 1000 } else { req.max.min(100_000) };
        let page = self.job("asm", |p, _| hh_asm::asm_scan(p, start, end, &req.pattern, max, &sess.tools.asm_cancel))?;
        Ok(AsmPageOut { hits: page.hits.into_iter().map(|h| AsmHitOut { addr: hex_addr(h.addr), text: h.text }).collect(), next: page.next.map(hex_addr) })
    }

    /// The next (or previous) instruction that references `target`, searching `max_bytes`.
    pub fn find_reference(&self, from: &str, target: &str, forward: bool, max_bytes: u64) -> R<Option<String>> {
        let (from, target) = (parse_addr(from)?, parse_addr(target)?);
        let sess = self.session()?;
        sess.tools.asm_cancel.store(false, Relaxed);
        let max = if max_bytes == 0 { 64 << 20 } else { max_bytes };
        Ok(self.job("asm", |p, _| hh_asm::find_reference(p, from, target, forward, max, &sess.tools.asm_cancel))?.map(hex_addr))
    }

    /// Symbols: user / script-registered first, then each module's (`module` only that one).
    pub fn symbol_list(&self, module: Option<&str>, filter: &str, offset: usize, limit: usize) -> R<Page<SymbolOut>> {
        let sess = self.session()?;
        self.sync_user_symbols(&sess);
        let syms = lock(&sess.syms).clone();
        let pg = hh_asm::symbol_list(&*sess.proc, &syms, module.filter(|m| !m.trim().is_empty()), filter.trim(), offset, limit);
        Ok(Page { total: pg.total, rows: pg.rows.into_iter().map(|r| SymbolOut { name: r.name, module: r.module, addr: hex_addr(r.addr), size: r.size, user: r.user }).collect() })
    }

    fn dissection(&self) -> R<Arc<Dissection>> {
        lock(&self.session()?.tools.dissection).clone().ok_or_else(|| "no code dissection yet".into())
    }

    pub fn dissect_summary(&self) -> R<Option<DissectSummary>> {
        Ok(self.session().ok().and_then(|s| lock(&s.tools.dissection).clone()).map(|d| d.summary()))
    }

    /// `kind`: `functions`, `called` (referenced functions), `strings`, `caves`. `filter`
    /// is a case-insensitive substring of the name/text or the address.
    pub fn dissect_list(&self, kind: &str, filter: &str, offset: usize, limit: usize) -> R<Page<serde_json::Value>> {
        let d = self.dissection()?;
        let f = filter.trim().to_lowercase();
        let f = f.trim_start_matches("0x");
        let limit = limit.min(MAX_PAGE);
        let hit = |a: Addr, text: Option<&str>| f.is_empty() || format!("{a:x}").contains(f) || text.is_some_and(|t| t.to_lowercase().contains(f));
        fn page<T: Serialize>(v: Vec<T>, offset: usize, limit: usize) -> R<Page<serde_json::Value>> {
            let total = v.len();
            let rows = v.into_iter().skip(offset).take(limit).map(|x| serde_json::to_value(x).map_err(s)).collect::<R<_>>()?;
            Ok(Page { total, rows })
        }
        match kind {
            "functions" | "called" => {
                let n = d.summary().functions;
                let all: Vec<Function> = if kind == "functions" { d.functions(0, n) } else { d.referenced_functions(0, n) };
                let all = all.into_iter().filter(|x| hit(x.addr, x.name.as_deref()) && (kind == "functions" || x.callers > 0)).collect();
                page(all, offset, limit)
            }
            "strings" => {
                let all: Vec<StringRef> = d.strings(None, 0, usize::MAX).into_iter().filter(|x| hit(x.addr, Some(&x.text))).collect();
                page(all, offset, limit)
            }
            "caves" => {
                let all: Vec<Cave> = d.caves(0, usize::MAX).into_iter().filter(|x| hit(x.addr, None)).collect();
                page(all, offset, limit)
            }
            k => Err(format!("unknown list {k:?}")),
        }
    }

    /// References to `[addr, addr+len)` (len 0 = 1), with the referencing instruction.
    pub fn dissect_xrefs(&self, addr: &str, len: u64, offset: usize, limit: usize) -> R<Page<XRefOut>> {
        let d = self.dissection()?;
        let sess = self.session()?;
        let lo = parse_addr(addr)?;
        let hi = lo.saturating_add(len.max(1));
        let total = d.xref_count(lo, hi, &[]);
        let syms = lock(&sess.syms).clone();
        let mods = sess.proc.modules().unwrap_or_default();
        let rows = d
            .xrefs_to(lo, hi, &[], offset, limit.min(MAX_PAGE))
            .into_iter()
            .map(|x| {
                let text = hh_asm::disassemble(&*sess.proc, &syms, x.from, 1).ok().and_then(|l| l.into_iter().next()).map_or_else(|| "??".into(), |l| l.text);
                let func = d.function_at(x.from).map(|f| f.name.clone().or_else(|| hh_asm::module_offset(&mods, f.addr)).unwrap_or_else(|| hex_addr(f.addr)));
                XRefOut { from: hex_addr(x.from), to: hex_addr(x.to), kind: x.kind, text, func }
            })
            .collect();
        Ok(Page { total, rows })
    }

    /// Incoming reference counts per address, when a dissection exists (for the disassembler).
    pub(crate) fn xref_counts(&self, addrs: &[Addr]) -> Option<Vec<XRefCounts>> {
        let d = self.session().ok().and_then(|s| lock(&s.tools.dissection).clone())?;
        Some(
            addrs
                .iter()
                .map(|&a| XRefCounts {
                    calls: d.xref_count(a, a + 1, &[RefKind::Call]),
                    jumps: d.xref_count(a, a + 1, &[RefKind::Jump, RefKind::CondJump]),
                    data: d.xref_count(a, a + 1, &[RefKind::Data]),
                })
                .collect(),
        )
    }

    // ---------------------------------------------------------------------- memory

    pub fn regions_info(&self) -> R<Vec<RegionInfo>> {
        guard(memory::regions(&*self.session()?.proc))
    }

    /// Changes protection; returns the old one.
    pub fn mem_protect(&self, addr: &str, size: u64, prot: Prot) -> R<Prot> {
        guard(self.session()?.proc.protect(parse_addr(addr)?, size, prot))
    }

    pub fn mem_save(&self, ranges: &[Range], path: &str) -> R<FileSummary> {
        self.job("save", |p, prog| memory::save_memory(p, ranges, Path::new(path), prog))
    }

    fn relocation(&self, relocate: Option<&str>) -> R<Option<Addr>> {
        relocate.filter(|r| !r.trim().is_empty()).map(|r| self.resolve_address(r).and_then(|a| parse_addr(&a))).transpose()
    }

    /// What loading an `.hhmem` file would write (nothing is written): each block's target,
    /// size, and whether it is mapped and writable now. `relocate` moves the first block there.
    pub fn mem_load_plan(&self, path: &str, relocate: Option<&str>) -> R<LoadPlan> {
        let to = self.relocation(relocate)?;
        dump_file(path)?;
        guard(memory::plan_load(&*self.session()?.proc, Path::new(path), to))
    }

    /// Writes only the `blocks` of a plan the user approved; nothing when the file changed
    /// since the plan.
    pub fn mem_load_approved(&self, path: &str, relocate: Option<&str>, blocks: &[PlanBlock]) -> R<RestoreSummary> {
        let to = self.relocation(relocate)?;
        dump_file(path)?;
        if blocks.is_empty() {
            return Ok(RestoreSummary { blocks: 0, bytes: 0, failed: Vec::new() });
        }
        guard(memory::load_memory_approved(&*self.session()?.proc, Path::new(path), to, blocks))
    }

    /// Searches a saved `.hhmem` file (no process needed): a byte pattern with `??`
    /// wildcards, or a typed value. At most `max` addresses (default 1000).
    pub fn mem_file_search(&self, req: &FileSearchReq) -> R<Vec<String>> {
        dump_file(&req.path)?;
        let max = if req.max == 0 { 1000 } else { req.max.min(100_000) };
        let path = Path::new(&req.path);
        let pat = if req.pattern.trim().is_empty() { None } else { Some(crate::search::parse_pattern(&req.pattern)?) };
        let run = |prog: &Progress| match (&pat, req.vtype) {
            (Some(p), _) => memory::search_file(path, p, max, prog),
            (None, Some(t)) if !req.value.trim().is_empty() => memory::search_file_value(path, t, &req.value, &req.fmt, max, prog),
            _ => Err(hh_core::Error::Other("give a byte pattern, or a type and a value".into())),
        };
        // No process needed: run as the session's job when there is one.
        let hits = match self.session() {
            Ok(_) => self.job("search", |_, prog| run(prog))?,
            Err(_) => guard(run(&Progress::new()))?,
        };
        Ok(hits.into_iter().map(hex_addr).collect())
    }

    /// Totals of the region view by protection, tag, kind and module.
    pub fn region_stats(&self) -> R<RegionStats> {
        Ok(memory::region_stats(&self.regions_info()?))
    }

    /// Page change map between snapshots `old` and `new` over `[start, end)` (empty = the
    /// span of `old`), at most `cells` cells.
    pub fn snapshot_change_map(&self, old: u64, new: u64, start: &str, end: &str, cells: usize) -> R<ChangeMap> {
        let sess = self.session()?;
        let snaps = lock(&sess.tools.snaps);
        let get = |id: u64| snaps.iter().find(|x| x.id == id).map(|x| x.snap.clone()).ok_or_else(|| format!("no snapshot {id}"));
        let (a, b) = (get(old)?, get(new)?);
        drop(snaps);
        let lo = match start.trim() {
            "" => a.blocks.iter().map(|x| x.addr).min().ok_or("the snapshot is empty")?,
            t => parse_addr(t)?,
        };
        let hi = match end.trim() {
            "" => a.blocks.iter().map(|x| x.addr.saturating_add(x.data.len() as u64)).max().ok_or("the snapshot is empty")?,
            t => parse_addr(t)?,
        };
        guard(memory::change_map(&a, &b, lo, hi, cells.clamp(1, memory::MAX_MAP_CELLS)))
    }

    /// Fills `len` bytes with the hex `pattern` repeated.
    pub fn mem_fill(&self, addr: &str, len: u64, pattern: &str) -> R<()> {
        let pat = hh_tools::hexbytes::parse(pattern).filter(|p| !p.is_empty()).ok_or_else(|| format!("bad hex pattern {pattern:?}"))?;
        guard(memory::fill(&*self.session()?.proc, parse_addr(addr)?, len, &pat))
    }

    pub fn mem_copy(&self, src: &str, dst: &str, len: u64) -> R<()> {
        guard(memory::copy(&*self.session()?.proc, parse_addr(src)?, parse_addr(dst)?, len))
    }

    /// Snapshots `ranges` (all writable memory when empty).
    pub fn snapshot_take(&self, ranges: &[Range], label: &str) -> R<SnapInfo> {
        let sess = self.session()?;
        let ranges = if ranges.is_empty() { guard(memory::readable_ranges(&*sess.proc, true))? } else { ranges.to_vec() };
        let snap = Arc::new(self.job("snapshot", |p, prog| memory::snapshot(p, &ranges, prog))?);
        let id = sess.tools.snap_seq.fetch_add(1, Relaxed) + 1;
        let info = SnapInfo { id, label: label.to_string(), blocks: snap.blocks.len(), bytes: snap.bytes() };
        lock(&sess.tools.snaps).push(Snap { id, label: label.to_string(), snap });
        Ok(info)
    }

    pub fn snapshot_list(&self) -> R<Vec<SnapInfo>> {
        Ok(lock(&self.session()?.tools.snaps)
            .iter()
            .map(|x| SnapInfo { id: x.id, label: x.label.clone(), blocks: x.snap.blocks.len(), bytes: x.snap.bytes() })
            .collect())
    }

    pub fn snapshot_delete(&self, id: u64) -> R<()> {
        lock(&self.session()?.tools.snaps).retain(|x| x.id != id);
        Ok(())
    }

    /// Differences between snapshot `id` and live memory (at most `max` ranges).
    pub fn snapshot_diff(&self, id: u64, max: usize) -> R<Vec<DiffRange>> {
        let snap = lock(&self.session()?.tools.snaps).iter().find(|x| x.id == id).map(|x| x.snap.clone()).ok_or_else(|| format!("no snapshot {id}"))?;
        self.job("diff", |p, prog| memory::diff_live(p, &snap, max.clamp(1, 100_000), prog))
    }

    /// A saved `.hhmem` file against live memory.
    pub fn mem_compare(&self, path: &str, max: usize) -> R<Vec<DiffRange>> {
        dump_file(path)?;
        let snap = guard(memory::load_snapshot(Path::new(path)))?;
        self.job("diff", |p, prog| memory::diff_live(p, &snap, max.clamp(1, 100_000), prog))
    }

    /// Start of the function holding `addr`: the dissection's when there is one, else the
    /// nearest prologue / padding boundary at or below it.
    pub fn code_function(&self, addr: &str) -> R<FuncOut> {
        let a = parse_addr(addr)?;
        let sess = self.session()?;
        if let Some(d) = lock(&sess.tools.dissection).clone()
            && let Some(f) = d.function_at(a)
        {
            return Ok(FuncOut { start: hex_addr(f.addr), name: f.name.clone(), source: "dissection" });
        }
        const BACK: u64 = 0x4000;
        let lo = a.saturating_sub(BACK);
        let mut buf = vec![0u8; (a - lo) as usize + 4];
        let n = sess.proc.read(lo, &mut buf).unwrap_or(0);
        buf.truncate(n);
        // shortcut: byte patterns only (endbr64, push rbp/mov rbp,rsp, sub rsp after pushes,
        // padding before a 16-aligned start); a dissection gives exact starts.
        let start = (0..=(a - lo) as usize)
            .rev()
            .filter(|&i| i + 4 <= buf.len())
            .find_map(|i| {
                let b = &buf[i..];
                let padded = i > 0 && matches!(buf[i - 1], 0xCC | 0x90 | 0xC3) && b[0] != buf[i - 1];
                if b.starts_with(&[0xF3, 0x0F, 0x1E, 0xFA]) || b.starts_with(&[0x55, 0x48, 0x89, 0xE5]) || (padded && (lo + i as u64).is_multiple_of(16)) {
                    return Some(i);
                }
                if !(b.starts_with(&[0x48, 0x83, 0xEC]) || b.starts_with(&[0x48, 0x81, 0xEC])) {
                    return None;
                }
                // Pushes of callee-saved registers right before `sub rsp` belong to the prologue.
                let mut j = i;
                loop {
                    if j >= 1 && (0x50..=0x57).contains(&buf[j - 1]) && !(j >= 2 && buf[j - 2] == 0x41) {
                        j -= 1;
                    } else if j >= 2 && buf[j - 2] == 0x41 && (0x50..=0x57).contains(&buf[j - 1]) {
                        j -= 2;
                    } else {
                        break Some(j);
                    }
                }
            })
            .map_or(a, |i| lo + i as u64);
        Ok(FuncOut { start: hex_addr(start), name: None, source: "heuristic" })
    }

    /// Direct call/jump targets of the function holding `addr`.
    pub fn code_targets(&self, addr: &str) -> R<Targets> {
        use iced_x86::{Decoder, DecoderOptions, Formatter, IntelFormatter};
        let f = self.code_function(addr)?;
        let start = parse_addr(&f.start)?;
        let sess = self.session()?;
        const MAX: usize = 0x10000;
        let mut buf = vec![0u8; MAX];
        let n = sess.proc.read(start, &mut buf).map_err(s)?;
        buf.truncate(n);
        let bits = if sess.proc.pointer_size() == 8 { 64 } else { 32 };
        let mut dec = Decoder::with_ip(bits, &buf, start, DecoderOptions::NONE);
        let mut fmt = IntelFormatter::new();
        let (mut rows, mut reach, mut end) = (Vec::new(), start, start);
        let syms = lock(&sess.syms).clone();
        for ins in dec.iter() {
            end = ins.next_ip();
            if ins.is_invalid() {
                break;
            }
            let kind = if ins.is_call_near() {
                "call"
            } else if ins.is_jmp_short_or_near() {
                "jump"
            } else if ins.is_jcc_short_or_near() {
                "cond_jump"
            } else {
                ""
            };
            if !kind.is_empty() {
                let to = ins.near_branch_target();
                if kind != "call" && to > reach && to < start + MAX as u64 {
                    reach = to;
                }
                let mut text = String::new();
                fmt.format(&ins, &mut text);
                rows.push(TargetRow { from: hex_addr(ins.ip()), to: hex_addr(to), kind, text, name: hh_asm::symbol_at(&*sess.proc, &syms, to) });
            }
            // The function ends at a return or unconditional jump that no earlier branch jumps past.
            let stop = matches!(ins.mnemonic(), iced_x86::Mnemonic::Ret | iced_x86::Mnemonic::Int3) || ins.is_jmp_short_or_near() || ins.is_jmp_far();
            if stop && ins.next_ip() > reach {
                break;
            }
        }
        Ok(Targets { start: f.start, end: hex_addr(end), source: f.source, rows })
    }

    pub fn find_pointers(&self, q: &PointerQuery) -> R<Vec<PointerHit>> {
        self.job("pointers", |p, prog| memory::find_pointers(p, q, prog))
    }

    pub fn module_header(&self, name: &str) -> R<HeaderSummary> {
        // A remote target's module paths name files on the other machine: memory only.
        let sess = self.session()?;
        let p = sess.proc.clone();
        let m = p.modules().map_err(s)?.into_iter().find(|m| m.name == name).ok_or_else(|| format!("no module {name:?}"))?;
        guard(hh_tools::headers::summary_with(&*p, &m, sess.info.remote.is_none()))
    }

    /// A unique signature for the instruction at `addr`, verified by scanning for it.
    pub fn aob_signature(&self, addr: &str) -> R<SigOut> {
        let p = self.session()?.proc.clone();
        let sig = guard(signature::make_signature(&*p, parse_addr(addr)?, &SigOptions::default()))?;
        let found = guard(signature::verify_signature(&*p, &sig.module, &sig.pattern, 8))?.into_iter().map(hex_addr).collect();
        Ok(SigOut { sig, found })
    }

    /// Auto Assembler template at `addr`: `code`, `aob` or `full` injection.
    pub fn aa_template(&self, addr: &str, kind: &str) -> R<String> {
        let k = match kind {
            "api" => hh_asm::Template::ApiHook,
            "code" => hh_asm::Template::CodeInjection,
            "aob" | "" => hh_asm::Template::AobInjection,
            "full" => hh_asm::Template::FullInjection,
            k => return Err(format!("unknown template {k:?}")),
        };
        guard(hh_asm::injection_template(&*self.session()?.proc, parse_addr(addr)?, k))
    }

    // ------------------------------------------------------------------- code list

    /// The code list with each entry's current state (original / nopped / changed / unreadable).
    pub fn code_list(&self) -> R<Vec<CodeRow>> {
        let codes = self.x.live.state().table.codes;
        let status = match self.session() {
            Ok(sess) => code_list(&codes).status(&*sess.proc, &lock(&sess.syms).clone()),
            Err(_) => codes.iter().map(|_| CodeStatus { addr: None, state: hh_tools::codelist::CodeState::Unreadable, current: Vec::new() }).collect(),
        };
        Ok(codes.into_iter().zip(status).map(|(entry, status)| CodeRow { entry, status }).collect())
    }

    /// Adds the instruction at `addr` (expression), recording its original bytes.
    pub fn code_add(&self, addr: &str, description: &str) -> R<usize> {
        let sess = self.session()?;
        let mut l = CodeList::default();
        guard(l.add(&*sess.proc, &lock(&sess.syms).clone(), addr, description))?;
        let e = &l.entries[0];
        let mut codes = self.x.live.state().table.codes;
        codes.push(CodeEntry { description: e.description.clone(), address: e.addr.clone(), bytes: hh_tools::hexbytes::to_string(&e.original), ..CodeEntry::default() });
        let n = codes.len() - 1;
        self.x.live.set_codes(codes);
        Ok(n)
    }

    pub fn code_remove(&self, index: usize) -> R<()> {
        let mut codes = self.x.live.state().table.codes;
        if index >= codes.len() {
            return Err(format!("no code entry {index}"));
        }
        codes.remove(index);
        self.x.live.set_codes(codes);
        Ok(())
    }

    /// NOPs entry `index` after checking memory still holds the recorded original.
    pub fn code_nop(&self, index: usize) -> R<()> {
        let sess = self.session()?;
        guard(code_list(&self.x.live.state().table.codes).nop(&*sess.proc, &lock(&sess.syms).clone(), index))
    }

    pub fn code_restore(&self, index: usize, force: bool) -> R<()> {
        let sess = self.session()?;
        guard(code_list(&self.x.live.state().table.codes).restore(&*sess.proc, &lock(&sess.syms).clone(), index, force))
    }
}
