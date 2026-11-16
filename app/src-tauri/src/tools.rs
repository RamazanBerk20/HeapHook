//! Analysis-tool commands over hh-tools: structure dissector, "Dissect code", memory tools
//! (regions, save/load, fill, copy, snapshots, pointers to X), module headers, AOB
//! signatures and the code list.
//!
//! Structure definitions and the code list belong to the cheat table (they are saved with
//! it), so they live in [`crate::cheat::Live`]; dissections, snapshots and the running job
//! belong to the session.
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};

use hh_core::{Addr, Process, Prot};
use hh_tools::Progress;
use hh_tools::codelist::{CodeList, CodeStatus};
use hh_tools::dissect::{self, Cave, DissectOptions, DissectSummary, Dissection, Function, RefKind, StringRef};
use hh_tools::headers::HeaderSummary;
use hh_tools::memory::{self, DiffRange, FileSummary, PointerHit, PointerQuery, Range, RegionInfo, RestoreSummary, Snapshot};
use hh_tools::signature::{self, SigOptions, Signature};
use hh_tools::structure::{self, FieldValue, SpiderHit, SpiderOptions, Structure};
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
        if let Some((_, p)) = self.session().ok().and_then(|s| lock(&s.tools.job).clone()) {
            p.cancel();
        }
        Ok(())
    }

    // ------------------------------------------------------------------ structures

    pub fn struct_get(&self) -> R<Vec<Structure>> {
        Ok(self.x.live.state().table.structures)
    }

    /// Replaces every definition (the UI edits elements, names, sizes locally).
    pub fn struct_set(&self, structs: Vec<Structure>) -> R<()> {
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
        let st = guard(structure::guess_structure(&*sess.proc, name, a, size.clamp(1, 0x10000)))?;
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
        let (name, a) = guard(structure::expand_pointer(&*sess.proc, &mut all, owner, index, parse_addr(field_addr)?, size.clamp(8, 0x10000)))?;
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
        let d = self.job("dissect", |p, prog| dissect::dissect(p, &mods, opts, prog))?;
        let sum = d.summary();
        *lock(&self.session()?.tools.dissection) = Some(Arc::new(d));
        Ok(sum)
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

    /// Loads an `.hhmem` file back; `relocate` moves its first block there.
    pub fn mem_load(&self, path: &str, relocate: Option<&str>) -> R<RestoreSummary> {
        let to = relocate.filter(|r| !r.trim().is_empty()).map(|r| self.resolve_address(r).and_then(|a| parse_addr(&a))).transpose()?;
        guard(memory::load_memory(&*self.session()?.proc, Path::new(path), to))
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

    pub fn find_pointers(&self, q: &PointerQuery) -> R<Vec<PointerHit>> {
        self.job("pointers", |p, prog| memory::find_pointers(p, q, prog))
    }

    pub fn module_header(&self, name: &str) -> R<HeaderSummary> {
        let p = self.session()?.proc.clone();
        let m = p.modules().map_err(s)?.into_iter().find(|m| m.name == name).ok_or_else(|| format!("no module {name:?}"))?;
        guard(hh_tools::headers::summary(&*p, &m))
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
