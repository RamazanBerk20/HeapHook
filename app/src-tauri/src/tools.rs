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
        if let Some((_, p)) = self.session().ok().and_then(|s| lock(&s.tools.job).clone()) {
            p.cancel();
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
        let len = std::fs::metadata(path).map_err(|e| format!("{path}: {e}"))?.len();
        if len > crate::table::MAX_FILE {
            return Err(format!("{path}: too big for a structure file"));
        }
        let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
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

    /// A saved `.hhmem` file against live memory.
    pub fn mem_compare(&self, path: &str, max: usize) -> R<Vec<DiffRange>> {
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
        // The header parser reads the module's file from this machine's disk.
        self.local_only("Module headers")?;
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
