//! "Dissect code": disassembles whole modules (parallel linear sweep over the executable
//! regions, then a recursive descent from the entry point, exports and call targets to pick
//! up code the sweep decoded out of step) and collects:
//! - call targets (the function list) with caller counts, including imported functions
//!   reached through `call [slot]` / `jmp [slot]` (the slot is read to name the target),
//! - cross references: calls, jumps and data references (RIP-relative / absolute memory
//!   operands, `lea`, and immediates that fall inside a dissected module),
//! - referenced strings (ASCII / UTF-16) with their referencing instructions,
//! - code caves (runs of 00 / CC / 90 in executable memory).
//!
//! References are stored column-wise sorted by target (17 bytes each) and queried in pages.
//! A dissection can grow by modules ([`Dissection::add_modules`]), filter functions by
//! executed-instruction sets the caller recorded ([`Dissection::code_filter`]), and be saved
//! and loaded.
//!
//! # `.hhdis` file format (version 1)
//! All integers little-endian:
//! ```text
//! magic     8 bytes  "HHDISS\0\0"
//! version   u32      1
//! flags     u32      0 (reserved)
//! meta_len  u64      length of the JSON that follows (at most MAX_META_BYTES)
//! meta      JSON     {modules, code_bytes, instructions, functions, strings, caves,
//!                    code, module_info}: the shapes the query methods return; `code`
//!                    lists the disassembled executable ranges as [start, end) number
//!                    pairs; `module_info` (since 1.0, optional) is a [`ModuleIdent`] per
//!                    module: where it was loaded and a fingerprint of its contents
//! ref_count u64      at most MAX_SAVED_REFS
//! ref_count times:   to u64, from u64, kind u8 (0 call, 1 jump, 2 cond_jump, 3 data),
//!                    sorted by (to, from, kind)
//! ```
//! Loading checks every count against the file size and the caps (also the memory the
//! metadata decodes to), every kind byte, the reference order and that functions, strings
//! and caves are sorted, so a hostile file fails with an error instead of allocating or
//! producing an inconsistent index.
//!
//! A loaded dissection holds absolute addresses of some earlier run: it is *unvalidated*
//! until [`Dissection::validate`] matched its modules against a live process (rebasing
//! the ones that moved, dropping the ones that changed). Nothing may write into a process
//! (e.g. arm breakpoints) from an unvalidated dissection; files without `module_info`
//! cannot be validated.
use std::cell::Cell;
use std::collections::{BTreeSet, HashMap};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;

use hh_core::{Addr, Error, Module, Process, Region, Result};
use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind, Register};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::{Progress, hexaddr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefKind {
    Call,
    Jump,
    CondJump,
    /// Memory operand, `lea` or address-like immediate.
    Data,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct XRef {
    /// The referencing instruction.
    #[serde(with = "hexaddr")]
    pub from: Addr,
    #[serde(with = "hexaddr")]
    pub to: Addr,
    pub kind: RefKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DissectOptions {
    /// Follow control flow from the entry point, exports and call targets after the sweep.
    pub recursive: bool,
    /// Minimum characters of a referenced string.
    pub min_string: usize,
    /// Longest string text kept.
    pub max_string: usize,
    /// Minimum code cave length in bytes.
    pub min_cave: usize,
    /// Module files may be read from the local disk (symbols, ELF headers). Set false for a
    /// remote target, whose module paths name files on another machine: then only target
    /// memory is read and functions get no symbol names.
    pub local_files: bool,
}

impl Default for DissectOptions {
    fn default() -> Self {
        DissectOptions {
            recursive: true,
            min_string: 4,
            max_string: 256,
            min_cave: 32,
            local_files: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Function {
    #[serde(with = "hexaddr")]
    pub addr: Addr,
    /// Number of call sites (direct and through call slots).
    pub callers: u32,
    /// Inside the dissected executable code (false for imports and other modules).
    pub internal: bool,
    /// Exported / debug symbol name if known.
    pub name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StringRef {
    #[serde(with = "hexaddr")]
    pub addr: Addr,
    pub text: String,
    pub utf16: bool,
    /// Number of referencing instructions; list them with [`Dissection::xrefs_to`].
    pub refs: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cave {
    #[serde(with = "hexaddr")]
    pub addr: Addr,
    pub len: u64,
    pub byte: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DissectSummary {
    pub modules: Vec<String>,
    /// Executable bytes disassembled.
    pub code_bytes: u64,
    pub instructions: u64,
    pub functions: usize,
    pub refs: usize,
    pub strings: usize,
    pub caves: usize,
    /// Matched against the live process ([`Dissection::validate`]); a loaded file is not
    /// until then.
    #[serde(default)]
    pub validated: bool,
}

/// Where a dissected module was loaded and what it contained.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleIdent {
    pub name: String,
    pub path: String,
    #[serde(with = "hexaddr")]
    pub base: Addr,
    pub size: u64,
    /// [`module_fingerprint`] when it was dissected.
    pub fingerprint: u64,
}

impl ModuleIdent {
    pub fn module(&self) -> Module {
        Module { name: self.name.clone(), path: self.path.clone(), base: self.base, size: self.size }
    }
}

/// What [`Dissection::validate`] did per module (names).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Validation {
    /// Loaded where they were.
    pub kept: Vec<String>,
    /// Loaded elsewhere, same contents: addresses moved with them.
    pub rebased: Vec<String>,
    /// Not loaded, or loaded with other contents: their addresses were dropped.
    pub dropped: Vec<String>,
}

impl Validation {
    /// Nothing moved or went.
    pub fn unchanged(&self) -> bool {
        self.rebased.is_empty() && self.dropped.is_empty()
    }
}

fn fnv(h: &mut u64, b: &[u8]) {
    for &x in b {
        *h = (*h ^ x as u64).wrapping_mul(0x100_0000_01b3);
    }
}

/// A cheap content fingerprint of a loaded module, the same wherever it is loaded: its size,
/// its header page (a PE's ImageBase field, which the loader rewrites, zeroed), and for
/// non-PE images (no base relocations in code) the first and last page of its first
/// executable mapping. `None` when the header cannot be read. Read through a view that
/// hides breakpoint bytes when a debugger may have patched the code.
pub fn module_fingerprint(p: &dyn Process, m: &Module, regions: &[Region]) -> Option<u64> {
    const PG: usize = 4096;
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    fnv(&mut h, &m.size.to_le_bytes());
    let mut page = vec![0u8; PG];
    let n = p.read(m.base, &mut page).ok()?;
    let hdr = &mut page[..n];
    let pe = hdr.starts_with(b"MZ");
    if pe && let Some(e) = hdr.get(0x3c..0x40).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize) {
        let opt = e + 24;
        let field = match hdr.get(opt..opt + 2) {
            Some([0x0b, 0x01]) => Some((opt + 28, 4)),
            Some([0x0b, 0x02]) => Some((opt + 24, 8)),
            _ => None,
        };
        if let Some((o, len)) = field
            && hdr.get(e..e + 4) == Some(b"PE\0\0")
            && let Some(b) = hdr.get_mut(o..o + len)
        {
            b.fill(0);
        }
    }
    fnv(&mut h, hdr);
    let end = m.base.saturating_add(m.size);
    if !pe && let Some(r) = regions.iter().find(|r| r.prot.x && r.start >= m.base && r.start < end) {
        let r_end = r.start.saturating_add(r.size).min(end);
        let last = r_end.saturating_sub(PG as u64).max(r.start);
        for a in [r.start, last] {
            let n = p.read(a, &mut page).unwrap_or(0);
            fnv(&mut h, &page[..n]);
        }
    }
    Some(h)
}

/// Identities of `modules` as loaded in `p` now.
fn idents(p: &dyn Process, modules: &[Module], regions: &[Region]) -> Vec<ModuleIdent> {
    modules
        .iter()
        .map(|m| ModuleIdent {
            name: m.name.clone(),
            path: m.path.clone(),
            base: m.base,
            size: m.size,
            fingerprint: module_fingerprint(p, m, regions).unwrap_or(0),
        })
        .collect()
}

/// Results of [`dissect`]; query in pages.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Dissection {
    modules: Vec<String>,
    code_bytes: u64,
    instructions: u64,
    // References sorted by (to, from, kind).
    to: Vec<Addr>,
    from: Vec<Addr>,
    kind: Vec<RefKind>,
    functions: Vec<Function>,
    by_callers: Vec<u32>,
    strings: Vec<StringRef>,
    caves: Vec<Cave>,
    /// Executable ranges disassembled, `[start, end)`, sorted.
    code: Vec<(Addr, Addr)>,
    /// Identity of each dissected module (empty for files from before 1.0).
    idents: Vec<ModuleIdent>,
    /// The addresses are those of the live process (see [`Dissection::validate`]).
    validated: bool,
}

fn page<T: Clone>(v: &[T], offset: usize, limit: usize) -> Vec<T> {
    v.iter().skip(offset).take(limit).cloned().collect()
}

impl Dissection {
    pub fn summary(&self) -> DissectSummary {
        DissectSummary {
            modules: self.modules.clone(),
            code_bytes: self.code_bytes,
            instructions: self.instructions,
            functions: self.functions.len(),
            refs: self.to.len(),
            strings: self.strings.len(),
            caves: self.caves.len(),
            validated: self.validated,
        }
    }

    /// The addresses are those of the live process: dissected from it, or a loaded file
    /// [`Dissection::validate`]d against it.
    pub fn is_validated(&self) -> bool {
        self.validated
    }

    /// Where each dissected module was (is, once validated) loaded.
    pub fn module_idents(&self) -> &[ModuleIdent] {
        &self.idents
    }

    /// Matches the dissected modules against `p` as it is now: a module loaded at the same
    /// path with the same size and fingerprint is kept, rebased when it moved (all its
    /// addresses move with it); any other module's addresses are dropped (functions,
    /// references from it or into it, strings, caves, code ranges), as is everything
    /// claiming to be code outside the kept modules. Then the dissection is validated.
    /// Errors (and stays unvalidated) for a file without module identities.
    pub fn validate(&mut self, p: &dyn Process) -> Result<Validation> {
        if self.idents.is_empty() {
            return Err(Error::Other("this dissection file has no module identities (saved before 1.0); dissect again".into()));
        }
        let live = p.modules()?;
        let regions = p.regions()?;
        let mut v = Validation::default();
        // (old start, old end, delta) of kept modules; old ranges of dropped ones.
        let mut keep: Vec<(Addr, Addr, u64)> = Vec::new();
        let mut gone: Vec<(Addr, Addr)> = Vec::new();
        let mut idents = Vec::new();
        for id in std::mem::take(&mut self.idents) {
            let old = (id.base, id.base.saturating_add(id.size));
            let found = live.iter().find(|m| {
                m.path == id.path && m.size == id.size && id.fingerprint != 0 && module_fingerprint(p, m, &regions) == Some(id.fingerprint)
            });
            match found {
                Some(m) => {
                    keep.push((old.0, old.1, m.base.wrapping_sub(id.base)));
                    if m.base == id.base { v.kept.push(id.name.clone()) } else { v.rebased.push(id.name.clone()) }
                    idents.push(ModuleIdent { base: m.base, ..id });
                }
                None => {
                    gone.push(old);
                    v.dropped.push(id.name);
                }
            }
        }
        self.idents = idents;
        self.modules = self.idents.iter().map(|i| i.name.clone()).collect();
        // Fast path: everything where it was.
        if !v.unchanged() || !self.all_inside(&keep) {
            self.remap(&keep, &gone);
        }
        self.validated = true;
        Ok(v)
    }

    /// Every code-like item lies inside a kept module.
    fn all_inside(&self, keep: &[(Addr, Addr, u64)]) -> bool {
        let inside = |a: Addr| keep.iter().any(|k| a >= k.0 && a < k.1);
        self.code.iter().all(|c| inside(c.0) && c.1 <= keep.iter().find(|k| c.0 >= k.0 && c.0 < k.1).map_or(0, |k| k.1))
            && self.functions.iter().all(|f| !f.internal || inside(f.addr))
            && self.caves.iter().all(|c| inside(c.addr))
            && self.from.iter().all(|&a| inside(a))
            && self.strings.iter().all(|s| inside(s.addr))
    }

    /// Moves addresses of kept modules by their delta and drops what is not in one.
    fn remap(&mut self, keep: &[(Addr, Addr, u64)], gone: &[(Addr, Addr)]) {
        // New address of `a` when it lies in a kept module.
        let moved = |a: Addr| keep.iter().find(|k| a >= k.0 && a < k.1).map(|k| a.wrapping_add(k.2));
        let in_gone = |a: Addr| gone.iter().any(|g| a >= g.0 && a < g.1);
        // Outside every dissected module (heap, other libraries): unchanged.
        let target = |a: Addr| match moved(a) {
            Some(n) => Some(n),
            None if in_gone(a) => None,
            None => Some(a),
        };
        let mut refs: Vec<Ref> = (0..self.to.len())
            .filter_map(|i| Some((target(self.to[i])?, moved(self.from[i])?, self.kind[i])))
            .collect();
        refs.par_sort_unstable();
        refs.dedup();
        (self.to, self.from, self.kind) = (Vec::with_capacity(refs.len()), Vec::with_capacity(refs.len()), Vec::with_capacity(refs.len()));
        for (t, f, k) in refs {
            self.to.push(t);
            self.from.push(f);
            self.kind.push(k);
        }
        let funcs = std::mem::take(&mut self.functions);
        self.functions = funcs
            .into_iter()
            .filter_map(|mut f| {
                f.addr = if f.internal { moved(f.addr)? } else { target(f.addr)? };
                Some(f)
            })
            .collect();
        self.functions.sort_by_key(|f| f.addr);
        self.functions.dedup_by_key(|f| f.addr);
        self.by_callers = rank(&self.functions);
        let strings = std::mem::take(&mut self.strings);
        self.strings = strings.into_iter().filter_map(|mut x| { x.addr = moved(x.addr)?; Some(x) }).collect();
        self.strings.sort_by_key(|x| x.addr);
        self.strings.dedup_by_key(|x| x.addr);
        let caves = std::mem::take(&mut self.caves);
        self.caves = caves.into_iter().filter_map(|mut x| { x.addr = moved(x.addr)?; Some(x) }).collect();
        self.caves.sort_by_key(|x| x.addr);
        let code = std::mem::take(&mut self.code);
        self.code = code
            .into_iter()
            .filter_map(|(s, e)| {
                let k = keep.iter().find(|k| s >= k.0 && s < k.1)?;
                (e > s && e <= k.1).then(|| (s.wrapping_add(k.2), e.wrapping_add(k.2)))
            })
            .collect();
        self.code.sort_unstable();
        self.code_bytes = self.code.iter().map(|c| c.1 - c.0).sum();
    }
    /// Functions sorted by address.
    pub fn functions(&self, offset: usize, limit: usize) -> Vec<Function> {
        page(&self.functions, offset, limit)
    }
    /// "Referenced functions": called functions, most callers first.
    pub fn referenced_functions(&self, offset: usize, limit: usize) -> Vec<Function> {
        self.by_callers
            .iter()
            .skip(offset)
            .take(limit)
            .map(|&i| self.functions[i as usize].clone())
            .collect()
    }
    /// Function containing or starting at `addr`: the closest function start at or below it.
    pub fn function_at(&self, addr: Addr) -> Option<&Function> {
        let i = self.functions.partition_point(|f| f.addr <= addr);
        self.functions[..i].iter().rev().find(|f| f.internal)
    }
    fn range(&self, lo: Addr, hi: Addr) -> std::ops::Range<usize> {
        self.to.partition_point(|&t| t < lo)..self.to.partition_point(|&t| t < hi)
    }
    /// Number of references to `[lo, hi)` (of `kinds`, all if empty).
    pub fn xref_count(&self, lo: Addr, hi: Addr, kinds: &[RefKind]) -> usize {
        self.range(lo, hi)
            .filter(|&i| kinds.is_empty() || kinds.contains(&self.kind[i]))
            .count()
    }
    /// References whose target lies in `[lo, hi)`: who calls / jumps to / reads an address
    /// (`hi = lo + 1`) or anything inside a structure or global.
    pub fn xrefs_to(
        &self,
        lo: Addr,
        hi: Addr,
        kinds: &[RefKind],
        offset: usize,
        limit: usize,
    ) -> Vec<XRef> {
        self.range(lo, hi)
            .filter(|&i| kinds.is_empty() || kinds.contains(&self.kind[i]))
            .skip(offset)
            .take(limit)
            .map(|i| XRef {
                from: self.from[i],
                to: self.to[i],
                kind: self.kind[i],
            })
            .collect()
    }
    /// Referenced strings sorted by address; `filter` is a case-insensitive substring.
    pub fn strings(&self, filter: Option<&str>, offset: usize, limit: usize) -> Vec<StringRef> {
        let f = filter.map(str::to_lowercase);
        self.strings
            .iter()
            .filter(|s| f.as_ref().is_none_or(|f| s.text.to_lowercase().contains(f)))
            .skip(offset)
            .take(limit)
            .cloned()
            .collect()
    }
    pub fn caves(&self, offset: usize, limit: usize) -> Vec<Cave> {
        page(&self.caves, offset, limit)
    }

    /// Incremental "add module": dissects the modules not dissected yet and merges them in.
    /// Strings in already-dissected modules referenced only from the new code are not added.
    pub fn add_modules(
        &mut self,
        p: &dyn Process,
        modules: &[Module],
        opts: &DissectOptions,
        progress: &Progress,
    ) -> Result<DissectSummary> {
        let new: Vec<Module> = modules.iter().filter(|m| !self.modules.contains(&m.name)).cloned().collect();
        if !new.is_empty() {
            let other = dissect(p, &new, opts, progress)?;
            self.merge(other);
        }
        Ok(self.summary())
    }

    /// Merges a dissection of other modules into this one.
    pub fn merge(&mut self, o: Dissection) {
        self.validated = (self.validated || self.modules.is_empty()) && o.validated;
        self.idents.extend(o.idents);
        self.modules.extend(o.modules);
        self.code_bytes += o.code_bytes;
        self.instructions += o.instructions;
        let mut refs: Vec<Ref> = (0..self.to.len()).map(|i| (self.to[i], self.from[i], self.kind[i])).collect();
        refs.extend((0..o.to.len()).map(|i| (o.to[i], o.from[i], o.kind[i])));
        refs.par_sort_unstable();
        refs.dedup();
        (self.to, self.from, self.kind) = (Vec::with_capacity(refs.len()), Vec::with_capacity(refs.len()), Vec::with_capacity(refs.len()));
        for (t, f, k) in refs {
            self.to.push(t);
            self.from.push(f);
            self.kind.push(k);
        }
        self.functions.extend(o.functions);
        self.functions.sort_by_key(|f| f.addr);
        self.functions.dedup_by(|x, keep| {
            x.addr == keep.addr && {
                keep.callers = keep.callers.saturating_add(x.callers);
                keep.internal |= x.internal;
                if keep.name.is_none() {
                    keep.name = x.name.take();
                }
                true
            }
        });
        self.by_callers = rank(&self.functions);
        self.strings.extend(o.strings);
        self.strings.sort_by_key(|s| s.addr);
        self.strings.dedup_by(|x, keep| x.addr == keep.addr && {
            keep.refs = keep.refs.saturating_add(x.refs);
            true
        });
        self.caves.extend(o.caves);
        self.caves.sort_by_key(|c| c.addr);
        self.code.extend(o.code);
        self.code.sort_unstable();
    }

    /// Code filter without tracing: the internal functions that contain an instruction of
    /// every `ran` set and of no `not_ran` set. Each set holds executed-instruction addresses
    /// (from breakpoints or a tracer, recorded by the caller during one action). Sorted by
    /// address; empty when `ran` is empty.
    pub fn code_filter(&self, ran: &[Vec<Addr>], not_ran: &[Vec<Addr>]) -> Vec<Function> {
        let in_code = |a: Addr| {
            let i = self.code.partition_point(|r| r.0 <= a);
            i > 0 && a < self.code[i - 1].1
        };
        let funcs = |set: &Vec<Addr>| -> BTreeSet<Addr> {
            set.iter().filter(|&&a| in_code(a)).filter_map(|&a| self.function_at(a)).map(|f| f.addr).collect()
        };
        let Some((first, rest)) = ran.split_first() else { return Vec::new() };
        let mut keep = funcs(first);
        for s in rest {
            let f = funcs(s);
            keep.retain(|a| f.contains(a));
        }
        for s in not_ran {
            for a in funcs(s) {
                keep.remove(&a);
            }
        }
        keep.into_iter()
            .filter_map(|a| self.functions.binary_search_by_key(&a, |f| f.addr).ok().map(|i| self.functions[i].clone()))
            .collect()
    }

    /// Writes the dissection as an `.hhdis` file (format in the module docs).
    pub fn save(&self, path: &Path, progress: &Progress) -> Result<()> {
        #[derive(Serialize)]
        struct MetaRef<'a> {
            modules: &'a [String],
            code_bytes: u64,
            instructions: u64,
            functions: &'a [Function],
            strings: &'a [StringRef],
            caves: &'a [Cave],
            code: &'a [(Addr, Addr)],
            #[serde(skip_serializing_if = "<[_]>::is_empty")]
            module_info: &'a [ModuleIdent],
        }
        let meta = serde_json::to_vec(&MetaRef {
            modules: &self.modules,
            code_bytes: self.code_bytes,
            instructions: self.instructions,
            functions: &self.functions,
            strings: &self.strings,
            caves: &self.caves,
            code: &self.code,
            module_info: &self.idents,
        })
        .map_err(|e| Error::Other(format!("dissection JSON: {e}")))?;
        progress.start(self.to.len() as u64);
        let mut w = BufWriter::new(std::fs::File::create(path)?);
        w.write_all(DMAGIC)?;
        w.write_all(&DVERSION.to_le_bytes())?;
        w.write_all(&0u32.to_le_bytes())?;
        w.write_all(&(meta.len() as u64).to_le_bytes())?;
        w.write_all(&meta)?;
        w.write_all(&(self.to.len() as u64).to_le_bytes())?;
        for i in 0..self.to.len() {
            if i % (1 << 16) == 0 {
                progress.check()?;
                progress.add(i.min(1 << 16) as u64);
            }
            w.write_all(&self.to[i].to_le_bytes())?;
            w.write_all(&self.from[i].to_le_bytes())?;
            w.write_all(&[self.kind[i] as u8])?;
        }
        w.flush()?;
        progress.start(self.to.len() as u64);
        progress.add(self.to.len() as u64);
        Ok(())
    }

    /// Reads an `.hhdis` file written by [`Dissection::save`], validating it.
    pub fn load(path: &Path, progress: &Progress) -> Result<Dissection> {
        let bad = |m: &str| Error::Parse(format!("dissection file: {m}"));
        let f = std::fs::File::open(path)?;
        let size = f.metadata()?.len();
        let mut r = BufReader::new(f);
        let mut head = [0u8; 24];
        r.read_exact(&mut head).map_err(|_| bad("too short"))?;
        if &head[..8] != DMAGIC {
            return Err(bad("not a HeapHook dissection"));
        }
        let u32_at = |o: usize| u32::from_le_bytes([head[o], head[o + 1], head[o + 2], head[o + 3]]);
        if u32_at(8) != DVERSION {
            return Err(bad(&format!("unsupported version {}", u32_at(8))));
        }
        let meta_len = u64::from_le_bytes(head[16..24].try_into().unwrap_or_default());
        if meta_len > MAX_META_BYTES || meta_len > size.saturating_sub(24) {
            return Err(bad("metadata length out of range"));
        }
        let mut meta = vec![0u8; meta_len as usize];
        r.read_exact(&mut meta).map_err(|_| bad("truncated"))?;
        #[derive(Deserialize)]
        struct Meta {
            #[serde(deserialize_with = "capped")]
            modules: Vec<String>,
            code_bytes: u64,
            instructions: u64,
            #[serde(deserialize_with = "capped")]
            functions: Vec<Function>,
            #[serde(deserialize_with = "capped")]
            strings: Vec<StringRef>,
            #[serde(deserialize_with = "capped")]
            caves: Vec<Cave>,
            #[serde(default, deserialize_with = "capped")]
            code: Vec<(Addr, Addr)>,
            #[serde(default, deserialize_with = "capped")]
            module_info: Vec<ModuleIdent>,
        }
        META_BUDGET.with(|b| b.set(MAX_META_DECODED));
        let m: std::result::Result<Meta, _> = serde_json::from_slice(&meta);
        META_BUDGET.with(|b| b.set(0));
        let mut m = m.map_err(|e| bad(&format!("metadata: {e}")))?;
        drop(meta);
        let sorted = |v: Vec<Addr>| v.windows(2).all(|w| w[0] < w[1]);
        if !sorted(m.functions.iter().map(|f| f.addr).collect())
            || !sorted(m.strings.iter().map(|s| s.addr).collect())
            || !sorted(m.caves.iter().map(|c| c.addr).collect())
        {
            return Err(bad("functions, strings and caves must be sorted by address"));
        }
        let mut n = [0u8; 8];
        r.read_exact(&mut n).map_err(|_| bad("truncated"))?;
        let count = u64::from_le_bytes(n);
        let left = size.saturating_sub(24 + meta_len + 8);
        if count > MAX_SAVED_REFS || count.saturating_mul(17) != left {
            return Err(bad("reference count does not match the file"));
        }
        progress.start(count);
        let count = count as usize;
        let (mut to, mut from, mut kind) = (Vec::with_capacity(count), Vec::with_capacity(count), Vec::with_capacity(count));
        let mut rec = [0u8; 17];
        let mut prev: Option<Ref> = None;
        for i in 0..count {
            if i % (1 << 16) == 0 {
                progress.check()?;
            }
            r.read_exact(&mut rec).map_err(|_| bad("truncated"))?;
            let k = match rec[16] {
                0 => RefKind::Call,
                1 => RefKind::Jump,
                2 => RefKind::CondJump,
                3 => RefKind::Data,
                b => return Err(bad(&format!("reference kind {b}"))),
            };
            let x: Ref = (u64::from_le_bytes(rec[..8].try_into().unwrap_or_default()), u64::from_le_bytes(rec[8..16].try_into().unwrap_or_default()), k);
            if prev.is_some_and(|p| p >= x) {
                return Err(bad("references not sorted"));
            }
            prev = Some(x);
            to.push(x.0);
            from.push(x.1);
            kind.push(x.2);
        }
        progress.add(count as u64);
        let by_callers = rank(&m.functions);
        m.code.sort_unstable();
        Ok(Dissection {
            modules: m.modules,
            code_bytes: m.code_bytes,
            instructions: m.instructions,
            to,
            from,
            kind,
            functions: m.functions,
            by_callers,
            strings: m.strings,
            caves: m.caves,
            code: m.code,
            idents: m.module_info,
            validated: false,
        })
    }
}

thread_local! {
    /// Bytes of elements the metadata being decoded may still produce (see [`capped`]).
    static META_BUDGET: Cell<u64> = const { Cell::new(0) };
}

/// Most memory the metadata's element structs may take once decoded (their strings take at
/// most the metadata's own size on top): many tiny JSON elements must not expand ~8×.
pub const MAX_META_DECODED: u64 = 192 << 20;

/// A `Vec` deserializer charging each element's size to [`META_BUDGET`].
fn capped<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(d: D) -> std::result::Result<Vec<T>, D::Error> {
    struct V<T>(std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for V<T> {
        type Value = Vec<T>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a list")
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut a: A) -> std::result::Result<Vec<T>, A::Error> {
            let mut v = Vec::new();
            let each = std::mem::size_of::<T>().max(1) as u64;
            while let Some(x) = a.next_element()? {
                let ok = META_BUDGET.with(|b| match b.get().checked_sub(each) {
                    Some(left) => {
                        b.set(left);
                        true
                    }
                    None => false,
                });
                if !ok {
                    return Err(serde::de::Error::custom("dissection metadata too large"));
                }
                v.push(x);
            }
            Ok(v)
        }
    }
    d.deserialize_seq(V(std::marker::PhantomData))
}

const DMAGIC: &[u8; 8] = b"HHDISS\0\0";
const DVERSION: u32 = 1;
/// Most references and most metadata bytes a dissection file may hold.
pub const MAX_SAVED_REFS: u64 = 1 << 27;
pub const MAX_META_BYTES: u64 = 256 << 20;

/// Readable images of the dissected modules, sorted by start.
struct Img {
    start: Addr,
    data: Vec<u8>,
    exec: bool,
    writable: bool,
}

struct Images {
    list: Vec<Img>,
    bits: u32,
    /// Module ranges, for address-like immediates.
    mods: Vec<(Addr, Addr)>,
}

impl Images {
    fn get(&self, a: Addr) -> Option<(&Img, usize)> {
        let i = self.list.partition_point(|m| m.start <= a);
        let m = self.list.get(i.checked_sub(1)?)?;
        let off = (a - m.start) as usize;
        (off < m.data.len()).then_some((m, off))
    }
    fn bytes(&self, a: Addr) -> Option<&[u8]> {
        self.get(a).map(|(m, o)| &m.data[o..])
    }
    fn ptr(&self, a: Addr) -> Option<Addr> {
        let n = if self.bits == 32 { 4 } else { 8 };
        let b = self.bytes(a)?.get(..n)?;
        let mut v = [0u8; 8];
        v[..n].copy_from_slice(b);
        Some(u64::from_le_bytes(v))
    }
    fn in_mods(&self, a: Addr) -> bool {
        self.mods.iter().any(|&(lo, hi)| a >= lo && a < hi)
    }
    fn is_code(&self, a: Addr) -> bool {
        self.get(a).is_some_and(|(m, _)| m.exec)
    }
    /// Pointer stored in a slot that cannot change: a read-only image part (import address
    /// table, GOT after RELRO).
    fn const_ptr(&self, a: Addr) -> Option<Addr> {
        let (m, _) = self.get(a)?;
        (!m.writable).then(|| self.ptr(a)).flatten().filter(|&v| v != 0)
    }
}

/// Address of a memory operand that does not depend on registers.
fn abs_mem(ins: &Instruction) -> Option<Addr> {
    if ins.is_ip_rel_memory_operand() {
        Some(ins.ip_rel_memory_address())
    } else if ins.memory_base() == Register::None
        && ins.memory_index() == Register::None
        && !matches!(ins.memory_segment(), Register::FS | Register::GS)
    {
        Some(ins.memory_displacement64())
    } else {
        None
    }
}

/// `mov reg, [slot]`: (full register, slot address).
fn slot_load(ins: &Instruction) -> Option<(Register, Addr)> {
    if ins.mnemonic() != Mnemonic::Mov || ins.op_count() != 2 || ins.op0_kind() != OpKind::Register || ins.op1_kind() != OpKind::Memory {
        return None;
    }
    Some((ins.op0_register().full_register(), abs_mem(ins)?))
}

/// Final target of a `jmp [slot]` thunk (PLT entry, import stub) at `a` whose slot is constant.
fn thunk_target(imgs: &Images, a: Addr) -> Option<Addr> {
    if !imgs.is_code(a) {
        return None;
    }
    let b = imgs.bytes(a)?;
    let mut d = Decoder::with_ip(imgs.bits, &b[..b.len().min(15)], a, DecoderOptions::NONE);
    let ins = d.decode();
    if ins.flow_control() != FlowControl::IndirectBranch || ins.op0_kind() != OpKind::Memory {
        return None;
    }
    imgs.const_ptr(abs_mem(&ins)?).filter(|&t| t != a)
}

/// Calls into a thunk also count as calls to the function the thunk jumps to. `refs` is
/// sorted and stays sorted.
fn resolve_thunks(imgs: &Images, refs: &mut Vec<Ref>) {
    let mut add = Vec::new();
    let mut cur: Option<(Addr, Option<Addr>)> = None;
    for r in refs.iter().filter(|r| r.2 == RefKind::Call) {
        let t = match cur {
            Some((a, t)) if a == r.0 => t,
            _ => {
                let t = thunk_target(imgs, r.0);
                cur = Some((r.0, t));
                t
            }
        };
        if let Some(t) = t {
            add.push((t, r.1, RefKind::Call));
        }
    }
    if !add.is_empty() {
        refs.extend(add);
        refs.par_sort_unstable();
        refs.dedup();
    }
}

/// Indexes of called functions, most callers first.
fn rank(functions: &[Function]) -> Vec<u32> {
    let mut v: Vec<u32> = (0..functions.len() as u32).filter(|&i| functions[i as usize].callers > 0).collect();
    v.sort_by_key(|&i| std::cmp::Reverse(functions[i as usize].callers));
    v
}

/// `call reg` right after `mov reg, [slot]` with a constant slot: a call to the slot's value.
fn reg_call(ins: &Instruction, prev: Option<(Register, Addr)>, imgs: &Images, out: &mut Vec<Ref>) {
    if ins.flow_control() == FlowControl::IndirectCall
        && ins.op0_kind() == OpKind::Register
        && let Some((r, slot)) = prev
        && ins.op0_register().full_register() == r
        && let Some(t) = imgs.const_ptr(slot)
    {
        out.push((t, ins.ip(), RefKind::Call));
    }
}

type Ref = (Addr, Addr, RefKind); // (to, from, kind)

/// Records the references of one decoded instruction.
fn refs_of(ins: &Instruction, imgs: &Images, out: &mut Vec<Ref>) {
    let ip = ins.ip();
    let fc = ins.flow_control();
    let kind = match fc {
        FlowControl::Call | FlowControl::IndirectCall => Some(RefKind::Call),
        FlowControl::UnconditionalBranch | FlowControl::IndirectBranch => Some(RefKind::Jump),
        FlowControl::ConditionalBranch => Some(RefKind::CondJump),
        _ => None,
    };
    for i in 0..ins.op_count() {
        match ins.op_kind(i) {
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                if let Some(k) = kind {
                    out.push((ins.near_branch_target(), ip, k));
                }
            }
            OpKind::Memory => {
                let a = if ins.is_ip_rel_memory_operand() {
                    ins.ip_rel_memory_address()
                } else if ins.memory_base() == Register::None
                    && ins.memory_index() == Register::None
                    && !matches!(ins.memory_segment(), Register::FS | Register::GS)
                    && ins.memory_displacement64() >= 0x10000
                {
                    ins.memory_displacement64()
                } else {
                    continue;
                };
                out.push((a, ip, RefKind::Data));
                // call/jmp [slot]: the function the slot points to.
                if matches!(fc, FlowControl::IndirectCall | FlowControl::IndirectBranch)
                    && let (Some(k), Some(t)) = (kind, imgs.ptr(a))
                    && t != 0
                {
                    out.push((t, ip, k));
                }
            }
            OpKind::Immediate32 | OpKind::Immediate64 | OpKind::Immediate32to64 => {
                let v = ins.immediate(i);
                if v >= 0x10000 && imgs.in_mods(v) {
                    out.push((v, ip, RefKind::Data));
                }
            }
            _ => {}
        }
    }
}

const CHUNK: usize = 256 << 10;

/// Disassembles the given modules. Progress counts code bytes swept; cancelling returns an
/// error. Unreadable parts are skipped.
pub fn dissect(
    p: &dyn Process,
    modules: &[Module],
    opts: &DissectOptions,
    progress: &Progress,
) -> Result<Dissection> {
    let regions = p.regions()?;
    let bits = if p.pointer_size() == 4 { 32 } else { 64 };
    let mut list = Vec::new();
    for m in modules {
        let end = m.base.saturating_add(m.size);
        for r in regions.iter().filter(|r| r.prot.r) {
            let (lo, hi) = (r.start.max(m.base), r.start.saturating_add(r.size).min(end));
            if lo >= hi {
                continue;
            }
            progress.check()?;
            let data = crate::read_some(p, lo, crate::check_len(hi - lo)?);
            if !data.is_empty() {
                list.push(Img {
                    start: lo,
                    data,
                    exec: r.prot.x,
                    writable: r.prot.w,
                });
            }
        }
    }
    list.sort_by_key(|m| m.start);
    let imgs = Images {
        list,
        bits,
        mods: modules
            .iter()
            .map(|m| (m.base, m.base.saturating_add(m.size)))
            .collect(),
    };
    let code_bytes: u64 = imgs.list.iter().filter(|m| m.exec).map(|m| m.data.len() as u64).sum();
    let code: Vec<(Addr, Addr)> = imgs.list.iter().filter(|m| m.exec).map(|m| (m.start, m.start + m.data.len() as u64)).collect();
    progress.start(code_bytes);

    // Linear sweep, chunk-parallel. A chunk starts decoding at its first byte; the sweep
    // re-synchronises within a few instructions, and the recursive pass covers real starts.
    // Each chunk also marks its instruction starts (CHUNK is a multiple of 64, so chunks own
    // whole bitset words) and finds its cave runs.
    let chunks: Vec<(usize, usize)> = imgs
        .list
        .iter()
        .enumerate()
        .filter(|(_, m)| m.exec)
        .flat_map(|(i, m)| (0..m.data.len()).step_by(CHUNK).map(move |o| (i, o)))
        .collect();
    let swept: Vec<Swept> = chunks
        .par_iter()
        .map(|&(i, o)| {
            progress.check()?;
            let m = &imgs.list[i];
            let end = (o + CHUNK).min(m.data.len());
            let slice = &m.data[o..(end + 15).min(m.data.len())];
            let mut d = Decoder::with_ip(bits, slice, m.start + o as u64, DecoderOptions::NONE);
            let mut ins = Instruction::default();
            let mut sw = Swept { starts: vec![0; (end - o).div_ceil(64)], ..Default::default() };
            let mut prev = None;
            while d.can_decode() && d.position() < end - o {
                let pos = d.position();
                d.decode_out(&mut ins);
                if !ins.is_invalid() {
                    sw.n += 1;
                    sw.starts[pos / 64] |= 1 << (pos % 64);
                    refs_of(&ins, &imgs, &mut sw.refs);
                    reg_call(&ins, prev, &imgs, &mut sw.refs);
                }
                prev = slot_load(&ins);
            }
            scan_caves(&m.data[o..end], m.start + o as u64, opts.min_cave, true, &mut sw.caves);
            progress.add((end - o) as u64);
            Ok(sw)
        })
        .collect::<Result<_>>()?;
    let instructions = swept.iter().map(|s| s.n).sum();
    let mut refs: Vec<Ref> = Vec::with_capacity(swept.iter().map(|s| s.refs.len()).sum());
    let mut starts: Vec<Vec<u64>> = imgs.list.iter().map(|_| Vec::new()).collect();
    let mut caves: Vec<Cave> = Vec::new();
    for (sw, &(i, _)) in swept.into_iter().zip(&chunks) {
        refs.extend_from_slice(&sw.refs);
        starts[i].extend_from_slice(&sw.starts);
        merge_caves(&mut caves, sw.caves);
    }
    caves.retain(|c| c.len >= opts.min_cave.max(1) as u64);

    // Seeds: entry points, exported / debug symbols.
    let mut names: HashMap<Addr, String> = HashMap::new();
    let mut seeds: Vec<Addr> = Vec::new();
    for m in modules {
        if let Ok(h) = crate::headers::summary_with(p, m, opts.local_files)
            && h.entry != 0
        {
            seeds.push(h.entry);
        }
        // shortcut: hh-asm (at this crate's start commit) has no memory-only symbol loader, so
        // a remote dissection has no names; switch to it once hh-asm has one.
        let syms = if opts.local_files { hh_asm::module_symbols(p, m) } else { Vec::new() };
        for s in syms {
            if imgs.is_code(s.addr) {
                seeds.push(s.addr);
                names.entry(s.addr).or_insert(s.name);
            }
        }
    }
    seeds.sort_unstable();
    seeds.dedup();
    if opts.recursive {
        progress.check()?;
        recursive(&imgs, starts, &seeds, &mut refs);
    }
    progress.check()?;
    refs.par_sort_unstable();
    refs.dedup();
    resolve_thunks(&imgs, &mut refs);

    // Functions: call targets (refs are sorted by target) plus seeds.
    let mut calls: Vec<(Addr, u32)> = Vec::new();
    for r in refs.iter().filter(|r| r.2 == RefKind::Call) {
        match calls.last_mut() {
            Some(l) if l.0 == r.0 => l.1 += 1,
            _ => calls.push((r.0, 1)),
        }
    }
    calls.extend(seeds.iter().map(|&s| (s, 0)));
    calls.sort_unstable_by_key(|c| c.0);
    calls.dedup_by(|x, keep| x.0 == keep.0 && {
        keep.1 += x.1;
        true
    });
    let functions: Vec<Function> = calls
        .into_iter()
        .map(|(addr, callers)| Function { addr, callers, internal: imgs.is_code(addr), name: names.get(&addr).cloned() })
        .collect();
    let by_callers = rank(&functions);

    // Strings at data targets.
    let mut strings = Vec::new();
    let mut i = 0;
    while i < refs.len() {
        let t = refs[i].0;
        let mut j = i;
        let mut n = 0;
        while j < refs.len() && refs[j].0 == t {
            n += (refs[j].2 == RefKind::Data) as u32;
            j += 1;
        }
        if n > 0
            && let Some((text, utf16)) = imgs.bytes(t).and_then(|b| string_at(b, opts))
        {
            strings.push(StringRef { addr: t, text, utf16, refs: n });
        }
        i = j;
    }

    let (mut to, mut from, mut kind) = (Vec::with_capacity(refs.len()), Vec::with_capacity(refs.len()), Vec::with_capacity(refs.len()));
    for (t, f, k) in refs {
        to.push(t);
        from.push(f);
        kind.push(k);
    }
    progress.add_found(functions.len() as u64);
    Ok(Dissection {
        idents: idents(p, modules, &regions),
        validated: true,
        modules: modules.iter().map(|m| m.name.clone()).collect(),
        code_bytes,
        instructions,
        to,
        from,
        kind,
        functions,
        by_callers,
        strings,
        caves,
        code,
    })
}

#[derive(Default)]
struct Swept {
    refs: Vec<Ref>,
    n: u64,
    starts: Vec<u64>,
    caves: Vec<Cave>,
}

/// Recursive descent for code the linear sweep decoded out of step. `starts` holds the
/// sweep's instruction starts: flow that reaches one continues exactly like the sweep did
/// (decoding is deterministic per address), so only branch targets and seeds that are not
/// sweep starts are explored, and only the references of newly decoded instructions added.
fn recursive(imgs: &Images, mut seen: Vec<Vec<u64>>, seeds: &[Addr], out: &mut Vec<Ref>) {
    let idx = |a: Addr| {
        let i = imgs.list.partition_point(|m| m.start <= a).checked_sub(1)?;
        let m = &imgs.list[i];
        let o = (a - m.start) as usize;
        (m.exec && o < m.data.len()).then_some((i, o))
    };
    let mut work: Vec<Addr> = seeds.to_vec();
    work.extend(out.iter().filter(|r| r.2 != RefKind::Data).map(|r| r.0));
    let is_seen = |seen: &[Vec<u64>], (i, o): (usize, usize)| seen[i].get(o / 64).is_none_or(|w| w & (1 << (o % 64)) != 0);
    work.retain(|&a| idx(a).is_some_and(|x| !is_seen(&seen, x)));
    let mut ins = Instruction::default();
    let mut local = Vec::new();
    while let Some(a) = work.pop() {
        let Some((i, o)) = idx(a) else { continue };
        let m = &imgs.list[i];
        let mut d = Decoder::with_ip(imgs.bits, &m.data[o..], a, DecoderOptions::NONE);
        let mut prev = None;
        while d.can_decode() {
            let o = o + d.position();
            if is_seen(&seen, (i, o)) {
                break;
            }
            seen[i][o / 64] |= 1 << (o % 64);
            d.decode_out(&mut ins);
            if ins.is_invalid() {
                break;
            }
            local.clear();
            refs_of(&ins, imgs, &mut local);
            reg_call(&ins, prev, imgs, &mut local);
            prev = slot_load(&ins);
            for r in &local {
                if r.2 != RefKind::Data && idx(r.0).is_some_and(|x| !is_seen(&seen, x)) {
                    work.push(r.0);
                }
            }
            out.extend_from_slice(&local);
            if matches!(
                ins.flow_control(),
                FlowControl::Return | FlowControl::UnconditionalBranch | FlowControl::IndirectBranch | FlowControl::Interrupt
            ) {
                break;
            }
        }
    }
}

fn printable(c: u8) -> bool {
    c.is_ascii_graphic() || c == b' ' || c == b'\t' || c == b'\n' || c == b'\r'
}

/// An ASCII or UTF-16LE string at the start of `b` (not necessarily NUL terminated).
fn string_at(b: &[u8], o: &DissectOptions) -> Option<(String, bool)> {
    let wide = b
        .chunks_exact(2)
        .take(o.max_string)
        .take_while(|c| c[1] == 0 && printable(c[0]))
        .count();
    if wide >= o.min_string.max(2) {
        let s = b.chunks_exact(2).take(wide).map(|c| c[0] as char).collect();
        return Some((s, true));
    }
    let n = b.iter().take(o.max_string).take_while(|&&c| printable(c)).count();
    (n >= o.min_string.max(1)).then(|| (String::from_utf8_lossy(&b[..n]).into_owned(), false))
}

/// Runs of one of 00 / CC / 90 of at least `min` bytes; with `borders`, shorter runs that
/// touch either end of `b` are kept too so chunked scans can merge them.
fn scan_caves(b: &[u8], start: Addr, min: usize, borders: bool, out: &mut Vec<Cave>) {
    let min = min.max(1);
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if !matches!(c, 0x00 | 0xCC | 0x90) {
            i += 1;
            continue;
        }
        let n = b[i..].iter().position(|&x| x != c).unwrap_or(b.len() - i);
        if n >= min || (borders && (i == 0 || i + n == b.len())) {
            out.push(Cave { addr: start + i as u64, len: n as u64, byte: c });
        }
        i += n;
    }
}

/// Appends `found` (from the next chunk) to `out`, joining a run that continues across.
fn merge_caves(out: &mut Vec<Cave>, found: Vec<Cave>) {
    for c in found {
        match out.last_mut() {
            Some(l) if l.addr + l.len == c.addr && l.byte == c.byte => l.len += c.len,
            _ => out.push(c),
        }
    }
}

/// Code caves in executable memory within `[start, stop)`, outside of a dissection.
pub fn find_code_caves(
    p: &dyn Process,
    start: Addr,
    stop: Addr,
    min_len: usize,
    progress: &Progress,
) -> Result<Vec<Cave>> {
    if start >= stop {
        return Err(Error::Other("empty range".into()));
    }
    let regions: Vec<_> = p
        .regions()?
        .into_iter()
        .filter(|r| r.prot.r && r.prot.x)
        .filter_map(|r| {
            let (lo, hi) = (r.start.max(start), r.start.saturating_add(r.size).min(stop));
            (lo < hi).then_some((lo, hi))
        })
        .collect();
    progress.start(regions.iter().map(|r| r.1 - r.0).sum());
    let mut out: Vec<Cave> = Vec::new();
    for (lo, hi) in regions {
        let mut a = lo;
        // Chunked reads; a run crossing a chunk border is merged below.
        while a < hi {
            progress.check()?;
            let n = (hi - a).min(16 << 20);
            let b = crate::read_some(p, a, n as usize);
            let mut found = Vec::new();
            scan_caves(&b, a, min_len, true, &mut found);
            merge_caves(&mut out, found);
            progress.add(n);
            a += n;
        }
    }
    out.retain(|c| c.len >= min_len as u64);
    progress.add_found(out.len() as u64);
    Ok(out)
}
