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
use std::collections::HashMap;

use hh_core::{Addr, Error, Module, Process, Result};
use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, OpKind, Register};
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
}

impl Default for DissectOptions {
    fn default() -> Self {
        DissectOptions {
            recursive: true,
            min_string: 4,
            max_string: 256,
            min_cave: 32,
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
}

/// Results of [`dissect`]; query in pages.
#[derive(Debug, Default)]
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
        }
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
}

/// Readable images of the dissected modules, sorted by start.
struct Img {
    start: Addr,
    data: Vec<u8>,
    exec: bool,
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
            while d.can_decode() && d.position() < end - o {
                let pos = d.position();
                d.decode_out(&mut ins);
                if !ins.is_invalid() {
                    sw.n += 1;
                    sw.starts[pos / 64] |= 1 << (pos % 64);
                    refs_of(&ins, &imgs, &mut sw.refs);
                }
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
        if let Ok(h) = crate::headers::summary(p, m)
            && h.entry != 0
        {
            seeds.push(h.entry);
        }
        for s in hh_asm::module_symbols(p, m) {
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
    let mut by_callers: Vec<u32> = (0..functions.len() as u32).filter(|&i| functions[i as usize].callers > 0).collect();
    by_callers.sort_by_key(|&i| std::cmp::Reverse(functions[i as usize].callers));

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
