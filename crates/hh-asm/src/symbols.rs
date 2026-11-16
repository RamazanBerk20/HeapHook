//! Exported and debug symbols of the target's modules: ELF `.dynsym` + `.symtab` (32/64-bit)
//! and PE export directories (32/64-bit, forwarders skipped). The file at `Module.path` is
//! preferred; without it the headers are parsed from target memory (ELF via `PT_DYNAMIC`, PE
//! via the mapped export directory). Tables are parsed lazily and cached per module; a module
//! that fails to parse just has no symbols.
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};
use std::sync::{Arc, Mutex, OnceLock};

use hh_core::{Addr, Error, Module, Process, Result};
use serde::{Deserialize, Serialize};

use crate::expr::{SymbolTable, module_offset, parse_num, quote_name};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Symbol {
    pub name: String,
    pub addr: Addr,
    /// 0 when unknown (PE exports).
    pub size: u64,
}

/// Largest single read a header may ask for; corrupt counts fail instead of allocating.
const MAX_READ: usize = 64 << 20;

/// Random access by offset (file) or virtual address (memory). May return fewer bytes.
type Src<'a> = &'a dyn Fn(u64, usize) -> Option<Vec<u8>>;

fn bad(what: &str) -> Error {
    Error::Parse(format!("bad image: {what}"))
}

fn read(src: Src, off: u64, len: usize) -> Result<Vec<u8>> {
    if len > MAX_READ {
        return Err(bad("size out of range"));
    }
    src(off, len)
        .filter(|v| v.len() == len)
        .ok_or_else(|| bad("truncated"))
}

fn u16_at(b: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        b.get(o..o.checked_add(2)?)?.try_into().ok()?,
    ))
}
fn u32_at(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        b.get(o..o.checked_add(4)?)?.try_into().ok()?,
    ))
}
fn u64_at(b: &[u8], o: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        b.get(o..o.checked_add(8)?)?.try_into().ok()?,
    ))
}
/// Word of the image's class: u64 for ELF64, u32 for ELF32.
fn word(b: &[u8], o: usize, is64: bool) -> Option<u64> {
    if is64 {
        u64_at(b, o)
    } else {
        u32_at(b, o).map(u64::from)
    }
}
fn cstr(b: &[u8]) -> Option<String> {
    let n = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    (n > 0).then(|| String::from_utf8_lossy(&b[..n]).into_owned())
}
fn sz(v: u64) -> Result<usize> {
    usize::try_from(v)
        .ok()
        .filter(|&n| n <= MAX_READ)
        .ok_or_else(|| bad("size out of range"))
}

// ------------------------------------------------------------------------------------ ELF

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;

struct Elf {
    is64: bool,
    loads: Vec<(u64, u64, u64)>, // (file offset, vaddr, filesz)
    dynamic: Option<(u64, u64)>, // (vaddr, memsz)
    shoff: u64,
    shentsize: usize,
    shnum: usize,
    bias: u64,
}

/// Header + program headers. `base` is where the lowest `PT_LOAD` page is mapped.
fn elf_header(src: Src, base: Addr) -> Result<Elf> {
    let h = src(0, 64).ok_or_else(|| bad("truncated"))?;
    if h.len() < 52 || &h[..4] != b"\x7fELF" {
        return Err(bad("not ELF"));
    }
    if h[5] != 1 {
        return Err(Error::Unsupported("big-endian ELF"));
    }
    let is64 = match h[4] {
        1 => false,
        2 if h.len() >= 64 => true,
        _ => return Err(bad("ELF class")),
    };
    let g16 = |o32, o64| u16_at(&h, if is64 { o64 } else { o32 }).map(usize::from);
    let gw = |o32, o64| word(&h, if is64 { o64 } else { o32 }, is64);
    let e = || bad("ELF header");
    let phoff = gw(0x1C, 0x20).ok_or_else(e)?;
    let shoff = gw(0x20, 0x28).ok_or_else(e)?;
    let phentsize = g16(0x2A, 0x36).ok_or_else(e)?;
    let phnum = g16(0x2C, 0x38).ok_or_else(e)?;
    let shentsize = g16(0x2E, 0x3A).ok_or_else(e)?;
    let shnum = g16(0x30, 0x3C).ok_or_else(e)?;
    if phentsize < if is64 { 56 } else { 32 } {
        return Err(bad("program header size"));
    }
    let ph = read(src, phoff, phentsize * phnum)?;
    let (mut loads, mut dynamic) = (Vec::new(), None);
    for p in ph.chunks_exact(phentsize) {
        let typ = u32_at(p, 0).ok_or_else(e)?;
        let (off, va, filesz, memsz) = if is64 {
            (u64_at(p, 8), u64_at(p, 16), u64_at(p, 32), u64_at(p, 40))
        } else {
            (
                u32_at(p, 4).map(u64::from),
                u32_at(p, 8).map(u64::from),
                u32_at(p, 16).map(u64::from),
                u32_at(p, 20).map(u64::from),
            )
        };
        let (off, va, filesz, memsz) = (
            off.ok_or_else(e)?,
            va.ok_or_else(e)?,
            filesz.ok_or_else(e)?,
            memsz.ok_or_else(e)?,
        );
        match typ {
            PT_LOAD => loads.push((off, va, filesz)),
            PT_DYNAMIC => dynamic = Some((va, memsz)),
            _ => {}
        }
    }
    let low = loads
        .iter()
        .map(|l| l.1)
        .min()
        .ok_or_else(|| bad("no PT_LOAD"))?;
    Ok(Elf {
        is64,
        loads,
        dynamic,
        shoff,
        shentsize,
        shnum,
        bias: base.wrapping_sub(low & !0xFFF),
    })
}

/// Decodes a symbol array. Keeps defined functions / objects / untyped labels.
fn elf_syms(elf: &Elf, syms: &[u8], strtab: &[u8], out: &mut Vec<(Symbol, bool)>) {
    let ent = if elf.is64 { 24 } else { 16 };
    for s in syms.chunks_exact(ent) {
        let name = u32_at(s, 0).unwrap_or(0) as usize;
        let (info, shndx, value, size) = if elf.is64 {
            (s[4], u16_at(s, 6), u64_at(s, 8), u64_at(s, 16))
        } else {
            (
                s[12],
                u16_at(s, 14),
                u32_at(s, 4).map(u64::from),
                u32_at(s, 8).map(u64::from),
            )
        };
        let (Some(shndx), Some(value), Some(size)) = (shndx, value, size) else {
            continue;
        };
        // Undefined, absolute, common and other reserved section indexes have no address here.
        if shndx == 0 || shndx >= 0xFF00 || value == 0 || !matches!(info & 0xF, 0 | 1 | 2 | 10) {
            continue;
        }
        let Some(name) = strtab.get(name..).and_then(cstr) else {
            continue;
        };
        out.push((
            Symbol {
                name,
                addr: elf.bias.wrapping_add(value),
                size,
            },
            info >> 4 != 0,
        ));
    }
}

/// `.dynsym` then `.symtab` from the section headers of a file.
fn elf_sections(elf: &Elf, src: Src) -> Result<Vec<(Symbol, bool)>> {
    let mut out = Vec::new();
    if elf.shoff == 0 || elf.shnum == 0 {
        return Ok(out);
    }
    if elf.shentsize < if elf.is64 { 64 } else { 40 } {
        return Err(bad("section header size"));
    }
    let sh = read(src, elf.shoff, elf.shentsize * elf.shnum)?;
    let sec = |i: usize| -> Option<(u32, u64, u64, usize)> {
        let s = sh.get(i * elf.shentsize..(i + 1) * elf.shentsize)?;
        Some(if elf.is64 {
            (
                u32_at(s, 4)?,
                u64_at(s, 24)?,
                u64_at(s, 32)?,
                u32_at(s, 40)? as usize,
            )
        } else {
            (
                u32_at(s, 4)?,
                u32_at(s, 16)?.into(),
                u32_at(s, 20)?.into(),
                u32_at(s, 24)? as usize,
            )
        })
    };
    for want in [11u32, 2] {
        // SHT_DYNSYM, SHT_SYMTAB
        for i in 0..elf.shnum {
            let Some((typ, off, size, link)) = sec(i) else {
                continue;
            };
            if typ != want {
                continue;
            }
            let (_, soff, ssize, _) = sec(link).ok_or_else(|| bad("string table"))?;
            let syms = read(src, off, sz(size)?)?;
            let strs = read(src, soff, sz(ssize)?)?;
            elf_syms(elf, &syms, &strs, &mut out);
        }
    }
    Ok(out)
}

/// Symbols reachable from `PT_DYNAMIC` (what the loader itself uses). `read_va` reads by
/// link-time virtual address; `fix` turns a dynamic-section pointer into one.
fn elf_dynamic(elf: &Elf, read_va: Src, fix: &dyn Fn(u64) -> u64) -> Result<Vec<(Symbol, bool)>> {
    let (va, memsz) = elf.dynamic.ok_or_else(|| bad("no PT_DYNAMIC"))?;
    let w = if elf.is64 { 8 } else { 4 };
    let dynamic = read(read_va, va, sz(memsz.min(0x10000))? / (2 * w) * (2 * w))?;
    let mut tags: HashMap<u64, u64> = HashMap::new();
    for e in dynamic.chunks_exact(2 * w) {
        let tag = word(e, 0, elf.is64).unwrap_or(0);
        if tag == 0 {
            break;
        }
        tags.entry(tag).or_insert(word(e, w, elf.is64).unwrap_or(0));
    }
    let get = |t: u64| {
        tags.get(&t)
            .copied()
            .ok_or_else(|| bad("dynamic tag missing"))
    };
    let (symtab, strtab, strsz) = (fix(get(6)?), fix(get(5)?), get(10)?);
    let count = if let Ok(h) = get(4) {
        // DT_HASH: nchain is the symbol count.
        u32_at(&read(read_va, fix(h).wrapping_add(4), 4)?, 0).unwrap_or(0) as u64
    } else {
        // DT_GNU_HASH: highest bucket start, then walk its chain to the end marker.
        let gh = fix(get(0x6fff_fef5)?);
        let hd = read(read_va, gh, 16)?;
        let nb = u32_at(&hd, 0).unwrap_or(0) as u64;
        let symoff = u32_at(&hd, 4).unwrap_or(0) as u64;
        let bloom = u32_at(&hd, 8).unwrap_or(0) as u64;
        let buckets_va = gh
            .wrapping_add(16)
            .wrapping_add(bloom.wrapping_mul(w as u64));
        let buckets = read(read_va, buckets_va, sz(nb * 4)?)?;
        let max = buckets
            .chunks_exact(4)
            .filter_map(|b| u32_at(b, 0))
            .max()
            .unwrap_or(0) as u64;
        if max < symoff {
            symoff
        } else {
            let chain = buckets_va.wrapping_add(nb * 4);
            let mut i = max;
            loop {
                let v = read(read_va, chain.wrapping_add((i - symoff) * 4), 4)?;
                i += 1;
                if u32_at(&v, 0).unwrap_or(1) & 1 == 1 || i - max > 1 << 20 {
                    break i;
                }
            }
        }
    };
    let ent = if elf.is64 { 24 } else { 16 };
    let syms = read(read_va, symtab, sz(count.saturating_mul(ent))?)?;
    let strs = read(read_va, strtab, sz(strsz)?)?;
    let mut out = Vec::new();
    elf_syms(elf, &syms, &strs, &mut out);
    Ok(out)
}

fn elf_file(src: Src, base: Addr) -> Result<Vec<(Symbol, bool)>> {
    let elf = elf_header(src, base)?;
    let out = elf_sections(&elf, src)?;
    if !out.is_empty() {
        return Ok(out);
    }
    // No section headers (stripped hard): map virtual addresses to file offsets.
    let read_va = |va: u64, len: usize| {
        let (off, lva, _) = elf
            .loads
            .iter()
            .find(|(_, lva, fsz)| va >= *lva && va - lva < *fsz)?;
        src(off + (va - lva), len)
    };
    elf_dynamic(&elf, &read_va, &|v| v)
}

// ------------------------------------------------------------------------------------- PE

/// PE export directory. `mapped`: `src` is indexed by RVA (a loaded image) instead of by
/// file offset.
fn pe(src: Src, mapped: bool, base: Addr) -> Result<Vec<(Symbol, bool)>> {
    let e = || bad("PE header");
    let dos = read(src, 0, 0x40)?;
    if &dos[..2] != b"MZ" {
        return Err(bad("not PE"));
    }
    let nt = u32_at(&dos, 0x3C).ok_or_else(e)? as u64;
    let coff = read(src, nt, 24)?;
    if &coff[..4] != b"PE\0\0" {
        return Err(bad("PE signature"));
    }
    let nsec = u16_at(&coff, 6).ok_or_else(e)? as usize;
    let optsz = u16_at(&coff, 20).ok_or_else(e)? as usize;
    let opt = read(src, nt + 24, optsz)?;
    let (ndirs, dirs) = match u16_at(&opt, 0) {
        Some(0x10b) => (92, 96),
        Some(0x20b) => (108, 112),
        _ => return Err(bad("optional header magic")),
    };
    if u32_at(&opt, ndirs).unwrap_or(0) == 0 {
        return Ok(Vec::new());
    }
    let (exp, exp_size) = (
        u32_at(&opt, dirs).ok_or_else(e)? as u64,
        u32_at(&opt, dirs + 4).ok_or_else(e)? as u64,
    );
    if exp == 0 {
        return Ok(Vec::new());
    }
    let secs = read(src, nt + 24 + optsz as u64, nsec * 40)?;
    let to_off = |rva: u64| -> Option<u64> {
        if mapped {
            return Some(rva);
        }
        let mut first = u64::MAX;
        for s in secs.chunks_exact(40) {
            let (vsz, va, raw, ptr) = (
                u32_at(s, 8)? as u64,
                u32_at(s, 12)? as u64,
                u32_at(s, 16)? as u64,
                u32_at(s, 20)? as u64,
            );
            first = first.min(va);
            if rva >= va && rva - va < vsz.max(raw) {
                return Some(ptr + (rva - va));
            }
        }
        (rva < first).then_some(rva)
    };
    let rd = |rva: u64, len: usize| read(src, to_off(rva).ok_or_else(|| bad("RVA"))?, len);
    let dir = rd(exp, 40)?;
    let nfuncs = u32_at(&dir, 20).ok_or_else(e)? as usize;
    let nnames = u32_at(&dir, 24).ok_or_else(e)? as usize;
    let funcs = rd(
        u32_at(&dir, 28).ok_or_else(e)? as u64,
        nfuncs.min(MAX_READ) * 4,
    )?;
    let names = rd(
        u32_at(&dir, 32).ok_or_else(e)? as u64,
        nnames.min(MAX_READ) * 4,
    )?;
    let ords = rd(
        u32_at(&dir, 36).ok_or_else(e)? as u64,
        nnames.min(MAX_READ) * 2,
    )?;
    // Names normally live inside the export directory: read it once.
    let blob = rd(exp, sz(exp_size)?).unwrap_or_default();
    let mut out = Vec::new();
    for i in 0..nnames {
        let (Some(nrva), Some(ord)) = (u32_at(&names, i * 4), u16_at(&ords, i * 2)) else {
            continue;
        };
        let Some(f) = u32_at(&funcs, ord as usize * 4).map(u64::from) else {
            continue;
        };
        if f == 0 || (f >= exp && f - exp < exp_size) {
            continue; // forwarder string, not code
        }
        let nrva = nrva as u64;
        let name = if nrva >= exp && nrva - exp < blob.len() as u64 {
            cstr(&blob[(nrva - exp) as usize..])
        } else {
            to_off(nrva)
                .and_then(|o| src(o, 256))
                .and_then(|b| cstr(&b))
        };
        if let Some(name) = name {
            out.push((
                Symbol {
                    name,
                    addr: base.wrapping_add(f),
                    size: 0,
                },
                true,
            ));
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------- dispatch

fn parse_file(src: Src, base: Addr) -> Result<Vec<(Symbol, bool)>> {
    match src(0, 4).as_deref() {
        Some(b"\x7fELF") => elf_file(src, base),
        Some([b'M', b'Z', ..]) => pe(src, false, base),
        _ => Err(bad("not an ELF or PE image")),
    }
}

fn parse_mem(p: &dyn Process, m: &Module) -> Result<Vec<(Symbol, bool)>> {
    let at = |a: u64, len: usize| {
        let mut b = vec![0u8; len.min(MAX_READ)];
        let n = p.read(a, &mut b).ok()?;
        b.truncate(n);
        Some(b)
    };
    let by_off = |o: u64, len: usize| at(m.base.wrapping_add(o), len);
    match by_off(0, 4).as_deref() {
        Some(b"\x7fELF") => {
            let elf = elf_header(&by_off, m.base)?;
            let bias = elf.bias;
            let read_va = |va: u64, len: usize| at(bias.wrapping_add(va), len);
            // The loader usually relocates dynamic-section pointers in place.
            let fix = |v: u64| {
                if bias != 0 && v >= m.base && v - m.base < m.size {
                    v - bias
                } else {
                    v
                }
            };
            elf_dynamic(&elf, &read_va, &fix)
        }
        Some([b'M', b'Z', ..]) => pe(&by_off, true, m.base),
        _ => Err(bad("not an ELF or PE image")),
    }
}

/// Parses the symbols of an ELF or PE file image (as stored on disk) loaded at `base`.
pub fn parse_symbols(file: &[u8], base: Addr) -> Result<Vec<Symbol>> {
    let src = |o: u64, len: usize| {
        let o = usize::try_from(o).ok()?;
        file.get(o..o.saturating_add(len).min(file.len()))
            .map(<[u8]>::to_vec)
    };
    Ok(parse_file(&src, base)?.into_iter().map(|s| s.0).collect())
}

// ------------------------------------------------------------------------------- cache

#[derive(Default)]
struct Table {
    by_name: HashMap<String, Addr>,
    /// By address; aliases at one address keep globals first.
    sorted: Vec<Symbol>,
}

impl Table {
    fn new(mut syms: Vec<(Symbol, bool)>) -> Self {
        syms.sort_by_key(|(s, g)| (s.addr, !*g));
        let mut by_name = HashMap::new();
        for global in [true, false] {
            for (s, _) in syms.iter().filter(|(_, g)| *g == global) {
                by_name.entry(s.name.to_ascii_lowercase()).or_insert(s.addr);
            }
        }
        Table {
            by_name,
            sorted: syms.into_iter().map(|s| s.0).collect(),
        }
    }
    fn get(&self, name: &str) -> Option<Addr> {
        self.by_name.get(&name.to_ascii_lowercase()).copied()
    }
    /// Symbol containing `a` (exactly at it when the size is unknown) and the offset.
    fn at(&self, a: Addr) -> Option<(&Symbol, u64)> {
        let i = self.sorted.partition_point(|s| s.addr <= a);
        let last = self.sorted.get(i.checked_sub(1)?)?;
        let s = &self.sorted[self.sorted.partition_point(|s| s.addr < last.addr)];
        let off = a - s.addr;
        (off == 0 || off < s.size).then_some((s, off))
    }
}

type Key = (u32, Addr, u64);
type Cache = Mutex<HashMap<Key, (String, Arc<Table>)>>;

fn table(p: &dyn Process, m: &Module) -> Arc<Table> {
    // shortcut: the cache is never pruned (a few MB per hundred modules); add eviction if
    // HeapHook ever attaches to many processes in one session.
    static CACHE: OnceLock<Cache> = OnceLock::new();
    let cache = CACHE.get_or_init(Default::default);
    let key = (p.pid(), m.base, m.size);
    if let Some((path, t)) = cache.lock().unwrap_or_else(|e| e.into_inner()).get(&key)
        && *path == m.path
    {
        return t.clone();
    }
    let t = Arc::new(Table::new(load(p, m).unwrap_or_default()));
    cache
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(key, (m.path.clone(), t.clone()));
    t
}

fn load(p: &dyn Process, m: &Module) -> Result<Vec<(Symbol, bool)>> {
    let mut paths = vec![m.path.clone()];
    if cfg!(target_os = "linux") && m.path.starts_with('/') {
        // The target may live in another mount namespace (containers, flatpak).
        paths.insert(0, format!("/proc/{}/root{}", p.pid(), m.path));
    }
    for path in paths {
        let Ok(f) = std::fs::File::open(&path) else {
            continue;
        };
        let f = std::cell::RefCell::new(f);
        let src = |o: u64, len: usize| {
            let mut f = f.borrow_mut();
            f.seek(SeekFrom::Start(o)).ok()?;
            let mut b = Vec::new();
            f.by_ref().take(len as u64).read_to_end(&mut b).ok()?;
            Some(b)
        };
        if let Ok(s) = parse_file(&src, m.base) {
            return Ok(s);
        }
    }
    parse_mem(p, m)
}

/// All symbols of one module (parsed once, then cached).
pub fn module_symbols(p: &dyn Process, m: &Module) -> Vec<Symbol> {
    table(p, m).sorted.clone()
}

fn stem(name: &str) -> &str {
    name.rsplit_once('.').map_or(name, |(s, _)| s)
}

/// `module.symbol` (full module name, without its last extension, or up to the first dot:
/// `libc.so.6.malloc`, `kernel32.Sleep`, `libc.malloc`) or a plain exported name.
pub(crate) fn lookup(p: &dyn Process, mods: &[Module], name: &str) -> Option<Addr> {
    for m in mods {
        let short = m.name.split('.').next().unwrap_or_default();
        for prefix in [m.name.as_str(), stem(&m.name), short] {
            let n = prefix.len();
            if name.len() > n + 1
                && name.as_bytes()[n] == b'.'
                && name
                    .get(..n)
                    .is_some_and(|h| h.eq_ignore_ascii_case(prefix))
                && let Some(a) = table(p, m).get(&name[n + 1..])
            {
                return Some(a);
            }
        }
    }
    // Plain names: hex-looking ones are numbers, and operators are never part of a symbol.
    let plain = name
        .chars()
        .all(|c| c.is_alphanumeric() || "_.@$?".contains(c));
    if !plain || parse_num(name).is_some() {
        return None;
    }
    mods.iter().find_map(|m| table(p, m).get(name))
}

/// Display name for `addr`: a registered symbol, `module.symbol[+off]`, `module+off`.
/// Every form reads back through `resolve_address`.
pub fn symbol_at(p: &dyn Process, syms: &SymbolTable, addr: Addr) -> Option<String> {
    let mods = p.modules().unwrap_or_default();
    symbol_for(p, syms, &mods, addr)
}

pub(crate) fn symbol_for(
    p: &dyn Process,
    syms: &SymbolTable,
    mods: &[Module],
    a: Addr,
) -> Option<String> {
    if let Some((k, _)) = syms.iter().find(|(_, v)| *v == a) {
        return Some(k.to_string());
    }
    let m = mods.iter().find(|m| a >= m.base && a - m.base < m.size)?;
    if let Some((s, off)) = table(p, m).at(a) {
        let name = format!("{}.{}", quote_name(&m.name), s.name);
        return Some(if off == 0 {
            name
        } else {
            format!("{name}+{off:X}")
        });
    }
    module_offset(mods, a)
}
