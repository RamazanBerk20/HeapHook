//! PE / ELF header summaries of a loaded module: format, machine, entry point, sections,
//! import / export counts. PE images are read from target memory (headers are mapped);
//! ELF files are read from disk (section headers are not mapped) with a memory fallback that
//! only knows the program headers; [`summary_with`] skips the disk for remote targets.
use hh_core::{Addr, Error, Module, Process, Prot, Result};
use serde::{Deserialize, Serialize};

use crate::hexaddr;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Section {
    pub name: String,
    /// Load address in the target.
    #[serde(with = "hexaddr")]
    pub addr: Addr,
    pub size: u64,
    pub prot: Prot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderSummary {
    /// `pe` or `elf`.
    pub format: String,
    pub is_64: bool,
    /// `x86_64`, `x86`, `aarch64` or the raw number.
    pub machine: String,
    /// `exe`, `dll` (PE); `exec`, `dyn`, `rel`, `core` (ELF).
    pub kind: String,
    /// Entry point in the target (0 if none).
    #[serde(with = "hexaddr")]
    pub entry: Addr,
    /// Preferred image base (PE) / lowest load address (ELF).
    #[serde(with = "hexaddr")]
    pub image_base: Addr,
    /// Sections (ELF from memory: loadable segments named `LOAD0`, `LOAD1`, ...).
    pub sections: Vec<Section>,
    /// Imported functions; `None` when unknown.
    pub imports: Option<usize>,
    /// Imported libraries (PE import descriptors, ELF `DT_NEEDED`).
    pub import_libs: Option<usize>,
    pub exports: Option<usize>,
    /// `memory` or `file`.
    pub source: String,
}

type Src<'a> = &'a dyn Fn(u64, usize) -> Option<Vec<u8>>;

fn bad(what: &str) -> Error {
    Error::Parse(format!("bad image header: {what}"))
}

fn rd(src: Src, off: u64, len: usize) -> Result<Vec<u8>> {
    if len > 64 << 20 {
        return Err(bad("size out of range"));
    }
    src(off, len).filter(|b| b.len() == len).ok_or_else(|| bad("truncated"))
}

fn uint(b: &[u8], o: usize, n: usize) -> u64 {
    b.get(o..o + n).map_or(0, |s| {
        let mut v = [0u8; 8];
        v[..n].copy_from_slice(s);
        u64::from_le_bytes(v)
    })
}

fn machine(m: u64, pe: bool) -> String {
    match (pe, m) {
        (true, 0x8664) | (false, 62) => "x86_64".into(),
        (true, 0x14c) | (false, 3) => "x86".into(),
        (true, 0xAA64) | (false, 183) => "aarch64".into(),
        _ => format!("{m:#x}"),
    }
}

/// Most import descriptors read, and most import slots counted over all of them.
const MAX_IMPORT_LIBS: usize = 4096;
const MAX_IMPORT_SLOTS: usize = 1 << 20;
/// Import slots fetched per read.
const SLOT_BLOCK: usize = 4096;
/// Longest section name shown; a hostile string table has no NUL for megabytes.
const MAX_NAME: usize = 256;

fn cstr(b: &[u8]) -> String {
    let b = &b[..b.len().min(MAX_NAME)];
    let n = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..n]).into_owned()
}

/// Header summary of a module (PE or ELF, 32 or 64-bit). Module files are read from the
/// local disk; use [`summary_with`] for a remote target.
pub fn summary(p: &dyn Process, m: &Module) -> Result<HeaderSummary> {
    summary_with(p, m, true)
}

/// [`summary`] with `local_files = false` for a target on another machine: the module path
/// from its memory map names a file over there, and a same-named local file must not be
/// parsed instead, so only target memory is read.
pub fn summary_with(p: &dyn Process, m: &Module, local_files: bool) -> Result<HeaderSummary> {
    let mem = |o: u64, len: usize| {
        let mut b = vec![0u8; len];
        let n = p.read(m.base.checked_add(o)?, &mut b).ok()?;
        b.truncate(n);
        Some(b)
    };
    match rd(&mem, 0, 4)?.as_slice() {
        [b'M', b'Z', ..] => parse_pe(&mem, m.base),
        [0x7f, b'E', b'L', b'F'] => {
            let mut paths = if local_files { vec![m.path.clone()] } else { Vec::new() };
            if local_files && cfg!(target_os = "linux") && m.path.starts_with('/') {
                paths.push(format!("/proc/{}/root{}", p.pid(), m.path));
            }
            for path in paths {
                // Regular files only, read by range: the path comes from the target's memory map.
                if let Ok(src) = hh_asm::module_file_reader(&path)
                    && let Ok(s) = parse_elf(&src, m.base, "file")
                {
                    return Ok(s);
                }
            }
            parse_elf(&mem, m.base, "memory")
        }
        _ => Err(bad("not a PE or ELF image")),
    }
}

/// PE image mapped at `base`; `src` reads by RVA.
pub(crate) fn parse_pe(src: Src, base: Addr) -> Result<HeaderSummary> {
    let dos = rd(src, 0, 0x40)?;
    let nt = uint(&dos, 0x3C, 4);
    let h = rd(src, nt, 24)?;
    if &h[..4] != b"PE\0\0" {
        return Err(bad("no PE signature"));
    }
    let nsec = uint(&h, 6, 2) as usize;
    let opt_size = uint(&h, 20, 2) as usize;
    let chars = uint(&h, 22, 2);
    let opt = rd(src, nt + 24, opt_size)?;
    let is_64 = match uint(&opt, 0, 2) {
        0x20b => true,
        0x10b => false,
        _ => return Err(bad("unknown optional header magic")),
    };
    let entry_rva = uint(&opt, 16, 4);
    let image_base = if is_64 { uint(&opt, 24, 8) } else { uint(&opt, 28, 4) };
    let dd = if is_64 { 112 } else { 96 };
    let ndd = uint(&opt, dd - 4, 4);
    let dir = |i: u64| {
        (i < ndd).then(|| (uint(&opt, dd + i as usize * 8, 4), uint(&opt, dd + i as usize * 8 + 4, 4)))
    };
    let st = rd(src, nt + 24 + opt_size as u64, nsec.min(96) * 40)?;
    let sections = st
        .chunks_exact(40)
        .map(|s| {
            let c = uint(s, 36, 4);
            Section {
                name: cstr(&s[..8]),
                addr: base.wrapping_add(uint(s, 12, 4)),
                size: uint(s, 8, 4),
                prot: Prot {
                    r: c & 0x4000_0000 != 0,
                    w: c & 0x8000_0000 != 0,
                    x: c & 0x2000_0000 != 0,
                },
            }
        })
        .collect();
    let exports = match dir(0) {
        Some((rva, size)) if rva != 0 && size != 0 => {
            rd(src, rva, 40).ok().map(|e| uint(&e, 0x14, 4) as usize)
        }
        _ => Some(0),
    };
    let (mut libs, mut funcs) = (0usize, 0usize);
    if let Some((rva, _)) = dir(1).filter(|d| d.0 != 0) {
        let w = if is_64 { 8 } else { 4 };
        // Bulk reads; a short read is the end of readable memory.
        let descs = src(rva, MAX_IMPORT_LIBS * 20).unwrap_or_default();
        for d in descs.chunks_exact(20) {
            if d.iter().all(|&b| b == 0) {
                break;
            }
            libs += 1;
            let mut at = match uint(d, 0, 4) {
                0 => uint(d, 16, 4),
                t => t,
            };
            'slots: while let Some(block) = src(at, SLOT_BLOCK * w) {
                for t in block.chunks_exact(w) {
                    if uint(t, 0, w) == 0 {
                        break 'slots;
                    }
                    funcs += 1;
                    if funcs > MAX_IMPORT_SLOTS {
                        return Err(bad("more than MAX_IMPORT_SLOTS import slots"));
                    }
                }
                if block.len() < SLOT_BLOCK * w {
                    break;
                }
                at = at.saturating_add((SLOT_BLOCK * w) as u64);
            }
        }
    }
    Ok(HeaderSummary {
        format: "pe".into(),
        is_64,
        machine: machine(uint(&h, 4, 2), true),
        kind: if chars & 0x2000 != 0 { "dll" } else { "exe" }.into(),
        entry: if entry_rva == 0 { 0 } else { base.wrapping_add(entry_rva) },
        image_base,
        sections,
        imports: Some(funcs),
        import_libs: Some(libs),
        exports,
        source: "memory".into(),
    })
}

/// ELF image; `src` reads by file offset (`source = "file"`) or by offset from the load
/// address (`"memory"`, program headers only).
pub(crate) fn parse_elf(src: Src, base: Addr, source: &str) -> Result<HeaderSummary> {
    let e = rd(src, 0, 64)?;
    if &e[..4] != b"\x7fELF" || e[5] != 1 {
        return Err(bad("not a little-endian ELF"));
    }
    let is_64 = e[4] == 2;
    let w = if is_64 { 8 } else { 4 };
    let (phoff, shoff) = if is_64 { (uint(&e, 32, 8), uint(&e, 40, 8)) } else { (uint(&e, 28, 4), uint(&e, 32, 4)) };
    let o = if is_64 { 54 } else { 42 };
    let (phentsize, phnum, shentsize, shnum, shstrndx) = (
        uint(&e, o, 2) as usize,
        uint(&e, o + 2, 2) as usize,
        uint(&e, o + 4, 2) as usize,
        uint(&e, o + 6, 2) as usize,
        uint(&e, o + 8, 2) as usize,
    );
    let etype = uint(&e, 16, 2);
    let ph = rd(src, phoff, phentsize * phnum.min(256))?;
    // (vaddr, memsz, flags) of PT_LOAD segments.
    let loads: Vec<(u64, u64, u64)> = ph
        .chunks_exact(phentsize.max(1))
        .filter(|s| uint(s, 0, 4) == 1)
        .map(|s| {
            if is_64 {
                (uint(s, 16, 8), uint(s, 40, 8), uint(s, 4, 4))
            } else {
                (uint(s, 8, 4), uint(s, 20, 4), uint(s, 24, 4))
            }
        })
        .collect();
    let lowest = loads.iter().map(|l| l.0 & !0xfff).min().unwrap_or(0);
    let bias = base.wrapping_sub(lowest);
    let entry = match uint(&e, 24, w) {
        0 => 0,
        v => v.wrapping_add(bias),
    };
    let mut out = HeaderSummary {
        format: "elf".into(),
        is_64,
        machine: machine(uint(&e, 18, 2), false),
        kind: match etype {
            1 => "rel",
            2 => "exec",
            3 => "dyn",
            4 => "core",
            _ => "unknown",
        }
        .into(),
        entry,
        image_base: lowest,
        sections: Vec::new(),
        imports: None,
        import_libs: None,
        exports: None,
        source: source.into(),
    };
    let seg_prot = |f: u64| Prot { r: f & 4 != 0, w: f & 2 != 0, x: f & 1 != 0 };
    if source != "file" || shoff == 0 || shnum == 0 {
        out.sections = loads
            .iter()
            .enumerate()
            .map(|(i, l)| Section { name: format!("LOAD{i}"), addr: l.0.wrapping_add(bias), size: l.1, prot: seg_prot(l.2) })
            .collect();
        return Ok(out);
    }
    let sh = rd(src, shoff, shentsize * shnum.min(4096))?;
    // (name, type, flags, addr, offset, size, link, entsize)
    let secs: Vec<[u64; 8]> = sh
        .chunks_exact(shentsize.max(1))
        .map(|s| {
            if is_64 {
                [uint(s, 0, 4), uint(s, 4, 4), uint(s, 8, 8), uint(s, 16, 8), uint(s, 24, 8), uint(s, 32, 8), uint(s, 40, 4), uint(s, 56, 8)]
            } else {
                [uint(s, 0, 4), uint(s, 4, 4), uint(s, 8, 4), uint(s, 12, 4), uint(s, 16, 4), uint(s, 20, 4), uint(s, 24, 4), uint(s, 36, 4)]
            }
        })
        .collect();
    let strtab = |i: usize| secs.get(i).and_then(|s| rd(src, s[4], s[5] as usize).ok());
    let names = strtab(shstrndx).unwrap_or_default();
    let name_at = |tab: &[u8], o: u64| tab.get(o as usize..).map(cstr).unwrap_or_default();
    out.sections = secs
        .iter()
        .filter(|s| s[2] & 2 != 0) // SHF_ALLOC
        .map(|s| Section {
            name: name_at(&names, s[0]),
            addr: s[3].wrapping_add(bias),
            size: s[5],
            prot: Prot { r: true, w: s[2] & 1 != 0, x: s[2] & 4 != 0 },
        })
        .collect();
    let (mut imports, mut exports, mut libs) = (0, 0, 0);
    for s in &secs {
        match s[1] {
            11 => {
                // SHT_DYNSYM
                let ent = if is_64 { 24 } else { 16 };
                let Ok(t) = rd(src, s[4], s[5] as usize) else { continue };
                for sym in t.chunks_exact(ent).skip(1) {
                    let (info, shndx) = if is_64 { (sym[4], uint(sym, 6, 2)) } else { (sym[12], uint(sym, 14, 2)) };
                    let named = uint(sym, 0, 4) != 0;
                    if shndx == 0 && named {
                        imports += 1;
                    } else if shndx != 0 && named && matches!(info >> 4, 1 | 2) {
                        exports += 1;
                    }
                }
            }
            6 => {
                // SHT_DYNAMIC
                let Ok(t) = rd(src, s[4], s[5] as usize) else { continue };
                libs += t.chunks_exact(2 * w).filter(|d| uint(d, 0, w) == 1).count();
            }
            _ => {}
        }
    }
    out.imports = Some(imports);
    out.exports = Some(exports);
    out.import_libs = Some(libs);
    Ok(out)
}
