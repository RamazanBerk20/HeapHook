//! AOB signatures: a byte pattern that finds an address again after the module is rebuilt
//! or relocated. Instructions are added from the address onward until the pattern matches
//! only once in the module; RIP-relative and absolute addresses, rel32 branch displacements
//! and address-like immediates become `??`.
use hh_core::{Addr, Error, Module, Process, Result};
use iced_x86::{Decoder, DecoderOptions, Instruction, OpKind, Register};
use serde::{Deserialize, Serialize};

use crate::hexaddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SigOptions {
    /// Give up (with `unique: false`) beyond this many bytes.
    pub max_len: usize,
}

impl Default for SigOptions {
    fn default() -> Self {
        SigOptions { max_len: 96 }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    /// `48 8B 05 ?? ?? ?? ??` (hh-asm `aob_scan` / Cheat Engine `aobscanmodule` syntax).
    pub pattern: String,
    #[serde(with = "hexaddr")]
    pub addr: Addr,
    pub module: String,
    /// `addr - module base` at generation time.
    pub module_offset: u64,
    pub unique: bool,
    /// Matches in the module (1 when unique; capped at the candidates left).
    pub matches: usize,
}

fn module_of(p: &dyn Process, addr: Addr) -> Result<Module> {
    p.modules()?
        .into_iter()
        .find(|m| addr >= m.base && addr - m.base < m.size)
        .ok_or_else(|| Error::Other(format!("{addr:#x} is not inside a module")))
}

/// Readable pieces of a module, sorted by address.
fn module_images(p: &dyn Process, m: &Module) -> Result<Vec<(Addr, Vec<u8>)>> {
    let end = m.base.saturating_add(m.size);
    let mut out = Vec::new();
    for r in p.regions()?.iter().filter(|r| r.prot.r) {
        let (lo, hi) = (r.start.max(m.base), r.start.saturating_add(r.size).min(end));
        if lo < hi {
            let d = crate::read_some(p, lo, crate::check_len(hi - lo)?);
            if !d.is_empty() {
                out.push((lo, d));
            }
        }
    }
    out.sort_by_key(|x| x.0);
    Ok(out)
}

fn bytes_at(imgs: &[(Addr, Vec<u8>)], a: Addr) -> &[u8] {
    let i = imgs.partition_point(|m| m.0 <= a);
    match i.checked_sub(1).map(|i| &imgs[i]) {
        Some((s, d)) if ((a - s) as usize) < d.len() => &d[(a - s) as usize..],
        _ => &[],
    }
}

fn matches(hay: &[u8], pat: &[(u8, bool)]) -> bool {
    hay.len() >= pat.len() && pat.iter().zip(hay).all(|(&(b, wild), &h)| wild || b == h)
}

/// Pattern bytes for one instruction: (byte, is wildcard).
fn insn_pattern(ins: &Instruction, d: &Decoder, raw: &[u8], mods: &[Module]) -> Vec<(u8, bool)> {
    let mut pat: Vec<(u8, bool)> = raw[..ins.len()].iter().map(|&b| (b, false)).collect();
    let mut wild = |off: usize, size: usize| {
        for x in pat.iter_mut().skip(off).take(size) {
            x.1 = true;
        }
    };
    let in_mod = |v: u64| mods.iter().any(|m| v >= m.base && v - m.base < m.size);
    let co = d.get_constant_offsets(ins);
    let is_branch = (0..ins.op_count()).any(|i| {
        matches!(ins.op_kind(i), OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64)
    });
    if is_branch && ins.len() >= 5 {
        // rel32 is always the last four bytes; rel8 short branches stay (position independent).
        wild(ins.len() - 4, 4);
    }
    if co.has_displacement() {
        let abs = ins.memory_base() == Register::None && ins.memory_index() == Register::None;
        if ins.is_ip_rel_memory_operand() || (abs && in_mod(ins.memory_displacement64())) {
            wild(co.displacement_offset(), co.displacement_size());
        }
    }
    for (i, has, off, size) in [
        (0u32, co.has_immediate(), co.immediate_offset(), co.immediate_size()),
        (1, co.has_immediate2(), co.immediate_offset2(), co.immediate_size2()),
    ] {
        if has && size >= 4 && !is_branch {
            let v = (0..ins.op_count())
                .filter(|&k| matches!(ins.op_kind(k), OpKind::Immediate32 | OpKind::Immediate64 | OpKind::Immediate32to64))
                .nth(i as usize)
                .map(|k| ins.immediate(k));
            if v.is_some_and(in_mod) {
                wild(off, size);
            }
        }
    }
    pat
}

fn render(pat: &[(u8, bool)]) -> String {
    pat.iter()
        .map(|&(b, w)| if w { "??".to_string() } else { format!("{b:02X}") })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Generates a signature for the instruction at `addr` that is unique in its module.
pub fn make_signature(p: &dyn Process, addr: Addr, opts: &SigOptions) -> Result<Signature> {
    let m = module_of(p, addr)?;
    let mods = p.modules().unwrap_or_default();
    let imgs = module_images(p, &m)?;
    let bits = if p.pointer_size() == 4 { 32 } else { 64 };
    let code = bytes_at(&imgs, addr);
    if code.is_empty() {
        return Err(Error::NoAccess { addr });
    }
    let mut pat: Vec<(u8, bool)> = Vec::new();
    let mut cands: Option<Vec<Addr>> = None;
    let mut d = Decoder::with_ip(bits, code, addr, DecoderOptions::NONE);
    let mut ins = Instruction::default();
    while pat.len() < opts.max_len && d.can_decode() {
        let pos = d.position();
        d.decode_out(&mut ins);
        if ins.is_invalid() {
            pat.push((code[pos], false));
        } else {
            pat.extend(insn_pattern(&ins, &d, &code[pos..], &mods));
        }
        let fixed = pat.iter().filter(|x| !x.1).count();
        if fixed < 4 {
            continue;
        }
        let c = match cands.take() {
            None => imgs
                .iter()
                .flat_map(|(s, data)| {
                    let pat = &pat;
                    (0..data.len()).filter(move |&i| matches(&data[i..], pat)).map(move |i| s + i as u64)
                })
                .collect::<Vec<_>>(),
            Some(c) => c.into_iter().filter(|&a| matches(bytes_at(&imgs, a), &pat)).collect(),
        };
        if c.len() <= 1 {
            return Ok(Signature {
                pattern: render(&pat),
                addr,
                module: m.name.clone(),
                module_offset: addr - m.base,
                unique: c == [addr],
                matches: c.len(),
            });
        }
        cands = Some(c);
    }
    Ok(Signature {
        pattern: render(&pat),
        addr,
        module: m.name.clone(),
        module_offset: addr - m.base,
        unique: false,
        matches: cands.map_or(0, |c| c.len()),
    })
}

/// Where `pattern` matches inside module `module` (up to `max` hits), via hh-asm's scanner.
pub fn verify_signature(p: &dyn Process, module: &str, pattern: &str, max: usize) -> Result<Vec<Addr>> {
    let m = p
        .modules()?
        .into_iter()
        .find(|m| m.name.eq_ignore_ascii_case(module))
        .ok_or_else(|| Error::Other(format!("no module {module:?}")))?;
    hh_asm::aob_scan(p, m.base, m.base.saturating_add(m.size), pattern, max)
}
