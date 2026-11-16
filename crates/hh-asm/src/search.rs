//! Searching code: Cheat Engine's "assembly scan" (instruction text with `?` / `*` wildcards)
//! and "find the next / previous instruction that references an address". Both decode by
//! linear sweep over readable, executable memory.
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};

use hh_core::{Addr, Error, Process, Result};
use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, OpKind, Register};
use serde::{Deserialize, Serialize};

use crate::asm::bitness;
use crate::disasm::formatter;

/// Longest assembly-scan pattern, in characters.
pub const MAX_ASM_PATTERN: usize = 1024;
/// Most instructions one assembly-scan pattern may chain with `;`.
pub const MAX_ASM_SEQUENCE: usize = 16;
/// Most bytes one `find_reference` call searches.
pub const MAX_REF_SEARCH: u64 = 1 << 30;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AsmHit {
    /// First instruction of the match.
    pub addr: Addr,
    /// The matched instructions, `; `-separated.
    pub text: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AsmScanPage {
    pub hits: Vec<AsmHit>,
    /// Where to continue (pass it as `start`) when the page filled up; `None` = done.
    pub next: Option<Addr>,
}

fn cancelled() -> Error {
    Error::Other("cancelled".into())
}

/// Calls `f` for every instruction decoded by linear sweep over readable + executable memory
/// in `[start, stop)`, with `None` at every gap (region change, unreadable or undecodable
/// bytes). Stops when `f` returns true; the result says whether it did.
fn sweep(
    p: &dyn Process,
    start: Addr,
    stop: Addr,
    cancel: &AtomicBool,
    f: &mut dyn FnMut(Option<&Instruction>) -> bool,
) -> Result<bool> {
    const CHUNK: usize = 1 << 16;
    let bits = bitness(p);
    let mut buf = vec![0u8; CHUNK + 15];
    let mut ins = Instruction::default();
    for r in p.regions()? {
        if !r.prot.r || !r.prot.x {
            continue;
        }
        let end = r.start.saturating_add(r.size);
        let (lo, hi) = (r.start.max(start), end.min(stop));
        if lo >= hi {
            continue;
        }
        if f(None) {
            return Ok(true);
        }
        let mut a = lo;
        while a < hi {
            if cancel.load(Ordering::Relaxed) {
                return Err(cancelled());
            }
            let want = (end - a).min(buf.len() as u64) as usize;
            let n = p.read(a, &mut buf[..want]).unwrap_or(0);
            if n == 0 {
                if f(None) {
                    return Ok(true);
                }
                a = (a | 0xFFF).saturating_add(1);
                continue;
            }
            // Instructions starting before `span` belong to this chunk.
            let span = ((hi - a) as usize).min(CHUNK).min(n);
            let mut d = Decoder::with_ip(bits, &buf[..n], a, DecoderOptions::NONE);
            while d.position() < span {
                let pos = d.position();
                d.decode_out(&mut ins);
                if ins.is_invalid() {
                    // One byte on, like the disassembler.
                    d.set_position(pos + 1)
                        .map_err(|e| Error::Other(e.to_string()))?;
                    d.set_ip(a.wrapping_add(pos as u64 + 1));
                    if f(None) {
                        return Ok(true);
                    }
                } else if f(Some(&ins)) {
                    return Ok(true);
                }
            }
            a = a.saturating_add(d.position() as u64);
        }
    }
    Ok(false)
}

/// Whitespace removed, lowercase: `mov eax, [rcx]` and `MOV EAX,[RCX]` compare equal.
fn normalize(s: &str) -> Vec<u8> {
    s.bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .map(|b| b.to_ascii_lowercase())
        .collect()
}

/// `?` = one character, `*` = any run (iterative, no recursion).
fn glob(p: &[u8], t: &[u8]) -> bool {
    let (mut i, mut j) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while j < t.len() {
        if i < p.len() && (p[i] == b'?' || p[i] == t[j]) {
            i += 1;
            j += 1;
        } else if i < p.len() && p[i] == b'*' {
            star = Some((i, j));
            i += 1;
        } else if let Some((si, sj)) = star {
            i = si + 1;
            j = sj + 1;
            star = Some((si, sj + 1));
        } else {
            return false;
        }
    }
    p[i..].iter().all(|c| *c == b'*')
}

/// Splits an assembly-scan pattern into normalized per-instruction globs (`;` or newline
/// separates consecutive instructions).
pub(crate) fn parse_asm_pattern(pattern: &str) -> Result<Vec<Vec<u8>>> {
    if pattern.len() > MAX_ASM_PATTERN {
        return Err(Error::Parse(format!(
            "pattern longer than {MAX_ASM_PATTERN} characters"
        )));
    }
    let pats: Vec<Vec<u8>> = pattern
        .split([';', '\n'])
        .map(normalize)
        .filter(|p| !p.is_empty())
        .collect();
    if pats.is_empty() {
        return Err(Error::Parse("empty assembly pattern".into()));
    }
    if pats.len() > MAX_ASM_SEQUENCE {
        return Err(Error::Parse(format!(
            "more than {MAX_ASM_SEQUENCE} instructions in one pattern"
        )));
    }
    Ok(pats)
}

/// Cheat Engine's assembly scan: instructions in `[start, stop)` whose Intel text (as
/// [`crate::disassemble`] prints it, without comments) matches `pattern`, e.g.
/// `mov [r?x+*],e?x`. Case and whitespace are ignored; `a;b` matches `a` directly followed by
/// `b`. At most `max` hits per page; cancelling gives `Err(Other("cancelled"))`.
pub fn asm_scan(
    p: &dyn Process,
    start: Addr,
    stop: Addr,
    pattern: &str,
    max: usize,
    cancel: &AtomicBool,
) -> Result<AsmScanPage> {
    let pats = parse_asm_pattern(pattern)?;
    let max = max.clamp(1, 1_000_000);
    let mut f = formatter();
    // (addr, len, text) of the last `pats.len()` instructions.
    let mut ring: VecDeque<(Addr, usize, String)> = VecDeque::new();
    let mut page = AsmScanPage::default();
    let mut text = String::new();
    sweep(p, start, stop, cancel, &mut |ins| {
        let Some(ins) = ins else {
            ring.clear();
            return false;
        };
        text.clear();
        f.format(ins, &mut text);
        if ring.len() == pats.len() {
            ring.pop_front();
        }
        ring.push_back((ins.ip(), ins.len(), text.clone()));
        let hit = ring.len() == pats.len()
            && ring
                .iter()
                .zip(&pats)
                .all(|((_, _, t), p)| glob(p, &normalize(t)));
        if !hit {
            return false;
        }
        let (a, len, _) = ring[0];
        let t: Vec<&str> = ring.iter().map(|r| r.2.as_str()).collect();
        page.hits.push(AsmHit {
            addr: a,
            text: t.join("; "),
        });
        if page.hits.len() >= max {
            page.next = Some(a.wrapping_add(len as u64));
            return true;
        }
        false
    })?;
    Ok(page)
}

/// Whether `ins` names `target`: branch target, absolute or RIP-relative memory operand, or
/// an immediate.
fn refers_to(ins: &Instruction, target: Addr) -> bool {
    (0..ins.op_count()).any(|i| match ins.op_kind(i) {
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
            ins.near_branch_target() == target
        }
        OpKind::Memory if ins.is_ip_rel_memory_operand() => {
            ins.ip_rel_memory_address() == target
        }
        OpKind::Memory => {
            ins.memory_base() == Register::None
                && ins.memory_index() == Register::None
                && ins.memory_displacement64() == target
        }
        OpKind::Immediate16
        | OpKind::Immediate32
        | OpKind::Immediate64
        | OpKind::Immediate32to64 => ins.immediate(i) == target,
        _ => false,
    })
}

/// The nearest instruction after (`forward`) or before `from` that references `target` (a
/// branch to it, a memory operand at it, or it as an immediate), searching at most
/// `max_bytes` (capped at [`MAX_REF_SEARCH`]). Backwards, each window is decoded from its
/// start, so a hit right after a window edge can be missed when the sweep lands mid
/// instruction.
pub fn find_reference(
    p: &dyn Process,
    from: Addr,
    target: Addr,
    forward: bool,
    max_bytes: u64,
    cancel: &AtomicBool,
) -> Result<Option<Addr>> {
    let max_bytes = max_bytes.min(MAX_REF_SEARCH);
    if forward {
        let mut found = None;
        let stop = from.saturating_add(max_bytes);
        sweep(p, from, stop, cancel, &mut |ins| {
            let hit = ins.filter(|i| i.ip() > from && refers_to(i, target));
            found = hit.map(|i| i.ip());
            found.is_some()
        })?;
        return Ok(found);
    }
    let (mut end, mut window, mut searched) = (from, 1u64 << 16, 0u64);
    while end > 0 && searched < max_bytes {
        let s = end.saturating_sub(window.min(max_bytes - searched));
        let mut found = None;
        sweep(p, s, end, cancel, &mut |ins| {
            if let Some(i) = ins.filter(|i| i.ip() < from && refers_to(i, target)) {
                found = Some(i.ip());
            }
            false
        })?;
        if found.is_some() {
            return Ok(found);
        }
        searched += end - s;
        end = s;
        window = (window * 2).min(16 << 20);
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::glob;

    #[test]
    fn glob_wildcards() {
        let g = |p: &str, t: &str| glob(p.as_bytes(), t.as_bytes());
        assert!(g("mov[r?x+*],e?x", "mov[rcx+e0],eax"));
        assert!(!g("mov[r?x+*],e?x", "mov[rsp+8],rbx"));
        assert!(g("*", ""));
        assert!(g("a*b*c", "aXXbYYc"));
        assert!(!g("a*b*c", "aXXbYY"));
        assert!(g("*ret", "ret"));
        // Many stars over a long text stay fast (no exponential backtracking).
        let t = "a".repeat(2000);
        assert!(!g(&format!("{}b", "*a".repeat(200)), &t));
    }
}
