//! Disassembler (iced-x86 Intel syntax, CE-style numbers: hex without prefix/suffix).
use hh_core::{Addr, Error, Module, Process, Result};
use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Formatter, Instruction, IntelFormatter, OpKind, Register,
};
use serde::{Deserialize, Serialize};

use crate::asm::bitness;
use crate::expr::SymbolTable;
use crate::symbols::symbol_for;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisasmLine {
    pub addr: Addr,
    pub bytes: Vec<u8>,
    pub text: String,
    pub comment: String,
}

pub(crate) fn formatter() -> IntelFormatter {
    let mut f = IntelFormatter::new();
    let o = f.options_mut();
    o.set_hex_prefix("");
    o.set_hex_suffix("");
    o.set_uppercase_hex(true);
    o.set_add_leading_zero_to_hex_numbers(false);
    o.set_space_after_operand_separator(false);
    o.set_branch_leading_zeros(false);
    o.set_show_branch_size(false);
    o.set_use_pseudo_ops(false);
    f
}

/// Decodes one instruction at `addr`. Unreadable memory is an error; undecodable bytes give
/// an instruction with `Code::INVALID` and length 1.
pub(crate) fn decode_at(p: &dyn Process, addr: Addr) -> Result<(Instruction, Vec<u8>)> {
    let mut buf = [0u8; 15];
    match p.read(addr, &mut buf)? {
        0 => Err(Error::NoAccess { addr }),
        n => Ok(decode_bytes(&buf[..n], addr, bitness(p))),
    }
}

fn decode_bytes(b: &[u8], addr: Addr, bits: u32) -> (Instruction, Vec<u8>) {
    let mut d = Decoder::with_ip(bits, b, addr, DecoderOptions::NONE);
    let ins = d.decode();
    let len = if ins.is_invalid() { 1 } else { ins.len() };
    (ins, b[..len.min(b.len())].to_vec())
}

/// Reads code in large blocks so bulk disassembly is not one syscall per instruction.
struct BlockReader<'a> {
    p: &'a dyn Process,
    start: Addr,
    buf: Vec<u8>,
}

impl BlockReader<'_> {
    const BLOCK: usize = 0x10000;

    /// Up to 15 bytes at `a` (fewer at the end of readable memory), exactly what a 15-byte
    /// read at `a` would give.
    fn at(&mut self, a: Addr) -> Result<&[u8]> {
        let off = a.wrapping_sub(self.start) as usize;
        if a < self.start || off.saturating_add(15) > self.buf.len() {
            self.start = a;
            self.buf.resize(Self::BLOCK, 0);
            let n = match self.p.read(a, &mut self.buf) {
                Ok(n) => n,
                // Some backends refuse a block that runs into unmapped memory.
                Err(_) => self.p.read(a, &mut self.buf[..15]).inspect_err(|_| {
                    self.buf.clear();
                })?,
            };
            self.buf.truncate(n);
        }
        let off = (a - self.start) as usize;
        match &self.buf[off.min(self.buf.len())..(off + 15).min(self.buf.len())] {
            [] => Err(Error::NoAccess { addr: a }),
            b => Ok(b),
        }
    }
}

fn value_hint(p: &dyn Process, a: Addr, size: usize) -> Option<String> {
    let mut b = [0u8; 16];
    let n = p.read(a, &mut b).ok()?;
    let printable = b[..n]
        .iter()
        .take_while(|c| c.is_ascii_graphic() || **c == b' ')
        .count();
    if printable >= 4 {
        return Some(format!("'{}'", String::from_utf8_lossy(&b[..printable])));
    }
    let size = if matches!(size, 1 | 2 | 4 | 8) {
        size
    } else {
        4
    };
    if n < size {
        return None;
    }
    let mut v = [0u8; 8];
    v[..size].copy_from_slice(&b[..size]);
    Some(format!("{:0w$X}", u64::from_le_bytes(v), w = size * 2))
}

fn comment(p: &dyn Process, syms: &SymbolTable, mods: &[Module], ins: &Instruction) -> String {
    let mut parts = Vec::new();
    for i in 0..ins.op_count() {
        match ins.op_kind(i) {
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                if let Some(s) = symbol_for(p, syms, mods, ins.near_branch_target()) {
                    parts.push(s);
                }
            }
            OpKind::Memory => {
                let a = if ins.is_ip_rel_memory_operand() {
                    ins.ip_rel_memory_address()
                } else if ins.memory_base() == Register::None
                    && ins.memory_index() == Register::None
                {
                    ins.memory_displacement64()
                } else {
                    continue;
                };
                let sym = symbol_for(p, syms, mods, a).unwrap_or_else(|| format!("{a:X}"));
                // call/jmp [slot] (IAT, GOT): name the function the slot points to.
                let target = matches!(
                    ins.flow_control(),
                    FlowControl::IndirectBranch | FlowControl::IndirectCall
                )
                .then(|| p.read_ptr(a).ok())
                .flatten()
                .and_then(|t| symbol_for(p, syms, mods, t));
                if let Some(t) = target {
                    parts.push(format!("[{sym}]->{t}"));
                    continue;
                }
                match value_hint(p, a, ins.memory_size().size()) {
                    Some(v) => parts.push(format!("[{sym}]={v}")),
                    None => parts.push(format!("[{sym}]")),
                }
            }
            _ => {}
        }
    }
    parts.join(" ")
}

/// Disassembles `count` instructions from `addr`. Unreadable bytes show as `??`.
pub fn disassemble(
    p: &dyn Process,
    syms: &SymbolTable,
    addr: Addr,
    count: usize,
) -> Result<Vec<DisasmLine>> {
    let mods = p.modules().unwrap_or_default();
    let mut f = formatter();
    let mut out = Vec::with_capacity(count.min(4096));
    let bits = bitness(p);
    let mut rd = BlockReader {
        p,
        start: 0,
        buf: Vec::new(),
    };
    let mut a = addr;
    for _ in 0..count {
        let line = match rd.at(a).map(|b| decode_bytes(b, a, bits)) {
            Err(_) => DisasmLine {
                addr: a,
                bytes: Vec::new(),
                text: "??".into(),
                comment: String::new(),
            },
            Ok((ins, bytes)) if ins.is_invalid() => DisasmLine {
                addr: a,
                text: format!("db {:02X}", bytes[0]),
                bytes,
                comment: String::new(),
            },
            Ok((ins, bytes)) => {
                let mut text = String::new();
                f.format(&ins, &mut text);
                DisasmLine {
                    addr: a,
                    bytes,
                    text,
                    comment: comment(p, syms, &mods, &ins),
                }
            }
        };
        a = a.wrapping_add(line.bytes.len().max(1) as u64);
        out.push(line);
    }
    Ok(out)
}

/// Best guess for the start of the instruction that ends at `addr` (for scrolling a memory
/// view backwards): decodes forward from up to 32 bytes back and keeps the earliest start
/// whose instruction stream lands exactly on `addr`.
pub fn previous_instruction(p: &dyn Process, addr: Addr) -> Result<Addr> {
    for back in (1..=32u64).rev() {
        let start = addr.saturating_sub(back);
        let mut buf = vec![0u8; (addr - start) as usize];
        if buf.is_empty() || p.read_exact(start, &mut buf).is_err() {
            continue;
        }
        let mut d = Decoder::with_ip(bitness(p), &buf, start, DecoderOptions::NONE);
        let mut last = start;
        let mut ins = Instruction::default();
        while d.can_decode() {
            last = d.ip();
            d.decode_out(&mut ins);
            if ins.is_invalid() {
                break;
            }
        }
        if !ins.is_invalid() && d.ip() == addr && d.position() == buf.len() {
            return Ok(last);
        }
    }
    addr.checked_sub(1).ok_or(Error::NoAccess { addr })
}
