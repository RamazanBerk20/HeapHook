//! Disassembler (iced-x86 Intel syntax, CE-style numbers: hex without prefix/suffix).
use std::sync::Arc;

use hh_core::{Addr, Error, Process, Result};
use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Formatter, GasFormatter, Instruction, IntelFormatter,
    MemorySize, OpKind, Register,
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

/// What a value in memory probably is (Cheat Engine's "auto guess" for the disassembler).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValueType {
    Byte,
    Word,
    Dword,
    Qword,
    Float,
    Double,
    /// Points into readable memory.
    Pointer,
    /// At least 4 printable ASCII characters.
    String,
    /// At least 4 printable UTF-16LE (ASCII range) characters.
    UnicodeString,
}

fn plausible_float(v: f64, exp_zero: bool, exp_max: bool) -> bool {
    !exp_zero && !exp_max && (1e-4..=1e9).contains(&v.abs())
}

/// Guesses the type of the value at `a` as an operand of `size` bytes (0 = unknown, taken as
/// 4); `float`: the instruction treats it as floating point. `None` if `a` is unreadable.
pub fn guess_value_type(p: &dyn Process, a: Addr, size: usize, float: bool) -> Option<ValueType> {
    let mut b = [0u8; 16];
    let n = p.read(a, &mut b).ok().filter(|n| *n > 0)?;
    let b = &b[..n];
    if float {
        return Some(if size == 8 {
            ValueType::Double
        } else {
            ValueType::Float
        });
    }
    let text = |c: u8| c.is_ascii_graphic() || c == b' ';
    if b.iter().take_while(|c| text(**c)).count() >= 4 {
        return Some(ValueType::String);
    }
    if b
        .chunks_exact(2)
        .take_while(|c| c[1] == 0 && text(c[0]))
        .count()
        >= 4
    {
        return Some(ValueType::UnicodeString);
    }
    let size = if matches!(size, 1 | 2 | 4 | 8) { size } else { 4 };
    if n < size {
        return None;
    }
    let mut v = [0u8; 8];
    v[..size].copy_from_slice(&b[..size]);
    let v = u64::from_le_bytes(v);
    if size == p.pointer_size() && v >= 0x10000 && p.read(v, &mut [0u8; 1]).is_ok_and(|k| k == 1)
    {
        return Some(ValueType::Pointer);
    }
    Some(match size {
        1 => ValueType::Byte,
        2 => ValueType::Word,
        4 => {
            let e = (v >> 23) & 0xFF;
            if plausible_float(f32::from_bits(v as u32) as f64, e == 0, e == 0xFF) {
                ValueType::Float
            } else {
                ValueType::Dword
            }
        }
        _ => {
            let e = (v >> 52) & 0x7FF;
            if plausible_float(f64::from_bits(v), e == 0, e == 0x7FF) {
                ValueType::Double
            } else {
                ValueType::Qword
            }
        }
    })
}

/// The value at `a` shown as `t`: `(float)1.5`, `->name`, `'text'`, hex for integers.
pub(crate) fn format_value(
    p: &dyn Process,
    a: Addr,
    t: ValueType,
    name: &dyn Fn(Addr) -> Option<String>,
) -> Option<String> {
    let mut b = [0u8; 32];
    let n = p.read(a, &mut b).ok()?;
    let b = &b[..n];
    let int = |w: usize| -> Option<u64> {
        let mut v = [0u8; 8];
        v[..w].copy_from_slice(b.get(..w)?);
        Some(u64::from_le_bytes(v))
    };
    Some(match t {
        ValueType::Byte | ValueType::Word | ValueType::Dword | ValueType::Qword => {
            let w = match t {
                ValueType::Byte => 1,
                ValueType::Word => 2,
                ValueType::Dword => 4,
                _ => 8,
            };
            format!("{:0w$X}", int(w)?, w = w * 2)
        }
        ValueType::Float => format!("(float){}", f32::from_bits(int(4)? as u32)),
        ValueType::Double => format!("(double){}", f64::from_bits(int(8)?)),
        ValueType::Pointer => {
            let v = int(p.pointer_size())?;
            format!("->{}", name(v).unwrap_or_else(|| format!("{v:X}")))
        }
        ValueType::String => {
            let k = b.iter().take_while(|c| c.is_ascii_graphic() || **c == b' ');
            format!("'{}'", String::from_utf8_lossy(&k.copied().collect::<Vec<_>>()))
        }
        ValueType::UnicodeString => {
            let s: String = b
                .chunks_exact(2)
                .take_while(|c| c[1] == 0 && (c[0].is_ascii_graphic() || c[0] == b' '))
                .map(|c| c[0] as char)
                .collect();
            format!("u'{s}'")
        }
    })
}

/// Element size and whether it is floating point, for a memory operand of `ins`.
pub(crate) fn mem_element(ins: &Instruction) -> (usize, bool) {
    let ms = ins.memory_size();
    let el = ms.element_type();
    let float = matches!(
        el,
        MemorySize::Float16 | MemorySize::Float32 | MemorySize::Float64 | MemorySize::Float80
    );
    (el.size(), float)
}

fn comment(
    p: &dyn Process,
    ins: &Instruction,
    name: &dyn Fn(Addr) -> Option<String>,
    guess: bool,
) -> String {
    let mut parts = Vec::new();
    for i in 0..ins.op_count() {
        match ins.op_kind(i) {
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                if let Some(s) = name(ins.near_branch_target()) {
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
                let sym = name(a).unwrap_or_else(|| format!("{a:X}"));
                // call/jmp [slot] (IAT, GOT): name the function the slot points to.
                let target = matches!(
                    ins.flow_control(),
                    FlowControl::IndirectBranch | FlowControl::IndirectCall
                )
                .then(|| p.read_ptr(a).ok())
                .flatten()
                .and_then(name);
                if let Some(t) = target {
                    parts.push(format!("[{sym}]->{t}"));
                    continue;
                }
                let v = if guess {
                    let (size, float) = mem_element(ins);
                    guess_value_type(p, a, size, float).and_then(|t| format_value(p, a, t, name))
                } else {
                    value_hint(p, a, ins.memory_size().size())
                };
                match v {
                    Some(v) if v.starts_with("->") => parts.push(format!("[{sym}]{v}")),
                    Some(v) => parts.push(format!("[{sym}]={v}")),
                    None => parts.push(format!("[{sym}]")),
                }
            }
            _ => {}
        }
    }
    parts.join(" ")
}

/// Instruction syntax of the disassembly text.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Syntax {
    /// Cheat Engine style Intel: `mov eax,[rcx+E0]`.
    #[default]
    Intel,
    /// AT&T (GNU as): `mov 0xe0(%rcx),%eax`. Display only; the assembler reads Intel.
    Att,
}

/// Instruction set to decode.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Arch {
    /// The target's own (32- or 64-bit x86).
    #[default]
    Auto,
    X86,
    X64,
    /// Not supported: [`disassemble_with`] returns `Error::Unsupported`.
    Arm,
    /// Not supported: [`disassemble_with`] returns `Error::Unsupported`.
    Arm64,
}

pub(crate) fn arch_bits(p: &dyn Process, arch: Arch) -> Result<u32> {
    match arch {
        Arch::Auto => Ok(bitness(p)),
        Arch::X86 => Ok(32),
        Arch::X64 => Ok(64),
        Arch::Arm | Arch::Arm64 => Err(Error::Unsupported(
            "ARM / AArch64 disassembly is not supported",
        )),
    }
}

/// Host-provided name for an address (Cheat Engine's `registerAddressLookupCallback`).
pub type AddressName = Arc<dyn Fn(Addr) -> Option<String>>;

/// Options of [`disassemble_with`]; the default is what [`disassemble`] does.
#[derive(Clone, Default)]
pub struct DisasmOptions {
    pub syntax: Syntax,
    pub arch: Arch,
    /// Comments show memory operands by guessed type (`(float)1.5`, `->name`, `'text'`)
    /// instead of plain hex.
    pub guess_types: bool,
    /// Asked first whenever a comment needs the name of an address.
    pub address_name: Option<AddressName>,
}

enum Fmt {
    Intel(IntelFormatter),
    Gas(GasFormatter),
}

impl Fmt {
    fn new(s: Syntax) -> Self {
        match s {
            Syntax::Intel => Fmt::Intel(formatter()),
            Syntax::Att => {
                let mut f = GasFormatter::new();
                f.options_mut().set_uppercase_hex(false);
                Fmt::Gas(f)
            }
        }
    }
    fn format(&mut self, ins: &Instruction, out: &mut String) {
        match self {
            Fmt::Intel(f) => f.format(ins, out),
            Fmt::Gas(f) => f.format(ins, out),
        }
    }
}

/// Disassembles `count` instructions from `addr`. Unreadable bytes show as `??`.
pub fn disassemble(
    p: &dyn Process,
    syms: &SymbolTable,
    addr: Addr,
    count: usize,
) -> Result<Vec<DisasmLine>> {
    disassemble_with(p, syms, addr, count, &DisasmOptions::default())
}

/// [`disassemble`] with a syntax, an instruction set, typed comments and a naming hook.
pub fn disassemble_with(
    p: &dyn Process,
    syms: &SymbolTable,
    addr: Addr,
    count: usize,
    opts: &DisasmOptions,
) -> Result<Vec<DisasmLine>> {
    let bits = arch_bits(p, opts.arch)?;
    let mods = p.modules().unwrap_or_default();
    let name = |a: Addr| {
        opts.address_name
            .as_ref()
            .and_then(|f| f(a))
            .or_else(|| symbol_for(p, syms, &mods, a))
    };
    let mut f = Fmt::new(opts.syntax);
    let mut out = Vec::with_capacity(count.min(4096));
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
                    comment: comment(p, &ins, &name, opts.guess_types),
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
