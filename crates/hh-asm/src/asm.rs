//! Single-line assembler: Cheat Engine style Intel syntax -> bytes, via iced-x86's encoder.
//!
//! The parser turns the text into register / memory / immediate operands, then every iced
//! `Code` with that mnemonic whose operand kinds fit is encoded; the shortest wins (with a
//! preference for dword memory operands when the size is not given, like CE).
use std::collections::HashMap;
use std::sync::OnceLock;

use hh_core::{Addr, Error, Process, Result};
use iced_x86::{
    Code, Encoder, EncodingKind, Instruction, MemorySize, Mnemonic, OpCodeOperandKind as K, OpKind,
    Register, RoundingControl,
};

use crate::expr::{Ctx, SymbolTable, eval, std_lookup};

struct Tables {
    regs: HashMap<String, Register>,
    mnems: HashMap<String, Mnemonic>,
    codes: HashMap<Mnemonic, Vec<Code>>,
}

fn tables() -> &'static Tables {
    static T: OnceLock<Tables> = OnceLock::new();
    T.get_or_init(|| {
        let regs: HashMap<String, Register> = Register::values()
            .filter(|r| *r != Register::None)
            .map(|r| (format!("{r:?}").to_ascii_lowercase(), r))
            .collect();
        let mut regs: HashMap<String, Register> = regs;
        for n in 8..16 {
            if let Some(r) = regs.get(&format!("r{n}l")).copied() {
                regs.insert(format!("r{n}b"), r);
            }
        }
        let mut mnems: HashMap<String, Mnemonic> = Mnemonic::values()
            .map(|m| (format!("{m:?}").to_ascii_lowercase(), m))
            .collect();
        // Condition-code synonyms iced does not have its own mnemonic for.
        let cc = [
            ("z", "e"),
            ("nz", "ne"),
            ("c", "b"),
            ("nae", "b"),
            ("nc", "ae"),
            ("nb", "ae"),
            ("na", "be"),
            ("nbe", "a"),
            ("pe", "p"),
            ("po", "np"),
            ("nge", "l"),
            ("nl", "ge"),
            ("ng", "le"),
            ("nle", "g"),
        ];
        for p in ["j", "cmov", "set"] {
            for (alias, real) in cc {
                if let Some(m) = mnems.get(&format!("{p}{real}")).copied() {
                    mnems.insert(format!("{p}{alias}"), m);
                }
            }
        }
        for (alias, real) in [
            ("movabs", Mnemonic::Mov),
            ("retn", Mnemonic::Ret),
            ("fwait", Mnemonic::Wait),
            ("xlat", Mnemonic::Xlatb),
        ] {
            mnems.insert(alias.into(), real);
        }
        let mut codes: HashMap<Mnemonic, Vec<Code>> = HashMap::new();
        for c in Code::values() {
            if c.op_code().is_instruction() {
                codes.entry(c.mnemonic()).or_default().push(c);
            }
        }
        Tables { regs, mnems, codes }
    })
}

pub(crate) fn parse_reg(s: &str) -> Option<Register> {
    let s: String = s
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_ascii_lowercase();
    let s = match s.as_str() {
        "st" => "st0".to_string(),
        _ if s.starts_with("st(") && s.ends_with(')') => format!("st{}", &s[3..s.len() - 1]),
        _ => s,
    };
    tables().regs.get(&s).copied()
}

#[derive(Debug, Clone)]
struct Mem {
    seg: Register,
    base: Register,
    index: Register,
    scale: u32,
    disp: u64,
}

#[derive(Debug, Clone)]
enum Opnd {
    Reg(Register),
    Mem(Mem),
    Imm(u64),
}

#[derive(Debug, Clone)]
struct Operand {
    op: Opnd,
    size: Option<usize>,
    far: bool,
    short: bool,
}

/// Splits on `sep` outside brackets, parens and quotes.
pub(crate) fn split_top(s: &str, sep: char) -> Vec<String> {
    let mut out = vec![String::new()];
    let (mut depth, mut quote) = (0i32, None::<char>);
    for c in s.chars() {
        match (quote, c) {
            (Some(q), _) if c == q => quote = None,
            (Some(_), _) => {}
            (None, '\'' | '"') => quote = Some(c),
            (None, '[' | '(') => depth += 1,
            (None, ']' | ')') => depth -= 1,
            (None, _) if c == sep && depth == 0 => {
                out.push(String::new());
                continue;
            }
            _ => {}
        }
        out.last_mut().unwrap().push(c);
    }
    out
}

fn parse_mem(inner: &str, seg: Register, ctx: &Ctx) -> Result<Mem> {
    let mut m = Mem {
        seg,
        base: Register::None,
        index: Register::None,
        scale: 1,
        disp: 0,
    };
    // Split into signed terms at top-level + and -.
    let mut terms: Vec<(bool, String)> = vec![(false, String::new())];
    let mut depth = 0;
    let mut i = 0;
    while let Some(c) = inner[i..].chars().next() {
        // Whole names first: "hh-target" and "libstdc++.so.6" are not subtractions.
        let at_start = !inner[..i].ends_with(crate::expr::is_ident_char);
        let n = match c {
            '"' | '\'' => inner[i + 1..].find(c).map_or(inner.len() - i, |e| e + 2),
            _ if at_start && crate::expr::is_ident_char(c) => {
                crate::expr::ident_len(&inner[i..], ctx.lookup)
            }
            _ => c.len_utf8(),
        };
        match c {
            '[' | '(' => depth += 1,
            ']' | ')' => depth -= 1,
            '+' | '-' if depth == 0 => {
                terms.push((c == '-', String::new()));
                i += 1;
                continue;
            }
            _ => {}
        }
        terms.last_mut().unwrap().1.push_str(&inner[i..i + n]);
        i += n;
    }
    for (neg, t) in terms {
        let t = t.trim();
        if t.is_empty() {
            if neg {
                // "-" directly after another operator, e.g. "rax+-8": keep sign for next term.
                return Err(Error::Parse(format!("bad memory operand [{inner}]")));
            }
            continue;
        }
        let as_reg = |s: &str| parse_reg(s).filter(|r| !r.is_segment_register());
        if let Some(r) = as_reg(t) {
            if neg {
                return Err(Error::Parse(format!(
                    "cannot subtract register in [{inner}]"
                )));
            }
            if m.base == Register::None {
                m.base = r;
            } else if m.index == Register::None {
                m.index = r;
            } else {
                return Err(Error::Parse(format!("too many registers in [{inner}]")));
            }
            continue;
        }
        if let Some((a, b)) = t.split_once('*') {
            let (reg, sc) = match (as_reg(a), as_reg(b)) {
                (Some(r), None) => (Some(r), b),
                (None, Some(r)) => (Some(r), a),
                _ => (None, ""),
            };
            if let Some(r) = reg {
                if neg || m.index != Register::None {
                    return Err(Error::Parse(format!("bad index in [{inner}]")));
                }
                m.index = r;
                m.scale = eval(sc, ctx)? as u32;
                if ![1, 2, 4, 8].contains(&m.scale) {
                    return Err(Error::Parse(format!("bad scale in [{inner}]")));
                }
                continue;
            }
        }
        let v = eval(t, ctx)?;
        m.disp = if neg {
            m.disp.wrapping_sub(v)
        } else {
            m.disp.wrapping_add(v)
        };
    }
    // 16-bit addressing only has bx/bp as base and si/di as index: accept [si+bx].
    if matches!(m.base, Register::SI | Register::DI)
        && matches!(m.index, Register::BX | Register::BP)
        && m.scale == 1
    {
        std::mem::swap(&mut m.base, &mut m.index);
    }
    Ok(m)
}

const SIZE_WORDS: &[(&str, usize)] = &[
    ("byte", 1),
    ("word", 2),
    ("dword", 4),
    ("fword", 6),
    ("qword", 8),
    ("tword", 10),
    ("tbyte", 10),
    ("xmmword", 16),
    ("oword", 16),
    ("ymmword", 32),
    ("zmmword", 64),
];

fn parse_operand(s: &str, ctx: &Ctx) -> Result<Operand> {
    let mut o = Operand {
        op: Opnd::Imm(0),
        size: None,
        far: false,
        short: false,
    };
    let mut rest = s.trim();
    loop {
        let w_end = rest
            .find(|c: char| !c.is_ascii_alphabetic())
            .unwrap_or(rest.len());
        let (w, after) = rest.split_at(w_end);
        if after.is_empty() && w != "short" {
            break; // a lone word is a register or symbol
        }
        let after_ok = after.starts_with(char::is_whitespace) || after.starts_with('[');
        let w = w.to_ascii_lowercase();
        if !after_ok {
            break;
        }
        if let Some(&(_, n)) = SIZE_WORDS.iter().find(|(k, _)| *k == w) {
            o.size = Some(n);
            o.far |= n == 6;
        } else if w == "far" {
            o.far = true;
        } else if w == "short" {
            o.short = true;
        } else if w != "ptr" && w != "near" {
            break;
        }
        rest = after.trim_start();
    }
    if let Some(lb) = rest.find('[') {
        let prefix = rest[..lb].trim().trim_end_matches(':').trim();
        let seg = if prefix.is_empty() {
            Register::None
        } else {
            parse_reg(prefix)
                .filter(|r| r.is_segment_register())
                .ok_or_else(|| Error::Parse(format!("bad segment '{prefix}'")))?
        };
        let rb = rest
            .rfind(']')
            .filter(|&rb| rb > lb && rest[rb + 1..].trim().is_empty());
        let rb = rb.ok_or_else(|| Error::Parse(format!("bad memory operand '{s}'")))?;
        o.op = Opnd::Mem(parse_mem(&rest[lb + 1..rb], seg, ctx)?);
    } else if let Some(r) = parse_reg(rest) {
        o.op = Opnd::Reg(r);
    } else {
        o.op = Opnd::Imm(eval(rest, ctx)?);
    }
    Ok(o)
}

fn fits(v: u64, bits: u32) -> bool {
    v >> bits == 0 || ((v as i64) < 0 && (v as i64) >= -(1i64 << (bits - 1)))
}
fn sext(v: u64, bits: u32) -> i64 {
    ((v << (64 - bits)) as i64) >> (64 - bits)
}

fn reg_ok(k: K, r: Register) -> bool {
    match k {
        K::r8_reg | K::r8_opcode | K::r8_or_mem => r.is_gpr8(),
        K::r16_reg | K::r16_reg_mem | K::r16_rm | K::r16_opcode | K::r16_or_mem => r.is_gpr16(),
        K::r32_reg
        | K::r32_reg_mem
        | K::r32_rm
        | K::r32_opcode
        | K::r32_vvvv
        | K::r32_or_mem
        | K::r32_or_mem_mpx => r.is_gpr32(),
        K::r64_reg
        | K::r64_reg_mem
        | K::r64_rm
        | K::r64_opcode
        | K::r64_vvvv
        | K::r64_or_mem
        | K::r64_or_mem_mpx => r.is_gpr64(),
        K::seg_reg => r.is_segment_register(),
        K::k_reg | K::kp1_reg | K::k_rm | K::k_vvvv | K::k_or_mem => r.is_k(),
        K::mm_reg | K::mm_rm | K::mm_or_mem => r.is_mm(),
        K::xmm_reg
        | K::xmm_rm
        | K::xmm_vvvv
        | K::xmmp3_vvvv
        | K::xmm_is4
        | K::xmm_is5
        | K::xmm_or_mem => r.is_xmm(),
        K::ymm_reg | K::ymm_rm | K::ymm_vvvv | K::ymm_is4 | K::ymm_is5 | K::ymm_or_mem => {
            r.is_ymm()
        }
        K::zmm_reg | K::zmm_rm | K::zmm_vvvv | K::zmmp3_vvvv | K::zmm_or_mem => r.is_zmm(),
        K::cr_reg => r.is_cr(),
        K::dr_reg => r.is_dr(),
        K::tr_reg => r.is_tr(),
        K::bnd_reg | K::bnd_or_mem_mpx => r.is_bnd(),
        K::tmm_reg | K::tmm_rm | K::tmm_vvvv => r.is_tmm(),
        K::sti_opcode => r.is_st(),
        K::es => r == Register::ES,
        K::cs => r == Register::CS,
        K::ss => r == Register::SS,
        K::ds => r == Register::DS,
        K::fs => r == Register::FS,
        K::gs => r == Register::GS,
        K::al => r == Register::AL,
        K::cl => r == Register::CL,
        K::ax => r == Register::AX,
        K::dx => r == Register::DX,
        K::eax => r == Register::EAX,
        K::rax => r == Register::RAX,
        K::st0 => r == Register::ST0,
        _ => false,
    }
}

fn is_mem_kind(k: K) -> bool {
    matches!(
        k,
        K::mem
            | K::mem_mpx
            | K::mem_mib
            | K::sibmem
            | K::mem_offs
            | K::mem_vsib32x
            | K::mem_vsib64x
            | K::mem_vsib32y
            | K::mem_vsib64y
            | K::mem_vsib32z
            | K::mem_vsib64z
            | K::r8_or_mem
            | K::r16_or_mem
            | K::r32_or_mem
            | K::r32_or_mem_mpx
            | K::r64_or_mem
            | K::r64_or_mem_mpx
            | K::mm_or_mem
            | K::xmm_or_mem
            | K::ymm_or_mem
            | K::zmm_or_mem
            | K::bnd_or_mem_mpx
            | K::k_or_mem
    )
}

fn is_string_mem(k: K) -> bool {
    matches!(k, K::seg_rSI | K::es_rDI | K::seg_rDI | K::seg_rBX_al)
}

/// Sets operand `i` of `ins` from `o` for operand kind `k`. `abs` picks the absolute (non
/// RIP-relative) form for a bare `[address]` in 64-bit code.
fn set_operand(
    ins: &mut Instruction,
    i: u32,
    k: K,
    o: &Operand,
    bitness: u32,
    abs: bool,
    nimm: &mut u32,
) -> bool {
    match &o.op {
        Opnd::Reg(r) => {
            if !reg_ok(k, *r) {
                return false;
            }
            ins.set_op_kind(i, OpKind::Register);
            ins.set_op_register(i, *r);
        }
        Opnd::Mem(m) if matches!(k, K::seg_rSI | K::es_rDI | K::seg_rDI | K::seg_rBX_al) => {
            // Explicit string operands: "movsb [rdi],[rsi]", "xlat [rbx+al]".
            let want = match k {
                K::seg_rSI => [Register::RSI, Register::ESI],
                K::seg_rBX_al => [Register::RBX, Register::EBX],
                _ => [Register::RDI, Register::EDI],
            };
            let idx_ok =
                m.index == Register::None || (k == K::seg_rBX_al && m.index == Register::AL);
            if !want.contains(&m.base) || !idx_ok || m.disp != 0 {
                return false;
            }
            set_implicit(ins, i, k, if m.base == want[0] { 64 } else { 32 });
            if k != K::es_rDI {
                ins.set_segment_prefix(m.seg);
            }
        }
        Opnd::Mem(m) => {
            if !is_mem_kind(k) {
                return false;
            }
            let vsib = matches!(
                k,
                K::mem_vsib32x
                    | K::mem_vsib64x
                    | K::mem_vsib32y
                    | K::mem_vsib64y
                    | K::mem_vsib32z
                    | K::mem_vsib64z
            );
            let vec_index = m.index.is_xmm() || m.index.is_ymm() || m.index.is_zmm();
            if vsib != vec_index {
                return false;
            }
            let bare = m.base == Register::None && m.index == Register::None;
            let mut base = m.base;
            let mut dsz = if m.disp == 0 { 0 } else { 1 };
            if bare {
                dsz = if bitness == 64 { 8 } else { 4 };
                let fs_gs = matches!(m.seg, Register::FS | Register::GS);
                if k == K::mem_offs && bitness == 64 {
                    dsz = 8;
                } else if bitness == 64 && !abs && !fs_gs {
                    base = Register::RIP;
                }
            } else if k == K::mem_offs {
                return false;
            }
            ins.set_op_kind(i, OpKind::Memory);
            ins.set_memory_base(base);
            ins.set_memory_index(m.index);
            ins.set_memory_index_scale(m.scale);
            ins.set_memory_displacement64(m.disp);
            ins.set_memory_displ_size(dsz);
            ins.set_segment_prefix(m.seg);
        }
        Opnd::Imm(v) => {
            let v = *v;
            *nimm += 1;
            let kind = match k {
                K::imm8 if fits(v, 8) => {
                    if *nimm == 2 {
                        OpKind::Immediate8_2nd
                    } else {
                        OpKind::Immediate8
                    }
                }
                K::imm8_const_1 if v == 1 => OpKind::Immediate8,
                K::imm8sex16 if fits(v, 16) && (-128..128).contains(&sext(v, 16)) => {
                    OpKind::Immediate8to16
                }
                K::imm8sex32 if fits(v, 32) && (-128..128).contains(&sext(v, 32)) => {
                    OpKind::Immediate8to32
                }
                K::imm8sex64 if (-128..128).contains(&(v as i64)) => OpKind::Immediate8to64,
                K::imm16 if fits(v, 16) => OpKind::Immediate16,
                K::imm32 if fits(v, 32) => OpKind::Immediate32,
                K::imm32sex64 if (i32::MIN as i64..=i32::MAX as i64).contains(&(v as i64)) => {
                    OpKind::Immediate32to64
                }
                K::imm64 => OpKind::Immediate64,
                K::br32_1 | K::br32_4 | K::br64_1 | K::br64_4 | K::xbegin_4 => {
                    let short = matches!(k, K::br32_1 | K::br64_1);
                    if o.short && !short {
                        return false;
                    }
                    if bitness == 64 {
                        ins.set_op_kind(i, OpKind::NearBranch64);
                        ins.set_near_branch64(v);
                    } else {
                        if v > u32::MAX as u64 {
                            return false;
                        }
                        ins.set_op_kind(i, OpKind::NearBranch32);
                        ins.set_near_branch32(v as u32);
                    }
                    return true;
                }
                _ => return false,
            };
            if o.short {
                return false;
            }
            ins.set_op_kind(i, kind);
            match kind {
                OpKind::Immediate8 => ins.set_immediate8(v as u8),
                OpKind::Immediate8_2nd => ins.set_immediate8_2nd(v as u8),
                OpKind::Immediate8to16 => ins.set_immediate8to16(sext(v, 16) as i16),
                OpKind::Immediate8to32 => ins.set_immediate8to32(sext(v, 32) as i32),
                OpKind::Immediate8to64 => ins.set_immediate8to64(v as i64),
                OpKind::Immediate16 => ins.set_immediate16(v as u16),
                OpKind::Immediate32 => ins.set_immediate32(v as u32),
                OpKind::Immediate32to64 => ins.set_immediate32to64(v as i64),
                _ => ins.set_immediate64(v),
            }
        }
    }
    true
}

fn set_implicit(ins: &mut Instruction, i: u32, k: K, bitness: u32) {
    let b64 = bitness == 64;
    let fixed = |r| (OpKind::Register, r);
    let (kind, reg) = match k {
        K::al => fixed(Register::AL),
        K::ax => fixed(Register::AX),
        K::eax => fixed(Register::EAX),
        K::rax => fixed(Register::RAX),
        K::st0 => fixed(Register::ST0),
        K::sti_opcode => fixed(Register::ST1),
        K::seg_rSI => (
            if b64 {
                OpKind::MemorySegRSI
            } else {
                OpKind::MemorySegESI
            },
            Register::None,
        ),
        K::es_rDI => (
            if b64 {
                OpKind::MemoryESRDI
            } else {
                OpKind::MemoryESEDI
            },
            Register::None,
        ),
        K::seg_rDI => (
            if b64 {
                OpKind::MemorySegRDI
            } else {
                OpKind::MemorySegEDI
            },
            Register::None,
        ),
        _ => {
            // xlat: [rbx+al]
            ins.set_op_kind(i, OpKind::Memory);
            ins.set_memory_base(if b64 { Register::RBX } else { Register::EBX });
            ins.set_memory_index(Register::AL);
            ins.set_memory_index_scale(1);
            return;
        }
    };
    ins.set_op_kind(i, kind);
    if kind == OpKind::Register {
        ins.set_op_register(i, reg);
    }
}

fn encode(ins: &Instruction, ip: u64, bitness: u32) -> Option<Vec<u8>> {
    let mut e = Encoder::try_new(bitness).ok()?;
    e.encode(ins, ip).ok()?;
    Some(e.take_buffer())
}

/// Lowercased mnemonic plus prefixes split off; returns (prefixes, mnemonic, operand text).
fn split_mnemonic(text: &str) -> (Vec<String>, String, String) {
    let mut prefixes = Vec::new();
    let mut rest = text.trim();
    loop {
        let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
        let w = rest[..end].to_ascii_lowercase();
        let tail = rest[end..].trim_start();
        if matches!(
            w.as_str(),
            "lock"
                | "rep"
                | "repe"
                | "repz"
                | "repne"
                | "repnz"
                | "xacquire"
                | "xrelease"
                | "bnd"
                | "notrack"
        ) && !tail.is_empty()
        {
            prefixes.push(w);
            rest = tail;
        } else {
            return (prefixes, w, tail.to_string());
        }
    }
}

fn parse_float(s: &str) -> Option<f64> {
    s.trim().trim_start_matches('#').parse::<f64>().ok()
}

/// `db/dw/dd/dq` items: numbers/expressions, quoted strings, `(float)x`, `(double)x`.
fn assemble_data(width: usize, args: &str, ctx: &Ctx) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let items = split_top(args, ',')
        .into_iter()
        .flat_map(|i| split_top(i.trim(), ' '));
    for item in items {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        if (item.starts_with('\'') || item.starts_with('"'))
            && item.len() >= 2
            && item.ends_with(&item[..1])
        {
            let s = &item[1..item.len() - 1];
            match width {
                1 => out.extend_from_slice(s.as_bytes()),
                2 => s
                    .encode_utf16()
                    .for_each(|u| out.extend_from_slice(&u.to_le_bytes())),
                _ => return Err(Error::Parse("strings only allowed in db/dw".into())),
            }
            continue;
        }
        let lower = item.to_ascii_lowercase();
        let (v, w) = if let Some(f) = lower.strip_prefix("(float)") {
            let f = parse_float(f).ok_or_else(|| Error::Parse(format!("bad float '{item}'")))?;
            ((f as f32).to_bits() as u64, width.max(4))
        } else if let Some(f) = lower.strip_prefix("(double)") {
            let f = parse_float(f).ok_or_else(|| Error::Parse(format!("bad double '{item}'")))?;
            (f.to_bits(), width.max(8))
        } else if let Some(i) = lower.strip_prefix("(int)") {
            let i: i64 = i
                .trim()
                .trim_start_matches('#')
                .parse()
                .map_err(|_| Error::Parse(format!("bad int '{item}'")))?;
            (i as u64, width)
        } else {
            (eval(item, ctx)?, width)
        };
        out.extend_from_slice(&v.to_le_bytes()[..w]);
    }
    Ok(out)
}

/// AVX-512 decorations: `{k1}`, `{z}`, `{1to16}`, `{rn-sae}`, `{sae}`.
#[derive(Debug, Default)]
struct Deco {
    mask: Option<Register>,
    zero: bool,
    bcst: bool,
    rc: Option<RoundingControl>,
    sae: bool,
}

impl Deco {
    fn any(&self) -> bool {
        self.mask.is_some() || self.zero || self.bcst || self.rc.is_some() || self.sae
    }
}

/// Removes every `{...}` decoration from the operand text (wherever iced or the user put it).
fn take_decorations(args: &str) -> Result<(String, Deco)> {
    let mut d = Deco::default();
    let mut out = String::new();
    let mut rest = args;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let close = rest[open..]
            .find('}')
            .ok_or_else(|| Error::Parse(format!("missing '}}' in '{args}'")))?;
        let tag = rest[open + 1..open + close].trim().to_ascii_lowercase();
        match tag.as_str() {
            "z" => d.zero = true,
            "sae" => d.sae = true,
            "rn-sae" | "rne-sae" => d.rc = Some(RoundingControl::RoundToNearest),
            "rd-sae" => d.rc = Some(RoundingControl::RoundDown),
            "ru-sae" => d.rc = Some(RoundingControl::RoundUp),
            "rz-sae" => d.rc = Some(RoundingControl::RoundTowardZero),
            _ if tag.starts_with("1to") && tag[3..].parse::<u8>().is_ok() => d.bcst = true,
            _ => match parse_reg(&tag) {
                Some(r) if r.is_k() && r != Register::K0 => d.mask = Some(r),
                _ => return Err(Error::Parse(format!("bad decoration {{{tag}}}"))),
            },
        }
        rest = &rest[open + close + 1..];
    }
    out.push_str(rest);
    // A rounding operand written on its own (",{rn-sae}") leaves an empty operand behind.
    let out = split_top(&out, ',')
        .into_iter()
        .filter(|o| !o.trim().is_empty())
        .collect::<Vec<_>>()
        .join(",");
    Ok((out, d))
}

fn select(
    m: Mnemonic,
    ops: &[Operand],
    prefixes: &[String],
    deco: &Deco,
    ip: Addr,
    bitness: u32,
) -> Option<Vec<u8>> {
    let t = tables();
    let no_size_mem = ops
        .iter()
        .any(|o| matches!(o.op, Opnd::Mem(_)) && o.size.is_none());
    let user_size = ops.iter().find_map(|o| o.size);
    let far = ops.iter().any(|o| o.far);
    let rip_like = ops.iter().any(
        |o| matches!(&o.op, Opnd::Mem(m) if m.base == Register::None && m.index == Register::None),
    );

    let mut best: Option<((u8, usize), Vec<u8>)> = None;
    for &code in t.codes.get(&m).map(|v| v.as_slice()).unwrap_or(&[]) {
        let oc = code.op_code();
        if !oc.is_available_in_mode(bitness)
            || (deco.any() && oc.encoding() != EncodingKind::EVEX)
            || (deco.bcst && !oc.can_broadcast())
        {
            continue;
        }
        let n = oc.op_count();
        let kinds: Vec<K> = (0..n).map(|i| oc.op_kind(i)).collect();
        // Operands the formatter hides (string accumulators, x87 st0/st1) may be omitted.
        if ops.len() > kinds.len() {
            continue;
        }
        let stringy = kinds.iter().any(|k| is_string_mem(*k));
        let hideable = |k: K| {
            (stringy && matches!(k, K::al | K::ax | K::eax | K::rax))
                || matches!(k, K::st0 | K::sti_opcode)
        };
        let need = kinds.len() - ops.len();
        let hide: Vec<usize> = (0..kinds.len())
            .filter(|&i| hideable(kinds[i]))
            .chain((0..kinds.len()).filter(|&i| is_string_mem(kinds[i])))
            .take(need)
            .collect();
        if hide.len() < need {
            continue;
        }
        if kinds.iter().any(|k| {
            matches!(
                k,
                K::br16_1 | K::br16_2 | K::xbegin_2 | K::brdisp_2 | K::brdisp_4
            )
        }) {
            continue;
        }
        let ms = oc.memory_size();
        let is_far_code = matches!(
            ms,
            MemorySize::SegPtr16 | MemorySize::SegPtr32 | MemorySize::SegPtr64
        );
        if is_far_code != far && (far || matches!(m, Mnemonic::Jmp | Mnemonic::Call)) {
            continue;
        }
        if let Some(sz) = user_size
            && ms.size() != 0
            && ms.size() != sz
            && !is_far_code
        {
            continue;
        }
        let penalty = u8::from(no_size_mem && ms.size() != 0 && ms.size() != 4);
        for abs in [false, true] {
            if abs && !(rip_like && bitness == 64) {
                break;
            }
            let mut ins = Instruction::default();
            ins.set_code(code);
            let mut nimm = 0;
            let mut ok = true;
            let mut user = ops.iter();
            for (i, k) in kinds.iter().enumerate() {
                if hide.contains(&i) {
                    set_implicit(&mut ins, i as u32, *k, bitness);
                } else if !user.next().is_some_and(|o| {
                    set_operand(&mut ins, i as u32, *k, o, bitness, abs, &mut nimm)
                }) {
                    ok = false;
                    break;
                }
            }
            if !ok {
                break;
            }
            for p in prefixes {
                match p.as_str() {
                    "lock" => ins.set_has_lock_prefix(true),
                    "rep" | "repe" | "repz" => ins.set_has_repe_prefix(true),
                    "repne" | "repnz" | "bnd" => ins.set_has_repne_prefix(true),
                    "notrack" => ins.set_segment_prefix(Register::DS),
                    "xacquire" => ins.set_has_xacquire_prefix(true),
                    _ => ins.set_has_xrelease_prefix(true),
                }
            }
            if let Some(k) = deco.mask {
                ins.set_op_mask(k);
            }
            ins.set_zeroing_masking(deco.zero);
            ins.set_is_broadcast(deco.bcst);
            if let Some(rc) = deco.rc {
                ins.set_rounding_control(rc);
            }
            ins.set_suppress_all_exceptions(deco.sae);
            if let Some(bytes) = encode(&ins, ip, bitness) {
                let key = (penalty, bytes.len());
                if best.as_ref().is_none_or(|(k, _)| key < *k) {
                    best = Some((key, bytes));
                }
                break;
            }
        }
    }
    best.map(|(_, b)| b)
}

/// Assembles one line at `ip`. `lookup` resolves symbols/labels (numbers are hex by default).
pub fn assemble_line(
    text: &str,
    ip: Addr,
    bitness: u32,
    lookup: &dyn Fn(&str) -> Option<u64>,
) -> Result<Vec<u8>> {
    if !matches!(bitness, 16 | 32 | 64) {
        return Err(Error::Parse(format!("bad bitness {bitness}")));
    }
    let ctx = Ctx { lookup, mem: None };
    let (prefixes, mnem, args) = split_mnemonic(text);
    let width = match mnem.as_str() {
        "db" => 1,
        "dw" => 2,
        "dd" => 4,
        "dq" => 8,
        _ => 0,
    };
    if width > 0 {
        return assemble_data(width, &args, &ctx);
    }
    if mnem == "nop" && !args.is_empty() && !args.contains('[') {
        let n = eval(&args, &ctx)?;
        if n > 0x10000 {
            return Err(Error::Parse(format!("nop count too large: {n:#x}")));
        }
        return Ok(vec![0x90; n as usize]);
    }
    let (mnem, args) = match args.get(..3) {
        Some(f) if mnem == "ret" && f.eq_ignore_ascii_case("far") => {
            ("retf".to_string(), args[3..].trim().to_string())
        }
        _ => (mnem, args),
    };
    let t = tables();
    let m = *t
        .mnems
        .get(&mnem)
        .ok_or_else(|| Error::Parse(format!("unknown instruction '{mnem}'")))?;
    let (args, deco) = take_decorations(&args)?;
    if matches!(m, Mnemonic::Jmp | Mnemonic::Call)
        && let Some(b) = far_direct(m, &args, ip, bitness, &ctx)?
    {
        return Ok(b);
    }
    let mut ops = if args.is_empty() {
        Vec::new()
    } else {
        split_top(&args, ',')
            .iter()
            .map(|s| parse_operand(s, &ctx))
            .collect::<Result<Vec<_>>>()?
    };
    // "imul r,imm" is shorthand for "imul r,r,imm".
    if m == Mnemonic::Imul
        && ops.len() == 2
        && matches!(ops[0].op, Opnd::Reg(_))
        && matches!(ops[1].op, Opnd::Imm(_))
    {
        ops.insert(1, ops[0].clone());
    }
    // Explicit [rip+x]: iced wants the absolute target, which depends on the length.
    let rip_rel = ops
        .iter()
        .position(|o| matches!(&o.op, Opnd::Mem(m) if m.base == Register::RIP));
    let mut best = None;
    if let Some(i) = rip_rel {
        let set = |ops: &mut [Operand], v: u64| {
            if let Opnd::Mem(mem) = &mut ops[i].op {
                mem.disp = v;
            }
        };
        let Opnd::Mem(mem) = &ops[i].op else {
            return Err(Error::Parse("internal".into()));
        };
        let rel = mem.disp;
        set(&mut ops, ip.wrapping_add(rel));
        if let Some(b) = select(m, &ops, &prefixes, &deco, ip, bitness) {
            set(&mut ops, ip.wrapping_add(b.len() as u64).wrapping_add(rel));
            best = select(m, &ops, &prefixes, &deco, ip, bitness);
        }
    } else {
        best = select(m, &ops, &prefixes, &deco, ip, bitness);
    }
    // iced's Intel formatter shows implicit st0 ("fld st,dword ptr [x]"); accept that form.
    if best.is_none() && ops.len() > 1 {
        let st0 = |o: &Operand| matches!(o.op, Opnd::Reg(Register::ST0));
        if st0(&ops[0]) {
            best = select(m, &ops[1..], &prefixes, &deco, ip, bitness);
        } else if st0(&ops[ops.len() - 1]) {
            best = select(m, &ops[..ops.len() - 1], &prefixes, &deco, ip, bitness);
        }
    }
    if let Some(b) = best {
        return Ok(b);
    }
    // 64-bit jmp/call to a target beyond rel32: indirect through an inline qword.
    if bitness == 64
        && ops.len() == 1
        && !ops[0].short
        && let Opnd::Imm(target) = ops[0].op
    {
        let mut b = match m {
            Mnemonic::Jmp => vec![0xFF, 0x25, 0, 0, 0, 0],
            Mnemonic::Call => vec![0xFF, 0x15, 2, 0, 0, 0, 0xEB, 0x08],
            _ => Vec::new(),
        };
        if !b.is_empty() {
            b.extend_from_slice(&target.to_le_bytes());
            return Ok(b);
        }
    }
    Err(Error::Parse(format!("cannot assemble '{}'", text.trim())))
}

/// `jmp far 401000,10` (iced's form) or `jmp 0010:00401000` (CE's form): ptr16:16/32.
fn far_direct(
    m: Mnemonic,
    args: &str,
    ip: Addr,
    bitness: u32,
    ctx: &Ctx,
) -> Result<Option<Vec<u8>>> {
    let a = args.trim();
    let a = match a.get(..4) {
        Some(w) if w.eq_ignore_ascii_case("far ") => a[4..].trim(),
        _ => a,
    };
    if a.contains('[') {
        return Ok(None);
    }
    let parts = split_top(a, ',');
    let (sel, off) = match (parts.as_slice(), a.split_once(':')) {
        ([off, sel], _) => (sel.as_str(), off.as_str()),
        ([_], Some((sel, off))) if parse_reg(sel.trim()).is_none() => (sel, off),
        _ => return Ok(None),
    };
    if bitness == 64 {
        return Err(Error::Parse(
            "direct far jmp/call does not exist in 64-bit code".into(),
        ));
    }
    let (sel, off) = (eval(sel, ctx)?, eval(off, ctx)?);
    let code = match (m, bitness) {
        (Mnemonic::Jmp, 32) => Code::Jmp_ptr1632,
        (Mnemonic::Jmp, _) => Code::Jmp_ptr1616,
        (_, 32) => Code::Call_ptr1632,
        _ => Code::Call_ptr1616,
    };
    let limit = if bitness == 32 {
        u32::MAX as u64
    } else {
        0xFFFF
    };
    if sel > 0xFFFF || off > limit {
        return Err(Error::Parse(format!(
            "far pointer {sel:X}:{off:X} out of range"
        )));
    }
    let ins = Instruction::with_far_branch(code, sel as u16, off as u32)
        .map_err(|e| Error::Parse(e.to_string()))?;
    encode(&ins, ip, bitness)
        .map(Some)
        .ok_or_else(|| Error::Parse(format!("cannot encode far {sel:X}:{off:X}")))
}

pub(crate) fn bitness(p: &dyn Process) -> u32 {
    if p.pointer_size() == 4 { 32 } else { 64 }
}

/// Assembles `text` (one instruction per line) at `addr` for the target's bitness. Symbols:
/// registered symbols and module names.
pub fn assemble(p: &dyn Process, syms: &SymbolTable, addr: Addr, text: &str) -> Result<Vec<u8>> {
    let mods = p.modules().unwrap_or_default();
    let lookup = |n: &str| std_lookup(p, syms, &mods, n);
    let mut out = Vec::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        out.extend(assemble_line(
            line,
            addr.wrapping_add(out.len() as u64),
            bitness(p),
            &lookup,
        )?);
    }
    Ok(out)
}
