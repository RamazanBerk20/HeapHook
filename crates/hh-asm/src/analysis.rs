//! Instruction analysis for the debugger: control-flow class and branch target (step over /
//! step out), effective addresses of memory accesses, and finding the instruction a data
//! breakpoint trapped after.
use std::collections::HashMap;

use hh_core::{Addr, Error, Process, Result};
use iced_x86::{
    FlowControl, Formatter, Instruction, InstructionInfoFactory, Mnemonic, OpAccess, OpKind,
    Register,
};
use serde::{Deserialize, Serialize};

use crate::disasm::{decode_at, formatter, previous_instruction};

/// Register snapshot: lowercase names as the disassembler prints them (`rax`, `r8`, `rip`,
/// `eflags`, ...). Sub-registers (`eax`, `al`, `ah`) are derived from the full register.
/// Segment bases go in `fs_base` / `gs_base` (`cs/ds/es/ss` default to base 0).
pub type Registers = HashMap<String, u64>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlowKind {
    /// Falls through to the next instruction.
    Normal,
    Call,
    Jump,
    CondJump,
    Ret,
    /// `int`, `syscall`, `sysenter`, ...
    Interrupt,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InsnInfo {
    pub addr: Addr,
    pub len: usize,
    pub text: String,
    pub kind: FlowKind,
    /// Branch target: always for direct branches; for indirect ones and `ret` only when
    /// registers were given and the memory could be read.
    pub target: Option<Addr>,
}

impl InsnInfo {
    /// Address of the next instruction in sequence (where step over stops).
    pub fn next(&self) -> Addr {
        self.addr.wrapping_add(self.len as u64)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemAccess {
    pub addr: Addr,
    pub size: usize,
    pub read: bool,
    pub write: bool,
}

fn decode_valid(p: &dyn Process, addr: Addr) -> Result<Instruction> {
    let (ins, _) = decode_at(p, addr)?;
    if ins.is_invalid() {
        return Err(Error::Parse(format!("no valid instruction at {addr:X}")));
    }
    Ok(ins)
}

/// Value of `r` from the snapshot, `None` if it is missing.
fn reg_value(regs: &Registers, ins: &Instruction, r: Register) -> Option<u64> {
    let name = |r: Register| format!("{r:?}").to_ascii_lowercase();
    match r {
        Register::RIP | Register::EIP => return Some(ins.next_ip()),
        Register::ES | Register::CS | Register::SS | Register::DS => {
            return Some(regs.get(&format!("{}_base", name(r))).copied().unwrap_or(0));
        }
        Register::FS | Register::GS => return regs.get(&format!("{}_base", name(r))).copied(),
        _ => {}
    }
    if let Some(v) = regs.get(&name(r)) {
        return Some(*v);
    }
    let shift = if matches!(r, Register::AH | Register::BH | Register::CH | Register::DH) {
        8
    } else {
        0
    };
    let v = [r.full_register(), r.full_register32()]
        .into_iter()
        .find_map(|f| regs.get(&name(f)))?;
    let bits = r.size() * 8;
    let v = v >> shift;
    Some(if bits >= 64 { v } else { v & ((1 << bits) - 1) })
}

/// Classifies the instruction at `addr`. With `regs`, indirect branch targets and the return
/// address of a `ret` are computed too.
pub fn analyze_instruction(
    p: &dyn Process,
    addr: Addr,
    regs: Option<&Registers>,
) -> Result<InsnInfo> {
    let ins = decode_valid(p, addr)?;
    let kind = match ins.flow_control() {
        FlowControl::Next | FlowControl::Exception | FlowControl::XbeginXabortXend => {
            FlowKind::Normal
        }
        FlowControl::UnconditionalBranch | FlowControl::IndirectBranch => FlowKind::Jump,
        FlowControl::ConditionalBranch => FlowKind::CondJump,
        FlowControl::Return => FlowKind::Ret,
        // iced files syscall/sysenter under calls; they return to the next instruction.
        _ if matches!(ins.mnemonic(), Mnemonic::Syscall | Mnemonic::Sysenter) => {
            FlowKind::Interrupt
        }
        FlowControl::Call | FlowControl::IndirectCall => FlowKind::Call,
        FlowControl::Interrupt => FlowKind::Interrupt,
    };
    let target = match ins.op0_kind() {
        _ if kind == FlowKind::Normal || kind == FlowKind::Interrupt => None,
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
            Some(ins.near_branch_target())
        }
        _ if kind == FlowKind::Ret => {
            regs.and_then(|r| p.read_ptr(reg_value(r, &ins, Register::RSP)?).ok())
        }
        OpKind::Register => regs.and_then(|r| reg_value(r, &ins, ins.op0_register())),
        OpKind::Memory => regs.and_then(|r| {
            let a = ins.virtual_address(0, 0, |reg, _, _| reg_value(r, &ins, reg))?;
            p.read_ptr(a).ok()
        }),
        _ => None, // far branches
    };
    let mut text = String::new();
    formatter().format(&ins, &mut text);
    Ok(InsnInfo {
        addr,
        len: ins.len(),
        text,
        kind,
        target,
    })
}

/// Memory the instruction at `addr` reads or writes with the given registers (explicit
/// operands and implicit ones such as the stack of `push`/`call` or string instructions).
/// Accesses whose address needs a register missing from `regs` are left out; `lea` and
/// `nop [mem]` access nothing.
pub fn memory_accesses(p: &dyn Process, addr: Addr, regs: &Registers) -> Result<Vec<MemAccess>> {
    let ins = decode_valid(p, addr)?;
    let mut f = InstructionInfoFactory::new();
    let info = f.info(&ins);
    let mut out = Vec::new();
    for m in info.used_memory() {
        let (read, write) = match m.access() {
            OpAccess::Read | OpAccess::CondRead => (true, false),
            OpAccess::Write | OpAccess::CondWrite => (false, true),
            OpAccess::ReadWrite | OpAccess::ReadCondWrite => (true, true),
            _ => continue,
        };
        // VSIB (gathers/scatters) needs vector register contents: not supported here.
        if let Some(a) = m.virtual_address(0, |r, _, _| {
            if r.is_xmm() || r.is_ymm() || r.is_zmm() {
                None
            } else {
                reg_value(regs, &ins, r)
            }
        }) {
            out.push(MemAccess {
                addr: a,
                size: m.memory_size().size(),
                read,
                write,
            });
        }
    }
    Ok(out)
}

/// The instruction that ends exactly at `ip`, e.g. the one a data breakpoint (which traps
/// after the access) fired on. Prefers the start that decodes consistently from further back;
/// if that one does not touch memory, a single memory-accessing instruction ending at `ip`
/// wins.
pub fn instruction_before(p: &dyn Process, ip: Addr) -> Result<InsnInfo> {
    let touches_mem = |ins: &Instruction| {
        let mut f = InstructionInfoFactory::new();
        f.info(ins)
            .used_memory()
            .iter()
            .any(|m| m.access() != OpAccess::NoMemAccess)
    };
    let ends_here = |a: Addr| {
        decode_at(p, a)
            .ok()
            .filter(|(i, _)| !i.is_invalid() && i.next_ip() == ip)
            .map(|(i, _)| i)
    };
    let best = previous_instruction(p, ip)
        .ok()
        .filter(|&a| ends_here(a).is_some());
    let chosen = match best {
        Some(a) if ends_here(a).is_some_and(|i| touches_mem(&i)) => Some(a),
        _ => (1..=15u64)
            .filter_map(|back| ip.checked_sub(back))
            .find(|&a| ends_here(a).is_some_and(|i| touches_mem(&i)))
            .or(best),
    };
    let a = chosen.ok_or_else(|| Error::Parse(format!("no instruction ends at {ip:X}")))?;
    analyze_instruction(p, a, None)
}
