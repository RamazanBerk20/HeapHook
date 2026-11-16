//! HeapHook code tools: disassembler, assembler, address expressions and the Cheat Engine
//! compatible Auto Assembler, built on iced-x86.
mod aa;
mod analysis;
mod asm;
mod disasm;
mod expr;
mod symbols;

pub use aa::{
    AaAlloc, AaError, AaHooks, AaState, Patch, Template, aa_check, aa_execute, aob_scan,
    injection_template, nop_instruction, restore_patch, write_code,
};
pub use analysis::{
    FlowKind, InsnInfo, MemAccess, Registers, analyze_instruction, instruction_before,
    memory_accesses,
};
pub use asm::{assemble, assemble_line};
pub use disasm::{DisasmLine, disassemble, previous_instruction};
pub use expr::{Ctx, SymbolTable, eval, module_offset, parse_num, resolve_address};
pub use symbols::{Symbol, module_symbols, parse_symbols, symbol_at};
