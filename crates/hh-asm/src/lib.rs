//! HeapHook code tools: disassembler, assembler, address expressions and the Cheat Engine
//! compatible Auto Assembler, built on iced-x86.
mod aa;
mod analysis;
mod asm;
mod disasm;
mod expr;
mod search;
mod symbols;

pub use aa::{
    AaAlloc, AaError, AaHooks, AaScan, AaState, AobUnique, MAX_ALIGN, MAX_AOB_COUNT,
    MAX_ASSEMBLED_BYTES, MAX_CUSTOM_COMMANDS, MAX_DEFINES, MAX_IF_DEPTH, MAX_INCLUDES,
    MAX_LUA_BLOCKS, MAX_PATTERN_LEN, MAX_READMEM_BYTES, MAX_SCRIPT_BYTES, NOT_AVAILABLE, Patch, Template,
    aa_check, aa_execute, aob_scan, aob_scan_cancellable, injection_template, nop_instruction,
    restore_patch, write_code,
};
pub use analysis::{
    FlowKind, InsnInfo, MemAccess, Registers, analyze_instruction, guess_operand_type,
    instruction_before, memory_accesses,
};
pub use asm::{assemble, assemble_line};
pub use disasm::{
    AddressName, Arch, DisasmLine, DisasmOptions, Syntax, ValueType, disassemble,
    disassemble_with, guess_value_type, previous_instruction,
};
pub use expr::{
    Ctx, MAX_EXPR_DEPTH, SymbolLookup, SymbolTable, eval, module_offset, parse_num,
    resolve_address, resolve_address_with,
};
pub use search::{
    AsmHit, AsmScanPage, MAX_ASM_PATTERN, MAX_ASM_SEQUENCE, MAX_REF_SEARCH, asm_scan,
    find_reference,
};
pub use symbols::{
    MAX_MODULE_FILE, MAX_SYMBOL_PAGE, MAX_SYMBOLS_PER_MODULE, Symbol, SymbolPage, SymbolRow,
    demangle, module_file_reader, module_symbols, parse_symbols, set_module_files_local,
    symbol_at, symbol_list,
};
