# HeapHook contract

HeapHook is an open-source memory scanner / debugger for Linux and Windows, aiming at
feature parity with Cheat Engine. Clean-room: never copy Cheat Engine source code.

## Layout and ownership

| Path | What | Depends on |
|------|------|-----------|
| `crates/hh-core` | Contract types + traits (`lib.rs`), OS backends (`platform/`) | – |
| `crates/hh-scan` | Value types, scanner, result storage, freezer | hh-core |
| `crates/hh-asm` | Disassembler, assembler, symbols, auto-assembler scripts | hh-core |
| `crates/hh-target` | Test target binary with known values | – |
| `crates/hh-debug` | Debugger: breakpoints, watchpoints, stepping, tracing | hh-core |
| `crates/hh-ptr` | Pointer scanner, pointer maps, rescan | hh-core |
| `app/ui` | Frontend: static HTML/CSS/ES modules, no bundler | IPC below |
| `app/src-tauri` | Tauri 2 shell exposing the IPC commands (later wave) | all crates |
| `docs/PARITY.md` | Cheat Engine feature matrix and status | – |

Rules for every agent:

- Touch only the paths your brief gives you. `crates/hh-core/src/lib.rs` and the root
  `Cargo.toml` are read-only; if you need a change there, say so in your report.
- Other agents edit sibling crates at the same time. Build with `-p <your-crate>`. If a
  sibling crate fails to compile for reasons outside your files, wait a minute and retry.
- Everything must compile for `x86_64-unknown-linux-gnu` and `x86_64-pc-windows-msvc`
  (`cargo check -p <crate> --target x86_64-pc-windows-msvc`; no mingw/C cross compiler is
  installed, so no C dependencies).
- Few dependencies, no speculative abstractions, tests for every non-trivial piece.
  Library crates never print or panic on bad input; they return `hh_core::Result`.
- Do not commit to git.

## IPC (frontend <-> backend)

Tauri commands, snake_case, all async, errors are strings. Top-level argument names are the
Rust parameter names camelCased by Tauri (`pass_signal` -> `passSignal`); fields inside a struct
argument keep their serde names. **Addresses are hex strings**
(`"0x7ffd12340000"`) because JS numbers lose precision above 2^53. Values travel as strings
formatted/parsed by the backend.

Value types (`vtype`): `binary byte 2bytes 4bytes 8bytes float double string aob all grouped`.
Display flags on an entry: `signed`, `hex`. Strings carry `len` and `utf16`.

Scan types (`scan_type`): `exact bigger smaller between unknown increased increased_by
decreased decreased_by changed unchanged same_as_first`, plus `not: bool` to invert.

| Command | Args | Returns |
|---------|------|---------|
| `list_processes` | – | `[{pid, name, exe}]` |
| `open_process` | `pid` | `{pid, name, is_64bit}` |
| `regions` | – | `[{start, size, prot:{r,w,x}, kind, path}]` |
| `modules` | – | `[{name, path, base, size}]` |
| `read_memory` | `addr, len` | hex string, `??` for unreadable bytes |
| `write_bytes` | `addr, hex` | – |
| `read_values` | `[{addr, vtype, len?, utf16?, signed?, hex?}]` | `[string or null]` |
| `write_value` | `addr, vtype, value` | – |
| `resolve_address` | `expr` (`"game.exe+1A2B"`, `"[[base+10]+8]"`, symbol) | addr |
| `scan_first` | `{vtype, scan_type, value, value2, not, opts}` | `{count}` |
| `scan_next` | `{scan_type, value, value2, not}` | `{count}` |
| `scan_undo` / `scan_new` / `scan_cancel` | – | – |
| `scan_progress` | – | `{done, total, found, running}` |
| `scan_results` | `offset, limit` | `[{addr, value, previous, first}]` |
| `set_frozen` | `[{addr, vtype, value, mode}]` (replaces the whole set; mode `exact`/`allow_increase`/`allow_decrease`) | – |
| `disassemble` | `addr, count` | `[{addr, bytes, text, comment}]` |
| `assemble` | `addr, text` | hex bytes |
| `aa_check` | `script` | `null` or `{line, message}` |
| `aa_execute` | `script, enable, state?` | `state` (opaque, pass back to disable) |
| `table_load` | `path` | table JSON (below); reads HeapHook JSON and Cheat Engine `.CT` XML |
| `table_save` | `path, table` | – |
| `write_value` (flags) | also `len?, utf16?, signed?, hex?` (the entry's flags; `set_frozen` entries take the same) | – |
| `pick_path` | `save, title, filters: [[name, [ext]]], default?` | path or `null` (native dialog) |
| `debug_attach` / `debug_detach` | – | status / – (while attached all memory access goes through the debugger) |
| `debug_status` | – | `{attached, state: detached/running/broken/suspended/exited, tid, reason, rip, exit_code}` |
| `debug_add_breakpoint` | `req: {addr, kind: execute/write/access, size, method: software/hardware, action: break/record/trace, steps, step_over_calls, ea}` | `id` |
| `debug_remove_breakpoint` / `debug_set_enabled` | `id` / `id, enabled` | – |
| `debug_breakpoints` | – | `[{id, addr, kind, size, method, action, ea, enabled, hits, slot}]` |
| `debug_records` / `debug_clear_records` | `id` | `[{addr, ip, bytes, text, count, address, context}]` / – (`addr` = accessing instruction) |
| `debug_trace` | `id` | `[{addr, text, context}]` |
| `debug_threads` / `debug_suspend_thread` | – / `tid, suspend` | `[{tid, suspended}]` / – |
| `debug_context` | `tid` | registers, hex strings; `fpu: {fcw, fsw, mxcsr, st: [{hex, value}], xmm: [hex]}` |
| `debug_set_register` | `tid, name, value` (hex; `rax`…`r15, rip, rflags, fs_base, gs_base`) | – |
| `debug_stack` | `tid, count` | `[{addr, value, comment}]` |
| `debug_continue` / `debug_pause` / `debug_step` / `debug_run_to` | `passSignal` / – / `tid, kind: into/over/out` / `addr` | – |
| `nop_instruction` | `addr` | original bytes (hex) |
| `ptr_scan` | `req: {target, opts: hh-ptr ScanOptions, base_start, base_end, alignment, writable_only, map_path, compare: [{path, target}]}` | `{count, max_level, target}` |
| `ptr_rescan` | `req: {target, value, vtype, fmt, base_start, base_end, starts_with, ends_with, max_level, map_path}` | `{count, max_level, target}` |
| `ptr_progress` / `ptr_cancel` | – | `{running, phase: collect/scan/rescan, done, total, found}` / – |
| `ptr_results` | `offset, limit, vtype, fmt?` | `[{base, offsets: [hex], text, address, value}]` |
| `ptr_entry` | `index, vtype, description` | cheat-table entry |
| `ptr_save_map` / `ptr_save_results` / `ptr_open_results` | `path` | – / – / `{count, max_level, target}` |
| `table_get` | – | `{version, table}`; the backend owns the live table (Lua and hotkeys change it too) |
| `table_put` | `table, base` (version the edit is based on) | new version; rejects `stale table version …` (refetch, replay the edit); never changes activation |
| `table_open` / `table_export` | `path` (`.json` or `.CT`), `force?` | `{version, table}` (all inactive; the Lua script is NOT run; the current table's active scripts are disabled first, and if one cannot be the open is refused with `… could not be disabled …` unless `force`, which carries those entries over, still active, into a group) / – |
| `table_trust` | `trust` | – (answer to a `needs consent: …` error from `table_set_active`: a table opened from a file runs no `{$lua}` until the user agrees, here or by running its table script; Settings `table_script: never` refuses instead of asking) |
| `aa_check` (no execution) | | never runs `{$lua}` blocks (they count as empty text while checking) |
| table limits | | groups nest at most 64 deep, at most 200000 entries, table files at most 64 MiB; `table_open`/`table_put` refuse more |
| `close_process` (scripts) | | while the process lives, active scripts are disabled first (failures go to the Lua log, the close goes on); the app does the same on exit |
| `table_set_active` | `ids, active` | – (CE activation: OnActivate/OnDeactivate, Auto Assembler with `{$lua}`, freeze, group options) |
| `table_set_value` | `ids, value` | – (frozen entries freeze to the new value; groups with `moRecursiveSetValue` set children) |
| `table_hotkey` | `id, index` | – (runs that entry hotkey's CE action) |
| `table_run_script` | – | – (runs `table.lua_script`; only after the user agreed) |
| `hotkey_press` | `keys: [vk]` (CE virtual-key codes, any order) | number of hotkeys fired (table and `createHotkey`) |
| `lua_exec` | `code` | – (echo, prints, results and errors with traceback go to the log) |
| `lua_interrupt` | – | – (also answers an open script dialog with cancel) |
| `lua_poll` | `since` | `{log: [{seq, kind: in/out/result/err/info, text}], next, dialog: {id, kind: message/dialog/input, title, text, dlg_type, buttons, initial} or null, table_version, hotkeys: [[vk]], busy, sound, process: {pid, name, is_64bit, alive} or null}` (`process`: the opened process; the UI closes it when `alive` turns false and picks it up after a reload) |
| `lua_dialog_reply` | `id, value` (`mb*` button for `dialog`, string for `input`, null = cancel) | – |
| `settings_get` / `settings_set` | – / `settings` | `{freeze_interval_ms, live_update_ms, fast_scan, scan_alignment, scan_writable, scan_executable, scan_copy_on_write, lua_budget_ms, table_script: ask/never, bp_method, hotkey_sound, theme: system/light/dark, scan_threads, signals}` (stored in the platform config dir) |
| `close_process` | – | – (detaches the debugger, stops scans/freezer, scripts marked off; patches stay) |
| `process_create` | `req: {program, args (shell-like string), cwd, speedhack}` | `{pid, name, is_64bit}` (launched via hh-inject and opened) |
| `speed_get` / `speed_set` | – / `speed` (0 < x <= 1000) | `{pid, addr, speed, generation}` or `null` / same (Lua `speedhack_setSpeed` uses it too) |
| `table_undo` / `table_redo` | – | `{version, table}` (backend history of user edits; active scripts a step removes are disabled first) |
| `table_put` (delete) | | active script entries the put removes run their `[DISABLE]` first; refused if that fails |
| `tools_progress` / `tools_cancel` | – | `{running, job: dissect/spider/snapshot/diff/pointers/save, done, total, found}` / – |
| `struct_get` / `struct_set` | – / `structs: [{name, elements: [{offset, description, vtype: byte/2bytes/4bytes/8bytes/float/double/string/aob/pointer/struct, size, hex, signed, utf16, child?}]}]` | structures (saved with the table: JSON `structures`, `.CT` `<Structures>`) / – |
| `struct_guess` | `name, addr` (expression), `size` | structure (added or replaced) |
| `struct_eval` | `reqs: [{name, addr}]` | `[{Ok: [{offset, addr, description, vtype, size, value, target, child, owner, index, children}]} or {Err: text}]` |
| `struct_expand` | `owner, index, fieldAddr, size` | `{name, addr}` (child auto-guessed and linked when missing) |
| `struct_entries` | `name, root` (expression), `path: [pointer-field offsets]`, `only: [element index]?` | cheat-table entries |
| `struct_spider` | `groups: [[addr]], opts: {size, max_depth, width, max_results}` | `[{path: [offset], values: [[hex bytes]]}]` |
| `dissect_run` / `dissect_summary` | `modules: [name]` (empty = all), `opts: {recursive, min_string, max_string, min_cave}` / – | `{modules, code_bytes, instructions, functions, refs, strings, caves}` / same or `null` |
| `dissect_list` | `kind: functions/called/strings/caves, filter, offset, limit` | `{total, rows}` (`{addr, callers, internal, name}` / `{addr, text, utf16, refs}` / `{addr, len, byte}`) |
| `dissect_xrefs` | `addr, len, offset, limit` | `{total, rows: [{from, to, kind: call/jump/cond_jump/data, text, func}]}` |
| `disassemble` (xrefs) | | rows also carry `xrefs: {calls, jumps, data}` when a dissection knows the address |
| `regions_info` | – | `[{start, size, prot, prot_text, kind, shared, path, module, tag: image/heap/stack/mapped/private/special}]` |
| `mem_protect` | `addr, size, prot: {r, w, x}` | old prot |
| `mem_save` / `mem_load` | `ranges: [{start, size}], path` / `path, relocate?` | `{blocks, bytes}` / `{blocks, bytes, failed: [addr]}` (`.hhmem`) |
| `mem_fill` / `mem_copy` | `addr, len, pattern` (hex) / `src, dst, len` | – |
| `snapshot_take` / `snapshot_list` / `snapshot_delete` | `ranges` (empty = writable memory), `label` / – / `id` | `{id, label, blocks, bytes}` / list / – |
| `snapshot_diff` | `id, max` | `[{addr, len, old, new}]` (hex bytes; `new` empty = unreadable now) |
| `find_pointers` | `query: {target, max_offset, static_only, writable_only, max_results}` | `[{addr, value, offset, module}]` |
| `module_header` | `name` | `{format: elf/pe, is_64, machine, kind, entry, image_base, sections: [{name, addr, size, prot}], imports, import_libs, exports, source}` |
| `aob_signature` | `addr` | `{pattern, addr, module, module_offset, unique, matches, found: [addr]}` |
| `aa_template` | `addr, kind: aob/code/full` | Auto Assembler script |
| `code_list` | – | `[{description, address, bytes, before, after, addr, state: original/nopped/changed/unreadable, current}]` (hh-tools CodeList over `table.codes`) |
| `code_add` / `code_remove` / `code_nop` / `code_restore` | `addr, description` / `index` / `index` / `index, force` | index / – (NOP verifies the original bytes first) |
| `debug_add_breakpoint` (condition) | `req.condition`: `rax==5 && rcx>0x100` (registers, numbers, `+ - * & \| ^`, comparisons, `! && \|\|`, parens) | rows of `debug_breakpoints` carry `condition` |
| `debug_set_condition` | `id, condition` (empty clears) | – |
| `debug_signals` | – | `[[signal, name, default action]]`; `settings.signals` maps signal -> pass/ignore/break |
| `ptr_sort` | `key: base/offset/value, column, desc, vtype, fmt?` | `{count, max_level, target}`; `ptr_results`/`ptr_entry` follow the order |

`scan_first.opts`: `{start, stop, writable, executable, copy_on_write` (each `yes`/`no`/`any`)`,
alignment, hex, case_sensitive, utf16, rounding` (`rounded`/`extreme`/`truncated`)`,
percent, pause_while_scanning}`.

Cheat table entry: `{id, description, addr` (expression)`, offsets: [hex], vtype, len, utf16,
signed, hex, frozen` (= active)`, freeze_mode, color, dropdown: {options: [{value, text}], read_only,
description_only, display_value_as_item}, hotkeys: [{action` (CE name, e.g. `Toggle Activation`,
`Set Value`, `Increase Value`)`, keys: [vk], value, description}], script` (auto-assembler text,
makes it a script entry)`, options: [CE group option names], ct_extra: [raw .CT XML], children: []}`.
Table: `{entries, lua_script, comments, codes: [{description, address, bytes, before, after}],
ct_extra: [raw .CT XML of unknown <CheatTable> children]}`.

## Development bridge (not shipped)

`cargo run -p heaphook --features dev-bridge -- --dev-bridge <port>` runs the backend without a
window and serves `app/ui` plus every command on `http://127.0.0.1:<port>`, guarded by a random
token printed at startup (open the printed URL; it carries `?hh_token=`). `POST /invoke/<cmd>`
with header `x-hh-token` and the Tauri-style args object as the body answers `{"ok": value}` or
`{"err": "text"}`. `main.rs` builds the Tauri commands and the bridge dispatch from one table, so
names and argument decoding are the same. No native dialogs (`pick_path` errors; the UI asks for
a path in a prompt like the mock) and no global hotkeys (in-app hotkeys still work).
