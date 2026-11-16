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
| `debug_add_breakpoint` | `req: {addr, kind: execute/write/access, size, method: software/hardware, action: break/record/trace, steps, step_over_calls, ea, skip_hits, one_shot, max_hits}` | `id` (hh-debug's id; hit options: ignore the first `skip_hits` hits, switch off after acting once, switch off at `max_hits`) |
| `debug_remove_breakpoint` / `debug_set_enabled` | `id` / `id, enabled` | – (enable/disable in place: hits, records and trace are kept) |
| `debug_breakpoints` | – | `[{id, addr, kind, size, len, method: software/hardware/page, action, ea, enabled, hits, slot, condition, options: {skip_hits, one_shot, max_hits}, records_dropped, owner: user/script, note}]` (`note`: why the debugger switched it off: exec, one-shot, max hits, code written over it; `owner: script` = set from Lua) |
| `debug_records` / `debug_clear_records` | `id` | `[{addr, ip, bytes, text, count, address, context}]` / – (`addr` = accessing instruction, from hh-debug's `HitRecord.insn`; `address` = accessed address for `ea` breakpoints and range watches) |
| `debug_trace` | `id` | `[{addr, text, context}]` |
| `debug_threads` / `debug_suspend_thread` | – / `tid, suspend` | `[{tid, suspended}]` / – |
| `debug_context` | `tid` | registers, hex strings; `fpu: {fcw, fsw, mxcsr, st: [{hex, value}], xmm: [hex]}` |
| `debug_set_register` | `tid, name, value` (hex; `rax`…`r15, rip, rflags, fs_base, gs_base`) | – |
| `debug_stack` | `tid, count` | `[{addr, value, comment}]` |
| `debug_continue` / `debug_pause` / `debug_step` / `debug_run_to` | `passSignal` / – / `tid, kind: into/over/out` / `addr, tid?` | – (`run_to` with `tid`: only that thread stops at `addr`, others pass it) |
| `nop_instruction` | `addr` | original bytes (hex) |
| `ptr_scan` | `req: {target, opts: hh-ptr ScanOptions, base_start, base_end, alignment, writable_only, map_path, compare: [{path, target}]}` | `{count, max_level, target}` |
| `ptr_rescan` | `req: {target, value, vtype, fmt, base_start, base_end, starts_with, ends_with, max_level, map_path}` | `{count, max_level, target}` |
| `ptr_progress` / `ptr_cancel` | – | `{running, phase: collect/scan/rescan, done, total, found}` / – |
| `ptr_results` | `offset, limit, vtype, fmt?` | `[{base, offsets: [hex], text, address, value}]` |
| `ptr_entry` | `index, vtype, description` | cheat-table entry |
| `ptr_save_map` / `ptr_save_results` / `ptr_open_results` | `path` | – / – / `{count, max_level, target}` |
| `table_get` | – | `{version, table, trust}`; the backend owns the live table (Lua and hotkeys change it too); `trust`: `own` (built in this session), `agreed`, `ask` (opened from a file, or loaded / merged by a script), `declined` |
| `table_put` | `table, base` (version the edit is based on) | new version; rejects `stale table version …` (refetch, replay the edit); never changes activation; keeps an entry's (or the table's) `ct_extra` only when it is exactly what the backend holds for it, drops option names that are not `[A-Za-z0-9_]+` and colours that are not `#RRGGBB` |
| `table_open` / `table_export` | `path` (`.json` or `.CT`), `force?` | `{version, table}` (all inactive; the Lua script is NOT run; the current table's active scripts are disabled first, and if one cannot be the open is refused with `… could not be disabled …` unless `force`, which carries those entries over, still active, into a group) / – |
| `table_trust` | `trust` | – (the only way a loaded table's Lua becomes runnable: its table script and the `{$lua}` of its entries, on every route — click, hotkeys, group options, Lua `memrec.Active`, forms, timers, `aa_execute`, undo/redo. Until then each refuses with `needs consent: <what>: …` (`… you chose not to …` once declined); Settings `table_script: never` refuses instead, and `table_trust(true)` errors then. Entry hotkeys of an untrusted table are not registered system-wide; a hotkey without Ctrl/Shift/Alt/Win never is) |
| `aa_check` (no execution) | | never runs `{$lua}` blocks (they count as empty text while checking) |
| table limits | | groups nest at most 64 deep, at most 200000 entries, table files at most 64 MiB; `table_open`/`table_put` refuse more |
| `close_process` (scripts) | | while the process lives, active scripts are disabled first (failures go to the Lua log, the close goes on); the app does the same on exit |
| `table_set_active` | `ids, active` | – (CE activation: OnActivate/OnDeactivate, Auto Assembler with `{$lua}`, freeze, group options) |
| `table_set_value` | `ids, value` | – (frozen entries freeze to the new value; groups with `moRecursiveSetValue` set children) |
| `table_hotkey` | `id, index` | – (runs that entry hotkey's CE action) |
| `table_run_script` | – | – (runs `table.lua_script`; refused with the consent error unless `trust` is `own` or `agreed`) |
| `hotkey_press` | `keys: [vk]` (CE virtual-key codes, any order) | number of hotkeys fired (table and `createHotkey`) |
| `lua_exec` | `code` | – (echo, prints, results and errors with traceback go to the log) |
| `lua_interrupt` | – | – (also answers an open script dialog with cancel) |
| `lua_poll` | `since` | `{log: [{seq, kind: in/out/result/err/info, text}], next, dialog: {id, kind: message/dialog/input, title, text, dlg_type, buttons, initial} or null, table_version, hotkeys: [[vk]], busy, sound, process: {pid, name, is_64bit, alive} or null, selection: {seq, ids}, ui_seq}` (`busy`: a console run or table script, or anything holding the Lua engine for 300 ms or more — `lua_interrupt` applies; `process`: the opened process — never a network round trip: a remote target's `alive`/`lost` is what a background check found last; the UI closes it when `alive` turns false and picks it up after a reload; `selection.seq` moves when a script sets `SelectedRecords`; `ui_seq` moves on every form change) |
| `ui_poll` | `since` | `{next, changes: [{seq, op: create/update/event/reparent/destroy/call, …}], snapshot: {roots: [control with children]} or null}` (hh-lua `UiChange`s of the forms scripts build; a snapshot instead when `since` is 0 or older than the kept changes; the UI applies both idempotently) |
| `ui_event` | `id, event, args?` | handler results (`OnClick`, `OnClose` (applies the close action), `OnDblClick`, `OnKeyPress`, …; no handler is not an error) |
| `ui_input` | `id, prop, value` | – (the user changed `Text` / `Checked` / `ItemIndex` / `Position` / `Left` / `Top`; stored without echo, fires `OnChange` / `OnClick` like CE) |
| `ui_image` | `path` | `data:` URL of a `TImage` picture file (png, jpg, gif, bmp, webp, svg; at most 8 MiB) |
| `key_state` | `keys: [vk]` | – (keys held in the app window, for Lua `isKeyPressed`; ignored while the table is not trusted; the UI sends none while focus is in a field or a dialog) |
| `table_select` | `ids` | – (the UI's selection, for Lua `SelectedRecord(s)`) |
| `trainer_script` | `req: {title, about, beep, show_keys, entries: [{id, label, keys: [vk]}]}` | Lua trainer block (`-- BEGIN HEAPHOOK TRAINER` … `-- END HEAPHOOK TRAINER`): a form with one toggle per entry and its hotkey (keys the entry already toggles with are shown, not registered twice); the UI puts it into the table script. Runs inside HeapHook; no standalone .exe |
| Lua hosts | | `createProcess` uses `process_create` (and attaches with `debug`); `getCurrentMemscan` is the scanner of the main scan; `loadTable(f)` = `table_open` (Lua state of the old table cleared), `loadTable(f, true)` appends entries with new ids; `saveTable` = `table_export`; `debug_setBreakpoint` & co drive this debugger (breakpoint functions run on the driver thread, the register globals are written back, returning non-zero continues); group options are applied by hh-lua once; record hotkeys fire through `hotkey_press` -> `fire_record_hotkey` (OnHotkey / OnPostHotkey) |
| `lua_dialog_reply` | `id, value` (`mb*` button for `dialog`, string for `input`, null = cancel) | – |
| `settings_get` / `settings_set` | – / `settings` | `{freeze_interval_ms, live_update_ms, fast_scan, scan_alignment, scan_writable, scan_executable, scan_copy_on_write, lua_budget_ms, lua_memory_mb (0 = unlimited), table_script: ask/never, lua_allow_os (files, programs, HeapHook's own memory; read when the engine is built, so it applies after a restart), bp_method, hotkey_sound, theme: system/light/dark, scan_threads, signals}` (stored in the platform config dir) |
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
| `mem_save` | `ranges: [{start, size}], path` | `{blocks, bytes}` (`.hhmem`) |
| `mem_load_plan` / `mem_load_approved` | `path, relocate?` / `path, relocate?, blocks: [plan block]` | `{blocks: [{index, addr, len, mapped, writable}], bytes, unmapped, read_only}` (nothing written) / `{blocks, bytes, failed: [addr]}` (writes only the approved blocks; refuses when the file changed since the plan). There is no unplanned load |
| `mem_fill` / `mem_copy` | `addr, len, pattern` (hex) / `src, dst, len` | – |
| `snapshot_take` / `snapshot_list` / `snapshot_delete` | `ranges` (empty = writable memory), `label` / – / `id` | `{id, label, blocks, bytes}` / list / – |
| `snapshot_diff` | `id, max` | `[{addr, len, old, new}]` (hex bytes; `new` empty = unreadable now) |
| `find_pointers` | `query: {target, max_offset, static_only, writable_only, max_results}` | `[{addr, value, offset, module}]` |
| `module_header` | `name` | `{format: elf/pe, is_64, machine, kind, entry, image_base, sections: [{name, addr, size, prot}], imports, import_libs, exports, source}` (a remote target's from its memory only) |
| `aob_signature` | `addr` | `{pattern, addr, module, module_offset, unique, matches, found: [addr]}` |
| `aa_template` | `addr, kind: aob/code/full` | Auto Assembler script |
| `code_list` | – | `[{description, address, bytes, before, after, addr, state: original/nopped/changed/unreadable, current}]` (hh-tools CodeList over `table.codes`) |
| `code_add` / `code_remove` / `code_nop` / `code_restore` | `addr, description` / `index` / `index` / `index, force` | index / – (NOP verifies the original bytes first) |
| `debug_add_breakpoint` (condition) | `req.condition`: `rax==5 && rcx>0x100` (registers, numbers, `+ - * & \| ^`, comparisons, `! && \|\|`, parens) | rows of `debug_breakpoints` carry `condition` |
| `debug_set_condition` | `id, condition` (empty clears) | – (in place; hits kept) |
| `debug_signals` | – | `[[signal, name, default action, current action or null]]` from hh-debug's `signal_table()` (`current`: the attached debugger's); `settings.signals` maps signal -> pass/ignore/break, codes left out use the default (applying resets every code first) |
| `debug_set_options` | `id, options: {skip_hits, one_shot, max_hits}` | – (in place; hits so far count) |
| `debug_watch_range` | `req: {addr, len, kind: write/access, max_hits?}` | `id` (page-protection watch that records, any length; refused inside a stack: the `[stack]` mapping or the region of a thread's stack pointer) |
| `debug_backtrace` | `tid, max` | `[{addr, module, symbol}]` (frame-pointer walk of a stopped thread) |
| `debug_log` | `since` | `{lines: [{seq, text}], next}` (exec, fork, breakpoints the debugger switched off, exit) |
| `ptr_sort` | `key: base/offset/value, column, desc, vtype, fmt?` | `{count, max_level, target}`; `ptr_results`/`ptr_entry` follow the order |
| `scan_next` (compare) | `req.compare_to`: `"first"` or a saved scan's name | `{count}` (increased/decreased/changed/unchanged/by/percent compare against that scan's value; entries it lacks drop out) |
| `scan_save` / `scan_saved` / `scan_delete_saved` | `name` / – / `name` | – / `[{name, count, kept}]` / – (saved scans live until a new scan or first scan; `first` is reserved; `kept` = rows of it the results' `saved` column can show, at most 200000) |
| `scan_results` (saved) | also `saved?` (a saved scan's name) | rows also carry `saved`: that scan's value at the address, or `null` |
| `scan_results` (rows) | | rows carry `vtype` (per row in "all" scans) and `bit` (binary scans: bit offset in the byte at `addr`) |
| `scan_pause` / `scan_resume` | – | – (`scan_progress` has `paused`; cancel also ends a paused scan) |
| `scan_progress` (spill) | | also `spilled` (result bytes on disk), `spill_dir` (where they go: Settings, `$HEAPHOOK_TMPDIR`, or the default) |
| `scan_first.opts` (more) | `all_types: [vtype]`, `custom: CustomType`, `binary_decimal`, `bit_len`, `bit_start` (0..7), `codepage` (65001/1252/28591), `priority: normal/low/idle` | – |
| custom types | `custom: {size, big_endian, float, signed, scale, offset, bit_start, bit_len, binary}` on `read_values` items, `write_value`, `set_frozen` entries and table entries (`custom` overrides `vtype`) | – |
| `custom_presets` / `custom_validate` | – / `custom` | `[{name, ...CustomType}]` (Cheat Engine's stock types) / `null` or the error |
| `resolve_many` | `exprs: [expr]` | `[addr or null]` |
| `remote_saved` / `remote_forget` | – | `{addr, has_token}` / – (remembered server; the token only when the user asked; `remote.json` in the config dir, mode 0600) |
| `remote_connect` | `addr, token, remember` (`token` empty = the remembered one) | `{addr}` (hh-net challenge-response; traffic is not encrypted after it) |
| `remote_status` / `remote_processes` | – | `{addr, connected}` or `null` / `[{pid, name, exe}]` |
| `remote_open` | `pid` | `{pid, name, is_64bit, remote}` (scanner, table, memory view, pointer scan, structures and tools work through it; debugger and speedhack are local only and refuse with a message; symbols, headers, dissections and structure guesses never read a same-named local file: hh-asm `set_module_files_local(pid, false)` until it is closed) |
| `remote_disconnect` | – | – (closes the remote target first) |
| `open_process` / `lua_poll.process` (remote) | | `remote: addr` on a remote target; `lua_poll.process.lost`: why the connection dropped (`alive` is false then) |
| `code_function` | `addr` | `{start, name, source: dissection/heuristic}` |
| `code_targets` | `addr` | `{start, end, source, rows: [{from, to, kind: call/jump/cond_jump, text, name}]}` (direct branches of the function holding `addr`) |
| `mem_compare` | `path` (`.hhmem`), `max` | `[{addr, len, old, new}]` (file contents against live memory) |
| `struct_export` / `struct_import` | `path, names` (empty = all) / `path` | – / `[name]` (`.json` `{structures}` or `.xml`/`.ct` CE `<Structures>`) |
| `app_info` | – | `{version, license, platform, lua_allow_os}` (`lua_allow_os`: what the running Lua engine allows) |
| settings (more) | | `scan_priority: normal/low/idle`, `scan_spill_dir` (empty = default), `hotkey_delay_ms` (a hotkey cannot fire again sooner) |
| `mem_search` | `req: {start, end?, pattern: "48 8B ?? 05", backward?, limit?}` | `[addr]` (readable memory; forward: matches at >= start ascending, below `end`; backward: matches below start descending, at or above `end`; at most 1000) |
| `disasm_search` | `req: {start, end, text, limit?}` | `[{addr, text}]` (linear decode of `start..end`, at most 64 MiB; instruction text contains `text`, case-insensitive) |
| `mem_alloc` / `mem_free` | `size, prot: {r, w, x}` / `addr, size` | addr / – |
| `process_pause` | `pause` | – (suspends / resumes every thread; refused while the debugger is attached; `close_process` and `debug_attach` resume first; `lua_poll.process.paused`) |
| `trace_save` / `trace_load` | `path, trace` (any JSON) / `path` | – / the saved `trace` (file `{"heaphook_trace": 1, "trace"}`, at most 256 MiB) |
| `table_export_text` | `path` | – (tab-separated listing: description indented by depth, address expression, type, live value) |
| `table_merge` | `path` | `TableState` (entries appended with new ids, inactive; entries that run Lua arrive untrusted; a table script it brings into a table without one makes the table `ask`) |
| `table_paste` | `entries, after?, base?` | `{version, ids}` (new ids after entry `after` in its list, or at the end; every entry that runs Lua arrives untrusted) |
| `table_trust_entries` | `ids` | – (consent for the untrusted entries in those subtrees; refused while Settings say never; "never" withdraws it again) |
| per-entry trust | | `TableState.untrusted: [id]`: entries whose Lua came from another table (paste, merge, `loadTable(f, true)`, a dropped file, or any put / undo that brings a script first seen in an untrusted source). Their Lua refuses on every route with `needs consent: entries: <what>: …` until `table_trust_entries`, whatever the table's own trust; their hotkeys are not registered system-wide before that |
| `table_dirty` | – | bool (the table differs from what was last opened or saved; activation does not count) |
| `table_open_data` | `name, data, force?` | like `table_open` for a file's text (a browser drop; `.CT` by name) |
| `aa_load_file` / `aa_trust` | `path` / `script` | script text / – (`aa_execute` refuses `{$lua}` of a script loaded from a file or an untrusted table until `aa_trust` of that exact text; what the user types runs) |
| `app_args` | – | `{table, pid, attach, launch: {program, args}}` or `null` (command line, handed out once) |
| `app_quit` | `quit` | – (desktop app only: the answer to `lua_poll.window.close_seq`, a close with unsaved changes; closing again while asked closes) |
| `lua_poll.window` | | `{close_seq, drop_seq, drops: [path]}` (window close requests and files dropped on the window) |
| `debug_set_register` (FPU) | | also `st0`..`st7` (decimal), `xmm0`..`xmm15` (32 hex digits, `debug_context` byte order), `mxcsr`, `fcw`, `fsw` |
| `debug_add_breakpoint` (trace) | `req.stop_when` | condition syntax; a trace breaks at the first step where it holds (reason `trace stop, breakpoint <id>`); `debug_breakpoints` rows carry `stop_when` |
| settings (1.0) | | `app_hotkeys: [{keys, action: speed/pause, value}]` (HeapHook's own hotkeys, registered like a table's) |
| table (1.0) | | table `bookmarks: [{address, name}]` (JSON only); entry `show_binary` (`.CT` `<HeapHookShowAsBinary>`) |
| table (more) | | entry `custom` (CustomType) and `custom_name` (CE `<CustomType>` name; a name without a definition is kept as unsupported and written back unchanged); table `custom_types: [{name, ...CustomType}]`, `symbols: [{name, address}]` (CE `<UserdefinedSymbols>`, registered for address expressions while the table is loaded), `disasm_comments: [{address, comment}]` (CE `<DisassemblerComments>`) |

`scan_first.opts`: `{start, stop, writable, executable, copy_on_write` (each `yes`/`no`/`any`)`,
alignment, hex, case_sensitive, utf16, rounding` (`rounded`/`extreme`/`truncated`)`,
percent, pause_while_scanning}`.

Cheat table entry: `{id, description, addr` (expression)`, offsets: [hex], vtype, len, utf16,
signed, hex, frozen` (= active)`, freeze_mode, color, dropdown: {options: [{value, text}], read_only,
description_only, display_value_as_item}, hotkeys: [{action` (CE name, e.g. `Toggle Activation`,
`Set Value`, `Increase Value`)`, keys: [vk], value, description, id?}], script` (auto-assembler text,
makes it a script entry)`, options: [CE group option names], ct_extra: [raw .CT XML], children: []}`.
Table: `{entries, lua_script, comments, codes: [{description, address, bytes, before, after}],
ct_extra: [raw .CT XML of unknown <CheatTable> children]}`. `ct_extra` only ever comes from a `.CT`
import (JSON input never carries it): whole elements HeapHook does not handle, none containing
`LuaScript`, `AssemblerScript`, `CheatEntries`, `Structures`, `CustomType` and the other parts it
handles itself, at most 4 MiB per import; the `.CT` export checks each fragment again.

## Development bridge (not shipped)

`cargo run -p heaphook --features dev-bridge -- --dev-bridge <port>` runs the backend without a
window and serves `app/ui` plus every command on `http://127.0.0.1:<port>`, guarded by a random
token printed at startup (open the printed URL; it carries `?hh_token=`). `POST /invoke/<cmd>`
with header `x-hh-token` and the Tauri-style args object as the body answers `{"ok": value}` or
`{"err": "text"}`. `main.rs` builds the Tauri commands and the bridge dispatch from one table, so
names and argument decoding are the same. No native dialogs (`pick_path` errors; the UI asks for
a path in a prompt like the mock) and no global hotkeys (in-app hotkeys still work).
| `scan_first.opts` (1.0) | `kinds: [Image/Mapped/Private]`, `modules: [name]`, `exclude_modules: [name]`, `ranges: [{start, end}]` (at most 4096), `min_region_size`, `max_region_size`, `simple_values` | – (hh-scan `ScanOptions`; an unknown module name is an error) |
| `scan_sort` | `key: address/value, desc` | – (`scan_results` follow the order until the results change; value sorts refuse more than 5,000,000 results) |
| `scan_remove` | `addrs: [addr]` | removed count (`scan_undo` brings them back) |
| `scan_export_addresses` / `scan_copy_addresses` | `path` / – | count / text (upper-case hex, one per line; copy refuses more than 1,000,000) |
| `scan_stats` | – | `[{start, size, kind, path, module, count}]` (results per region; `size` 0 = no longer mapped) |
| `scan_pointer` | `req: {opts, modules, ranges}` | `{count}` (new scan of pointer-sized values pointing into readable memory, or into those modules / ranges) |
| `scan_results` (saved, 1.0) | | `saved` comes from hh-scan's `saved_values` (every row; `scan_saved.kept` = `count`); `scan_progress.spill_dir` is the directory in use |
| `lua_poll.freeze_failures` | | `[{id, addr, error}]`: frozen entries whose write fails now (the freezer keeps retrying) |
| entry `freeze_interval_ms` | | the entry's own freezer interval (JSON only; 1..60000) |
| custom types (1.0) | | records carry `custom`: Lua `memrec.Value`, hotkey `Set Value` / `Increase Value` / `Decrease Value` and freezing work in converted units (`raw * scale + offset`) |
| `ptr_pause` / `ptr_resume` | – | – (`ptr_progress.paused`; cancel still ends a paused scan) |
| `ptr_scan.opts` (1.0) | `starts_with: [i64]`, `allowed_offsets: [i64]`, `stop_at_static`, `time_limit_secs` | – (local targets: every thread's stack is a `THREADSTACK<n>` base; `PtrInfo.compact` false = a pre-1.0 result file, still read) |
| `mem_file_search` | `req: {path, pattern?, vtype?, value?, fmt?, max?}` | `[addr]` (in a saved `.hhmem`; no process needed; at most `max`, default 1000) |
| `region_stats` | – | `{regions, bytes, by_prot, by_tag, by_kind, by_module: [{key, regions, bytes}]}` |
| `snapshot_change_map` | `old, new` (snapshot ids), `start?, end?` (default the old snapshot's span), `cells` | `{start, cell_size, compared: [pages], changed: [pages]}` |
| `struct_view` | `reqs: [{name, addr}]` | `[{Ok: {fields, changed: [leaf index], locked, class}} or {Err}]` (`changed`: since this column's previous view, or while locked between the locked copy shown and live memory; `class`: C++ class from RTTI) |
| `struct_lock` / `struct_write` | `name, addr, on` / `name, addr, leaf, value` | – (`leaf`: index in the flattened leaf order) |
| `struct_code` | `names, lang: c/csharp, path?` | source text (also written to `path`) |
| `struct_field_entry` | `name, root, path: [element index]` | cheat-table entry (pointer hops become offsets; bit fields carry `custom`) |
| element (1.0) | | `bit_offset`, `bit_len`, `count` (array), `child_start`; `struct_set` validates every definition; `struct_guess` names a structure after its RTTI class when `name` is empty |
| `dissect_add` / `dissect_save` / `dissect_load` | `modules, opts` / `path` / `path` | summary / – / summary (`.hhdis`, validated; a remote target never reads local module files) |
| `code_filter_start` / `code_filter_stop` / `code_filter_state` / `code_filter_reset` | – / `ran` / – / – | `{recording, armed, ran_sets, not_ran_sets, last_hits, matches}` (one-shot int3 on every function entry of the current dissection, nothing else; needs the debugger) |
| `code_filter_list` | `offset, limit` | `{total, rows: [function]}` (in every ran set, in no did-not-run set) |
| `asm_scan` | `req: {start, end?, pattern, max?}` | `{hits: [{addr, text}], next}` (instruction text with `?` / `*`; `;` chains instructions; `tools_cancel` stops it) |
| `find_reference` | `from, target, forward, maxBytes?` | addr or `null` |
| `symbol_list` | `module?, filter, offset, limit` | `{total, rows: [{name, module, addr, size, user}]}` |
| `disassemble` (1.0) | `opts?: {att, typed}` | AT&T text (display only), typed operand comments |
| `aa_template` (1.0) | `kind: api` | API hook template |
| `aa_execute` (1.0) | | returns `scans: [{name, addr, matches}]`; Settings `aob_unique: off/warn/fail`; `loadbinary` reads a file only when the script is trusted (typed, or consented with `aa_trust` / `table_trust`) and Settings allow Lua and scripts to access files (regular files, at most 64 MiB). Table entries run through hh-lua, which has no `loadbinary` host: refused |
| `debug_launch` | `req: {program, args, cwd, stop: entry/first/run}` | `{pid, name, is_64bit}` (started under the debugger and opened, stopped with reason `started: …`; reaped by the app once it exits and is untraced) |
| `debug_set_break_on` / `debug_break_on` | `on: {thread_created, thread_exited, module_loaded: [pattern], module_unloaded: [pattern]}` / – | – / same |
| `debug_add_breakpoint` (1.0) | `req.pending` (expression; armed when it resolves), `thread`, `outside_module`, `log` + `message` (tracepoint: `{rax}`, `{old}`, `{new}`, `{address}` become hex), `value_condition` (write / access: `old`, `new`, `address`, registers), `trace: {skip_modules, stay_start, stay_end, until_return, max_ms, capture_memory}` | `debug_breakpoints` rows carry them plus `resolved`; the debugger log shows tracepoint lines, resolutions and debug-event stops |
| `debug_step` / `debug_run_to` (1.0) | `skipBreakpoints?` / `count?` | – |
| `debug_run_until_return` / `debug_set_ip` | `tid, frame` / `tid, addr` | – |
| `debug_threads` (1.0) | | rows carry `name`, `state`, `user_ms`, `kernel_ms` |
| `debug_context` (1.0) | | `fpu.has_ymm`, `fpu.ymm_hi: [hex]` (upper halves of YMM0..15) |
| `debug_trace` (1.0) | | rows carry `accesses: [{addr, size, read, write, before, after}]` with `capture_memory` |
| `debug_status.reason` (1.0) | | the debug event that stopped it (`thread 12 created`, `module loaded: libz.so.1`, `started: …`) |
| settings (1.0 RC) | | `aob_unique: off/warn/fail` |
