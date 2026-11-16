# Changelog

## 1.0.0-rc.1 - 2026-11-16

First release candidate. Linux is the tested platform. The Windows build is compiled and unit-tested in CI but has not been run on Windows.

Process handling

- Process list with filter, attach by PID, Create process, close and detach, 32/64-bit detection, pause and resume of all threads.
- Command-line arguments: a table to open, `--pid`, `--attach NAME`, `--launch PROGRAM ARGS...`, `--help`.
- Help dialog for the Linux ptrace restriction, with the `setcap` command and the Create process alternative.

Scanner

- First, next and undo scans for binary, byte, 2/4/8 bytes, float, double, string (ASCII, UTF-16, three code pages), byte arrays with wildcards, All and grouped.
- Compare modes: exact, bigger, smaller, between, unknown initial value, increased, increased by, decreased, decreased by, changed, unchanged, same as first, with Not and percent.
- Region filters: address range, writable, executable, copy-on-write, region kinds, module include and exclude lists, size limits, alignment.
- Saved scans, compare to first scan, removing results, results per region or module, export and copy of addresses, pointer-value scan.
- Pause, cancel, scan priority and thread count. Large result sets spill to disk (`HEAPHOOK_TMPDIR` or a setting).
- Custom value types with scale, offset, endianness and bit fields, plus Cheat Engine's stock types.

Cheat table

- Address list with groups, group options, pointer paths, hex, signed and binary display, colours, drop-down lists, per-entry freeze interval.
- Freeze modes: exact, allow increase, allow decrease.
- Per-entry hotkeys: toggle, activate, deactivate, set, increase, decrease value.
- Undo and redo, cut, copy and paste, merge, filter, labels and table comments.
- Load and save HeapHook JSON and Cheat Engine `.CT` files, open by drag and drop or recent list, table export as text.
- Unsaved-changes prompt when opening another table or closing the window.

Consent for table Lua

- A table opened from a file asks before any of its Lua runs; entries that were pasted, merged or dropped in ask again per entry.
- Settings can set tables to never run Lua, and can turn off file and program access for Lua.
- Auto Assembler scripts loaded from a file ask before `{$lua}` or `loadbinary` runs.
- Hotkeys with modifiers are registered system-wide only after the table is trusted.

Memory viewer and disassembler

- Hex view with byte and value editing, data inspector, lock, search, bookmarks, second viewer.
- x86 and x86-64 disassembler and assembler, symbols and module resolution, user comments and labels, AT&T syntax display, operand info.
- Search by instruction text or bytes, assembly pattern scan, references to an address, function start and branch targets, symbol list, AOB signatures.

Auto Assembler

- Editor with completion, find and replace, error marking, and a stand-alone Auto Assemble window.
- `[ENABLE]` and `[DISABLE]`, `{$lua}` blocks, AOB scans with a setting for ambiguous matches.
- Generators for AOB injection, code injection, full injection and API hook scripts.

Debugger

- Attach and detach, software (int3) and hardware breakpoints, conditions, hit options, one-shot, pending and thread-specific breakpoints, tracepoints.
- Step into, over and out, run to cursor, run until return, set instruction pointer, signal handling settings, break on thread and module events.
- Find what writes or accesses an address, find what an instruction accesses, break and trace, range watches, code list with NOP and restore.
- Registers including FPU, XMM and YMM, threads, stack, backtrace, debugger log, saved traces.
- Launch a program under the debugger.

Pointer scanner

- Scan with level, offset, base, thread-stack and path filters, saved pointer maps, comparison against other maps, rescan, pause and cancel, saved results.

Structure dissector

- Auto-guess from an address, element editing, nested, pointer and array types, bit fields, RTTI class names, several address columns, lock and highlight changes, spider, import and export, C and C# source output.

Code analysis

- Dissect modules for functions, referenced functions, strings and code caves, with cross references, save and load of dissections.
- Code filter: records which functions ran during an action.

Memory tools

- Fill, copy, allocate, free, protection change, region statistics, find pointers to an address, module headers.
- Snapshots with diff and a page change map.
- Save and load `.hhmem` files with a load plan (nothing is written until blocks are approved), compare with a file, search in files.

Lua

- Console with history, table scripts, timers, forms built from Lua, a coverage of Cheat Engine's Lua API that is partial (see docs/PARITY.md).
- Time and memory limits per run, interrupt with Esc.

Trainer generator

- Generates a Lua form with toggles and hotkeys into the table script. No standalone `.exe`.

Remote targets

- `hh-server` and a client with challenge-response authentication, minimum token length 16, read-only mode, connection and handshake limits.
- Scanner, table, memory viewer, pointer scanner, structures and tools work on a remote target. Debugger, speedhack and Create process are local only.
- Traffic is not encrypted after the handshake.

Speedhack

- Preloaded library for programs started from Create process on Linux, speed up to 1000 with slider, presets and hotkeys.
- The library is refused if another user could replace it.

Settings

- Theme, freeze and update intervals, scan defaults, Lua limits and permissions, breakpoint method, hotkey delay and sound, HeapHook's own hotkeys, debugger signal actions.

Packaging

- deb and rpm bundles (Linux package version `1.0.0+rc.1`), AppImage and NSIS bundles built by the release workflow, `hh-server` built as a separate artifact.
- License: Apache-2.0.

Not included

- Injecting a library into a running process, Mono/.NET and graphics hooks, kernel-mode and hypervisor features, standalone `.exe` trainers, ceserver protocol compatibility, Ultimap and Intel PT, plugins, translations.
