# HeapHook

HeapHook is an open-source memory scanner, editor and debugger for Linux and Windows, written in Rust with a Tauri 2 interface. It covers the everyday feature set of Cheat Engine and is a clean-room implementation that shares no code with it.

## Status

This is release candidate 1.0.0-rc.1. Linux is the tested platform. The Windows build is compiled and unit-tested in CI, but the application had not been run on a Windows machine at the time of writing.

Progress against the Cheat Engine feature list is tracked row by row in [docs/PARITY.md](docs/PARITY.md). Of 712 rows: 428 done, 2 engine only (implemented in a library crate, no UI), 68 partial, 181 planned, 33 needing a design decision.

More documentation:

- [docs/USER_GUIDE.md](docs/USER_GUIDE.md): how to do common tasks.
- [docs/TESTING.md](docs/TESTING.md): a hands-on test plan for the release candidate.
- [docs/CONTRACT.md](docs/CONTRACT.md): crate layout and the command interface between the UI and the backend.

## Features

Scanner

- First, next and undo scans for binary, 1/2/4/8-byte integers, float, double, string (ASCII, UTF-16, three code pages), byte arrays with `??` wildcards, "All" and grouped values.
- Compare modes: exact, bigger, smaller, between, unknown initial value, increased, decreased, changed, unchanged, same as first, each with "Not".
- Region filters: address range, writable, executable, copy-on-write, region kind, module include and exclude lists, size limits. Saved scans to compare against.
- Large result sets spill to disk. Scans can be paused and cancelled.

Cheat table

- Address list with groups, pointer paths, freezing (exact, allow increase, allow decrease), per-entry hotkeys, drop-down lists, colours, custom value types.
- Undo and redo of edits, copy and paste between tables, merge.
- Load and save HeapHook JSON and Cheat Engine `.CT` files.

Memory viewer and disassembler

- Hex view with editing, data inspector, bookmarks and a second viewer; x86 and x86-64 disassembler and assembler, symbols, comments and labels.
- Search in memory and in disassembly, assembly pattern scan, references to an address, AOB signatures.

Auto Assembler

- Script editor with checking, `[ENABLE]` and `[DISABLE]`, `{$lua}` blocks, and generators for AOB, code, full and API-hook injection scripts.

Debugger

- Software (int3) and hardware breakpoints with conditions and hit options, stepping, run to cursor, registers (including FPU, XMM and YMM), threads, stack and backtrace.
- Find what writes or accesses an address, break and trace, tracepoints, page-based range watches, a code list with NOP and restore.
- Launch a program under the debugger.

Pointer scanner

- Pointer scan with level, offset and base filters, thread stacks as bases, saved pointer maps, comparison against other maps, and rescan.

Structure dissector

- Auto-guess a layout, edit elements, nested and array types, bit fields, several address columns, lock and highlight changes, spider, export as C or C#.

Code analysis

- Dissect modules for functions, referenced functions, strings and code caves, with cross references; a code filter that narrows down the code behind one action.

Memory tools

- Fill, copy, allocate and free, protection changes, snapshots with diff and change map, save and load `.hhmem` files with a load plan, search inside saved files, module headers, region statistics, find pointers to an address.

Lua

- Console, table scripts and forms built from Lua. Coverage of Cheat Engine's Lua API is partial; see PARITY.md.

Trainer generator

- Builds a Lua form with one toggle per chosen entry and its hotkey into the table script. It runs inside HeapHook.

Remote targets

- `hh-server` serves the processes of one machine to a HeapHook client. Scanner, table, memory viewer, pointer scanner, structures and tools work on a remote target.

Speedhack

- For programs started from HeapHook's Create process dialog on Linux. Set the speed with a slider, presets or hotkeys.

## Not included

- Injecting a library into an already-running process. So: speedhack works only for programs launched from HeapHook on Linux; there are no Mono/.NET tools and no graphics overlays; scripts have no `loadlibrary` or `createthread`.
- Kernel-mode and hypervisor features.
- Standalone `.exe` trainers. The generator makes a Lua trainer that runs inside HeapHook.
- Compatibility with Cheat Engine's ceserver protocol. `hh-server` uses its own protocol.
- Ultimap and Intel PT.
- Plugins.
- Translations. The interface is in English only.

## Build and run

Prerequisites:

- Rust (stable, edition 2024) and the Tauri 2 system libraries.
- Arch: `sudo pacman -S webkit2gtk-4.1 gtk3 libayatana-appindicator librsvg libsoup3 base-devel`
- Debian family: `sudo apt install libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev libsoup-3.0-dev build-essential`

Run from a checkout:

    cargo run -p heaphook

Command-line arguments (all optional):

    heaphook [TABLE] [--pid PID | --attach NAME] [--launch PROGRAM [ARGS...]]

- `TABLE`: a cheat table to open (`.CT` or HeapHook `.json`). It gets the same consent question as File > Open before any of its Lua can run.
- `--pid PID`: open that process.
- `--attach NAME`: open the first running process with that name (exact match first, then ignoring case).
- `--launch PROGRAM ARGS...`: start the program (everything after it is passed as its arguments; an argument may not contain `"`) and open it, like Create process.
- Give only one of `--pid`, `--attach` and `--launch`, and at most one table.
- `-h`, `--help`: print the usage text.

With `cargo run`, put the arguments after `--`: `cargo run -p heaphook -- game.CT --attach game`.

Build the speedhack library (Linux). It is needed to launch a program with the speedhack:

    cargo build --release --manifest-path crates/hh-inject/payload/Cargo.toml

HeapHook looks for `libhh_speedhack.so` in this order: next to its executable, in `<prefix>/lib/HeapHook/` (where the deb and rpm install it), in the file named by `$HH_SPEEDHACK_LIB`, and (debug builds only) in the payload build output above. On Unix it refuses a library that another user could replace: the file and every directory above it must be owned by you or root and not writable by group or others (a sticky directory is accepted).

Build `hh-server`:

    cargo build --release -p hh-net --bin hh-server

Release bundles. Build the speedhack library first (it is packaged as a resource), then install the Tauri CLI once:

    cargo install tauri-cli --version "^2" --locked
    cd app/src-tauri && cargo tauri build --bundles deb,rpm

The packages land in `target/release/bundle/deb/` and `target/release/bundle/rpm/`. The AppImage and the Windows installer are built by CI only (`.github/workflows/release.yml`). CI (`.github/workflows/ci.yml`) runs clippy and the tests on Linux and builds and tests on Windows.

Linux package version: `app/src-tauri/tauri.linux.conf.json` sets the Linux package version to `1.0.0+rc.1` instead of `1.0.0-rc.1`, because the rpm builder rejects a `-` in the version. The cost: dpkg and rpm sort `1.0.0+rc.1` after a final `1.0.0`, so uninstall a release-candidate package before installing the final release. Delete this override when the final 1.0.0 is cut.

## Permissions on Linux

With `kernel.yama.ptrace_scope=1` (the default on most distributions), a process may only trace its own children, so attaching to an unrelated process fails. Two options:

- Launch the target from HeapHook's Create process dialog. It then is a child of HeapHook and no system change is needed.
- Give the executable the ptrace capability: `sudo setcap cap_sys_ptrace=eip <path-to-heaphook>`. Run it again after each update of the binary.

The capability lets the application read and write the memory of any process of your user. Apply it only to a binary you trust and that others cannot replace.

## Safety of cheat tables

A cheat table can carry Lua. Lua in a table has full access to your files and can run programs once it is allowed to run. Treat a table like a program you downloaded.

- HeapHook asks before any Lua of a table runs. The question names what wants to run and shows the start of the script and the hotkeys the table defines.
- Entries pasted or merged into a table, or dropped in from another table, are marked and ask again, per entry, even if the table itself was trusted.
- Until you agree, the Lua of the table refuses to run by every route: clicking, hotkeys, group options, forms and timers. Hotkeys with Ctrl, Shift or Alt are registered system-wide only after you agree.
- Settings > Lua > "Lua script in a loaded table" has a "Never run" choice. With it, tables never run Lua and the question is not shown.
- Settings > Lua > "Allow Lua scripts to access files and run programs" turns off file and program access for Lua. Scripts can still read and change the attached process. It applies after a restart.
- Auto Assembler scripts loaded from a file ask in the same way before their `{$lua}` blocks or `loadbinary` run.

Open tables only from sources you trust.

## Remote targets

`hh-server` is not part of the deb or rpm package. Build it from source (see Build and run) or take it from the release workflow's artifacts, and copy it to the machine whose processes you want to reach.

`hh-server` serves the processes of a machine to a HeapHook client:

    hh-server [--listen ADDR:PORT] [--allow-remote] [--token TOKEN] [--read-only]

- `--listen` defaults to `127.0.0.1:52736`. Any address that is not loopback needs `--allow-remote`.
- The token is a shared secret of at least 16 characters. It comes from `--token`, else from `$HH_SERVER_TOKEN`, else a random one is generated and printed. Prefer the environment variable: command lines are visible to other users.
- `--read-only` rejects write, alloc, free, protect, suspend and resume.
- Limits (fixed, no flags): 16 authenticated connections; 8 connections may be in the handshake at once (when more arrive, the oldest is dropped); a client has 10 seconds to finish the handshake; failed logins are delayed by 0.5 s, server-wide.
- The server exposes the memory of every process the user running it can access.

Authentication is challenge-response, so the token is never sent. Traffic is not encrypted after the handshake. Use a trusted network or an SSH tunnel:

    ssh -L 52736:127.0.0.1:52736 user@host

then connect HeapHook to `127.0.0.1:52736`. The debugger, speedhack and Create process work on local processes only.

## Environment variables

- `HEAPHOOK_HOTKEY_LOG=1`: print on stderr whether each system-wide hotkey was registered and when one fires. For diagnosing a desktop.
- `HEAPHOOK_TMPDIR`: directory for scan result spill files. Settings > "Directory for large scan results" takes precedence. Without either, the system temp directory is used, unless it is RAM-backed (tmpfs); then `/var/tmp` or `~/.cache/heaphook` (`$XDG_CACHE_HOME/heaphook`) is used.
- `HH_SPEEDHACK_LIB`: path of the speedhack library, checked after the executable's directory and `<prefix>/lib/HeapHook/`.
- `HH_SERVER_TOKEN`: the token for `hh-server`.

## Known issues and limits

- Windows is untested: the code builds and passes its unit tests in CI, but nobody has run the application on Windows.
- Global hotkeys are registered with the system, but delivery to HeapHook while another window has focus is unverified under Wayland. Table hotkeys are certain only while HeapHook has focus. On X11 they should work system-wide. A key without Ctrl, Shift, Alt or Win is never taken from other programs.
- Page-range watches slow the target a lot, because every access to the watched pages stops it for a moment. Do not use them on stack memory (HeapHook refuses ranges inside a stack).
- If HeapHook is force-killed while debugging, software breakpoint bytes (int3) stay in the target. Detach from the debugger before closing HeapHook.
- `.CT` import was developed against the documented format and hand-written tables. If a table loads wrong, please report it.
- Custom-type scripts defined at table level in Cheat Engine tables are not preserved on re-export.
- Linux release candidate packages are versioned `1.0.0+rc.1` (see above).

## Responsible use

Use HeapHook on single-player games and on software you own or are permitted to modify. Do not use it to cheat in online multiplayer games or against software you are not permitted to modify.

## License

Licensed under [Apache-2.0](LICENSE).
