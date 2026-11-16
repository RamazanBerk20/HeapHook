# HeapHook

HeapHook is an open-source memory scanner, editor and debugger for Linux and Windows, written in Rust with a Tauri 2 interface. It aims at the everyday feature set of Cheat Engine and is a clean-room implementation that shares no code with it.

## Status

This is release candidate 1.0.0-rc.1. Linux is the tested platform. The Windows build is compiled and unit-tested in CI but had not been run on a Windows machine at the time of writing.

Progress against the Cheat Engine feature list is tracked row by row in [docs/PARITY.md](docs/PARITY.md). Of 712 rows: 303 done, 20 engine only (implemented in a library crate, no UI yet), 64 partial, 292 planned, 33 needing a design decision.

## Features

- Process handling: process list with filter, attach by PID, create process, 32/64-bit detection.
- Memory scanning: first/next/undo scans for the numeric, string and byte-array types, with the usual comparison modes, frozen values.
- Address list and cheat tables: groups, pointer entries, hotkeys, load and save of HeapHook JSON and Cheat Engine .CT files.
- Memory viewer: hex view with editing, disassembler and assembler (x86/x86-64), symbol and module resolution.
- Auto Assembler scripts: check, enable and disable.
- Debugger: software and hardware breakpoints, watchpoints, stepping, tracing, thread and register views.
- Pointer scanner: pointer maps, scan and rescan.
- Structure dissector.
- Code tools: find what accesses or writes an address, and related helpers.
- Lua scripting: partially implemented (see PARITY.md).
- Remote targets through the `hh-server` helper (see below).

## Not included

- Library injection into running processes. Speedhack therefore works only for programs launched from HeapHook on Linux (through `LD_PRELOAD`). Mono/.NET tools and graphics overlays are absent because they depend on injection.
- Kernel-mode and hypervisor features.
- Trainer generator.
- Compatibility with Cheat Engine's ceserver protocol. `hh-server` uses its own protocol.

## Build and run

Prerequisites:

- Rust (stable, edition 2024), and the Tauri 2 system libraries.
- Arch: `sudo pacman -S webkit2gtk-4.1 gtk3 libayatana-appindicator librsvg libsoup3 base-devel`
- Debian family: `sudo apt install libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev libsoup-3.0-dev build-essential`

Run from a checkout:

    cargo run -p heaphook

Build the speedhack library (Linux), needed for launching with speedhack:

    cargo build --release --manifest-path crates/hh-inject/payload/Cargo.toml

HeapHook looks for `libhh_speedhack.so` next to its executable, then in `$HH_SPEEDHACK_LIB`, then in the payload build output above. If you move the executable elsewhere, copy the library beside it or set `HH_SPEEDHACK_LIB`.

Release bundles (needs `cargo install tauri-cli --version "^2" --locked`, plus `patchelf` and `rpm` on Linux):

    cd app/src-tauri && cargo tauri build

## Permissions on Linux

With `kernel.yama.ptrace_scope=1`, a process may only trace its own children, so attaching to an unrelated process fails. Two options:

- Give the executable the ptrace capability: `sudo setcap cap_sys_ptrace+ep <path-to-heaphook>`.
- Launch the target from HeapHook's Create process dialog, which makes it a child.

Granting the capability lets the application read and write the memory of any process of your user, so apply it only to a binary you trust.

## Remote targets

`hh-server` serves the processes of a machine to a HeapHook client:

    hh-server [--listen ADDR:PORT] [--allow-remote] [--token TOKEN] [--read-only]

- `--listen` defaults to `127.0.0.1:52736`. Anything other than a loopback address requires `--allow-remote`.
- The token is a shared secret. It is taken from `--token`, else from `$HH_SERVER_TOKEN`, else a random one is generated and printed. Prefer the environment variable, since command lines are visible to other users.
- `--read-only` rejects write, alloc, free, protect, suspend and resume.

Authentication is challenge-response, but traffic is unencrypted after the handshake. Use an SSH tunnel (`ssh -L 52736:127.0.0.1:52736 host`) or a trusted network.

## Cheat tables

Tables are saved as HeapHook JSON and can load and save Cheat Engine `.CT` files. Lua scripts inside a table never run without your confirmation.

## Responsible use

Use HeapHook on single-player games and on software you own or are permitted to modify. Do not use it to cheat in online multiplayer games or against software you are not permitted to modify.

## License

Licensed under [Apache-2.0](LICENSE).
