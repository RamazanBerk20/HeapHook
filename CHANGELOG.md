# Changelog

## 1.0.0-rc.1 - 2026-11-15

First release candidate.

- hh-core: process, memory and region abstractions with Linux and Windows backends.
- hh-scan: first/next/undo scanner for numeric, string and byte-array values, result storage, value freezer.
- hh-asm: x86/x86-64 disassembler and assembler, symbol resolution, Auto Assembler scripts.
- hh-debug: software and hardware breakpoints, watchpoints, stepping, tracing, register and thread access.
- hh-ptr: pointer scanner, pointer maps, rescan.
- hh-lua: Lua scripting engine (partial coverage of Cheat Engine's API).
- hh-tools: code and structure tools.
- hh-inject: speedhack for programs launched from HeapHook on Linux, through an LD_PRELOAD library.
- hh-net: `hh-server` and a client for remote targets, with token authentication and an optional read-only mode.
- App: Tauri 2 desktop interface covering process selection, scanning, address list, memory viewer, debugger, pointer scanner and structure dissector.
- Cheat tables: load and save HeapHook JSON and Cheat Engine .CT files.
- Packaging: deb, rpm, AppImage and NSIS bundles built by the release workflow.
- Not included: injection into running processes, Mono/.NET and graphics hooks, kernel-mode and hypervisor features, trainer generator, ceserver protocol compatibility.
- Windows builds are compiled in CI but untested on Windows.
