HeapHook 1.0.0-rc.2 is the second release candidate of an open-source memory scanner and debugger in the spirit of Cheat Engine.

## Changes since 1.0.0-rc.1

- Windows: closing a Lua interpreter no longer waits for a program a script started with `io.popen`.
- Windows: shutting down `hh-server` now ends client connections, so a target a client had suspended is resumed.
- The README states the Windows test coverage accurately.
- Tests that assumed Unix-only behaviour are gated, and one test that read uninitialised padding is fixed. CI passes on Linux and Windows.

## Status

- **Linux is the tested platform.** The test suite runs against real processes there.
- **Windows builds are compiled in CI and had not been run on Windows when this was published.** Treat the Windows files as untested and please report what breaks.
- About 60% of Cheat Engine's features are covered; see `docs/PARITY.md` for the full list and `README.md` for what is not included and why.

## Files

| File | What it is |
|---|---|
| `heaphook-*-linux-x86_64.deb` / `.rpm` | Linux packages (need GTK 3 and WebKitGTK 4.1) |
| `heaphook-*-linux-x86_64.AppImage` | Linux, runs without installing |
| `heaphook-*-linux-x86_64.tar.gz` | Linux, plain executable plus the speedhack library |
| `heaphook-*-windows-x86_64-setup.exe` | Windows installer (untested) |
| `heaphook-*-windows-x86_64.exe` | Windows, plain executable (untested; needs the WebView2 runtime) |
| `hh-server-*` | Optional server for scanning processes on another machine |
| `SHA256SUMS-*.txt` | Checksums |

Linux packages carry the version `1.0.0+rc.2`: uninstall a release-candidate package before installing a later final release.

## Before you use it

- On Linux, attaching to a process you did not start from HeapHook needs the ptrace capability or a relaxed `ptrace_scope`; the README explains the options. Launching the program from HeapHook's Create process dialog needs neither.
- Cheat tables can carry Lua with full access to your files. HeapHook asks before any table Lua runs. Open tables only from sources you trust, and read the README's "Safety of cheat tables" section.
- Use it on single-player games and software you are permitted to modify, not to cheat in online multiplayer games.

Full list of changes: `CHANGELOG.md`.
