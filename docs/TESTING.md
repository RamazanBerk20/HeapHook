# HeapHook 1.0.0-rc.1: hands-on test plan

For the project owner. Work through it before any release. Each item says what to do and what should happen. Tick the box when it does. Write down anything that does not.

Notes for the run:

- Use a test target you can restart. `crates/hh-target` is a test binary with known values; a game works too (see the last section).
- Keep a terminal open for stderr output of HeapHook.
- Do not tag, push or publish anything until this plan is done.

Environment (fill in):

- Distribution and kernel:
- Desktop (X11 or Wayland, which compositor):
- `kernel.yama.ptrace_scope` value:
- Build tested (commit, deb or rpm or `cargo run`):

## 1. Build and launch

- [ ] `cargo run -p heaphook` from a clean checkout. The window opens, the top bar shows "No process" and the Scanner view.
- [ ] `cargo run -p heaphook -- --help` prints the usage text and exits without opening a window.
- [ ] `cargo run -p heaphook -- --bogus` prints an error with the usage text and exits with a non-zero status.
- [ ] `heaphook --pid <pid of a running program>` opens that process (it may show the permission dialog, see section 2).
- [ ] `heaphook --attach <name>` opens the first process with that name.
- [ ] `heaphook --launch /path/to/program arg1 "arg two"` starts the program and opens it; the arguments arrive as three separate values.
- [ ] `heaphook --pid 1 --attach x` is refused with a message.
- [ ] `heaphook some.CT` opens the table and asks the trust question if it has Lua (see section 5).
- [ ] Close the window with no changes. It closes at once. Reopen: the window has the same size and position as before.
- [ ] Settings (Ctrl ,) opens. Change the theme to dark and back. Close and reopen HeapHook: the theme is kept.
- [ ] F1 opens the shortcut list. The About button shows the version `1.0.0-rc.1` and the license Apache-2.0.

## 2. Permissions

Set `kernel.yama.ptrace_scope` to 1 (`sudo sysctl kernel.yama.ptrace_scope=1`) for this section.

- [ ] Start a program in another terminal. In HeapHook press Ctrl P and open it. A dialog "HeapHook may not trace this process" appears with the `setcap` command and a Create process button.
- [ ] The Copy button puts the command on the clipboard.
- [ ] Press Create process and start a test program from the dialog. It opens without a permission error.
- [ ] Run `sudo setcap cap_sys_ptrace=eip <path to the heaphook binary>` and restart. Now the unrelated process from the first step opens.
- [ ] Remove the capability (`sudo setcap -r <path>`) afterwards, unless you want to keep it.

## 3. Scanner

Use the test target or a program with a number you can change.

- [ ] First scan for a 4-byte exact value. The result count appears and the results list fills.
- [ ] Change the value in the target. Next scan "Exact value" with the new number. The count drops.
- [ ] Repeat with "Increased", "Decreased", "Changed", "Unchanged". The counts follow what the target did.
- [ ] Ctrl Z undoes the last scan; the previous results return. Ctrl N starts over.
- [ ] Unknown initial value: first scan with "Unknown initial value" on a small process, then "Changed" after changing the value. It finishes and finds the address.
- [ ] Float and Double scans find a float value; "Rounded", "Rounded (extreme)" and "Truncated" differ for a value like 1.999.
- [ ] String scan (ASCII, then UTF-16) finds a known text. Array of byte with `??` finds a pattern.
- [ ] Region filters: set Writable to "no" and Executable to "yes": the result set changes. With a start and stop range, no result lies outside it.
- [ ] Pause the scan with the pause button during a large scan, then resume. Cancel with Esc: the scan ends and the results stay as before.
- [ ] Save a scan, make a next scan, set "Next scan compares to" the saved scan. The results list can show a "Diff against" column.
- [ ] Del on selected results removes them; Ctrl Z brings them back.
- [ ] Do a scan with a very large result set (unknown initial value on a large process). The scan finishes without HeapHook using memory beyond what the system has, and the "spill" note shows a directory that is not a RAM-backed tmpfs. With `HEAPHOOK_TMPDIR=/some/dir` set, that directory is used.

## 4. Cheat table

- [ ] Select results, press Enter. They appear in the table.
- [ ] Enter on the Value cell, type a number: the target's value changes.
- [ ] Space on an entry freezes it. Change the value in the target: it is written back. Space again: it stops.
- [ ] Allow increase: the target can raise the value but not lower it. Allow decrease: the reverse.
- [ ] Ctrl Shift A adds an address by hand. Tick "Pointer", add two offsets, and check the preview line shows the resolved address.
- [ ] Ctrl G groups two entries. Collapse and expand with the arrow keys. Delete the group; Ctrl Z restores it.
- [ ] Ctrl H on an entry: set a hotkey with Ctrl and a letter, action "Toggle activation". Press it while HeapHook has focus: the entry toggles.
- [ ] Set a "Set value" hotkey and an "Increase value by" hotkey: they change the value as set.
- [ ] Dropdown list: add `0 = Off`, `1 = On` to an entry. The cell shows the names.
- [ ] Custom type: change an entry's type to a Cheat Engine stock custom type (for example a big-endian 4-byte type). The value reads correctly. Create your own type with a scale of 2 and check the converted value.
- [ ] Save the table as `test.json`, close the process, reopen the process, open the table. All entries come back.
- [ ] Save as `test.CT`. Open it again: entries, groups, hotkeys and dropdowns are kept.
- [ ] Undo and redo (Ctrl Z, Ctrl Y) after editing a description, moving an entry and deleting an entry.
- [ ] Tools menu (Alt T) > "Save the table as text...": the file lists the entries.
- [ ] Ctrl F filters the table by description.
- [ ] Ctrl Alt M switches to compact mode and back.

## 5. Scripts and consent

Prepare a table `consent.json` or `.CT` with: a table Lua script that writes a file `/tmp/hh-consent-ran` (for example `io.open('/tmp/hh-consent-ran','w'):write('x')`), an entry with a hotkey (Ctrl Alt F9) that toggles an Auto Assembler script with `{$lua}` writing the same file, and at least one normal entry. Delete `/tmp/hh-consent-ran` before each run below.

- [ ] Open the table. A "Trust this table?" prompt appears. It names the script size, shows its start, lists the number of Lua entries and the hotkeys, and says the code runs with your user rights. The default button is "Do not trust".
- [ ] Press "Do not trust". Confirm `/tmp/hh-consent-ran` does not exist.
- [ ] Activate the Lua entry with Space: HeapHook asks again; decline again; no file.
- [ ] Press the table's hotkey (Ctrl Alt F9) with HeapHook focused and then with another window focused: no file. With HeapHook focused it may show the consent question again; decline.
- [ ] In the table menu, run the table script (Table script button, then run): it refuses or asks. Decline: no file.
- [ ] Reopen the table and press "Trust and run its script". The file appears.
- [ ] Settings > Lua > "Lua script in a loaded table" > "Never run". Reopen the table: no prompt, a message says the Lua was not run, the file does not appear. Activating the Lua entry also refuses without asking. Set it back to "Always ask".
- [ ] Open a second table that contains Lua entries. In the trusted table, paste or merge one of its Lua entries (copy from the second table, paste into the first; also try "Merge a table into this one"). The pasted entry shows a shield mark. Activate it: a prompt "Trust this entry" appears. Decline: nothing runs. Trust it: it runs.
- [ ] Drop `.CT` file onto the window while the first table is open: entries that carry Lua arrive marked.
- [ ] Trust, then withdraw: open the table, trust it and run its script (the file appears; delete it). The table header reads "Table trusted". Press "Withdraw trust" next to it: the question says Lua restarts and console globals are lost; confirm. The header reads "Table not trusted", the console says "Lua was reset", and the Lua entry and its hotkey no longer run (no file).
- [ ] Paste into a trusted table: paste three Lua entries (one with a hotkey, one with a script over 40 lines) into a trusted table and activate their group. The per-entry question lists all three with "Agreeing covers the 3 entries listed", says each was pasted, shows the hotkey, and "View full script" shows every line numbered. "Do not run" is focused; at 900 px wide the buttons stay visible while the list scrolls. Trust them: they run, and the header counts 3 trusted entries. Select them and use "Withdraw trust from the selected entries..." in the entry menu: they are marked again and ask again.
- [ ] A table script that creates a record: give the table the script `local m = getAddressList().createMemoryRecord() m.Description = 'made' m.Script = '[ENABLE]\n{$lua}\nio.open([[/tmp/hh-consent-ran]],[[w]]):write([[x]])\n{$asm}\n[DISABLE]\n'`, open it and trust it. The console shows a one-line note that what Lua creates from now on depends on this consent. Activate "made": the file appears (delete it). Withdraw the table's trust: Lua restarts and "made" gets a shield. Activating it asks "Run Lua of this entry?", which says it was made by Lua after the table's Lua had run and that after you agree it counts as yours. Agree: it runs.
- [ ] The console note: after a trusted table's script ran, create a record from the console (`getAddressList().createMemoryRecord()`): it depends on the table's consent too (withdraw: it gets a shield). After the restart, a record created from the console is your own (no shield).
- [ ] "Never run" with consent given: trust a table and an entry, then switch Settings to "Never run". The console says Lua was reset because Settings now say never; nothing of the table or the entry runs, and activating them refuses without asking.
- [ ] Drop a table while a question is open: with "Trust this table?" (or the per-entry question) on screen, drop another table file onto the window. The question closes as "no", the new table opens and asks its own question, and answering nothing of the old one runs.
- [ ] Settings > Lua > turn off "Allow Lua scripts to access files and run programs", restart. Run a script that calls `io.open` for writing: it fails. A script that reads memory (`readInteger`) still works.
- [ ] Auto Assembler: Ctrl Alt A, write `[ENABLE]` `{$lua}` `print('hi')` `{$asm}` `[DISABLE]` and press Execute: it runs without asking (typed text). Use "Open file" on a saved script with `{$lua}`: executing asks first.
- [ ] Generate a code injection script from the disassembler context menu, check it (Ctrl K), execute it on a harmless instruction, run [DISABLE]: the original bytes return.
- [ ] A script entry in the table: Space enables it, Space disables it, and the memory change is undone.
- [ ] An `aobscan` that matches twice uses the first match; with Settings "report the count", the status line says so; with "refuse", enabling fails.

## 6. Memory viewer

- [ ] Ctrl M on a table entry shows its memory in the hex view. Ctrl D disassembles there.
- [ ] Ctrl G in the hex view accepts a hex address, `module+offset`, and a table label.
- [ ] Type hex digits over bytes: the memory changes. Ctrl L locks editing; typing then does nothing.
- [ ] Change the display type (4 Bytes, Float): the values redraw. Ctrl I shows the data inspector.
- [ ] Select bytes with Shift and arrows, copy as hex (Ctrl C), paste elsewhere (Ctrl V in the hex view asks for hex or text).
- [ ] Ctrl F searches memory for a byte pattern with `??`; F3 goes to the next match.
- [ ] In the disassembler, select an instruction and press Enter, type `nop`: it assembles. Check the bytes in the hex view.
- [ ] Space follows a call or jump; Backspace goes back. `;` adds a comment and `:` a label; the label works in the Go to field.
- [ ] Ctrl B bookmarks an address, Shift 1 goes to it.
- [ ] Regions and Modules tabs list the memory map; the Regions filter accepts `heap` and `rwx`.
- [ ] Ctrl Shift S: take a snapshot, change something in the target, take a second snapshot, compare: the diff shows the change. The change map highlights the page.
- [ ] Save a region to a `.hhmem` file. Change the memory. Load the file: a plan lists the blocks; nothing changes until you press "Write chosen blocks". After writing, the old bytes are back. Unmapped blocks show as such and are off by default.
- [ ] Fill memory, Copy memory, Allocate memory and Free memory work on a scratch block you allocated.

## 7. Debugger

Use a target that stays alive and whose value you can change.

- [ ] Ctrl Shift D attaches. The top bar shows the debugger state. The target keeps running.
- [ ] On a table entry press F6 (what writes). The Debugger view lists instructions with counts as the target writes. Select one: registers show below. Press F5 (what accesses) on another entry.
- [ ] Press N on a record to replace the instruction with NOPs: the value stops changing. Open the code list: the item shows "nopped". Press Space to restore it.
- [ ] Set an execute breakpoint in the disassembler with F5. When it hits, the state shows "broken" and the disassembler shows the hit. F7, F8 and Shift F8 step; F9 continues.
- [ ] Edit a condition on the breakpoint (E), for example `rax==0`. It breaks only when the condition holds.
- [ ] Switch the breakpoint to hardware with H and back.
- [ ] Break and trace from the disassembler menu: 100 instructions. The trace list fills. Save the trace and open it again.
- [ ] Range watch: watch 16 or more bytes of heap memory for writes. A warning about slowdown is shown. The target slows down but runs. The watch records writes. Stop it. Try it on a stack address: it is refused.
- [ ] Add a tracepoint with a message such as `hit {rax}`: the debugger log shows lines and the target does not stop.
- [ ] Detach with Ctrl Shift D while the target is running and while it is stopped on a breakpoint. The target keeps running, the original bytes are back (check the disassembly at the breakpoint address), and the target does not crash.
- [ ] Close the target program while the debugger is attached: HeapHook shows that the process exited and does not hang.
- [ ] Launch under debugger: Create process with "Debug it, stop at the entry point". The program starts stopped, with reason "started". Set a breakpoint, press F9: the program runs and stops at the breakpoint. Repeat with "stop before the first instruction" and "do not stop". Detach: the program keeps running.
- [ ] Break on events (B in the breakpoint list): break when a module loads, matching a library name. Run a program that loads it: the debugger stops with the reason.
- [ ] Settings > Debugger signals: set one signal to "break", send it with `kill -<signal> <pid>`: the debugger stops and asks. Set it back.
- [ ] Pause the process (Ctrl Alt P): the target freezes and a "paused" badge shows. Resume with Ctrl Alt P.

## 8. Pointer scan across a restart

- [ ] In a program whose value lives behind pointers (a game works best), find the value's address with the scanner and add it to the table.
- [ ] Pointer scan for that address: level 4 or 5, static bases only. Results appear. Save the results and also save a pointer map.
- [ ] Restart the target (through Create process, or any way you can). Find the new address of the same value with the scanner.
- [ ] Rescan: set "Must point to address" to the new address. The list shrinks to paths that still hold.
- [ ] Alternatively do a new scan with "Compare with saved pointer maps" using the map from the first run.
- [ ] Add one remaining path to the table with Enter. Restart once more: the entry still shows the right value.
- [ ] Pause a running pointer scan with P and resume; cancel with Esc.
- [ ] Open the saved results file: the paths load.

## 9. Structures

- [ ] Press G in the Structures view and dissect a known object (a struct in the test target, or a game object). A layout is guessed with plausible types.
- [ ] Edit a value with Enter: the target changes. Change a type with T and a description with F2.
- [ ] Expand a pointer field with the Right arrow: a child structure appears.
- [ ] Add a second address column (A) with another object of the same type. Lock a column (L), change a value in the target, check that H highlights the change.
- [ ] Ctrl Enter on a field adds it to the cheat table with its pointer path; the value shows.
- [ ] Export as C and as C# (C): the text is sensible.
- [ ] Export structures (Ctrl Shift E), delete them, import them (Ctrl I).
- [ ] Save the table, reopen: structures are still there.

## 10. Code analysis

- [ ] In the Code view, tick the main module and press Run. Functions, strings and code caves are listed with counts.
- [ ] Select a string, press Alt X: references are listed. Enter jumps to the referencing instruction.
- [ ] Save the dissection (`.hhdis`) and load it again.
- [ ] Code filter (Alt C): attach the debugger, start recording, do an action in the target, stop as "ran"; record again without the action, stop as "did not run". The list shrinks. The target keeps running during recording and is usable.
- [ ] In the disassembler, X on a line shows references from the dissection. Ctrl Home goes to the function start. T lists call or jump targets.

## 11. Lua and forms

- [ ] In the Lua view run `print(1+1)`. The output shows 2.
- [ ] Run `print(readInteger(<address of a known value>))`: the value prints. Run a `writeInteger`: the target changes.
- [ ] Run `while true do end`, then press Esc: the script stops. Without Esc, it stops by itself after the time limit (30 s).
- [ ] Run a script that allocates a lot of memory in a loop: it is stopped by the memory limit with an error, and HeapHook stays up.
- [ ] Create a form from Lua with a button that prints on click (`createForm`, `createButton`). The form appears; clicking works. Ctrl Shift L focuses it. Esc closes it. The top-bar "Close scripts" button closes all forms.
- [ ] A timer or a table script that keeps running shows "Stop script" in the top bar; pressing it stops the script.
- [ ] Ctrl Up and Ctrl Down walk through history.
- [ ] Table script: set a script in the table, save, reopen, trust and run it.

## 12. Trainer generator

- [ ] With three entries in the table, click Trainer. Pick two, give each a hotkey and a label. Press "Generate and run".
- [ ] A form appears with two toggles. Clicking a toggle activates the entry (the target value changes or is frozen).
- [ ] The hotkey toggles the entry while HeapHook has focus.
- [ ] The table script now contains a block between `-- BEGIN HEAPHOOK TRAINER` and `-- END HEAPHOOK TRAINER`. Generate again: the block is replaced, not duplicated.
- [ ] Save the table, reopen it, decline trust: the trainer does not start. Trust it and run the table script: the trainer starts.

## 13. Remote session through hh-server

Use two machines if you can, or one machine and a loopback address.

- [ ] `cargo build --release -p hh-net --bin hh-server`. Run `hh-server --help`: the usage text prints.
- [ ] `hh-server --token short` fails with a message that the token must be at least 16 characters.
- [ ] `hh-server --listen 0.0.0.0:52736` without `--allow-remote` fails; with `--allow-remote` it starts.
- [ ] `hh-server` with no token prints a random token. Note it.
- [ ] In HeapHook: Ctrl P, Connect to server, address `127.0.0.1:52736`, wrong token: a clear error and a short delay. Correct token: the list shows processes of the server machine.
- [ ] Open a process: the top bar shows the remote badge. Scan, add to the table, change a value, freeze it, view memory, pointer scan. They work.
- [ ] Debugger, Create process, speedhack and pause refuse with a message that the target is remote.
- [ ] Restart `hh-server --read-only`, reconnect: reading works; writing a value fails with a permission message.
- [ ] SSH tunnel: `ssh -L 52736:127.0.0.1:52736 user@host`, with `hh-server` on the host. Connect to `127.0.0.1:52736`: it works.
- [ ] Stop `hh-server` while connected: HeapHook closes the remote target and says the connection was lost. No hang.
- [ ] "Remember the token on this device": reconnect with an empty token field after a restart. "Forget the saved server" clears it.

## 14. Speedhack on a launched program

- [ ] Build the library: `cargo build --release --manifest-path crates/hh-inject/payload/Cargo.toml`.
- [ ] Create process with a program that shows time (a clock or a game) and "Load the speedhack". A speed button appears in the top bar.
- [ ] Set 0.25x with the dialog. The program slows down. Set 2x: it speeds up. R resets to 1.
- [ ] Ctrl Shift Up, Ctrl Shift Down and Ctrl Shift Backspace change the speed while HeapHook has focus.
- [ ] A running program opened with Ctrl P has no speed button, and the speed dialog says to start it with Create process.
- [ ] Create process with both "Debug it" and the speedhack: the dialog says they cannot be combined (or the combination is refused).
- [ ] Make the library world-writable (`chmod o+w`) or put `HH_SPEEDHACK_LIB` at a file in a world-writable directory without the sticky bit: Create process with speedhack fails with a message about refusing the library. Restore the mode.
- [ ] With `HH_SPEEDHACK_LIB` pointing to a copy of the library, and the library not next to the executable, it is found.

## 15. Packaging

- [ ] Build: `cargo build --release --manifest-path crates/hh-inject/payload/Cargo.toml`, then `cd app/src-tauri && cargo tauri build --bundles deb,rpm`.
- [ ] The deb file and the rpm file exist and carry the version `1.0.0+rc.1` (`dpkg-deb -I`, `rpm -qpi`).
- [ ] Install the deb (or rpm) on a clean system or container. `dpkg -L heap-hook` (or `rpm -ql`) shows `libhh_speedhack.so` under `lib/HeapHook`.
- [ ] HeapHook appears in the application menu with its icon and the category for developer tools. Launch it from the menu.
- [ ] From the installed app: Create process with the speedhack finds the library (the speed button appears).
- [ ] Open a table from the command line: `heaphook /path/to/table.CT` opens it and shows the consent prompt if it carries Lua. (The package does not register a `.CT` file association; double-click is not expected to work.)
- [ ] Uninstall the package. The files are removed. Settings in the user config directory remain (they are not part of the package).
- [ ] Known limit to confirm: a final `1.0.0` package is treated as older than `1.0.0+rc.1` by dpkg and rpm, so the release-candidate package must be uninstalled first. Check that uninstalling leaves nothing behind (`dpkg -L heap-hook` or `rpm -ql heap-hook` reports the package is not installed).

## 16. Needs a human, not verified by automation

These cannot be checked by the automated tests.

- [ ] System-wide hotkey delivery under Wayland and X11. Set a table hotkey with Ctrl or Alt (and a letter), trust the table, put another window in focus, press the hotkey. Under X11 it should fire. Under Wayland note whether it fires. Run with `HEAPHOOK_HOTKEY_LOG=1` and check stderr: each hotkey says "registered" or "not registered", and "global hotkey pressed" appears when it fires. Also check a hotkey without a modifier: it must work only while HeapHook has focus.
- [ ] Native file dialogs. Open, Save, "Save results", "Open results", "Save trace", Browse in Create process, in all cases: the system dialog opens, the filters make sense, Cancel does nothing, the chosen file is used.
- [ ] Drag and drop of a table file onto the window. A `.CT` and a `.json` open (with the unsaved-changes question if needed). A file of another type does not break anything.
- [ ] The unsaved-changes prompt on window close. Edit the table, close the window: a prompt offers Save, Discard changes and Cancel. Cancel keeps the window. Save writes and closes. Discard closes without writing. Closing again while the prompt is open closes the window. With no changes, no prompt.
- [ ] Changing and freezing a real game's health value. Suggested: GZDoom. Launch from HeapHook's Create process, so no extra permissions are needed: program `gzdoom`, arguments `-iwad <path to DOOM2.WAD> -warp 1 -skill 2 -window`. Scan for the player's health (starts at 100, scan exact, take damage, scan the new value), change it, freeze it, confirm health stays while enemies hit you. Also try a pointer scan and restart to see if a pointer path survives.
- [ ] Visual check of both themes (light and dark) at small (about 900 by 600, the minimum) and large (maximized on a big screen) window sizes: no clipped text, no overlapping controls, readable contrast, dialogs fit.
- [ ] Long sessions. Leave HeapHook attached to a game for an hour or more with a table with several frozen entries and a debugger watch. Watch HeapHook's memory use (it should not grow without bound) and CPU use. Do several scans and close them. Memory should come back.
- [ ] A real Cheat Engine `.CT` table from the wild. Open it: it loads, the entries and groups look right, scripts show, nothing runs before consent. Save as `.CT` and open the result in a table viewer or compare the XML. Report tables that load wrong.
- [ ] Anything on Windows. The Windows build is compiled in CI but has not been run. Try: install the NSIS bundle, launch, open a process, scan, edit, a table, the debugger, Create process. Write down every failure.
