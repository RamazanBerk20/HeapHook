# HeapHook user guide

This guide covers common tasks, in the order you meet them. For what HeapHook can and cannot do, see the README. For the full feature list against Cheat Engine, see [PARITY.md](PARITY.md).

Use HeapHook on single-player games and on software you are permitted to modify. Do not use it against online multiplayer games.

## 1. First run

The window has a top bar and seven views, switched with Ctrl 1 to Ctrl 7: Scanner, Memory, Debugger, Pointers, Lua, Structures, Code. The Scanner view also holds the cheat table.

### Permissions (Linux)

HeapHook reads another process through `ptrace`. With `kernel.yama.ptrace_scope=1`, which is the default on most distributions, a process can only trace its own children. There are two ways to deal with that.

- Start the program from HeapHook (Create process, below). It becomes a child of HeapHook and needs no system change. This is the simplest way and the only one that works with the speedhack.
- Give the HeapHook binary the capability: `sudo setcap cap_sys_ptrace+ep <path-to-heaphook>`, then restart HeapHook. Run the command again after you update the binary. The capability lets HeapHook read and write any process of your user, so use it only on a binary that others cannot replace.

If you try to open a process you may not trace, HeapHook shows a dialog that explains this and offers to copy the command or open Create process.

### Open a running process

1. Press Ctrl P.
2. Type in the filter box (name, PID or path), pick the process with the arrow keys, press Enter.

The top bar then shows the name and PID. Ctrl Shift W closes the process (or use Close process in the same dialog).

### Create a process

1. Press Ctrl P, then Ctrl N (or click Create process).
2. Enter the program, its arguments and a working directory (empty means the program's directory).
3. Choose a debugger option: not debugged, stop at the entry point, stop before the first instruction, or debug and do not stop.
4. Tick "Load the speedhack" if you want to change the program's clock (section 12).

Debugging and the speedhack cannot be combined.

You can also start HeapHook with `--launch PROGRAM ARGS...`, `--pid PID` or `--attach NAME`, and with a table file as the first argument.

## 2. Find and change a value

Example: a health value that shows as 100 in the game.

1. Open the process. Value type "4 Bytes" and scan type "Exact value" are a good start.
2. Type 100 in the Value box and press Enter (First scan).
3. Lose some health in the game. Type the new value and press Enter again (Next scan). Repeat until few results are left.
4. Select a result and press Enter to add it to the cheat table.
5. In the table, press Enter on the Value cell to type a new value. Press Space on the row to freeze it.

Notes:

- Ctrl Z undoes the last scan. Ctrl N starts a new scan.
- Esc cancels a running scan. The pause button next to the progress bar pauses it.
- "Pause process while scanning" in the scan options stops the target during the scan so values do not change under you.

### Value types

Binary, Byte, 2 Bytes, 4 Bytes, 8 Bytes, Float, Double, String, Array of byte, All, Grouped, and custom types.

- Float and Double: "Float matching" chooses rounded, rounded (extreme) or truncated comparison.
- String: options for case sensitivity, UTF-16 and code page (UTF-8, Windows-1252, ISO-8859-1).
- Array of byte: hex bytes, `??` is any byte, for example `48 8B ?? 05`.
- All: tries every numeric type at once. Tick types under "Types to try" to narrow it.
- Binary: a bit pattern; the options set the bit length and start bit.
- Grouped: several values at fixed offsets matched as one group.
- Custom types appear at the bottom of the type list (see "Custom types" in section 3).

### Scan types

Exact value, bigger than, smaller than, value between, unknown initial value, increased, increased by, decreased, decreased by, changed, unchanged, same as first. "Not" inverts the match. "Percent" appears for "between", "increased by" and "decreased by".

### Unknown initial value

When you do not know the number (a health bar, for example): choose "Unknown initial value" and press First scan. HeapHook stores all matching memory. Then use "Decreased", "Increased", "Changed" or "Unchanged" after each change in the game. This keeps a lot of data. Large result sets spill to disk (see Settings, section 13).

### Region filters

In "Memory scan options":

- Start and Stop limit the address range.
- Writable, Executable, Copy-on-write are three-state boxes: yes, no, any. The defaults come from Settings (writable yes, executable any, copy-on-write no).
- "Fast scan, alignment" checks only addresses that are a multiple of the number (4 by default). Turn it off for packed data.
- More filters are available for region kind, module include or exclude lists, size limits and extra ranges.

### Saved scans and comparing

"Save scan..." keeps the current result set under a name. "Next scan compares to" can then use the first scan or a saved scan instead of the previous one. The results list can show a "Diff against" column with a saved scan's values.

### Results list

- Right-click or Shift F10 for the menu: add to table, browse memory (Ctrl M), copy addresses (Ctrl C), find what accesses (F5) or writes (F6), pointer scan.
- Del removes selected results, Ctrl Z brings them back.
- You can export all addresses to a file, copy them, or see how many results sit in each region or module.
- A pointer-value scan looks for pointer-sized values that point into readable memory.

## 3. The cheat table

### Add entries

- From scan results: select and press Enter.
- By hand: Ctrl Shift A (Add address). Enter a description, an address (a number, `game+1A2B`, or any expression such as `[[base+10]+8]`), a type and options.
- Tick "Pointer" and add offsets (hex, applied top to bottom: each step reads a pointer and adds the offset).
- From the memory viewer: Ins on a byte in the hex view.

### Edit

- Enter: edit the value (for a script entry: edit the script). F2: description. Ctrl E: the full entry dialog.
- Right-click, Shift F10: show as hexadecimal, signed or binary; colours; hotkeys; drop-down list; group options; columns.
- Drag rows or use Alt Up and Alt Down to move them.

### Freeze

Space toggles freezing. The freezer rewrites the value every 100 ms by default (Settings). Three modes are in the context menu:

- Freeze: the value is written back exactly.
- Allow increase: the value may go up but is pushed back if it goes down.
- Allow decrease: the reverse.

"Freeze interval..." gives one entry its own interval from 1 to 60000 ms. If a frozen entry cannot be written, HeapHook keeps retrying.

### Groups

Select entries and press Ctrl G. Groups nest. "Group options..." controls whether activating a group activates or deactivates its children. Left and Right arrows collapse and expand; Ctrl Right and Ctrl Left do it for all.

### Hotkeys

Ctrl H opens the hotkey dialog for an entry. Click the key box, press the combination, choose the action: toggle activation (also allow increase or decrease), activate, deactivate, set value, increase value, decrease value.

- A hotkey without Ctrl, Shift, Alt or Win works only while HeapHook has focus.
- A hotkey with a modifier is registered with the system, but only after the table is trusted (section 5). On X11 this should work in other windows. Under Wayland the desktop decides; count on it only while HeapHook has focus.
- Settings can add a beep and a minimum delay between two firings of a hotkey.

### Drop-down lists

"Dropdown list..." on an entry maps values to names, like `0 = Off`, `1 = On`. Options let you show only the name, or make the list read-only.

### Custom types

Custom types are numbers with a size of 1 to 8 bytes, optional big-endian, float, signed, a scale and offset (`raw * scale + offset`) and a bit field. HeapHook has Cheat Engine's stock presets, and you can define your own; those are saved in the table. A table that names a custom type HeapHook cannot define keeps it as is: the value cannot be read or written, and the name is written back on export.

### Save, load, import, export

- Ctrl S saves, Ctrl O opens. Tables are saved as HeapHook JSON or as Cheat Engine `.CT`. The file type follows the name you give.
- You can drop a `.CT` or `.json` file on the window to open it.
- "Merge a table into this one..." (Tools menu, Alt T) appends the entries of another table with new ids.
- "Save the table as text..." writes a tab-separated listing.
- If the table has unsaved changes, opening another table or closing the window asks first.
- Recent tables are in the small arrow next to Open.

### Undo and redo

Ctrl Z and Ctrl Y step through your edits to the table (adding, deleting, moving, changing values of entries). Scripts that an undone step removes are disabled first.

### Compact mode

Ctrl Alt M shows only the cheat table. Ctrl Alt M again returns.

## 4. Pointers

A value that moves each time the game starts is usually reached through a chain of pointers from a fixed (static) address.

### Find what accesses or writes an address

Select an entry or a result and press F6 (what writes) or F5 (what accesses). The debugger attaches if needed and the Debugger view lists the instructions that touched the address, with counts. Select a record to see the registers at that moment. The "Accessed" column shows the address used. From a record you can replace the instruction with NOPs (N), add it to the code list (L), or open its base register in the structure dissector (D).

Replacing an instruction with NOPs changes the program's code in memory. The code list shows which entries are original, NOPped or changed, and can restore them.

### Pointer scan

1. Right-click an entry or result and choose "Pointer scan for this address...", or press N in the Pointers view.
2. Set the maximum level, the maximum offset, and the filters. The defaults use static bases only and do not allow loops. Thread stacks count as static bases unless you turn that off.
3. Press Scan. The results are paths like `game+1A2B -> 10 -> 8`. Pause with P, cancel with Esc.
4. Select a path and press Enter to add it to the cheat table.

Results can be saved (Save results) and opened again.

### Narrowing the paths after a restart

Paths found once are mostly useless after a restart. To keep the good ones:

- Rescan (R): keeps the paths that still resolve and pass the filters. After restarting the game, find the new address of the value, then rescan with "Must point to address" set to it. You can also filter by value, base range, or the first and last offsets.
- Or save a pointer map (Save pointer map) from each run, then do a new scan with "Compare with saved pointer maps": a path must lead to the given address in each map.

Repeat until a few paths are left, and add the best one to the table.

## 5. Scripts

### Auto Assembler in the table

- "Script" (toolbar) or "Add script..." in the table menu creates a script entry. Press Enter on it to edit.
- A script has `[ENABLE]` and `[DISABLE]` sections. Activating the entry (Space) runs `[ENABLE]`. Deactivating it runs `[DISABLE]`.
- The editor checks the script as you type and marks the error line. Ctrl Space completes. Ctrl F finds, Ctrl H replaces.
- If you close HeapHook or the process, active scripts are disabled first.

### Auto Assemble window and templates

Ctrl Alt A opens a stand-alone Auto Assemble window. Execute (Ctrl Enter) runs `[ENABLE]`, "Run [DISABLE]" (Ctrl Shift Enter) undoes it. What you type here is not saved in the table. "Open file" loads a script from disk.

In the disassembler, the context menu creates scripts for the instruction under the cursor:

- Generate AOB signature, and Create AOB injection script.
- Create code injection script, and Create full injection script.
- Create API hook script.

### `aobscan` with several matches

An `aobscan` that matches more than once uses the first match by default, like Cheat Engine. Settings can report the count or refuse to enable the script.

### `{$lua}`

A script can contain `{$lua} ... {$asm}` blocks that run Lua. The checker never runs them. Lua runs with your user rights, so it falls under the consent rules below.

### The consent prompt

Lua in a table can read, change and delete your files, start programs and use the network. HeapHook never runs it without asking.

- When you open a table that has a table script, Lua entries or hotkeys, HeapHook asks "Trust this table?". The prompt says what the table contains: the script's size and start (with "View full script"), how many entries run Lua, and the hotkeys it defines. "Trust and run its script" lets it run. "Do not trust" is the default button (Esc).
- If you decline, nothing runs: not the table script, not Lua entries, not hotkeys. If you try to activate such an entry, HeapHook asks again.
- Entries that you paste into a table, merge into it, or drop in from another table are marked with a shield. Their Lua asks again per entry ("Trust this entry") even if the table is trusted. You can also use "Trust the selected entries' Lua..." in the context menu.
- Settings > Lua > "Lua script in a loaded table": "Never run" refuses without asking. Then no table Lua runs at all.
- Settings > Lua > "Allow Lua scripts to access files and run programs": turn it off to stop that access. It applies after a restart. Scripts can still read and change the attached process.
- An Auto Assembler script loaded from a file asks before its `{$lua}` or `loadbinary` runs. A script you type yourself runs without asking.

Open tables only from sources you trust.

## 6. The debugger

### Attach

Ctrl Shift D attaches or detaches (also the debugger button in the top bar). While attached, all memory access goes through the debugger. The debugger works on local processes only.

To debug from the very start, use Create process with a debugger option, or `--launch`. The program stops at its entry point or before its first instruction, so you can set breakpoints before its code runs.

Detach before you close HeapHook. If HeapHook is force-killed while attached, software breakpoint bytes (int3) stay in the target.

### Breakpoints

- F5 in the disassembler toggles a breakpoint. In the hex view, F5 sets one on the byte under the cursor. Insert in the breakpoint list opens the full dialog.
- Method: software (int3, any number) or hardware (debug registers, a limited number, works for data). H switches an execute breakpoint between the two. The default for new ones is in Settings.
- Options: a condition (`rax==5 && rcx>0x100`), skip the first N hits, switch off after one hit, switch off at a maximum number of hits. E edits them.
- Other kinds: tracepoints (log a message with `{rax}`, `{old}`, `{new}`, `{address}` and carry on), pending breakpoints on an address that does not exist yet, and breakpoints for one thread. B sets "Break on events" for thread start and exit, and module load and unload.

### Controls

F9 continue, Shift F9 break, F7 step into, F8 step over, Shift F8 step out, F4 run to cursor (Shift F4: this thread only). Ctrl F7 and Ctrl F8 step while skipping breakpoints. "Set instruction pointer here..." in the disassembler menu moves RIP.

The side panel of the Memory view shows Registers (F2 edits one), Stack, Backtrace and Threads once the debugger is attached.

### Signals

Settings > Debugger signals chooses what happens to each signal: pass it to the process, ignore it, or break.

### Find what writes and accesses

See section 4. For eight bytes or less this uses debug registers and is fast.

### Break and trace

In the disassembler menu, "Break and trace..." breaks at an address, then single-steps for the number of instructions you set (up to 100000), optionally stepping over calls and stopping when a condition holds. The result is a list of instructions with register values. "Save this trace..." writes it to a file.

### Range watch

A range watch records writes or accesses to any number of bytes. It works by taking page protection away. It has a cost: every access to those memory pages, even outside your range, stops the process for a moment. The target runs much slower while the watch is on. Never use it on stack memory; HeapHook refuses ranges inside a stack. Use it when the range is longer than a debug register can cover, and stop it when you are done (S).

### Code list

Replace with NOPs (N) and Add to code list (L) fill the code list. Space toggles an item between NOP and original. Del removes it from the list.

## 7. Structure dissector

Use it to see a game object as fields.

1. Open the Structures view (Ctrl 6). Press G, enter an address or expression (or use "Open in structure dissector" on an entry).
2. Choose "New: auto-guess the layout" and a size. HeapHook guesses the field types from the memory. If the object has C++ run-time type information, the class name is used.
3. Select a field: Enter or 1-9 to edit its value, F2 for the description, T for the type, S for the size, Ins to add and Del to remove an element. E edits bit fields, array counts and pointer child offsets.
4. Pointer fields expand with the Right arrow into child structures.
5. A adds another address column to compare two objects. L locks a column (shows a frozen copy). H highlights the changes. Alt S runs the spider.
6. Ctrl Enter adds the field under the cursor to the cheat table, with its pointer path.

Structures are saved with the cheat table. Ctrl Shift E exports them, Ctrl I imports them (HeapHook JSON, or Cheat Engine structures XML). C exports the layout as C or C# source.

## 8. Code analysis

Open the Code view (Ctrl 7).

1. Tick the modules to examine and press Run (Ctrl Enter). Ctrl Shift Enter adds more modules to an existing result.
2. Use the tabs: Functions, Strings, Referenced functions, Code caves. The filter box (Ctrl F) searches the list. Enter disassembles the selected item. The References panel (Alt X) lists who calls or refers to it.
3. Save and load dissections as `.hhdis` files.
4. "What references this address" (X) in the disassembler or hex view uses the dissection.

### Code filter

Alt C opens the code filter. It finds the code behind one action, such as a jump.

1. Dissect the module first, and attach the debugger.
2. Start recording. Do the action in the game. Stop with "it ran".
3. Start again, do everything except that action, and stop with "it did not run".
4. Repeat until the list is short. The list keeps the functions that ran in every "ran" set and in no "did not run" set.

While recording, HeapHook puts a one-shot breakpoint on every function entry the dissection found. That is a lot of breakpoints (tens of thousands), but each one costs time only the first time that function runs.

## 9. Memory tools

Shift F10 in the hex view, or the Tools button above it, opens the menu.

- Fill memory and Copy memory take addresses and lengths in hex.
- Allocate memory and Free memory manage blocks in the target. Protection can be changed per region.
- Region statistics summarizes memory by protection, kind and module.
- "Find what points to this address" (Ctrl Shift P) lists pointers into a region.
- A module header dialog shows sections, imports and exports.

### Snapshots

"Snapshots and compare..." (Ctrl Shift S) copies a range, or all writable memory, to HeapHook's memory. Take a second one later and compare: the diff lists the changed bytes, and the change map shows which pages changed (C, then Enter to show a cell in the hex view).

### Save and load memory files

- "Save this region to a file..." writes a `.hhmem` file.
- "Load memory file..." first builds a plan: a checklist of the blocks in the file, each marked as writable, read-only (the protection is lifted for the write and restored) or not mapped. Nothing is written until you approve blocks (Ctrl Enter). You can relocate the blocks to another address.
- "Compare with saved file..." shows differences between a file and the live process.
- "Search in a memory file..." finds a pattern or value inside a `.hhmem` file without a process.

### Search in memory

Ctrl F in the hex view searches memory for bytes or text. F3 and Shift F3 find next and previous. In the disassembler, Ctrl F searches the module by instruction text or bytes, and Ctrl Shift F runs an assembly pattern scan, for example `mov [r?x+*],e?x; ret`.

### Bookmarks, labels and comments

Ctrl B bookmarks an address, Ctrl Shift B lists bookmarks. In the disassembler, `;` adds a comment and `:` a label. Labels work in every address field. Both are saved with the cheat table.

## 10. Lua, forms and the trainer generator

### Console

The Lua view (Ctrl 5) runs Lua against the opened process. Ctrl Enter runs the text. Ctrl Up and Down walk through history. Esc interrupts a script. The table's Lua script is edited with the "Table script" button. Each run has a time limit (30 seconds by default) and a memory limit (1024 MiB), both in Settings.

HeapHook implements part of Cheat Engine's Lua API. If a function you need is missing, check PARITY.md.

### Table scripts and forms

A table script runs when the table is trusted and you choose to run it (the consent prompt offers to run it on open). Scripts can create windows (forms) with buttons, text and lists; they open as HeapHook windows. Ctrl Shift L focuses the next form, Esc closes it, F10 opens its menu bar, Alt and the arrow keys move it. "Stop script" and "Close scripts" in the top bar appear while a script runs or forms are open.

### Trainer generator

Open it with the Trainer button or "Generate a trainer...".

1. Pick the entries to include. Edit the label and set a hotkey for each. If an entry already has a "Toggle activation" hotkey, it is shown and not registered twice.
2. Set the title, an optional text, whether to beep and whether to show hotkeys.
3. Press "Generate and run" or "Generate".

The result is a block of Lua in the table script, between `-- BEGIN HEAPHOOK TRAINER` and `-- END HEAPHOOK TRAINER`. It shows a form with one toggle per entry. Generating again replaces the block. The trainer runs inside HeapHook when the table script runs. It is not a stand-alone program, and the table must be trusted for it to run.

## 11. Remote targets

A remote target lets HeapHook on one machine scan a process on another.

On the machine with the process:

    hh-server --listen 127.0.0.1:52736

It prints a random token unless you give one with `--token` or `HH_SERVER_TOKEN` (at least 16 characters). `--read-only` blocks writes. `--allow-remote` is required to listen on any non-loopback address. Traffic is not encrypted after the handshake, so tunnel it:

    ssh -L 52736:127.0.0.1:52736 user@host

In HeapHook:

1. Press Ctrl P, then "Connect to server...".
2. Enter `127.0.0.1:52736` (the tunnel) and the token. "Remember the token on this device" stores it in HeapHook's config file, readable only by you.
3. Pick a process from the remote list. A "remote" badge appears in the top bar; click it to disconnect.

Scanner, table, memory viewer, pointer scanner, structures and memory tools work on the remote process. The debugger, speedhack, Create process and pause are local only and refuse with a message. Symbols, module headers and dissections of a remote target are read from its memory only, never from a same-named local file. If the connection drops, HeapHook closes the target and says why.

## 12. Speedhack

The speedhack changes the clock the program sees (libc time functions), so a game runs faster or slower.

- Start the program with Create process and tick "Load the speedhack". It works only for programs started this way, on Linux, and only for dynamically linked programs that use libc's time functions. It cannot be loaded into a program that is already running.
- Click the speed button in the top bar to open the Speedhack dialog. Slider (0.1x to 10x), exact value (up to 1000), presets 1 to 5 (0.25x, 0.5x, 1x, 2x, 5x), R resets to 1.
- Ctrl Shift Up doubles the speed, Ctrl Shift Down halves it, Ctrl Shift Backspace returns to 1.
- Settings > HeapHook hotkeys can bind keys to a speed or to pause and resume the process. Same hotkey rules as table hotkeys.
- A Lua `speedhack_setSpeed` call works too.
- If HeapHook says the library is missing or refused: it must be found next to the executable, in `<prefix>/lib/HeapHook/` or at `$HH_SPEEDHACK_LIB`, and neither it nor any directory above it may be writable by other users.
- A program that checks time against another clock, or a time source libc does not provide, may not be affected.

## 13. Settings

Ctrl , opens Settings. The file is saved in the platform config directory; its path is shown at the bottom of the dialog.

- Theme: system, light or dark.
- Values: freeze interval (default 100 ms) and live update interval (300 ms).
- Scan defaults: fast scan and alignment (4), writable (yes), executable (any), copy-on-write (no), scan threads (0 = one per core), scan priority (normal, low, idle), and a directory for large scan results.
- Lua: time limit per run (30000 ms), memory limit (1024 MiB), table script (ask or never run), file and program access, `aobscan` ambiguity.
- Debugger and hotkeys: breakpoint method (software by default), beep on hotkeys, hotkey repeat delay (150 ms).
- HeapHook hotkeys, and debugger signal actions.

The environment variable `HEAPHOOK_TMPDIR` also sets the spill directory, and `HEAPHOOK_HOTKEY_LOG=1` logs hotkey registration to stderr.

## 14. Keyboard shortcuts

F1 opens this list in the app. This is the list from the app's help dialog, followed by lines that individual views add to it.

### Global

| Keys | Action |
|---|---|
| Ctrl P | Open process |
| Ctrl 1 ... Ctrl 7 | Scanner, Memory, Debugger, Pointers, Lua, Structures, Code |
| Ctrl Shift W | Close process |
| Ctrl Shift Up / Down | Speedhack |
| Ctrl , | Settings |
| Ctrl Shift D | Attach / detach debugger |
| Alt 1 ... Alt 5 | Focus value, results, table, disassembler, hex |
| Ctrl O / Ctrl S | Open / save table |
| F1 | This list |
| Alt T | Tools menu |
| Ctrl Alt K | Calculator |
| Ctrl Alt A | Auto Assemble window |
| Ctrl Alt P | Pause / resume the process |
| Ctrl Alt M | Compact mode (only the cheat table) |
| Ctrl Shift Backspace | Speedhack back to 1x |

### Scanning

| Keys | Action |
|---|---|
| Enter | First / next scan (in value field) |
| Ctrl Enter | First / next scan |
| Ctrl N | New scan |
| Ctrl Z | Undo last scan |
| Esc | Cancel running scan |

### Results

| Keys | Action |
|---|---|
| Shift Up / Down | Extend selection |
| Enter | Add selection to table |
| Ctrl C | Copy addresses |
| Ctrl M | Browse memory |
| F6 / F5 | What writes / accesses (also in the table) |
| Del | Remove selected results (Ctrl Z brings them back) |
| Ctrl Shift C | Copy every result address |

### Pointer scanner

| Keys | Action |
|---|---|
| N | New scan |
| R | Rescan (list focused) |
| Enter | Add path to table |
| Esc | Cancel |
| P | Pause / resume a running scan |

### Cheat table

| Keys | Action |
|---|---|
| Space | Activate / freeze |
| Enter | Edit value (script: edit script) |
| F2 | Edit description |
| Ctrl E | Edit entry |
| Ctrl Shift A | Add address |
| Ctrl G | Group selected |
| Alt Up / Down | Move |
| Ctrl X / C / V | Cut, copy, paste |
| Del | Delete |
| Ctrl Z | Restore deleted (undo) |
| Left / Right | Collapse / expand |
| Ctrl H | Hotkeys |
| Ctrl M / Ctrl D | Browse / disassemble region |
| Shift F10 | Context menu |
| Ctrl F | Filter |
| Ctrl Right / Ctrl Left | Expand / collapse all |
| Ctrl Y | Redo (context menu) |

### Lua console

| Keys | Action |
|---|---|
| Ctrl Enter | Run |
| Ctrl Up / Down | History |
| Esc | Interrupt a running script |

### Memory viewer

| Keys | Action |
|---|---|
| Ctrl G | Go to address |
| Space | Follow jump (disassembler) / follow the pointer (hex view) |
| Backspace | Back |
| Enter | Assemble line / edit value |
| 0-9 A-F | Type over bytes |
| Shift F10 | Tools: fill, copy, snapshots, pointers to here |
| Shift Left / Right / Up / Down | Select bytes (hex view) |
| Ctrl Shift R | Watch the selection |
| X | What references this (disassembler) |
| ; | Comment |
| : | Label |
| T | Call / jump targets |
| Ctrl Home | Function start (disassembler) |
| F5 | Breakpoint here (hex view) |
| Ctrl F | Search memory (hex view) / the module (disassembler) |
| F3 / Shift F3 | Next / previous match |
| Alt Left / Alt Right | Back / forward |
| Shift Up / Down | Select lines (disassembler) |
| Ctrl C | Copy the selection: hex (hex view), text (disassembler) |
| Ctrl Shift C | Copy lines as an AOB pattern (disassembler) |
| Ctrl V / Ctrl Shift V | Paste hex or text / always as text (hex view) |
| Ctrl B / Ctrl Shift B | Bookmark here / list bookmarks |
| Shift 1 ... 0 / Ctrl Shift 1 ... 0 | Go to / set a numbered bookmark |
| Ins | Add to the table with the display type (hex view) |
| Ctrl I / Ctrl L | Data inspector / lock editing (hex view) |
| Ctrl = / Ctrl - / Ctrl 0 | Larger / smaller / default text |
| Ctrl Shift M | Second memory viewer (Esc closes it) |
| S | Sync disassembler and hex view |
| M / B / I | Module + offset addresses / bytes column / target info (disassembler) |
| Ctrl Shift F | Assembly scan: instruction patterns with ? and * (disassembler) |
| R / Shift R | Next / previous instruction referencing an address (Alt R: another address) |

### Memory tools

| Keys | Action |
|---|---|
| Space / A / N | Load memory file: toggle a block / all / none |
| Ctrl Enter | Load memory file: write the chosen blocks |
| C | Snapshots: compare two snapshots (page change map) |
| Enter | Change map: show the cell in the hex view (arrows move) |

### Structures

| Keys | Action |
|---|---|
| Right / Left | Expand / collapse |
| Enter / 1-9 | Edit value |
| F2 | Description |
| T | Type |
| S | Size |
| Ins / Del | Add / remove element |
| A | Address column |
| G | Dissect at |
| Ctrl Enter | Add to table |
| L | Lock column |
| H | Highlight changes |
| Ctrl I / Ctrl Shift E | Import / export |
| E | Edit element: bit field, array count, pointer child start |
| C | Export as C / C# (copy or save) |

### Debugger

| Keys | Action |
|---|---|
| F5 | Toggle breakpoint |
| F4 / Shift F4 | Run to cursor / this thread only |
| F9 / Shift F9 | Continue / break |
| F7 / F8 / Shift F8 | Into / over / out |
| Ctrl F7 / Ctrl F8 / Ctrl Shift F8 | Step into / over / out, skipping breakpoints |
| Watch list: Enter, N, L, S, Del, R | Disassemble, NOP, code list, stop, close, watch a range |
| Breakpoints: E, H | Condition and hit options, int3 / debug register |
| Ctrl F / F3 / Shift F3 / Esc | Filter the watch list, next / previous match, clear filter |
| I | More information on a watch record |
| A / Shift A | Copy the accessed address (all listed) to the address list |
| D | Open a record's base register in the structure dissector |
| F2 | Edit the selected register, also ST, XMM, MXCSR, FCW, FSW |
| B | Break on events: thread start / exit, module load / unload (breakpoint list) |
| R | Run until the selected backtrace frame returns (backtrace list) |

### Code analysis

| Keys | Action |
|---|---|
| Ctrl Enter | Dissect the ticked modules |
| Ctrl Shift Enter | Add the ticked modules to the dissection |
| Alt C | Code filter |
| R / Y / N | Code filter: record, stop as "ran", stop as "did not run" |

### Script editor

| Keys | Action |
|---|---|
| Ctrl F, F3 / Shift F3 | Find, next / previous |
| Ctrl H, Ctrl Alt Enter | Replace, replace all |
| Ctrl Z, Ctrl Y / Ctrl Shift Z | Undo, redo |
| Tab / Shift Tab | Indent / outdent selected lines |
| Ctrl Space | Complete (Up and Down choose, Enter or Tab inserts) |
| Esc | Close the find bar or the completion list |
| Ctrl Enter, Ctrl Shift Enter | Execute, run [DISABLE] (Auto Assemble window) |
| Ctrl K | Check (Auto Assemble window) |

### Lua forms

| Keys | Action |
|---|---|
| Ctrl Shift L | Focus the next form |
| Esc | Close it |
| F10 | Its menu bar |
| Alt Left / Right / Up / Down | Move it |
