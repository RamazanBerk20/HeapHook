# Cheat Engine parity matrix

Statuses are `done`, `engine only`, `partial`, `planned`, `needs decision`.

| Status | Rows |
|---|---|
| done | 303 |
| engine only | 20 |
| partial | 64 |
| planned | 292 |
| needs decision | 33 |

Row counts per section:

- Process handling: 17
- Memory scanning: 65
- Address list / cheat table: 90
- Memory viewer / hex editor: 41
- Disassembler and assembler: 51
- Auto Assembler: 65
- Debugger: 72
- Pointer scanner: 36
- Structure dissector: 23
- Code tools: 30
- Speedhack: 13
- Lua engine: 44
- Trainer generator: 15
- Mono / .NET / Java features: 23
- Graphics hooks: 19
- Kernel-mode and hypervisor tools: 23
- Network: 17
- Tools and misc: 68

Total: 712

## Process handling

| Feature | CE behaviour (one short sentence) | HeapHook crate | Status | Platforms |
|---|---|---|---|---|
| Open process dialog | Lists running processes with PID and name to attach to | app | done | linux+windows |
| Process list filter | Search box filters the process list by name | app | done | linux+windows |
| Applications / Processes / Windows tabs | Separate lists for windowed apps, all processes, and top-level windows | app | planned | windows |
| Process icons | Shows the executable icon beside each process | app | planned | linux+windows |
| Attach by PID | Opens a process handle by numeric id | hh-core | done | linux+windows |
| Open file as process | Loads an arbitrary file into a pseudo-process for hex editing | hh-core | planned | linux+windows |
| Create process | Launches an executable and attaches to it | hh-core | done | linux+windows |
| Process info in title bar | Shows attached process name and PID in the main window | app | done | linux+windows |
| Detach process | Releases the target and clears scans | hh-core | done | linux+windows |
| 32-bit / 64-bit target detection | Detects target bitness and adapts pointer size | hh-core | done | linux+windows |
| Process watcher | Shows process create/exit events | hh-core | planned | windows |
| Open process via Lua | openProcess/getOpenedProcessID switch the target from scripts | hh-lua | done | linux+windows |
| Pause/resume process | Suspends or resumes all target threads | hh-core | engine only | linux+windows |
| Auto attach to process name | Lua/table can attach automatically when a named process starts | hh-lua | planned | linux+windows |
| Handle list | Enumerates open handles of the target | hh-core | planned | windows |
| Run as admin / elevation | Requests privileges needed to open protected processes | hh-core | planned | linux+windows |
| Ptrace scope / permission guidance | Explains access denial to the user | hh-core | done | linux |

## Memory scanning

| Feature | CE behaviour (one short sentence) | HeapHook crate | Status | Platforms |
|---|---|---|---|---|
| Value type: Binary | Scans individual bits/bit-fields | hh-scan | partial | linux+windows |
| Value type: Byte | 1-byte integer scan | hh-scan | done | linux+windows |
| Value type: 2 Bytes | 16-bit integer scan | hh-scan | done | linux+windows |
| Value type: 4 Bytes | 32-bit integer scan | hh-scan | done | linux+windows |
| Value type: 8 Bytes | 64-bit integer scan | hh-scan | done | linux+windows |
| Value type: Float | Single-precision float scan | hh-scan | done | linux+windows |
| Value type: Double | Double-precision float scan | hh-scan | done | linux+windows |
| Value type: String | Text scan in ASCII or UTF-16 | hh-scan | done | linux+windows |
| Value type: Array of byte | Byte pattern scan with `??` wildcards | hh-scan | done | linux+windows |
| Value type: All | Scans every numeric type at once | hh-scan | done | linux+windows |
| Value type: Grouped | Scans several values at fixed offsets as one group | hh-scan | done | linux+windows |
| Custom value types (Lua) | User-defined types with Lua conversion functions | hh-lua | planned | linux+windows |
| Custom value types (Auto Assembler) | User-defined types with assembler conversion routines | hh-asm | planned | linux+windows |
| Custom type from .CT | Custom types stored and loaded with the table | app | planned | linux+windows |
| Scan type: Exact value | Matches memory equal to the entered value | hh-scan | done | linux+windows |
| Scan type: Bigger than | Matches values greater than the entry | hh-scan | done | linux+windows |
| Scan type: Smaller than | Matches values less than the entry | hh-scan | done | linux+windows |
| Scan type: Value between | Matches values within an inclusive range | hh-scan | done | linux+windows |
| Scan type: Unknown initial value | First scan stores all memory; later scans compare against it | hh-scan | done | linux+windows |
| Scan type: Increased value | Keeps addresses whose value grew | hh-scan | done | linux+windows |
| Scan type: Increased value by | Keeps addresses that grew by exactly N | hh-scan | done | linux+windows |
| Scan type: Decreased value | Keeps addresses whose value shrank | hh-scan | done | linux+windows |
| Scan type: Decreased value by | Keeps addresses that shrank by exactly N | hh-scan | done | linux+windows |
| Scan type: Changed value | Keeps addresses whose value changed | hh-scan | done | linux+windows |
| Scan type: Unchanged value | Keeps addresses whose value stayed | hh-scan | done | linux+windows |
| Scan type: Same as first scan | Compares against the first-scan snapshot | hh-scan | done | linux+windows |
| Invert scan (Not) | Inverts the match condition of the chosen scan type | hh-scan | done | linux+windows |
| Percentage scans | Increased/decreased by a percentage or percent range | hh-scan | done | linux+windows |
| Hex input | Treat the typed value as hexadecimal | hh-scan | done | linux+windows |
| Signed vs unsigned display | Chooses signed display for integer results | hh-scan | partial | linux+windows |
| Rounding: Rounded (default) | Float equality matches values that round to the entry | hh-scan | done | linux+windows |
| Rounding: Rounded (extreme) | Float equality matches anything between entry and entry+1 | hh-scan | done | linux+windows |
| Rounding: Truncated | Float equality matches truncated values | hh-scan | done | linux+windows |
| Scan start / stop address | Restricts the scan to an address range | hh-scan | done | linux+windows |
| Writable filter | Include, exclude, or ignore writable pages | hh-scan | done | linux+windows |
| Executable filter | Include, exclude, or ignore executable pages | hh-scan | done | linux+windows |
| Copy-on-write filter | Include, exclude, or ignore copy-on-write pages | hh-scan | done | windows |
| Fast scan with alignment | Checks only addresses aligned to N bytes | hh-scan | done | linux+windows |
| Last-digits fast scan | Alignment expressed as ending digits | hh-scan | done | linux+windows |
| Case sensitive string scan | Toggles case sensitivity for string scans | hh-scan | done | linux+windows |
| Unicode (UTF-16) string scan | Scans wide strings | hh-scan | done | linux+windows |
| Pause the game while scanning | Suspends the target during a scan for consistency | hh-scan | done | linux+windows |
| Memory scan options: scan image / mapped / private | Choose which memory types (MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE) to scan | hh-scan | planned | linux+windows |
| Compare to saved scan | Compares current memory with a named saved scan | hh-scan | engine only | linux+windows |
| Save scan as snapshot | Stores a named result set for later comparison | hh-scan | engine only | linux+windows |
| Next scan | Filters previous results with a new condition | hh-scan | done | linux+windows |
| New scan | Clears results and starts over | hh-scan | done | linux+windows |
| Undo scan | Restores the previous result set | hh-scan | done | linux+windows |
| Cancel scan | Aborts a running scan | hh-scan | done | linux+windows |
| Scan progress bar | Shows progress and found count | app | done | linux+windows |
| Result list with previous/first values | Shows address, value, previous and first values | app | done | linux+windows |
| Result list limit and paging | Shows large result sets lazily | app | done | linux+windows |
| Add selected results to address list | Double-click or button copies results to the table | app | done | linux+windows |
| Show results as hex | Displays values in hexadecimal | app | done | linux+windows |
| Show as signed | Toggles signed rendering of results | app | planned | linux+windows |
| Compare to first scan, hotkey scan | Scan hotkeys trigger first/next scan from any window | app | planned | linux+windows |
| Multi-threaded scanning | Scans memory with a configurable number of threads | hh-scan | done | linux+windows |
| Scan memory via ptrace/process_vm_readv backend | Reads target memory without kernel driver | hh-core | done | linux |
| Lua scan API (MemScan/FoundList) | Scripts drive scans and read result lists | hh-lua | done | linux+windows |
| AOB scan from Lua | AOBScan family finds byte patterns and returns a list | hh-lua | done | linux+windows |
| Freeze found results in bulk | Freeze all selected results at once | hh-scan | planned | linux+windows |
| Scan on stopped debugger state | Results stay consistent when target paused by debugger | hh-scan | partial | linux+windows |
| Scan settings: default scan options | Settings page for default scan options | app | done | linux+windows |
| Scan settings: use dbk (kernel) for reading | Uses driver for memory access in scans | hh-core | needs decision | windows |
| Scan settings: scan writable only default | Default writable-only restriction | app | done | linux+windows |

## Address list / cheat table

| Feature | CE behaviour (one short sentence) | HeapHook crate | Status | Platforms |
|---|---|---|---|---|
| Add address manually | Dialog to add an address, type, and description | app | done | linux+windows |
| Address list columns | Active, description, address, type, value | app | done | linux+windows |
| Edit description | Inline rename of an entry | app | done | linux+windows |
| Edit address | Change the address or pointer chain of an entry | app | done | linux+windows |
| Edit value | Write a new value to the target | hh-scan | done | linux+windows |
| Change type | Changes an entry's value type | app | done | linux+windows |
| Freeze (active checkbox) | Continuously rewrites the value | hh-scan | done | linux+windows |
| Freeze: allow increase | Frozen value may only go up | hh-scan | done | linux+windows |
| Freeze: allow decrease | Frozen value may only go down | hh-scan | done | linux+windows |
| Freeze interval setting | Configure how often frozen values are rewritten | hh-scan | done | linux+windows |
| Pointer entries | Entries defined by base plus offset chain | hh-scan | done | linux+windows |
| Pointer chain editor | Add/remove offsets with live address preview | app | done | linux+windows |
| Symbol and module+offset addresses | Addresses like `game.exe+1A2B` | hh-asm | done | linux+windows |
| Lua expression addresses | Address field can be a Lua expression | hh-lua | planned | linux+windows |
| Auto Assembler script entry | Entry holding an AA script toggled by the checkbox | hh-asm | done | linux+windows |
| Script entry editor | Edit scripts of an entry in an editor window | app | done | linux+windows |
| Groups | Entries can be grouped hierarchically | app | done | linux+windows |
| Group: activate children | Group checkbox toggles all children | app | done | linux+windows |
| Group header only | Entries with no value act as headers | app | done | linux+windows |
| Drag and drop reorder | Move entries and groups by dragging | app | done | linux+windows |
| Entry color | Set text color per entry | app | done | linux+windows |
| Show as hexadecimal | Display value in hex | app | done | linux+windows |
| Show as signed | Display integer as signed | app | done | linux+windows |
| Show as binary | Display value as bits | app | planned | linux+windows |
| Show as decimal override | Force decimal for a hex-set entry | app | done | linux+windows |
| Bit entries (start bit, length) | Entries covering part of a byte range | hh-scan | partial | linux+windows |
| String entries (length, unicode) | Fixed-length string records | hh-scan | done | linux+windows |
| Byte array entries | Array-of-byte records | hh-scan | done | linux+windows |
| Custom type entries | Entries using a custom value type | hh-scan | engine only | linux+windows |
| Dropdown list (value to text) | Maps stored values to labels, editable via a combo | app | done | linux+windows |
| Dropdown: show only listed values | Optionally hide raw value, display label only | app | done | linux+windows |
| Dropdown: disallow unlisted values | Restricts writes to listed items | app | done | linux+windows |
| Hotkeys per entry | Global hotkey bound to an entry | app | done | linux+windows |
| Hotkey action: toggle | Toggles freeze/script state | app | done | linux+windows |
| Hotkey action: toggle on/off explicit | Separate activate/deactivate keys | app | done | linux+windows |
| Hotkey action: set value | Writes a fixed value | app | done | linux+windows |
| Hotkey action: increase value | Adds a number to the value | app | done | linux+windows |
| Hotkey action: decrease value | Subtracts a number from the value | app | done | linux+windows |
| Hotkey sound feedback | Plays a sound when a hotkey fires | app | done | linux+windows |
| Hotkey activation delay | Delay before a hotkey repeats | app | planned | linux+windows |
| Global hotkey capture | Hotkeys work when the target window has focus | app | planned | linux+windows |
| Hotkey conflict handling | Keys with modifiers and chords | app | partial | linux+windows |
| Memory record Lua events (OnActivate/OnDeactivate/OnChange) | Scripts react to record state changes | hh-lua | done | linux+windows |
| Memory record OnGetDisplayValue | Lua can rewrite displayed value | hh-lua | planned | linux+windows |
| Collapsed/expanded groups with options | Groups can be saved collapsed or expanded | app | done | linux+windows |
| Manual expand with children | Expand all/collapse all commands | app | planned | linux+windows |
| Show/hide column options | Toggle which address list columns appear | app | planned | linux+windows |
| Description column wide text | Long text and multi-line comments | app | planned | linux+windows |
| Address list context menu | Right-click operations on entries | app | done | linux+windows |
| Browse this memory region | Jump from an entry to the memory viewer | app | done | linux+windows |
| Disassemble this memory region | Jump from an entry to the disassembler | app | done | linux+windows |
| Find out what accesses/writes this address | Start debugger watch on entry | hh-debug | done | linux+windows |
| Pointer scan for this address | Launch pointer scan for an entry | hh-ptr | done | linux+windows |
| Generate pointermap shortcut | Create a pointermap from the entry | hh-ptr | partial | linux+windows |
| Show as ... group | Submenu for display formats | app | partial | linux+windows |
| Change record type: group | Convert entry into group | app | planned | linux+windows |
| Add address to cheat table by dissect | Add selected structure elements as entries | app | done | linux+windows |
| Set/change hotkey dialog | Edit hotkey list for an entry | app | done | linux+windows |
| Delete / cut / copy / paste records | Clipboard operations on entries as text | app | done | linux+windows |
| Select all / invert selection | Selection helpers | app | partial | linux+windows |
| Sort by column | Sort address list | app | planned | linux+windows |
| Search address list | Find entries by description | app | planned | linux+windows |
| Cheat table file format (.CT XML) | Cheat table stored as XML | hh-core | done | linux+windows |
| .CT load: entries and groups | Reads CheatEntries, nested entries | hh-core | done | linux+windows |
| .CT load: scripts | Reads AssemblerScript entries | hh-core | done | linux+windows |
| .CT load: Lua script | Reads the table Lua script block | hh-core | done | linux+windows |
| .CT load: structures | Reads Structures definitions | hh-core | done | linux+windows |
| .CT load: comments | Reads table comments | hh-core | done | linux+windows |
| .CT load: user-defined symbols | Reads UserdefinedSymbols | hh-core | planned | linux+windows |
| .CT load: disassembler comments | Reads DisassemblerComments | hh-core | planned | linux+windows |
| .CT load: files stored in table | Reads embedded files | hh-core | planned | linux+windows |
| .CT load: custom types | Reads CustomTypes | hh-core | planned | linux+windows |
| .CT save | Writes XML compatible with Cheat Engine | hh-core | partial | linux+windows |
| .CT signed tables | Verifies/creates signed tables | hh-core | planned | windows |
| .CT compressed/ extra format (.CETRAINER, .EXE) | Loads tables from trainers | hh-core | planned | windows |
| CT file version compatibility | Reads old and new CheatTable versions | hh-core | planned | linux+windows |
| HeapHook JSON table format | Native JSON table alongside CT | hh-core | done | linux+windows |
| Table open/save/save as menu | File menu operations | app | done | linux+windows |
| Merge table | Append another table to the current one | app | planned | linux+windows |
| Recent tables list | Re-open recent files | app | planned | linux+windows |
| Drag and drop table file | Drop a table onto the window to load | app | planned | linux+windows |
| Unsaved changes prompt | Warn on close with unsaved table | app | planned | linux+windows |
| Table comments window | Show per-table comment text | app | done | linux+windows |
| Table Lua script window | Edit the script run on table load | app | done | linux+windows |
| Ask to run table script on load | Prompt when loading a table with Lua | app | done | linux+windows |
| Table extras: files stored in table | Embed files in the table | hh-core | planned | linux+windows |
| Table extras: show on load as form | Table can display custom forms | hh-lua | planned | linux+windows |
| Address list from Lua | getAddressList and MemoryRecord API | hh-lua | done | linux+windows |
| Address expression editor | Evaluate symbols, modules, and brackets | hh-asm | done | linux+windows |
| Save address list as text | Export entries in text form | app | planned | linux+windows |

## Memory viewer / hex editor

| Feature | CE behaviour (one short sentence) | HeapHook crate | Status | Platforms |
|---|---|---|---|---|
| Memory viewer window | Combined disassembler and hex view of target memory | app | done | linux+windows |
| Hex view | Bytes in hex with ASCII column | app | done | linux+windows |
| Hex view display types | Byte, word, dword, qword, float, double, text | app | done | linux+windows |
| Hex view: edit bytes | Type over bytes to write memory | app | done | linux+windows |
| Hex view: goto address | Jump to address/expression | app | done | linux+windows |
| Hex view: search memory | Find text/bytes/values in memory | hh-scan | planned | linux+windows |
| Hex view: back/forward navigation | History of visited addresses | app | planned | linux+windows |
| Hex view: highlight changes | Colors recently changed bytes | app | done | linux+windows |
| Hex view: data type conversion panel | Interprets selection as several types | app | planned | linux+windows |
| Hex view: copy selection | Copy as hex, text, or address | app | planned | linux+windows |
| Hex view: paste | Paste bytes into memory | app | planned | linux+windows |
| Hex view: set breakpoint on address | Set data breakpoint from hex view | hh-debug | partial | linux+windows |
| Hex view: find what accesses this address | Open access tracer for a byte | hh-debug | planned | linux+windows |
| Hex view: add to address list | Add selected address to the table | app | planned | linux+windows |
| Hex view: structure view | Open structure dissector at address | app | done | linux+windows |
| Hex view: lock/unlock editing | Safety toggle for edit mode | app | planned | linux+windows |
| Hex view: text encoding selection | ASCII, UTF-8, UTF-16 | app | planned | linux+windows |
| Hex view: bytes per row setting | Adjusts column count | app | planned | linux+windows |
| Hex view: font and colors | Appearance options | app | planned | linux+windows |
| Multiple memory viewers | Open several viewer windows | app | planned | linux+windows |
| Memory view: scroll/page keys | Navigation with arrow, PgUp/PgDn | app | done | linux+windows |
| Memory view: show protection of region | Displays region protection info | app | done | linux+windows |
| Memory view: bookmarks | Up to 10 bookmarked addresses with hotkeys | app | planned | linux+windows |
| Memory view: set and delete bookmark | Manage bookmarks | app | planned | linux+windows |
| Memory view: goto bookmark | Jump to a stored bookmark | app | planned | linux+windows |
| Memory view: symbol handler | Resolves module+offset labels | hh-asm | done | linux+windows |
| Memory view: add/define user symbol | Name an address | hh-asm | engine only | linux+windows |
| Memory view: show symbols window | List and edit user-defined symbols | app | planned | linux+windows |
| Memory view: view side-by-side | Split between disassembler and hex | app | planned | linux+windows |
| Memory view: registers pane | Shows registers when broken | app | done | linux+windows |
| Memory view: stack pane | Shows stack contents | app | done | linux+windows |
| Memory view: dissect data / structures | Open structure dissector on selection | app | done | linux+windows |
| Memory view: save memory region to file | Dump a range to a file | hh-core | done | linux+windows |
| Memory view: load memory from file | Write file contents to memory | hh-core | done | linux+windows |
| Memory view: compare memory with file | Diff memory and file | hh-core | partial | linux+windows |
| Memory view: allocate memory | Allocates a block in the target | hh-core | engine only | linux+windows |
| Memory view: change protection | Changes page protection | hh-core | done | linux+windows |
| Memory view: free memory | Releases an allocation | hh-core | engine only | linux+windows |
| Memory view: show writable/ex flags | Shows page permission flags | app | done | linux+windows |
| Memory view: refresh interval | Control the refresh rate | app | done | linux+windows |
| Memory view: hotkeys list | Documented hotkeys such as Ctrl+G | app | partial | linux+windows |

## Disassembler and assembler

| Feature | CE behaviour (one short sentence) | HeapHook crate | Status | Platforms |
|---|---|---|---|---|
| x86 disassembly | Decodes 32-bit instructions | hh-asm | done | linux+windows |
| x86-64 disassembly | Decodes 64-bit instructions | hh-asm | done | linux+windows |
| SSE/AVX decoding | Decodes vector instruction sets | hh-asm | done | linux+windows |
| AVX-512 decoding | Decodes EVEX instructions | hh-asm | done | linux+windows |
| ARM / AArch64 disassembly | Decodes ARM for Android targets | hh-asm | planned | linux |
| Disassembler view | Scrollable listing with bytes and opcodes | app | done | linux+windows |
| Disassembler: symbolic addresses | Shows module+offset and names | hh-asm | done | linux+windows |
| Disassembler: show module addresses | Toggle address formatting | app | planned | linux+windows |
| Disassembler: show symbols | Toggle symbol display | app | partial | linux+windows |
| Disassembler: opcode bytes column | Raw bytes column | app | done | linux+windows |
| Disassembler: jump lines | Draws arrows between jump source and target | app | planned | linux+windows |
| Disassembler: comments | Per-address user comments | app | partial | linux+windows |
| Disassembler: header lines | User-defined headers | app | planned | linux+windows |
| Disassembler: syntax (Intel/AT&T) | Intel syntax display, AT&T option | hh-asm | partial | linux+windows |
| Disassembler: color highlighting | Colors for jumps, calls, registers | app | partial | linux+windows |
| Disassembler: goto address | Jump to address/expression | app | done | linux+windows |
| Disassembler: follow jump/call | Navigate to target of branch | app | done | linux+windows |
| Disassembler: go back | Navigation history | app | done | linux+windows |
| Disassembler: set breakpoint (F5) | Toggle breakpoint at instruction | hh-debug | done | linux+windows |
| Disassembler: run to here | Run until selected address | hh-debug | done | linux+windows |
| Disassembler: set current instruction (new EIP) | Redirect execution | hh-debug | partial | linux+windows |
| Disassembler: find what addresses this code accesses | Trace memory accessed by instruction | hh-debug | done | linux+windows |
| Disassembler: replace with NOPs | Overwrites selection with NOP | hh-asm | done | linux+windows |
| Disassembler: assemble/edit instruction | Type asm to patch bytes | hh-asm | done | linux+windows |
| Disassembler: copy to clipboard | Copy address/bytes/opcodes | app | planned | linux+windows |
| Disassembler: search for assembly | Search text in disassembly | hh-asm | planned | linux+windows |
| Disassembler: previous/next function | Navigate by function boundary | hh-asm | planned | linux+windows |
| Disassembler: show register state | Displays registers next to code when broken | app | planned | linux+windows |
| Disassembler: tooltips | Hover shows pointed data | app | planned | linux+windows |
| Disassembler: find call / jump targets | Reference finder for branches | hh-asm | partial | linux+windows |
| Disassembler: go to function start | Detects function start heuristic | hh-asm | partial | linux+windows |
| Disassembler: sync with hex view | Selection mirrors in hex view | app | planned | linux+windows |
| Disassembler: add to code list | Record the address in the code list | app | done | linux+windows |
| Disassembler: auto-guess value type | Guess data type used by instruction | hh-asm | planned | linux+windows |
| Disassembler: custom override via Lua | Lua can extend disassembler output | hh-lua | planned | linux+windows |
| Disassembler: DBVM watch / cloak | Right-click DBVM watch options | hh-debug | needs decision | windows |
| Inline assembler | Single-instruction assembler with x86/x64 syntax | hh-asm | done | linux+windows |
| Assembler: labels and symbols | Accepts symbolic operands | hh-asm | done | linux+windows |
| Assembler: data directives (db, dw, dd, dq) | Emits raw data | hh-asm | done | linux+windows |
| Assembler: SSE/AVX encoding | Encodes vector instructions | hh-asm | done | linux+windows |
| Assembler: relative jump auto-size | Chooses short or near jumps | hh-asm | done | linux+windows |
| Assembler: registerAssembler Lua extension | Scripts add pseudo-instructions | hh-lua | planned | linux+windows |
| Assembler: bytes preview | Shows encoded bytes before applying | app | planned | linux+windows |
| Symbol handler: module exports | Reads export tables for names | hh-asm | done | linux+windows |
| Symbol handler: PDB / debug symbols | Loads debug symbol files | hh-asm | planned | windows |
| Symbol handler: ELF symbols / DWARF | Reads ELF symtab and DWARF info | hh-asm | partial | linux |
| Symbol handler: user-defined symbols | Register names for addresses | hh-asm | partial | linux+windows |
| Symbol handler: reinitialize | Refresh module and symbol lists | hh-asm | planned | linux+windows |
| Symbol handler: Lua registerSymbolLookup | Scripts add symbol resolvers | hh-lua | planned | linux+windows |
| Symbol handler: dotnet/mono symbols | Managed method names in disassembly | hh-inject | planned | linux+windows |
| Expression evaluator | Evaluate `[base+10]+8` style expressions | hh-asm | done | linux+windows |

## Auto Assembler

| Feature | CE behaviour (one short sentence) | HeapHook crate | Status | Platforms |
|---|---|---|---|---|
| Script structure `[ENABLE]`/`[DISABLE]` | Splits a script into enable and disable sections | hh-asm | done | linux+windows |
| Syntax check | Validates the script without running it | hh-asm | done | linux+windows |
| Execute / disable with state | Runs a script and tracks allocations for disable | hh-asm | done | linux+windows |
| `alloc(name,size[,address])` | Allocates memory in the target, optionally near an address | hh-asm | done | linux+windows |
| `dealloc(name)` | Frees an allocation | hh-asm | done | linux+windows |
| `label(name)` | Declares a label | hh-asm | done | linux+windows |
| `define(name,value)` | Declares a text replacement | hh-asm | done | linux+windows |
| `undefine(name)` | Removes a define | hh-asm | planned | linux+windows |
| `registersymbol(name)` | Makes a symbol available globally | hh-asm | done | linux+windows |
| `unregistersymbol(name)` | Removes a global symbol | hh-asm | done | linux+windows |
| `aobscan(name,pattern)` | Scans for a byte pattern and defines a symbol | hh-asm | done | linux+windows |
| `aobscanmodule(name,module,pattern)` | AOB scan restricted to a module | hh-asm | done | linux+windows |
| `aobscanregion(name,start,stop,pattern)` | AOB scan restricted to a range | hh-asm | done | linux+windows |
| `assert(address,bytes)` | Aborts if the bytes at address differ | hh-asm | done | linux+windows |
| `readmem(address,size)` | Copies target bytes into the script as data | hh-asm | done | linux+windows |
| `loadbinary(address,filename)` | Writes a file's contents to memory | hh-asm | planned | linux+windows |
| `loadlibrary(dllname)` | Loads a library into the target | hh-inject | planned | windows |
| `createthread(address)` | Starts a thread in the target | hh-inject | planned | linux+windows |
| `createthreadandwait(address,timeout)` | Starts a thread and waits for it | hh-inject | planned | linux+windows |
| `fullaccess(address,size)` | Makes a range readable, writable, executable | hh-asm | done | linux+windows |
| `include(file)` | Includes another script from the table | hh-asm | partial | linux+windows |
| `luacall(code)` | Runs Lua code during assembly | hh-lua | planned | linux+windows |
| `{$lua}` / `{$asm}` blocks | Embeds Lua code executed at assembly time | hh-lua | done | linux+windows |
| `{$luacode}` blocks | Compiles Lua to run inside the target process | hh-inject | planned | linux+windows |
| `{$c}` / `{$ccode}` blocks | Compiles C code with the built-in compiler | hh-asm | planned | linux+windows |
| `{$strict}` | Makes the assembler strict about operand sizes | hh-asm | partial | linux+windows |
| `{$nostrict}` | Disables strict mode | hh-asm | planned | linux+windows |
| `{$define}` / `{$ifdef}` / `{$ifndef}` / `{$else}` / `{$endif}` | Conditional assembly | hh-asm | planned | linux+windows |
| `{$ifdef}` with 64-bit/32-bit target flags | Branches on target bitness | hh-asm | planned | linux+windows |
| `{$try}` / `{$except}` | Error-tolerant sections that fall back on failure | hh-asm | partial | linux+windows |
| `{$ccode}` symbol import | C code can use script symbols | hh-asm | planned | linux+windows |
| `{$dotnet}`/`cscompile` | Compiles C# and loads it into a .NET target | hh-inject | planned | windows |
| `globalalloc(name,size)` | Allocation that survives script disable | hh-asm | done | linux+windows |
| `struct` definitions | Defines a structure for symbolic offsets | hh-asm | done | linux+windows |
| `reassemble(address)` | Reassembles instructions at an address | hh-asm | done | linux+windows |
| `prefer(32/64)` hints | Prefers a code size for ambiguous instructions | hh-asm | planned | linux+windows |
| `db`/`dw`/`dd`/`dq` | Emits raw data | hh-asm | done | linux+windows |
| `dw`/`dd` with floats (`dd (float)1.5`) | Emits float data | hh-asm | done | linux+windows |
| `org address` | Moves the assembly pointer | hh-asm | planned | linux+windows |
| `align n[,byte]` | Pads to alignment | hh-asm | planned | linux+windows |
| `nop n` | Emits N NOP bytes | hh-asm | done | linux+windows |
| `{$lua}` return values / `[ENABLE]` error handling | Lua can abort the script | hh-lua | done | linux+windows |
| Address-based code patch (`address:` + bytes) | Writes assembled code at a given address | hh-asm | done | linux+windows |
| `address-offset` expressions | Supports `symbol+offset` targets | hh-asm | done | linux+windows |
| Original-bytes auto-restore in `[DISABLE]` | Restores overwritten bytes automatically via comment blocks | hh-asm | done | linux+windows |
| Code injection template | Generates full injection script template | app | engine only | linux+windows |
| AOB injection template | Generates AOB-based injection script | app | done | linux+windows |
| Full injection template | Template with allocated code cave and return jump | app | engine only | linux+windows |
| API hook template | Template hooking a Windows API by name | hh-asm | planned | windows |
| Cheat table framework code template | Generates framework code for tables | app | planned | linux+windows |
| Lua-registered templates | `registerAutoAssemblerTemplate` adds templates | hh-lua | planned | linux+windows |
| Custom AA commands from Lua | `registerAutoAssemblerCommand` adds commands | hh-lua | planned | linux+windows |
| Script editor with syntax highlighting | Editor with highlighting for AA and Lua | app | planned | linux+windows |
| Script editor: find/replace | Search text in the script | app | planned | linux+windows |
| Script editor: assign to current cheat table | Saves script into a table entry | app | done | linux+windows |
| Script editor: execute | Run the script immediately | app | partial | linux+windows |
| Script editor: undo/redo | Edit history | app | planned | linux+windows |
| Script editor: auto-complete | Completion for symbols and commands | app | planned | linux+windows |
| Script editor: tab/ F9 hotkeys | Shortcuts for running and checking | app | partial | linux+windows |
| Mono AA commands (`monopipe`, `mono_*`) | Mono-specific script commands | hh-inject | planned | linux+windows |
| Script disable via checkbox | Toggling the entry runs `[DISABLE]` | hh-asm | done | linux+windows |
| Script error reporting with line | Reports syntax errors with line number | hh-asm | done | linux+windows |
| Code cave finder | Locate unused executable space | hh-asm | done | linux+windows |
| Near allocation (within +-2GB) | Allocates close to a given address for relative jumps | hh-asm | done | linux+windows |
| Scan hooks: `aobscanmodule` unique check | Fails when pattern is not unique | hh-asm | planned | linux+windows |

## Debugger

| Feature | CE behaviour (one short sentence) | HeapHook crate | Status | Platforms |
|---|---|---|---|---|
| Attach debugger | Starts debugging the opened process | hh-debug | done | linux+windows |
| Detach debugger | Stops debugging without killing the target | hh-debug | done | linux+windows |
| Debugger interface: Windows native debugger | Uses Win32 debug API | hh-debug | done | windows |
| Debugger interface: VEH debugger | Injects an exception handler for in-process debugging | hh-debug | planned | windows |
| Debugger interface: Kernel debugger (DBK) | Driver-based debugging stealthier than Win32 | hh-debug | needs decision | windows |
| Debugger interface: ptrace | Uses ptrace on Linux | hh-debug | done | linux |
| Debugger interface: gdb server | Connect to a GDB stub | hh-debug | planned | linux |
| Software breakpoint (int3) | Execution breakpoint by patching an int3 | hh-debug | done | linux+windows |
| Hardware breakpoint: execute | Debug register breakpoint on execution | hh-debug | done | linux+windows |
| Hardware breakpoint: write | Break when memory is written | hh-debug | done | linux+windows |
| Hardware breakpoint: read/write | Break on read or write | hh-debug | done | linux+windows |
| Hardware breakpoint sizes 1/2/4/8 | Watches ranges up to 8 bytes | hh-debug | done | linux+windows |
| Page-exception breakpoint | Uses guard-page protection to catch access | hh-debug | planned | windows |
| Breakpoint list | Window listing all breakpoints | app | done | linux+windows |
| Breakpoint conditions | Break only if an expression/Lua condition is true | hh-debug | done | linux+windows |
| Breakpoint: trigger count | Break after N hits | hh-debug | planned | linux+windows |
| Breakpoint: break and trace | Single-steps and logs instructions after a hit | hh-debug | done | linux+windows |
| Trace: max count | Limits number of traced instructions | hh-debug | done | linux+windows |
| Trace: step over calls | Do not trace into calls | hh-debug | done | linux+windows |
| Trace: stop condition | Stop on a given condition | hh-debug | engine only | linux+windows |
| Trace: step over system modules | Skip traces inside system DLLs | hh-debug | planned | windows |
| Trace window | Tree of traced instructions with registers | app | done | linux+windows |
| Trace: save/load trace | Persist trace to file | hh-debug | planned | linux+windows |
| Trace: search | Search in traced instructions | app | planned | linux+windows |
| Find out what accesses this address | Lists instructions that read/write the address | hh-debug | done | linux+windows |
| Find out what writes to this address | Lists instructions that write the address | hh-debug | done | linux+windows |
| Find out what addresses this instruction accesses | Lists addresses touched by an instruction | hh-debug | done | linux+windows |
| Access/write result window | Shows instruction, count, and register state | app | done | linux+windows |
| Result window: show register values | Registers at the time of the hit | app | done | linux+windows |
| Result window: more info | Extended hit details and stack | app | planned | linux+windows |
| Result window: replace with code that does nothing | NOPs the found instruction | hh-asm | done | linux+windows |
| Result window: add to code list | Saves instruction in the code list | app | done | linux+windows |
| Result window: show disassembler | Jump to instruction | app | done | linux+windows |
| Result window: show structure | Open dissector from register | app | planned | linux+windows |
| Result window: copy to address list | Adds found addresses to table | app | planned | linux+windows |
| Result window: stop/start | Pause recording | app | partial | linux+windows |
| Exception handling options | Choose which exceptions break | hh-debug | done | linux+windows |
| Step into | Execute one instruction | hh-debug | done | linux+windows |
| Step over | Execute one instruction, skipping calls | hh-debug | done | linux+windows |
| Step out / run till return | Run until current function returns | hh-debug | done | linux+windows |
| Run | Continue execution | hh-debug | done | linux+windows |
| Run to cursor | Run until selected address | hh-debug | done | linux+windows |
| Pause / break | Stops execution on demand | hh-debug | done | linux+windows |
| Single-step options (step ignore exceptions) | Handle exceptions while stepping | hh-debug | planned | linux+windows |
| Change registers | Edit general-purpose registers while stopped | hh-debug | done | linux+windows |
| Edit flags | Edit EFLAGS bits | hh-debug | done | linux+windows |
| Edit FPU / XMM registers | Edit floating point and vector registers | hh-debug | engine only | linux+windows |
| Register view | Registers with change highlights | app | done | linux+windows |
| Set new instruction pointer | Continue from another address | hh-debug | done | linux+windows |
| Stack view | Shows stack with symbol annotations | app | done | linux+windows |
| Stack trace / call stack | Walks frames of the current thread | hh-debug | engine only | linux+windows |
| Stack: follow pointer in disassembler/hex | Navigate from a stack slot | app | done | linux+windows |
| Thread list | Lists threads with state | hh-debug | done | linux+windows |
| Thread list: break thread | Break on a specific thread | hh-debug | planned | linux+windows |
| Thread list: suspend/resume thread | Control individual threads | hh-debug | done | linux+windows |
| Thread list: show context | View registers of a thread | app | done | linux+windows |
| Break on thread creation | Break when a thread starts | hh-debug | planned | windows |
| Break on module load | Break when a library loads | hh-debug | planned | windows |
| Debug-print output (OutputDebugString) | Shows target debug strings | hh-debug | planned | windows |
| Debug output window | Log of events | app | planned | linux+windows |
| Debugger Lua API | debug_* functions and breakpoint callbacks | hh-lua | planned | linux+windows |
| Breakpoint callback (onBreakpoint) | Lua hook invoked on break | hh-lua | planned | linux+windows |
| Handle breakpoint in Lua with context table | Scripts read/write registers on break | hh-lua | planned | linux+windows |
| Exception break on access violation | Break on crashes | hh-debug | done | linux+windows |
| Stealth: hide debugger | Hides debug registers and flags from the target | hh-debug | needs decision | windows |
| Remote debugging via ceserver | Debug a remote target | hh-debug | planned | linux+windows |
| Hardware breakpoint conflicts | Handles limited debug registers | hh-debug | partial | linux+windows |
| Breakpoint on API calls by name | Resolve and break on exported functions | hh-debug | planned | linux+windows |
| Break on memory allocation / free (heap) | Logs heap events | hh-debug | planned | windows |
| Auto-attach debugger on process start | Debugs a spawned process from the first instruction | hh-debug | planned | linux+windows |
| Debug child processes | Follows forks/child creation | hh-debug | planned | linux+windows |
| DBVM breakpoints (hypervisor) | Invisible breakpoints via DBVM | hh-debug | needs decision | windows |

## Pointer scanner

| Feature | CE behaviour (one short sentence) | HeapHook crate | Status | Platforms |
|---|---|---|---|---|
| Pointer scan for address | Finds pointer paths reaching a target address | hh-ptr | done | linux+windows |
| Max offset per level | Limits offset size | hh-ptr | done | linux+windows |
| Max level | Limits chain depth | hh-ptr | done | linux+windows |
| Static addresses only | Restricts base to module/static memory | hh-ptr | done | linux+windows |
| Allow stack addresses as base | Includes stack bases | hh-ptr | done | linux+windows |
| Pointer must end with offset | Requires specific final offsets | hh-ptr | done | linux+windows |
| Pointer alignment | Only aligned pointers | hh-ptr | done | linux+windows |
| Same-offsets-only mode | Restricts chains to a given offset list | hh-ptr | partial | linux+windows |
| No looping pointers | Prevents cyclic paths | hh-ptr | done | linux+windows |
| Compare results with other saved pointer scans | Intersects scan files | hh-ptr | done | linux+windows |
| Stop at module address only | Base must be a module-relative address | hh-ptr | done | linux+windows |
| Use heap data for scan | Treat heap allocations as pointer sources | hh-ptr | done | windows |
| Pointer path via pointermap | Uses a saved pointermap as the data source | hh-ptr | done | linux+windows |
| Generate pointermap | Saves all pointers of the process to a file | hh-ptr | done | linux+windows |
| Compare two pointermaps | Scans using two maps to filter stable paths | hh-ptr | done | linux+windows |
| Pointer scan result window | Table of base, offsets, and current value | app | done | linux+windows |
| Pointer rescan | Re-checks paths against a new address | hh-ptr | done | linux+windows |
| Rescan: compare to other scan results | Keeps paths pointing to a second address | hh-ptr | done | linux+windows |
| Rescan: value must match | Filter by value at the resolved address | hh-ptr | done | linux+windows |
| Rescan: use other process / after restart | Verify paths after game restart | hh-ptr | done | linux+windows |
| Pointer scan save/load (.PTR) | Stores scan results to disk | hh-ptr | done | linux+windows |
| Pointer scan export | Export results to text/CT | hh-ptr | planned | linux+windows |
| Pointer scan: add to address list | Adds a path as a pointer entry | app | done | linux+windows |
| Pointer scan: sort / filter results | Sorts by column, searches | app | done | linux+windows |
| Pointer scan: multithreaded | Configurable thread count | hh-ptr | done | linux+windows |
| Pointer scan: low-memory mode | Writes results to disk incrementally | hh-ptr | done | linux+windows |
| Pointer scan: compressed paths | Prefix-shared path storage | hh-ptr | planned | linux+windows |
| Pointer scan: reverse scan from base | Search from candidate bases | hh-ptr | planned | linux+windows |
| Pointer scan: scan region limit | Restrict regions scanned | hh-ptr | done | linux+windows |
| Pointer scan: pause and resume | Pause scan; continue later | hh-ptr | planned | linux+windows |
| Pointer scan: progress and ETA | Progress display | app | partial | linux+windows |
| Distributed pointer scan | Offload scanning to other machines | hh-ptr | planned | linux+windows |
| Pointer scan: Lua API | Scripts drive pointer scans | hh-lua | planned | linux+windows |
| Pointer scan: default settings page | Settings defaults for the scanner | app | planned | linux+windows |
| Auto-guess structure from pointer chain | Names levels from known structures | hh-ptr | planned | linux+windows |
| Instant "Find what accesses" pointer helper | Walks accessor instructions to build chains | hh-ptr | planned | linux+windows |

## Structure dissector

| Feature | CE behaviour (one short sentence) | HeapHook crate | Status | Platforms |
|---|---|---|---|---|
| Dissect data/structures window | Interprets memory as editable structure | app | done | linux+windows |
| Auto-guess structure | Detects likely types per offset | hh-core | done | linux+windows |
| Define new structure | Create named structure definitions | app | done | linux+windows |
| Element types | Byte, word, dword, qword, float, double, string, pointer, array | app | done | linux+windows |
| Change element type | Retype fields | app | done | linux+windows |
| Add/delete element | Edit field layout | app | done | linux+windows |
| Pointer expansion | Expand a pointer field into a nested structure | app | done | linux+windows |
| Nested structures | Child structures inside structures | app | done | linux+windows |
| Multiple structure windows | Compare several addresses at once | app | done | linux+windows |
| Structure compare columns | Compare same structure at several addresses | app | done | linux+windows |
| Lock/unlock structure | Prevent edits | app | planned | linux+windows |
| Structure in global list | Shared definitions across windows | app | done | linux+windows |
| Structure save/load in table | Stored in the cheat table | hh-core | done | linux+windows |
| Structure export/import | Save/load definitions as XML/files | hh-core | partial | linux+windows |
| Structure: add to address list | Adds elements as entries | app | done | linux+windows |
| Structure: show hex/decimal/signed | Display options | app | done | linux+windows |
| Structure: highlight changes | Highlights elements that changed | app | planned | linux+windows |
| Structure: auto-refresh | Periodic update | app | done | linux+windows |
| Structure: generate C/C# definition | Export to code | app | planned | linux+windows |
| Structure: RTTI/class name detection | Reads vtable RTTI names | hh-core | planned | linux+windows |
| Structure: Lua override registration | Scripts customize structure naming | hh-lua | planned | linux+windows |
| Structure: Mono/.NET class import | Fill structure from managed classes | hh-inject | planned | linux+windows |
| Structure: bit fields | Show bit-level view of an element | app | planned | linux+windows |

## Code tools

| Feature | CE behaviour (one short sentence) | HeapHook crate | Status | Platforms |
|---|---|---|---|---|
| Advanced options window | List of code modified or watched, with pause | app | partial | windows |
| Code list | Stores addresses of modified/found code | app | done | linux+windows |
| Code list: replace with NOPs | Patch and keep original bytes for restore | hh-asm | done | linux+windows |
| Code list: restore original code | Undo patch | hh-asm | done | linux+windows |
| Code list: save/load | Persist code list | app | done | linux+windows |
| Code list: pause the game | Pause target from the advanced window | app | planned | linux+windows |
| Code list: hotkey to pause | Hotkey to pause/resume | app | planned | linux+windows |
| Code list: find out what addresses | Run debug tracing from list entries | hh-debug | planned | linux+windows |
| Dissect code | Scans modules for calls, jumps, strings | hh-asm | done | linux+windows |
| Dissect code: referenced strings | Lists strings and who references them | hh-asm | done | linux+windows |
| Dissect code: referenced functions | Lists called functions and call counts | hh-asm | done | linux+windows |
| Dissect code: show references | Shows callers of an address | hh-asm | done | linux+windows |
| Dissect code: module selection | Choose modules to scan | app | done | linux+windows |
| Dissect code: save/load results | Persist results | app | planned | linux+windows |
| Dissect code: Lua access | Scripts use dissected data | hh-lua | planned | linux+windows |
| Find assembly instruction | Search code for text/pattern | hh-asm | planned | linux+windows |
| Find assembly instruction: range and options | Limit range, case, jumps | hh-asm | planned | linux+windows |
| Code filter | Records which code ran during an interval | hh-debug | planned | linux+windows |
| Code filter: add module | Select modules to filter | hh-debug | planned | linux+windows |
| Code filter: mark as ran / not ran | Narrow code addresses by action | hh-debug | planned | linux+windows |
| Code filter: save results | Persist filtered code set | app | planned | linux+windows |
| Ultimap 1 | Uses branch trace store to record executed code | hh-debug | planned | windows |
| Ultimap 2 | Uses Intel PT to record execution | hh-debug | planned | windows |
| Ultimap: record ranges | Restrict recorded address range | hh-debug | planned | windows |
| Ultimap: filter by "ran" | Narrow code by what ran | hh-debug | planned | windows |
| Ultimap: Lua API | Scripts control Ultimap | hh-lua | planned | windows |
| Intel PT / coverage on Linux | perf-based execution recording | tbd | planned | linux |
| Code coverage view | Visualize executed blocks | app | planned | linux+windows |
| Function finder / call graph | Show callers and callees | hh-asm | partial | linux+windows |
| Break on execute of dissected function | Set breakpoints from reference lists | hh-debug | planned | linux+windows |

## Speedhack

| Feature | CE behaviour (one short sentence) | HeapHook crate | Status | Platforms |
|---|---|---|---|---|
| Speedhack enable | Injects a DLL scaling time functions | hh-inject | partial | linux+windows |
| Speed multiplier | User sets speed factor (0.1x to many x) | hh-inject | partial | linux+windows |
| Speedhack presets | Stored speed values with hotkeys | app | planned | linux+windows |
| Speedhack hotkeys | Global keys to apply speeds | app | partial | linux+windows |
| Hooked time APIs: QueryPerformanceCounter | Scales performance counter | hh-inject | planned | windows |
| Hooked time APIs: GetTickCount/GetTickCount64 | Scales tick counts | hh-inject | planned | windows |
| Hooked time APIs: timeGetTime | Scales multimedia timer | hh-inject | planned | windows |
| Hooked time APIs: clock_gettime / gettimeofday | Scales Linux time sources | hh-inject | partial | linux |
| Speedhack: Lua speedhack_setSpeed | Script control of speed | hh-lua | partial | linux+windows |
| Speedhack: get current speed | Query active speed | hh-lua | partial | linux+windows |
| Speedhack: sleep scaling | Scales sleep and waits | hh-inject | partial | linux+windows |
| Speedhack in trainer | Trainer can include speedhack | app | planned | windows |
| Speedhack: disable and restore | Turn off cleanly | hh-inject | partial | linux+windows |

## Lua engine

| Feature | CE behaviour (one short sentence) | HeapHook crate | Status | Platforms |
|---|---|---|---|---|
| Embedded Lua 5.3 interpreter | Runs Lua in the CE process with CE bindings | hh-lua | done | linux+windows |
| Lua engine window | Console for running Lua with history and output | app | done | linux+windows |
| Lua: memory read/write (about 40 functions: readInteger, readFloat, readString, readBytes, readPointer, writeInteger, writeBytes, writeString) | Reads and writes target memory | hh-lua | done | linux+windows |
| Lua: local memory access (about 12 functions: readIntegerLocal, writeIntegerLocal, readBytesLocal) | Reads/writes CE's own memory | hh-lua | done | linux+windows |
| Lua: memory allocation and copy (about 10 functions: allocateMemory, deAlloc, copyMemory, compareMemory, mapMemory, allocateSharedMemory) | Manages target memory blocks | hh-lua | partial | linux+windows |
| Lua: address and symbols (about 25 functions: getAddress, getAddressSafe, getNameFromAddress, registerSymbol, unregisterSymbol, inModule, getModuleSize, reinitializeSymbolhandler) | Resolves names and addresses | hh-lua | partial | linux+windows |
| Lua: process (about 20 functions: openProcess, getOpenedProcessID, getProcesslist, createProcess, enumModules, enumMemoryRegions, pause, unpause, getHandleList) | Controls and inspects processes | hh-lua | partial | linux+windows |
| Lua: threads and sync (about 10 functions: getCPUCount, getThreadlist, synchronize, queue, createThread, inMainThread) | Thread helpers and CE thread class | hh-lua | partial | linux+windows |
| Lua: scanning (about 15 functions plus MemScan/FoundList classes: AOBScan, AOBScanUnique, AOBScanModuleUnique, createMemScan, getCurrentMemscan) | Drives scans and reads results | hh-lua | partial | linux+windows |
| Lua: cheat table / memory records (about 20 functions plus MemoryRecord class: getAddressList, loadTable, saveTable, createTableFile, findTableFile) | Manipulates table entries and files | hh-lua | partial | linux+windows |
| Lua: forms and GUI classes (about 120 classes/functions: createForm, createButton, createLabel, createEdit, createListView, createTimer, createImage, showMessage, inputQuery, messageDialog) | Builds custom GUIs | hh-lua | partial | linux+windows |
| Lua: CE UI access (about 20 functions: getMainForm, getMemoryViewForm, getFormCount, getForm, getSettings, getApplication) | Reaches built-in CE windows | hh-lua | planned | linux+windows |
| Lua: input devices (about 15 functions: isKeyPressed, keyDown, keyUp, doKeyPress, getMousePos, setMousePos, mouse_event, createHotkey) | Simulates and reads input | hh-lua | partial | linux+windows |
| Lua: screen and windows (about 15 functions: getScreenWidth, getPixel, findWindow, getWindow, sendMessage, hookWndProc) | Screen and window helpers | hh-lua | planned | windows |
| Lua: debugger (about 25 functions: debugProcess, debug_setBreakpoint, debug_removeBreakpoint, debug_continueFromBreakpoint, debug_getContext, debugger_onBreakpoint) | Controls the debugger | hh-lua | planned | linux+windows |
| Lua: assembler and AA (about 20 functions: autoAssemble, autoAssembleCheck, disassemble, getInstructionSize, registerAssembler, registerAutoAssemblerCommand, generateAPIHookScript) | Assembles and disassembles from scripts | hh-lua | partial | linux+windows |
| Lua: disassembler classes (about 10 functions: getVisibleDisassembler, DisassemblerView, Disassembler.disassemble) | Disassembler objects and view hooks | hh-lua | planned | linux+windows |
| Lua: files and directories (about 20 functions: fileExists, deleteFile, getFileList, getDirectoryList, extractFileName, getFileVersion, md5file) | File system helpers | hh-lua | planned | linux+windows |
| Lua: streams and strings classes (about 15 classes: createMemoryStream, createStringlist, createStringStream, createFileStream) | Stream and list utilities | hh-lua | partial | linux+windows |
| Lua: conversions and bit ops (about 25 functions: bAnd, bOr, bXor, bShl, bShr, bNot, byteTableToString, stringToMD5String, ansiToUtf8) | Number and string conversions | hh-lua | partial | linux+windows |
| Lua: structures (about 12 functions plus Structure classes: createStructure, registerStructureDissectOverride, registerStructureNameLookup) | Creates and customizes structures | hh-lua | planned | linux+windows |
| Lua: custom types (about 4 functions: registerCustomTypeLua, registerCustomTypeAutoAssembler, onAutoGuess) | Defines custom value types | hh-lua | planned | linux+windows |
| Lua: injection and external code (about 10 functions: injectDll, executeCode, executeCodeLocal, executeCodeEx, loadPlugin, shellExecute) | Runs code in processes | hh-lua | planned | linux+windows |
| Lua: DBK kernel API (about 30 functions: dbk_initialize, dbk_readMSR, dbk_getCR3, dbk_getPhysicalAddress, dbk_useKernelmodeOpenProcess) | Driver-based kernel access | hh-lua | needs decision | windows |
| Lua: DBVM API (about 40 functions: dbvm_initialize, dbvm_watch_writes, dbvm_watch_reads, dbvm_cloak_activate, dbvm_read_physical_memory) | Hypervisor functions | hh-lua | needs decision | windows |
| Lua: Mono / .NET API (about 60 functions: mono_enumDomains, mono_findClass, mono_findMethod, mono_invoke_method, mono_object_getClass, dotnet*) | Managed runtime inspection | hh-lua | planned | linux+windows |
| Lua: Java API (about 10 functions: java_* class and field inspection) | JVM inspection | hh-lua | planned | linux+windows |
| Lua: translation (about 6 functions: getTranslationFolder, loadPOFile, translate, translateID) | Localization helpers | hh-lua | planned | linux+windows |
| Lua: sound and speech (about 6 functions: playSound, beep, speak, speakEnglish, createSoundObject) | Audio helpers | hh-lua | partial | linux+windows |
| Lua: graphics objects (about 25 classes: Canvas, Bitmap, Picture, Font, Pen, Brush) | Drawing objects used by forms | hh-lua | planned | linux+windows |
| Lua: D3D hook API (about 20 functions: createD3DHook, D3DHook_Texture, D3DHook_FontMap, D3DHook_RenderObject) | Overlay rendering objects | hh-lua | planned | windows |
| Lua: networking and pipes (about 12 functions: getInternet, createPipe, createTCPClient, createSocket, SQL classes) | Network and IPC helpers | hh-lua | planned | linux+windows |
| Lua: SQL and XML (about 15 functions/classes: SQLQuery, SQLConnection, XMLDocument) | Database and XML access | hh-lua | planned | linux+windows |
| Lua: misc system (about 40 functions: getCEVersion, cheatEngineIs64Bit, getCheatEngineDir, closeCE, sleep, createRef, getRef, writeToClipboard, resetLuaState) | General helpers | hh-lua | partial | linux+windows |
| Lua: trainers and protection (about 8 functions: registerEXETrainerFeature, activateProtection, enableDRM, signTable) | Trainer and table protection | hh-lua | planned | windows |
| Lua: remote and CEServer (about 5 functions: connectToCEServer, getOpenedProcessID remote variants) | Connect to remote server | hh-lua | planned | linux+windows |
| Lua: native compile (about 6 functions: compile, compileCS, compileTCC, addCIncludePath) | Compile C or C# at runtime | hh-lua | planned | linux+windows |
| Lua: object model (about 20 functions: inheritsFromObject, getPropertyList, setProperty, getProperty, Component/Control base classes) | Class and property access | hh-lua | planned | linux+windows |
| Lua: events and timers (about 8 functions: createTimer, createThread, synchronize, queue) | Timer and callback support | hh-lua | done | linux+windows |
| Lua auto-run scripts folder (autorun) | Runs scripts from the CE autorun folder at start | hh-lua | planned | linux+windows |
| Lua script error reporting | Shows errors with line numbers | app | done | linux+windows |
| Lua sandbox policy for tables | Warn before running table scripts | app | done | linux+windows |
| Lua: onOpenProcess / onAutoGuess callbacks | Event hooks into CE | hh-lua | partial | linux+windows |
| Lua: undocumented/`ce-plugin` extension hooks | Hooks from plugins into Lua | hh-lua | planned | linux+windows |

## Trainer generator

| Feature | CE behaviour (one short sentence) | HeapHook crate | Status | Platforms |
|---|---|---|---|---|
| Generate trainer from table | Builds a standalone EXE from the current table | app | planned | windows |
| Trainer: custom form designer | Visual designer for trainer UI | app | planned | linux+windows |
| Trainer: embedded Lua script | Trainer runs the table Lua | hh-lua | planned | linux+windows |
| Trainer: hotkey activation of cheats | Hotkeys toggle entries | app | planned | linux+windows |
| Trainer: compression and packing | Compresses payload | app | planned | windows |
| Trainer: icon and title | Custom icon and window title | app | planned | windows |
| Trainer: about text / website link | Text in the trainer UI | app | planned | windows |
| Trainer: audio files | Embedded music and sounds | app | planned | windows |
| Trainer: auto attach to game | Trainer opens target by name | app | planned | linux+windows |
| Trainer: DBVM/driver option | Include driver in the trainer | app | needs decision | windows |
| Trainer: 32/64-bit templates | Separate stubs per arch | app | planned | windows |
| Trainer: Linux executable | Generate Linux trainer binary | app | planned | linux |
| Trainer: signed tables / DRM | Protect trainer content | app | planned | windows |
| Trainer: CETRAINER file format | Open and edit trainer files | hh-core | planned | windows |
| Trainer: extract table from trainer | Recover table from a trainer | hh-core | planned | windows |

## Mono / .NET / Java features

| Feature | CE behaviour (one short sentence) | HeapHook crate | Status | Platforms |
|---|---|---|---|---|
| Mono data collector injection | Injects a collector DLL to inspect Mono processes | hh-inject | planned | linux+windows |
| Mono: activate Mono features menu | Menu to turn Mono support on | app | planned | linux+windows |
| Mono dissector | Tree of domains, assemblies, images, classes | app | planned | linux+windows |
| Mono: class fields and methods | Shows fields and methods for classes | app | planned | linux+windows |
| Mono: JIT a method | Forces compile and shows address | hh-inject | planned | linux+windows |
| Mono: invoke method | Call a method with parameters | hh-inject | planned | linux+windows |
| Mono: find instances of class | Scan for live objects | hh-inject | planned | linux+windows |
| Mono: dissect structure from object | Structure layout from class | app | planned | linux+windows |
| Mono: break on method | Set breakpoint at a method | hh-debug | planned | linux+windows |
| Mono: AA commands | Script syntax to reference Mono methods and fields | hh-asm | planned | linux+windows |
| Mono: symbol resolution in AA | Use `Class:Method` names in scripts | hh-asm | planned | linux+windows |
| Mono: IL2CPP support | Inspect IL2CPP metadata | hh-inject | planned | linux+windows |
| Mono: Unity helpers | Common Unity patterns | hh-inject | planned | linux+windows |
| .NET: dotnet data collector | Reads symbols from CLR processes | hh-inject | planned | windows |
| .NET: invasive collector | Runtime JIT info via invasive injection | hh-inject | planned | windows |
| .NET dissector | Browse .NET types and methods | app | planned | windows |
| .NET: compile C# (cscompile) | Compile C# in scripts | hh-inject | planned | windows |
| .NET Core / modern runtime support | Handle .NET 5+ runtimes | hh-inject | planned | linux+windows |
| Java: JVMTI agent | Inspect Java processes via JVMTI | hh-inject | planned | linux+windows |
| Java dissector | Browse classes, fields, methods | app | planned | linux+windows |
| Java: find objects of class | Locate live instances | hh-inject | planned | linux+windows |
| Java: invoke methods and set fields | Manipulate JVM objects | hh-inject | planned | linux+windows |
| Mono/Java via Lua API | Scripted access | hh-lua | planned | linux+windows |

## Graphics hooks

| Feature | CE behaviour (one short sentence) | HeapHook crate | Status | Platforms |
|---|---|---|---|---|
| D3D9 hook | Hooks Present for overlay rendering | hh-inject | planned | windows |
| D3D10 hook | Same for D3D10 | hh-inject | planned | windows |
| D3D11 hook | Same for D3D11 | hh-inject | planned | windows |
| D3D12 hook | Overlay support for D3D12 | hh-inject | planned | windows |
| OpenGL hook | Hooks SwapBuffers for overlay | hh-inject | planned | linux+windows |
| Vulkan hook | Layer-based overlay | hh-inject | planned | linux+windows |
| D3D overlay: textures | Draw images over the game | hh-inject | planned | windows |
| D3D overlay: text and fonts | Draw text with font maps | hh-inject | planned | windows |
| D3D overlay: render objects | Render objects with Lua events | hh-inject | planned | windows |
| D3D overlay: mouse and keyboard capture | Forwards input to overlay | hh-inject | planned | windows |
| D3D snapshot | Captures a frame and its draw calls | hh-inject | planned | windows |
| D3D snapshot viewer | Browse textures and primitives in a snapshot | app | planned | windows |
| D3D: texture dump/replace | Save or replace textures | hh-inject | planned | windows |
| D3D: wireframe / wallhack-style toggles | Modify render states for debugging | hh-inject | planned | windows |
| D3D: depth/Z toggle | Disable depth testing | hh-inject | planned | windows |
| D3D: create object from structure | Overlay objects bound to memory | hh-lua | planned | windows |
| Screenshot / frame capture | Capture rendered frame | hh-inject | planned | linux+windows |
| Overlay via Lua | Scripted overlay content | hh-lua | planned | windows |
| Overlay events (onClick, onKey) | Overlay input callbacks | hh-lua | planned | windows |

## Kernel-mode and hypervisor tools

| Feature | CE behaviour (one short sentence) | HeapHook crate | Status | Platforms |
|---|---|---|---|---|
| DBK driver load | Loads a kernel driver for privileged access | tbd | needs decision | windows |
| DBK: kernel memory read/write | Read/write memory via driver | tbd | needs decision | windows |
| DBK: open process via kernel | Opens process handles through the driver | tbd | needs decision | windows |
| DBK: physical memory access | Read/write physical addresses | tbd | needs decision | windows |
| DBK: MSR read/write | Access model-specific registers | tbd | needs decision | windows |
| DBK: CR3 / page table access | Query paging structures | tbd | needs decision | windows |
| DBK: kernel debugger interface | Debug without user-mode debug API | tbd | needs decision | windows |
| DBK: kernel-mode symbols and SSDT | Inspect SSDT and kernel modules | tbd | needs decision | windows |
| DBK: Ultimap support | BTS recording through the driver | tbd | needs decision | windows |
| DBK: driver name randomization | Randomizes driver/device name | tbd | needs decision | windows |
| DBK: use unsigned driver / test signing | Loading modes for unsigned drivers | tbd | needs decision | windows |
| DBVM hypervisor load | Loads a thin hypervisor under the OS | tbd | needs decision | windows |
| DBVM: watch reads/writes | Page-level access tracing invisible to the target | tbd | needs decision | windows |
| DBVM: cloak (hidden code edits) | Hides patches from integrity checks | tbd | needs decision | windows |
| DBVM: physical memory read/write | Access guest physical memory | tbd | needs decision | windows |
| DBVM: CR3 logging | Track process switches | tbd | needs decision | windows |
| DBVM: trace and breakpoints | Invisible breakpoints and single-step | tbd | needs decision | windows |
| DBVM: change guest registers | Alter state from the hypervisor | tbd | needs decision | windows |
| DBVM: wallhack-style memory protections | Per-page permission control | tbd | needs decision | windows |
| DBVM: Linux/KVM equivalent | Kernel/hypervisor assist on Linux | tbd | needs decision | linux |
| Stealth options (hide from detection) | Settings to reduce detectability | tbd | needs decision | windows |
| Extra settings: kernel mode options page | Settings tab for driver functions | tbd | needs decision | windows |
| Use kernel-mode OpenProcess / memory | Settings to route access through driver | tbd | needs decision | windows |

## Network

| Feature | CE behaviour (one short sentence) | HeapHook crate | Status | Platforms |
|---|---|---|---|---|
| ceserver daemon | Small server exposing process memory over TCP | tbd | engine only | linux |
| Connect to ceserver | Attach to a remote host from the CE open-process dialog | hh-core | engine only | linux+windows |
| Remote process list | Lists processes on the remote machine | hh-core | engine only | linux+windows |
| Remote memory read/write | Reads and writes remote memory | hh-core | engine only | linux+windows |
| Remote scanning | Run scans against a remote target | hh-scan | engine only | linux+windows |
| Remote module and region lists | Enumerate modules and regions remotely | hh-core | engine only | linux+windows |
| Remote debugging | Debug remote processes | hh-debug | planned | linux+windows |
| Remote symbol loading | Load symbols from remote targets | hh-asm | planned | linux+windows |
| Android target support | ceserver on Android (ARM) | tbd | planned | linux |
| Remote: pause/resume | Suspend remote process | hh-core | engine only | linux+windows |
| Remote: allocate / protect memory | Remote allocation and protection changes | hh-core | engine only | linux+windows |
| Remote: file transfer / extension commands | Extra ceserver commands | hh-core | planned | linux+windows |
| Distributed pointer scan: server | Master distributes scan work | hh-ptr | planned | linux+windows |
| Distributed pointer scan: client | Worker machines join a scan | hh-ptr | planned | linux+windows |
| Distributed pointer scan: password / port | Connection settings | hh-ptr | planned | linux+windows |
| Network update check | Optional check for new versions | app | planned | linux+windows |
| Network: TCP/pipe Lua helpers | Sockets exposed to Lua | hh-lua | planned | linux+windows |

## Tools and misc

| Feature | CE behaviour (one short sentence) | HeapHook crate | Status | Platforms |
|---|---|---|---|---|
| Memory regions list | Shows virtual memory regions with protection | hh-core | done | linux+windows |
| Memory regions: save region | Save selected region to file | hh-core | done | linux+windows |
| Memory regions: change protection | Change protection from list | hh-core | done | linux+windows |
| Memory regions: filter by type | Image, mapped, private, free | app | done | linux+windows |
| Heap list | Enumerates heap blocks | hh-core | planned | windows |
| Heap: show entries per heap | Expand heap blocks | app | planned | windows |
| Module list | Lists loaded modules with base and size | hh-core | done | linux+windows |
| Module list: dump module | Saves module memory to a file | hh-core | done | linux+windows |
| Thread list window | Lists threads of the process | app | done | linux+windows |
| PE header viewer | Shows PE headers, sections, imports, exports | hh-core | partial | windows |
| PE: imports/exports list | Names of imported/exported functions | hh-asm | partial | windows |
| ELF header viewer | Shows ELF headers, sections, symbols | hh-core | partial | linux |
| Fill memory | Fills a range with a byte value | hh-core | done | linux+windows |
| Save memory regions to file | Writes selected regions to disk | hh-core | done | linux+windows |
| Load memory region from file | Write file contents into memory | hh-core | done | linux+windows |
| Create process dialog | Launch an executable with arguments | app | done | linux+windows |
| Tutorial | Built-in step-by-step tutorial app | app | planned | linux+windows |
| Tutorial: Step 2-9 flows | Value scan, unknown value, floats, code finder, pointers, injection | app | planned | linux+windows |
| Settings dialog | Multi-page preferences | app | done | linux+windows |
| Settings: General | Auto-attach, update check, hide cheat engine option | app | partial | linux+windows |
| Settings: Hotkeys | Global hotkey configuration | app | partial | linux+windows |
| Settings: Unrandomizer | Mimic RNG function with fixed values | hh-debug | planned | windows |
| Settings: Scan options | Defaults for scanning | app | done | linux+windows |
| Settings: Plugins | Enable/disable plugins | app | planned | linux+windows |
| Settings: Languages | Choose UI language | app | planned | linux+windows |
| Settings: Debugger options | Choose interface and defaults | app | done | linux+windows |
| Settings: Extra | Kernel/driver settings page | app | needs decision | windows |
| Settings: Signing | Table signing options | app | planned | windows |
| Settings: Lua / auto-run folder | Script and autorun settings | app | partial | linux+windows |
| Settings: Tools / custom tools menu | Add external tools to the menu | app | planned | linux+windows |
| Settings: Always on top | Keep CE above windows | app | planned | linux+windows |
| Settings: Hide window hotkey | Hotkey to hide the main window | app | planned | windows |
| Settings: Randomize window title | Changes CE title to evade detection | app | planned | windows |
| Settings: Dark mode / theme | Appearance themes | app | done | linux+windows |
| Settings: Font and DPI scaling | Scale UI | app | planned | linux+windows |
| Translations (.po files) | Localization via PO files | app | planned | linux+windows |
| Plugin system | Native plugins extend CE via an API | tbd | planned | linux+windows |
| Plugin: add menu items | Plugins add menu entries | tbd | planned | linux+windows |
| Plugin: disassembler context hooks | Plugins add context-menu items | tbd | planned | linux+windows |
| Plugin: Lua function registration | Plugins export Lua functions | tbd | planned | linux+windows |
| Sound / beep on events | Plays sounds on hotkeys and events | app | partial | linux+windows |
| Text to speech | Speaks text from scripts | hh-lua | planned | windows |
| Memory record hotkeys list | Overview of all assigned hotkeys | app | planned | linux+windows |
| Save/load window layout | Remember window positions | app | partial | linux+windows |
| Compact mode | Smaller main window | app | planned | linux+windows |
| Hide/show main window hotkey | Toggle visibility | app | planned | linux+windows |
| Command line arguments | Open table or process from CLI | app | planned | linux+windows |
| Table file association (.CT) | Opens tables on double-click | app | planned | windows |
| Installer / portable mode | Distribution formats | app | planned | linux+windows |
| Update check | Checks for new versions | app | planned | linux+windows |
| Anti-detection: renamed binaries | Randomized exe/driver names on install | app | needs decision | windows |
| Unrandomizer | Forces random function results to fixed values | hh-debug | planned | windows |
| Network table sharing | Open table from URL | app | planned | linux+windows |
| Process/Window hider | Hide windows of other processes | app | planned | windows |
| Memory view: auto-assemble window | Open AA editor from menu | app | planned | linux+windows |
| Pause/resume CE hotkeys | Hotkeys to pause target | app | planned | linux+windows |
| Calculator / hex converter | Tools to convert numbers | app | planned | linux+windows |
| Help file | In-app documentation | app | planned | linux+windows |
| About dialog | Version and credits | app | planned | linux+windows |
| Crash handling | Reports exceptions in CE | app | planned | linux+windows |
| Multiple CE windows (Open another instance) | Run several instances | app | planned | linux+windows |
| Cheat table open via drag-drop file | Drop table or exe | app | planned | linux+windows |
| DLL injection tool | Inject DLL into process | hh-inject | planned | windows |
| Shared object injection tool | Inject .so into process | hh-inject | planned | linux |
| Code execution in target (executeCode) | Runs code via remote thread/ptrace | hh-inject | planned | linux+windows |
| Window list tab | Shows visible windows for attaching | app | planned | windows |
| Virtual memory page map | Visual map of address space | app | planned | linux+windows |
| Scan-result diff tools | Compare saved memory dumps | hh-scan | partial | linux+windows |
