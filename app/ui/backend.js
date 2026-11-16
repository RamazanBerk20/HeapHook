// The only module that talks to the backend. Uses Tauri's invoke when running inside the
// app (withGlobalTauri), the development HTTP bridge when the page was opened from
// `heaphook --dev-bridge <port>` (URL carries ?hh_token=), otherwise the in-browser mock.
// One function per IPC command of docs/CONTRACT.md; argument names below are the Tauri
// command parameter names.
import { mockInvoke } from './mock.js';

const tauri = window.__TAURI__?.core;
const bridgeToken = !tauri && new URLSearchParams(location.search).get('hh_token');
export const isMock = !tauri && !bridgeToken;
/** Real backend without native dialogs or global hotkeys (the dev bridge). */
export const isBridge = !!bridgeToken;
async function bridgeInvoke(cmd, args = {}) {
  let r;
  try {
    r = await (await fetch('/invoke/' + cmd, { method: 'POST', headers: { 'x-hh-token': bridgeToken }, body: JSON.stringify(args) })).json();
  } catch (e) { throw `dev bridge unreachable: ${e?.message || e}`; }
  if ('err' in r) throw r.err;
  return r.ok;
}
const call = tauri ? (cmd, args) => tauri.invoke(cmd, args) : bridgeToken ? bridgeInvoke : mockInvoke;

export const api = {
  listProcesses: () => call('list_processes', {}),
  openProcess: (pid) => call('open_process', { pid }),
  regions: () => call('regions', {}),
  modules: () => call('modules', {}),
  readMemory: (addr, len) => call('read_memory', { addr, len }),
  writeBytes: (addr, hex) => call('write_bytes', { addr, hex }),
  /** reqs: [{addr, vtype, len?, utf16?, signed?, hex?}] -> [string|null] */
  readValues: (reqs) => call('read_values', { reqs }),
  /** fmt: {len?, utf16?, signed?, hex?} of the entry, so strings and hex ints are encoded right */
  writeValue: (addr, vtype, value, fmt = {}) => call('write_value', { addr, vtype, value, ...fmt }),
  resolveAddress: (expr) => call('resolve_address', { expr }),
  /** req: {vtype, scan_type, value, value2, not, opts} -> {count} */
  scanFirst: (req) => call('scan_first', { req }),
  /** req: {scan_type, value, value2, not, compare_to?: 'first' | saved scan name} -> {count} */
  scanNext: (req) => call('scan_next', { req }),
  scanUndo: () => call('scan_undo', {}),
  scanNew: () => call('scan_new', {}),
  scanCancel: () => call('scan_cancel', {}),
  scanProgress: () => call('scan_progress', {}),
  scanResults: (offset, limit) => call('scan_results', { offset, limit }),
  /** entries: [{addr, vtype, value, mode, len?, utf16?, signed?, hex?}] — replaces the whole frozen set */
  setFrozen: (entries) => call('set_frozen', { entries }),
  /** opts: {att?: AT&T syntax, typed?: typed operand comments} */
  disassemble: (addr, count, opts = null) => call('disassemble', { addr, count, opts }),
  assemble: (addr, text) => call('assemble', { addr, text }),
  /** where: {session} (Auto Assemble window) or {entry} (a table entry's script): the capabilities it is checked with; none without */
  aaCheck: (script, where = {}) => call('aa_check', { script, session: where.session ?? null, entry: where.entry ?? null }),
  /** session: the Auto Assemble window's (aaSession); without one the script gets no Lua or file access */
  aaExecute: (script, enable, state, session = null) => call('aa_execute', { script, enable, state: state ?? null, session }),
  tableLoad: (path) => call('table_load', { path }),
  tableSave: (path, table) => call('table_save', { path, table }),
  // ---------- live cheat table (the backend owns it) ----------
  /** -> {version, table: {entries, lua_script, comments, codes, ct_extra}} */
  tableGet: () => call('table_get', {}),
  /** Whole-table edit based on `base`; rejects with "stale table version …" when the table moved -> new version */
  tablePut: (table, base) => call('table_put', { table, base }),
  /** Loads a .json/.CT file as the live table (everything inactive) -> {version, table} */
  tableOpen: (path, force = false) => call('table_open', { path, force }),
  /** Answer to a "needs consent:" error: may the loaded table's {$lua} blocks run? */
  /** generation: the table's (TableState.generation) when the question was asked; refused once another table was opened */
  tableTrust: (trust, generation) => call('table_trust', { trust, generation }),
  tableExport: (path) => call('table_export', { path }),
  /** CE activation: OnActivate/OnDeactivate, Auto Assembler, freeze, group options */
  tableSetActive: (ids, active) => call('table_set_active', { ids, active }),
  tableSetValue: (ids, value) => call('table_set_value', { ids, value }),
  tableHotkey: (id, index) => call('table_hotkey', { id, index }),
  /** Runs the table's Lua script; only after the user agreed. */
  tableRunScript: (generation) => call('table_run_script', { generation }),
  /** keys: virtual-key codes -> how many hotkeys fired */
  hotkeyPress: (keys) => call('hotkey_press', { keys }),
  // ---------- Lua ----------
  luaExec: (code) => call('lua_exec', { code }),
  luaInterrupt: () => call('lua_interrupt', {}),
  /** -> {log: [{seq, kind, text}], next, dialog, table_version, hotkeys: [[vk]], busy, sound} */
  luaPoll: (since) => call('lua_poll', { since }),
  luaDialogReply: (id, value) => call('lua_dialog_reply', { id, value }),
  settingsGet: () => call('settings_get', {}),
  settingsSet: (settings) => call('settings_set', { settings }),
  /** Native file dialog -> path or null. filters: [[name, [ext]]]. Not in the mock (callers prompt). */
  pickPath: (save, title, filters = [], dflt = null) => call('pick_path', { save, title, filters, default: dflt }),

  // ---------- debugger ----------
  debugAttach: () => call('debug_attach', {}),
  debugDetach: () => call('debug_detach', {}),
  /** -> {attached, state: detached|running|broken|suspended|exited, tid, reason, rip, exit_code} */
  debugStatus: () => call('debug_status', {}),
  /** req: {addr, kind: execute|write|access, size, method: software|hardware, action: break|record|trace, steps, step_over_calls, ea} -> id */
  debugAddBreakpoint: (req) => call('debug_add_breakpoint', { req }),
  debugRemoveBreakpoint: (id) => call('debug_remove_breakpoint', { id }),
  debugSetEnabled: (id, enabled) => call('debug_set_enabled', { id, enabled }),
  debugBreakpoints: () => call('debug_breakpoints', {}),
  /** -> [{addr, ip, bytes, text, count, address, context}] */
  debugRecords: (id) => call('debug_records', { id }),
  debugClearRecords: (id) => call('debug_clear_records', { id }),
  /** -> [{addr, text, context}] */
  debugTrace: (id) => call('debug_trace', { id }),
  debugThreads: () => call('debug_threads', {}),
  debugSuspendThread: (tid, suspend) => call('debug_suspend_thread', { tid, suspend }),
  debugContext: (tid) => call('debug_context', { tid }),
  debugSetRegister: (tid, name, value) => call('debug_set_register', { tid, name, value }),
  debugStack: (tid, count) => call('debug_stack', { tid, count }),
  debugContinue: (passSignal = false) => call('debug_continue', { passSignal }),
  debugPause: () => call('debug_pause', {}),
  /** kind: into|over|out; skipBreakpoints: breakpoints are ignored until the step completes */
  debugStep: (tid, kind, skipBreakpoints = false) => call('debug_step', { tid, kind, skipBreakpoints }),
  /** tid: only that thread stops at addr (others pass it); null = any thread; count: break at the count-th arrival */
  debugRunTo: (addr, tid = null, count = 1) => call('debug_run_to', { addr, tid, count }),
  /** options: {skip_hits, one_shot, max_hits} — changed in place, hits so far count */
  debugSetOptions: (id, options) => call('debug_set_options', { id, options }),
  /** req: {addr, len, kind: write|access, max_hits?} -> id (page-protection watch that records; refuses stack memory) */
  debugWatchRange: (req) => call('debug_watch_range', { req }),
  /** -> [{addr, module, symbol}] */
  debugBacktrace: (tid, max = 64) => call('debug_backtrace', { tid, max }),
  /** -> {lines: [{seq, text}], next}: exec, fork, breakpoints the debugger disabled, exit */
  debugLog: (since) => call('debug_log', { since }),
  /** -> original bytes (hex) for write_bytes to restore */
  nopInstruction: (addr) => call('nop_instruction', { addr }),

  // ---------- gaps ----------
  closeProcess: () => call('close_process', {}),
  /** -> {version, table} */
  tableUndo: () => call('table_undo', {}), tableRedo: () => call('table_redo', {}),
  /** -> [{description, address, bytes, before, after, addr: hex|null, state: original|nopped|changed|unreadable, current}] */
  codeList: () => call('code_list', {}),
  /** -> index */
  codeAdd: (addr, description) => call('code_add', { addr, description }),
  codeRemove: (index) => call('code_remove', { index }), codeNop: (index) => call('code_nop', { index }), codeRestore: (index, force = false) => call('code_restore', { index, force }),
  debugSetCondition: (id, condition) => call('debug_set_condition', { id, condition }),
  /** -> [[number, name, defaultAction, currentAction|null]] (current: from the attached debugger) */
  debugSignals: () => call('debug_signals', {}),
  /** key: base|offset|value -> {count, max_level, target} */
  ptrSort: (key, column, desc, vtype, fmt) => call('ptr_sort', { key, column, desc, vtype, fmt }),

  // ---------- pointer scanner ----------
  /** req: {target, opts: ScanOptions, base_start, base_end, alignment, writable_only, map_path, compare: [{path, target}]} -> {count, max_level, target} */
  ptrScan: (req) => call('ptr_scan', { req }),
  /** req: {target, value, vtype, fmt, base_start, base_end, starts_with, ends_with, max_level, map_path} -> {count, max_level, target} */
  ptrRescan: (req) => call('ptr_rescan', { req }),
  /** -> {running, phase, done, total, found} */
  ptrProgress: () => call('ptr_progress', {}),
  ptrCancel: () => call('ptr_cancel', {}),
  /** -> [{base, offsets, text, address, value}] */
  ptrResults: (offset, limit, vtype, fmt) => call('ptr_results', { offset, limit, vtype, fmt }),
  ptrEntry: (index, vtype, description) => call('ptr_entry', { index, vtype, description }),
  ptrSaveMap: (path) => call('ptr_save_map', { path }),
  ptrSaveResults: (path) => call('ptr_save_results', { path }),
  ptrOpenResults: (path) => call('ptr_open_results', { path }),

  // ---------- analysis tools (hh-tools) ----------
  /** -> {running, job, done, total, found} of the session's one long operation */
  toolsProgress: () => call('tools_progress', {}),
  toolsCancel: () => call('tools_cancel', {}),
  structGet: () => call('struct_get', {}),
  structSet: (structs) => call('struct_set', { structs }),
  structGuess: (name, addr, size) => call('struct_guess', { name, addr, size }),
  /** reqs: [{name, addr}] -> [{Ok: [FieldValue]} | {Err: text}] */
  structEval: (reqs) => call('struct_eval', { reqs }),
  /** -> {name, addr} of the child structure (auto-guessed when the pointer has none) */
  structExpand: (owner, index, fieldAddr, size = 0x100) => call('struct_expand', { owner, index, fieldAddr, size }),
  /** path: pointer-field offsets from root to the structure -> table entries */
  structEntries: (name, root, path, only) => call('struct_entries', { name, root, path, only }),
  structSpider: (groups, opts) => call('struct_spider', { groups, opts }),
  dissectRun: (modules, opts = {}) => call('dissect_run', { modules, opts }),
  dissectSummary: () => call('dissect_summary', {}),
  /** kind: functions|called|strings|caves -> {total, rows} */
  dissectList: (kind, filter, offset, limit) => call('dissect_list', { kind, filter, offset, limit }),
  /** -> {total, rows: [{from, to, kind, text, func}]} */
  dissectXrefs: (addr, len, offset, limit) => call('dissect_xrefs', { addr, len, offset, limit }),
  /** -> [{start, size, prot, prot_text, kind, shared, path, module, tag}] */
  regionsInfo: () => call('regions_info', {}),
  memProtect: (addr, size, prot) => call('mem_protect', { addr, size, prot }),
  memSave: (ranges, path) => call('mem_save', { ranges, path }),
  /** -> {blocks: [{index, addr, len, mapped, writable}], bytes, unmapped, read_only}; writes nothing */
  memLoadPlan: (path, relocate) => call('mem_load_plan', { path, relocate: relocate || null }),
  /** blocks: the plan blocks the user approved -> {blocks, bytes, failed: [addr]} */
  memLoadApproved: (path, relocate, blocks) => call('mem_load_approved', { path, relocate: relocate || null, blocks }),
  memFill: (addr, len, pattern) => call('mem_fill', { addr, len, pattern }),
  memCopy: (src, dst, len) => call('mem_copy', { src, dst, len }),
  snapshotTake: (ranges, label) => call('snapshot_take', { ranges, label }),
  snapshotList: () => call('snapshot_list', {}),
  snapshotDelete: (id) => call('snapshot_delete', { id }),
  /** -> [{addr, len, old, new}] */
  snapshotDiff: (id, max = 10000) => call('snapshot_diff', { id, max }),
  /** query: {target, max_offset, static_only, writable_only, max_results} -> [{addr, value, offset, module}] */
  findPointers: (query) => call('find_pointers', { query }),
  moduleHeader: (name) => call('module_header', { name }),
  /** -> {pattern, addr, module, module_offset, unique, matches, found: [addr]} */
  aobSignature: (addr) => call('aob_signature', { addr }),
  /** kind: aob|code|full -> Auto Assembler script */
  aaTemplate: (addr, kind = 'aob') => call('aa_template', { addr, kind }),
  /** req: {program, args, cwd, speedhack} -> {pid, name, is_64bit} */
  processCreate: (req) => call('process_create', { req }),
  /** -> {pid, addr, speed, generation} or null when the process has no speedhack */
  speedGet: () => call('speed_get', {}),
  speedSet: (speed) => call('speed_set', { speed }),

  // ---------- Lua forms, key state, selection, trainer ----------
  /** -> {next, changes: [{seq, op, ...}], snapshot: {roots} | null} (snapshot when since is 0 or too far behind) */
  uiPoll: (since) => call('ui_poll', { since }),
  /** User event on a form control (OnClick, OnClose, OnDblClick, …) -> handler results */
  uiEvent: (id, event, args = []) => call('ui_event', { id, event, args }),
  /** The user changed a value (Text, Checked, ItemIndex, Position, …); not echoed back */
  uiInput: (id, prop, value) => call('ui_input', { id, prop, value }),
  /** Image file of a TImage -> data: URL */
  uiImage: (path) => call('ui_image', { path }),
  /** Keys held in the app window (CE virtual-key codes), for Lua isKeyPressed */
  keyState: (keys) => call('key_state', { keys }),
  /** The table selection, for Lua's SelectedRecords */
  tableSelect: (ids) => call('table_select', { ids }),
  /** req: {title, about, beep, show_keys, entries: [{id, label, keys}]} -> Lua trainer script */
  trainerScript: (req) => call('trainer_script', { req }),

  // ---------- scanner: saved scans, custom types, pause ----------
  /** Saves the current results under `name` (also kept for the results' "saved" column) */
  scanSave: (name) => call('scan_save', { name }),
  /** -> [{name, count, kept}] (kept = rows whose saved value the results can show) */
  scanSaved: () => call('scan_saved', {}),
  scanDeleteSaved: (name) => call('scan_delete_saved', { name }),
  scanPause: () => call('scan_pause', {}),
  scanResume: () => call('scan_resume', {}),
  /** Like scanResults; rows carry `saved` (that saved scan's value at the address, or null) */
  scanResultsSaved: (offset, limit, saved) => call('scan_results', { offset, limit, saved }),
  /** -> [{name, size, big_endian, float, signed, scale, offset, bit_start, bit_len, binary}] (Cheat Engine's stock custom types) */
  customPresets: () => call('custom_presets', {}),
  /** -> null or the error text of an invalid custom type */
  customValidate: (custom) => call('custom_validate', { custom }),
  /** exprs: [address expression] -> [hex addr | null] (one call for many table rows) */
  resolveMany: (exprs) => call('resolve_many', { exprs }),

  // ---------- remote targets (hh-net) ----------
  /** -> {addr, has_token} of the remembered server ("" when none) */
  remoteSaved: () => call('remote_saved', {}),
  /** token: "" = use the remembered token; remember: store the token (config file, 0600) -> {addr} */
  remoteConnect: (addr, token, remember) => call('remote_connect', { addr, token, remember }),
  /** -> {addr, connected} or null when no server is connected */
  remoteStatus: () => call('remote_status', {}),
  remoteProcesses: () => call('remote_processes', {}),
  /** -> {pid, name, is_64bit, remote: addr} */
  remoteOpen: (pid) => call('remote_open', { pid }),
  /** Closes the remote process (if it is the target) and the connection */
  remoteDisconnect: () => call('remote_disconnect', {}),
  /** Forgets the remembered address and token */
  remoteForget: () => call('remote_forget', {}),

  // ---------- code, memory, structures, app ----------
  /** -> {start, name, source: dissection|heuristic} of the function holding addr */
  codeFunction: (addr) => call('code_function', { addr }),
  /** -> {start, end, source, rows: [{from, to, kind: call|jump|cond_jump, text, name}]} branch targets of that function */
  codeTargets: (addr) => call('code_targets', { addr }),
  /** Live memory against a saved .hhmem file -> [{addr, len, old, new}] */
  memCompare: (path, max = 10000) => call('mem_compare', { path, max }),
  /** names: [] = all; .json or .xml/.ct (CE <Structures>) by extension */
  structExport: (path, names) => call('struct_export', { path, names }),
  /** -> names of the structures added or replaced */
  structImport: (path) => call('struct_import', { path }),
  /** -> {version, license, remote_ok, platform} */
  appInfo: () => call('app_info', {}),

  // ---------- 1.0: search, memory, process, trust per entry, files ----------
  /** req: {start, end?, pattern: "48 8B ?? 05", backward?, limit?} -> [addr] (forward: matches at >= start, ascending; backward: below start, descending) */
  memSearch: (req) => call('mem_search', { req }),
  /** req: {start, end, text, limit?} -> [{addr, text}] (instructions whose text contains `text`, case-insensitive) */
  disasmSearch: (req) => call('disasm_search', { req }),
  /** -> addr of a new block (prot: {r, w, x}) */
  memAlloc: (size, prot) => call('mem_alloc', { size, prot }),
  memFree: (addr, size) => call('mem_free', { addr, size }),
  /** Suspends (true) or resumes the whole process; lua_poll.process.paused follows */
  processPause: (pause) => call('process_pause', { pause }),
  /** trace: whatever the UI wants back from traceLoad (JSON) */
  traceSave: (path, trace) => call('trace_save', { path, trace }),
  traceLoad: (path) => call('trace_load', { path }),
  /** Readable listing of the live table */
  tableExportText: (path) => call('table_export_text', { path }),
  /** Appends a table file's entries (they arrive untrusted) -> {version, table, trust, untrusted} */
  tableMerge: (path) => call('table_merge', { path }),
  /** Inserts entries (new ids) after entry `after` (null: at the end); every one arrives untrusted -> {version, ids} */
  tablePaste: (entries, after, base) => call('table_paste', { entries, after, base }),
  /** The user's new entries (new address, script, group, from results / structures / pointers / disassembler): the backend issues their ids -> {version, ids}. A put cannot add entries. */
  tableNew: (entries, after, base) => call('table_new', { entries, after: after ?? null, base: base ?? null }),
  /** Consent for the Lua of these entries (and their children) that arrived from another table */
  tableTrustEntries: (ids, generation) => call('table_trust_entries', { ids, generation }),
  /** -> true when the table changed since it was opened or saved */
  tableDirty: () => call('table_dirty', {}),
  /** A dropped file's text (browser drop) opened like table_open -> {version, table, trust, untrusted} */
  tableOpenData: (name, data, force = false) => call('table_open_data', { name, data, force }),
  /** A new Auto Assemble window session -> id: typed text is the user's own */
  aaSession: () => call('aa_session', {}),
  /** Reads an Auto Assembler script file into session `session`: from now on its content gets Lua and file access only after aaTrust */
  /** -> {script, load}: `load` names this load for aaTrust */
  aaLoadFile: (path, session) => call('aa_load_file', { path, session }),
  /** Consent for what was loaded into the session */
  /** load: what aaLoadFile returned; refused once another file was loaded into the session */
  aaTrust: (session, load) => call('aa_trust', { session, load }),
  /** "Assign to table": the session's script as a new entry (a loaded file stays untrusted) -> {version, ids} */
  aaAssign: (session, script, description, after, base) => call('aa_assign', { session, script, description, after: after ?? null, base: base ?? null }),
  /** An injection template (kind aob | code | full | api) at addr as a new entry; untrusted for a remote target -> {version, ids} */
  tableAddTemplate: (addr, kind, description, after, base) => call('table_add_template', { addr, kind, description, after: after ?? null, base: base ?? null }),
  /** ids: [entry id] -> [hex addr | null], each resolved with the lookups its origin allows */
  tableResolve: (ids) => call('table_resolve', { ids }),
  /** Command-line arguments, once: {table, pid, attach, launch: {program, args}|null} */
  appArgs: () => call('app_args', {}),
  /** Quits (after the unsaved-changes question) */
  appQuit: () => call('app_quit', {}),

  // ---------- 1.0 RC: scanner ----------
  /** key: address|value; value sorts refuse more than 5,000,000 results */
  scanSort: (key, desc = false) => call('scan_sort', { key, desc }),
  /** addrs: [hex] -> how many results were removed (scan_undo brings them back) */
  scanRemove: (addrs) => call('scan_remove', { addrs }),
  /** Every result address, one per line, into a file -> count */
  scanExportAddresses: (path) => call('scan_export_addresses', { path }),
  /** Every result address as text (refused above 1,000,000) */
  scanCopyAddresses: () => call('scan_copy_addresses', {}),
  /** -> [{start, size, kind, path, module, count}] results per region */
  scanStats: () => call('scan_stats', {}),
  /** req: {opts: scan options, modules: [name], ranges: [{start, end}]} -> {count}; pointer-sized values pointing into readable memory (or those modules / ranges) */
  scanPointer: (req) => call('scan_pointer', { req }),
  // ---------- 1.0 RC: pointer scanner ----------
  ptrPause: () => call('ptr_pause', {}),
  ptrResume: () => call('ptr_resume', {}),
  // ---------- 1.0 RC: memory tools ----------
  /** req: {path, pattern: "48 ?? 05" | "", vtype?, value?, fmt?, max?} -> [addr] (a saved .hhmem file, no process needed) */
  memFileSearch: (req) => call('mem_file_search', { req }),
  /** -> {regions, bytes, by_prot, by_tag, by_kind, by_module: [{key, regions, bytes}]} */
  regionStats: () => call('region_stats', {}),
  /** -> {start, cell_size, compared: [n], changed: [n]} pages per cell; start/end null = the old snapshot's span */
  snapshotChangeMap: (old, nw, start = null, end = null, cells = 1024) => call('snapshot_change_map', { old, new: nw, start, end, cells }),
  // ---------- 1.0 RC: structures ----------
  /** reqs: [{name, addr}] -> [{Ok: {fields, changed: [leaf index], locked, class}} | {Err}] */
  structView: (reqs) => call('struct_view', { reqs }),
  structLock: (name, addr, on) => call('struct_lock', { name, addr, on }),
  /** leaf: index in the flattened leaf order of struct_view's fields */
  structWrite: (name, addr, leaf, value) => call('struct_write', { name, addr, leaf, value }),
  /** lang: c|csharp; names: [] = all -> source text (also written to `path` when given) */
  structCode: (names, lang, path = null) => call('struct_code', { names, lang, path }),
  /** path: element indexes (array element then item index; pointer / nested element then the path inside its child) -> table entry */
  structFieldEntry: (name, root, path) => call('struct_field_entry', { name, root, path }),
  // ---------- 1.0 RC: code analysis ----------
  dissectAdd: (modules, opts = {}) => call('dissect_add', { modules, opts }),
  dissectSave: (path) => call('dissect_save', { path }),
  dissectLoad: (path) => call('dissect_load', { path }),
  /** -> {recording, armed, ran_sets, not_ran_sets, last_hits, matches} (needs the debugger attached) */
  codeFilterStart: () => call('code_filter_start', {}),
  /** ran: the recording becomes a "ran" set (true) or a "did not run" set (false) */
  codeFilterStop: (ran) => call('code_filter_stop', { ran }),
  codeFilterState: () => call('code_filter_state', {}),
  codeFilterReset: () => call('code_filter_reset', {}),
  /** -> {total, rows: [{addr, callers, internal, name}]} */
  codeFilterList: (offset, limit) => call('code_filter_list', { offset, limit }),
  /** req: {start, end, pattern: "mov [r?x+*],e?x; ret", max} -> {hits: [{addr, text}], next: addr|null} */
  asmScan: (req) => call('asm_scan', { req }),
  /** -> addr of the next (forward) / previous instruction referencing target, or null */
  findReference: (from, target, forward = true, maxBytes = null) => call('find_reference', { from, target, forward, maxBytes }),
  /** module: null = user symbols and every module -> {total, rows: [{name, module, addr, size, user}]} */
  symbolList: (module, filter, offset, limit) => call('symbol_list', { module, filter, offset, limit }),
  // ---------- 1.0 RC: debugger ----------
  /** req: {program, args, cwd, stop: entry|first|run} -> {pid, name, is_64bit}; opened with the debugger attached */
  debugLaunch: (req) => call('debug_launch', { req }),
  /** on: {thread_created, thread_exited, module_loaded: [pattern], module_unloaded: [pattern]} */
  debugSetBreakOn: (on) => call('debug_set_break_on', { on }),
  debugBreakOn: () => call('debug_break_on', {}),
  debugSetIp: (tid, addr) => call('debug_set_ip', { tid, addr }),
  /** frame: backtrace frame index (0 = the current function) */
  debugRunUntilReturn: (tid, frame = 0) => call('debug_run_until_return', { tid, frame }),
};

/** Ask for a file path: native dialog in the app, a text prompt in a browser (mock or bridge). */
export async function askPath({ save, title, filters = [], dflt = '' }) {
  if (!tauri) {
    const { prompt } = await import('./util.js');
    return prompt(title, dflt, { label: 'File path' });
  }
  return api.pickPath(save, title, filters, dflt || null);
}
