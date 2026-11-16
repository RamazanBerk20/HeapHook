// The only module that talks to the backend. Uses Tauri's invoke when running inside the
// app (withGlobalTauri), otherwise the in-browser mock. One function per IPC command of
// docs/CONTRACT.md; argument names below are the Tauri command parameter names.
import { mockInvoke } from './mock.js';

const tauri = window.__TAURI__?.core;
export const isMock = !tauri;
const call = tauri ? (cmd, args) => tauri.invoke(cmd, args) : mockInvoke;

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
  /** req: {scan_type, value, value2, not} -> {count} */
  scanNext: (req) => call('scan_next', { req }),
  scanUndo: () => call('scan_undo', {}),
  scanNew: () => call('scan_new', {}),
  scanCancel: () => call('scan_cancel', {}),
  scanProgress: () => call('scan_progress', {}),
  scanResults: (offset, limit) => call('scan_results', { offset, limit }),
  /** entries: [{addr, vtype, value, mode, len?, utf16?, signed?, hex?}] — replaces the whole frozen set */
  setFrozen: (entries) => call('set_frozen', { entries }),
  disassemble: (addr, count) => call('disassemble', { addr, count }),
  assemble: (addr, text) => call('assemble', { addr, text }),
  aaCheck: (script) => call('aa_check', { script }),
  aaExecute: (script, enable, state) => call('aa_execute', { script, enable, state: state ?? null }),
  tableLoad: (path) => call('table_load', { path }),
  tableSave: (path, table) => call('table_save', { path, table }),
  // ---------- live cheat table (the backend owns it) ----------
  /** -> {version, table: {entries, lua_script, comments, codes, ct_extra}} */
  tableGet: () => call('table_get', {}),
  /** Whole-table edit based on `base`; rejects with "stale table version …" when the table moved -> new version */
  tablePut: (table, base) => call('table_put', { table, base }),
  /** Loads a .json/.CT file as the live table (everything inactive) -> {version, table} */
  tableOpen: (path) => call('table_open', { path }),
  tableExport: (path) => call('table_export', { path }),
  /** CE activation: OnActivate/OnDeactivate, Auto Assembler, freeze, group options */
  tableSetActive: (ids, active) => call('table_set_active', { ids, active }),
  tableSetValue: (ids, value) => call('table_set_value', { ids, value }),
  tableHotkey: (id, index) => call('table_hotkey', { id, index }),
  /** Runs the table's Lua script; only after the user agreed. */
  tableRunScript: () => call('table_run_script', {}),
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
  /** kind: into|over|out */
  debugStep: (tid, kind) => call('debug_step', { tid, kind }),
  debugRunTo: (addr) => call('debug_run_to', { addr }),
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
  /** -> [[number, name, defaultAction]] */
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
  memLoad: (path, relocate) => call('mem_load', { path, relocate: relocate || null }),
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
};

/** Ask for a file path: native dialog in the app, a text prompt in the browser mock. */
export async function askPath({ save, title, filters = [], dflt = '' }) {
  if (isMock) {
    const { prompt } = await import('./util.js');
    return prompt(title, dflt, { label: 'File path' });
  }
  return api.pickPath(save, title, filters, dflt || null);
}
