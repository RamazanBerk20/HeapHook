// No console window on Windows release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use heaphook::cheat::TableState;
use heaphook::commands::{App, DisasmOut, ModuleOut, Opened, R, RegionOut};
use heaphook::lua::{DialogReply, LuaPoll};
use heaphook::settings::Settings;
use heaphook::debug::{BpOut, BpReq, DebugStatus, RecordOut, StackOut, TraceOut};
use heaphook::ptr::{PtrInfo, PtrProgress, PtrRescanReq, PtrRow, PtrScanReq};
use heaphook::table::{Table, TableIn};
use hh_asm::{AaError, AaState};
use hh_core::ProcessInfo;
use hh_debug::ThreadInfo;
use hh_scan::{FirstScan, Fmt, FrozenEntry, NextScan, ResultRow, ScanCount, ScanProgress, VType, ValueRef};
use serde_json::Value;
use tauri::{Manager, State};
use tauri_plugin_dialog::DialogExt;
use tauri_plugin_global_shortcut::{Code, GlobalShortcutExt, Modifiers, Shortcut, ShortcutState};

/// Runs command logic on the blocking pool so scans and big reads never stall IPC or the UI.
async fn run<T: Send + 'static>(app: &App, f: impl FnOnce(&App) -> R<T> + Send + 'static) -> R<T> {
    let app = app.clone();
    tauri::async_runtime::spawn_blocking(move || f(&app)).await.map_err(|e| format!("command failed: {e}"))?
}

type St<'a> = State<'a, App>;

#[tauri::command]
async fn list_processes(app: St<'_>) -> R<Vec<ProcessInfo>> { run(&app, |a| a.list_processes()).await }
#[tauri::command]
async fn open_process(app: St<'_>, pid: u32) -> R<Opened> { run(&app, move |a| a.open_process(pid)).await }
#[tauri::command]
async fn regions(app: St<'_>) -> R<Vec<RegionOut>> { run(&app, |a| a.regions()).await }
#[tauri::command]
async fn modules(app: St<'_>) -> R<Vec<ModuleOut>> { run(&app, |a| a.modules()).await }
#[tauri::command]
async fn read_memory(app: St<'_>, addr: String, len: usize) -> R<String> { run(&app, move |a| a.read_memory(&addr, len)).await }
#[tauri::command]
async fn write_bytes(app: St<'_>, addr: String, hex: String) -> R<()> { run(&app, move |a| a.write_bytes(&addr, &hex)).await }
#[tauri::command]
async fn read_values(app: St<'_>, reqs: Vec<ValueRef>) -> R<Vec<Option<String>>> { run(&app, move |a| a.read_values(reqs)).await }
#[tauri::command]
#[allow(clippy::too_many_arguments)]
async fn write_value(app: St<'_>, addr: String, vtype: VType, value: String, len: Option<usize>, utf16: Option<bool>, signed: Option<bool>, hex: Option<bool>) -> R<()> {
    let fmt = Fmt { len: len.filter(|&l| l > 0), utf16: utf16.unwrap_or(false), signed: signed.unwrap_or(false), hex: hex.unwrap_or(false) };
    run(&app, move |a| a.write_value(&addr, vtype, &value, &fmt)).await
}
#[tauri::command]
async fn resolve_address(app: St<'_>, expr: String) -> R<String> { run(&app, move |a| a.resolve_address(&expr)).await }
#[tauri::command]
async fn scan_first(app: St<'_>, req: FirstScan) -> R<ScanCount> { run(&app, move |a| a.scan_first(&req)).await }
#[tauri::command]
async fn scan_next(app: St<'_>, req: NextScan) -> R<ScanCount> { run(&app, move |a| a.scan_next(&req)).await }
#[tauri::command]
async fn scan_undo(app: St<'_>) -> R<()> { run(&app, |a| a.scan_undo()).await }
#[tauri::command]
async fn scan_new(app: St<'_>) -> R<()> { run(&app, |a| a.scan_new()).await }
#[tauri::command]
async fn scan_cancel(app: St<'_>) -> R<()> { app.scan_cancel() }
#[tauri::command]
async fn scan_progress(app: St<'_>) -> R<ScanProgress> { app.scan_progress() }
#[tauri::command]
async fn scan_results(app: St<'_>, offset: u64, limit: usize) -> R<Vec<ResultRow>> { run(&app, move |a| a.scan_results(offset, limit)).await }
#[tauri::command]
async fn set_frozen(app: St<'_>, entries: Vec<FrozenEntry>) -> R<()> { run(&app, move |a| a.set_frozen(&entries)).await }
#[tauri::command]
async fn disassemble(app: St<'_>, addr: String, count: usize) -> R<Vec<DisasmOut>> { run(&app, move |a| a.disassemble(&addr, count)).await }
#[tauri::command]
async fn assemble(app: St<'_>, addr: String, text: String) -> R<String> { run(&app, move |a| a.assemble(&addr, &text)).await }
#[tauri::command]
async fn aa_check(app: St<'_>, script: String) -> R<Option<AaError>> { run(&app, move |a| a.aa_check(&script)).await }
#[tauri::command]
async fn aa_execute(app: St<'_>, script: String, enable: bool, state: Option<AaState>) -> R<AaState> { run(&app, move |a| a.aa_execute(&script, enable, state.as_ref())).await }
#[tauri::command]
async fn table_load(app: St<'_>, path: String) -> R<Table> { run(&app, move |a| a.table_load(&path)).await }
#[tauri::command]
async fn table_save(app: St<'_>, path: String, table: TableIn) -> R<()> { run(&app, move |a| a.table_save(&path, table)).await }

// ---------- live cheat table, Lua, hotkeys, settings ----------
#[tauri::command]
async fn table_get(app: St<'_>) -> R<TableState> { app.table_get() }
#[tauri::command]
async fn table_put(app: St<'_>, table: Table, base: u64) -> R<u64> { run(&app, move |a| a.table_put(table, base)).await }
#[tauri::command]
async fn table_open(app: St<'_>, path: String) -> R<TableState> { run(&app, move |a| a.table_open(&path)).await }
#[tauri::command]
async fn table_export(app: St<'_>, path: String) -> R<()> { run(&app, move |a| a.table_export(&path)).await }
#[tauri::command]
async fn table_set_active(app: St<'_>, ids: Vec<i64>, active: bool) -> R<()> { run(&app, move |a| a.table_set_active(&ids, active)).await }
#[tauri::command]
async fn table_set_value(app: St<'_>, ids: Vec<i64>, value: String) -> R<()> { run(&app, move |a| a.table_set_value(&ids, &value)).await }
#[tauri::command]
async fn table_hotkey(app: St<'_>, id: i64, index: usize) -> R<()> { run(&app, move |a| a.table_hotkey(id, index)).await }
#[tauri::command]
async fn table_run_script(app: St<'_>) -> R<()> { run(&app, |a| a.table_run_script()).await }
#[tauri::command]
async fn hotkey_press(app: St<'_>, keys: Vec<u32>) -> R<usize> { run(&app, move |a| a.hotkey_press(&keys)).await }
#[tauri::command]
async fn lua_exec(app: St<'_>, code: String) -> R<()> { run(&app, move |a| a.lua_exec(&code)).await }
#[tauri::command]
async fn lua_interrupt(app: St<'_>) -> R<()> { app.lua_interrupt() }
#[tauri::command]
async fn lua_poll(app: St<'_>, since: u64) -> R<LuaPoll> { app.lua_poll(since) }
#[tauri::command]
async fn lua_dialog_reply(app: St<'_>, id: u64, value: Value) -> R<()> { app.lua_dialog_reply(DialogReply { id, value }) }
#[tauri::command]
async fn settings_get(app: St<'_>) -> R<Settings> { app.settings_get() }
#[tauri::command]
async fn settings_set(app: St<'_>, settings: Settings) -> R<Settings> { run(&app, move |a| a.settings_set(settings)).await }

/// CE virtual-key code -> the key's `Code` name (modifiers excluded).
fn code_name(vk: u32) -> Option<String> {
    Some(match vk {
        65..=90 => format!("Key{}", vk as u8 as char),
        48..=57 => format!("Digit{}", vk - 48),
        96..=105 => format!("Numpad{}", vk - 96),
        112..=135 => format!("F{}", vk - 111),
        _ => match vk {
            8 => "Backspace", 9 => "Tab", 13 => "Enter", 19 => "Pause", 27 => "Escape", 32 => "Space",
            33 => "PageUp", 34 => "PageDown", 35 => "End", 36 => "Home", 37 => "ArrowLeft", 38 => "ArrowUp",
            39 => "ArrowRight", 40 => "ArrowDown", 45 => "Insert", 46 => "Delete", 106 => "NumpadMultiply",
            107 => "NumpadAdd", 109 => "NumpadSubtract", 110 => "NumpadDecimal", 111 => "NumpadDivide",
            186 => "Semicolon", 187 => "Equal", 188 => "Comma", 189 => "Minus", 190 => "Period", 191 => "Slash",
            192 => "Backquote", 219 => "BracketLeft", 220 => "Backslash", 221 => "BracketRight", 222 => "Quote",
            _ => return None,
        }
        .to_string(),
    })
}

/// A combo with modifiers and exactly one other key, as a global shortcut.
fn shortcut_of(keys: &[u32]) -> Option<Shortcut> {
    let mut mods = Modifiers::empty();
    let mut code = None;
    for &k in keys {
        match k {
            16 | 160 | 161 => mods |= Modifiers::SHIFT,
            17 | 162 | 163 => mods |= Modifiers::CONTROL,
            18 | 164 | 165 => mods |= Modifiers::ALT,
            91 | 92 => mods |= Modifiers::SUPER,
            _ if code.is_some() => return None,
            _ => code = Some(code_name(k)?.parse::<Code>().ok()?),
        }
    }
    Some(Shortcut::new((!mods.is_empty()).then_some(mods), code?))
}

// ---------- debugger ----------
#[tauri::command]
async fn debug_attach(app: St<'_>) -> R<DebugStatus> { run(&app, |a| a.debug_attach()).await }
#[tauri::command]
async fn debug_detach(app: St<'_>) -> R<()> { run(&app, |a| a.debug_detach()).await }
#[tauri::command]
async fn debug_status(app: St<'_>) -> R<DebugStatus> { run(&app, |a| a.debug_status()).await }
#[tauri::command]
async fn debug_add_breakpoint(app: St<'_>, req: BpReq) -> R<u32> { run(&app, move |a| a.debug_add_breakpoint(&req)).await }
#[tauri::command]
async fn debug_remove_breakpoint(app: St<'_>, id: u32) -> R<()> { run(&app, move |a| a.debug_remove_breakpoint(id)).await }
#[tauri::command]
async fn debug_set_enabled(app: St<'_>, id: u32, enabled: bool) -> R<()> { run(&app, move |a| a.debug_set_enabled(id, enabled)).await }
#[tauri::command]
async fn debug_breakpoints(app: St<'_>) -> R<Vec<BpOut>> { run(&app, |a| a.debug_breakpoints()).await }
#[tauri::command]
async fn debug_records(app: St<'_>, id: u32) -> R<Vec<RecordOut>> { run(&app, move |a| a.debug_records(id)).await }
#[tauri::command]
async fn debug_clear_records(app: St<'_>, id: u32) -> R<()> { run(&app, move |a| a.debug_clear_records(id)).await }
#[tauri::command]
async fn debug_trace(app: St<'_>, id: u32) -> R<Vec<TraceOut>> { run(&app, move |a| a.debug_trace(id)).await }
#[tauri::command]
async fn debug_threads(app: St<'_>) -> R<Vec<ThreadInfo>> { run(&app, |a| a.debug_threads()).await }
#[tauri::command]
async fn debug_suspend_thread(app: St<'_>, tid: u32, suspend: bool) -> R<()> { run(&app, move |a| a.debug_suspend_thread(tid, suspend)).await }
#[tauri::command]
async fn debug_context(app: St<'_>, tid: u32) -> R<Value> { run(&app, move |a| a.debug_context(tid)).await }
#[tauri::command]
async fn debug_set_register(app: St<'_>, tid: u32, name: String, value: String) -> R<()> { run(&app, move |a| a.debug_set_register(tid, &name, &value)).await }
#[tauri::command]
async fn debug_stack(app: St<'_>, tid: u32, count: usize) -> R<Vec<StackOut>> { run(&app, move |a| a.debug_stack(tid, count)).await }
#[tauri::command]
async fn debug_continue(app: St<'_>, pass_signal: bool) -> R<()> { run(&app, move |a| a.debug_continue(pass_signal)).await }
#[tauri::command]
async fn debug_pause(app: St<'_>) -> R<()> { run(&app, |a| a.debug_pause()).await }
#[tauri::command]
async fn debug_step(app: St<'_>, tid: u32, kind: String) -> R<()> { run(&app, move |a| a.debug_step(tid, &kind)).await }
#[tauri::command]
async fn debug_run_to(app: St<'_>, addr: String) -> R<()> { run(&app, move |a| a.debug_run_to(&addr)).await }
#[tauri::command]
async fn nop_instruction(app: St<'_>, addr: String) -> R<String> { run(&app, move |a| a.nop_instruction(&addr)).await }

// ---------- pointer scanner ----------
#[tauri::command]
async fn ptr_scan(app: St<'_>, req: PtrScanReq) -> R<PtrInfo> { run(&app, move |a| a.ptr_scan(&req)).await }
#[tauri::command]
async fn ptr_rescan(app: St<'_>, req: PtrRescanReq) -> R<PtrInfo> { run(&app, move |a| a.ptr_rescan(&req)).await }
#[tauri::command]
async fn ptr_progress(app: St<'_>) -> R<PtrProgress> { app.ptr_progress() }
#[tauri::command]
async fn ptr_cancel(app: St<'_>) -> R<()> { app.ptr_cancel() }
#[tauri::command]
async fn ptr_results(app: St<'_>, offset: u64, limit: usize, vtype: VType, fmt: Option<Fmt>) -> R<Vec<PtrRow>> {
    run(&app, move |a| a.ptr_results(offset, limit, vtype, &fmt.unwrap_or_default())).await
}
#[tauri::command]
async fn ptr_entry(app: St<'_>, index: u64, vtype: String, description: String) -> R<Value> { run(&app, move |a| a.ptr_entry(index, &vtype, &description)).await }
#[tauri::command]
async fn ptr_save_map(app: St<'_>, path: String) -> R<()> { run(&app, move |a| a.ptr_save_map(&path)).await }
#[tauri::command]
async fn ptr_save_results(app: St<'_>, path: String) -> R<()> { run(&app, move |a| a.ptr_save_results(&path)).await }
#[tauri::command]
async fn ptr_open_results(app: St<'_>, path: String) -> R<PtrInfo> { run(&app, move |a| a.ptr_open_results(&path)).await }

// ---------- tools (hh-tools), table history, process close ----------
use heaphook::tools::{CodeRow, EvalReq, JobProgress, Page, SigOut, SnapInfo, XRefOut};
use hh_tools::dissect::{DissectOptions, DissectSummary};
use hh_tools::headers::HeaderSummary;
use hh_tools::memory::{DiffRange, FileSummary, PointerHit, PointerQuery, Range, RegionInfo, RestoreSummary};
use hh_tools::structure::{FieldValue, SpiderHit, SpiderOptions, Structure};

#[tauri::command]
async fn close_process(app: St<'_>) -> R<()> { run(&app, |a| a.close_process()).await }
#[tauri::command]
async fn table_undo(app: St<'_>) -> R<TableState> { run(&app, |a| a.table_history(false)).await }
#[tauri::command]
async fn table_redo(app: St<'_>) -> R<TableState> { run(&app, |a| a.table_history(true)).await }
#[tauri::command]
async fn tools_progress(app: St<'_>) -> R<JobProgress> { app.tools_progress() }
#[tauri::command]
async fn tools_cancel(app: St<'_>) -> R<()> { app.tools_cancel() }
#[tauri::command]
async fn struct_get(app: St<'_>) -> R<Vec<Structure>> { app.struct_get() }
#[tauri::command]
async fn struct_set(app: St<'_>, structs: Vec<Structure>) -> R<()> { run(&app, move |a| a.struct_set(structs)).await }
#[tauri::command]
async fn struct_guess(app: St<'_>, name: String, addr: String, size: usize) -> R<Structure> { run(&app, move |a| a.struct_guess(&name, &addr, size)).await }
#[tauri::command]
async fn struct_eval(app: St<'_>, reqs: Vec<EvalReq>) -> R<Vec<Result<Vec<FieldValue>, String>>> { run(&app, move |a| a.struct_eval(&reqs)).await }
#[tauri::command]
async fn struct_expand(app: St<'_>, owner: String, index: usize, field_addr: String, size: usize) -> R<EvalReq> { run(&app, move |a| a.struct_expand(&owner, index, &field_addr, size)).await }
#[tauri::command]
async fn struct_entries(app: St<'_>, name: String, root: String, path: Vec<u64>, only: Option<Vec<usize>>) -> R<Vec<heaphook::table::Entry>> {
    run(&app, move |a| a.struct_entries(&name, &root, &path, only)).await
}
#[tauri::command]
async fn struct_spider(app: St<'_>, groups: Vec<Vec<String>>, opts: SpiderOptions) -> R<Vec<SpiderHit>> { run(&app, move |a| a.struct_spider(&groups, &opts)).await }
#[tauri::command]
async fn dissect_run(app: St<'_>, modules: Vec<String>, opts: DissectOptions) -> R<DissectSummary> { run(&app, move |a| a.dissect_run(&modules, &opts)).await }
#[tauri::command]
async fn dissect_summary(app: St<'_>) -> R<Option<DissectSummary>> { app.dissect_summary() }
#[tauri::command]
async fn dissect_list(app: St<'_>, kind: String, filter: String, offset: usize, limit: usize) -> R<Page<Value>> { run(&app, move |a| a.dissect_list(&kind, &filter, offset, limit)).await }
#[tauri::command]
async fn dissect_xrefs(app: St<'_>, addr: String, len: u64, offset: usize, limit: usize) -> R<Page<XRefOut>> { run(&app, move |a| a.dissect_xrefs(&addr, len, offset, limit)).await }
#[tauri::command]
async fn regions_info(app: St<'_>) -> R<Vec<RegionInfo>> { run(&app, |a| a.regions_info()).await }
#[tauri::command]
async fn mem_protect(app: St<'_>, addr: String, size: u64, prot: hh_core::Prot) -> R<hh_core::Prot> { run(&app, move |a| a.mem_protect(&addr, size, prot)).await }
#[tauri::command]
async fn mem_save(app: St<'_>, ranges: Vec<Range>, path: String) -> R<FileSummary> { run(&app, move |a| a.mem_save(&ranges, &path)).await }
#[tauri::command]
async fn mem_load(app: St<'_>, path: String, relocate: Option<String>) -> R<RestoreSummary> { run(&app, move |a| a.mem_load(&path, relocate.as_deref())).await }
#[tauri::command]
async fn mem_fill(app: St<'_>, addr: String, len: u64, pattern: String) -> R<()> { run(&app, move |a| a.mem_fill(&addr, len, &pattern)).await }
#[tauri::command]
async fn mem_copy(app: St<'_>, src: String, dst: String, len: u64) -> R<()> { run(&app, move |a| a.mem_copy(&src, &dst, len)).await }
#[tauri::command]
async fn snapshot_take(app: St<'_>, ranges: Vec<Range>, label: String) -> R<SnapInfo> { run(&app, move |a| a.snapshot_take(&ranges, &label)).await }
#[tauri::command]
async fn snapshot_list(app: St<'_>) -> R<Vec<SnapInfo>> { app.snapshot_list() }
#[tauri::command]
async fn snapshot_delete(app: St<'_>, id: u64) -> R<()> { app.snapshot_delete(id) }
#[tauri::command]
async fn snapshot_diff(app: St<'_>, id: u64, max: usize) -> R<Vec<DiffRange>> { run(&app, move |a| a.snapshot_diff(id, max)).await }
#[tauri::command]
async fn find_pointers(app: St<'_>, query: PointerQuery) -> R<Vec<PointerHit>> { run(&app, move |a| a.find_pointers(&query)).await }
#[tauri::command]
async fn module_header(app: St<'_>, name: String) -> R<HeaderSummary> { run(&app, move |a| a.module_header(&name)).await }
#[tauri::command]
async fn aob_signature(app: St<'_>, addr: String) -> R<SigOut> { run(&app, move |a| a.aob_signature(&addr)).await }
#[tauri::command]
async fn aa_template(app: St<'_>, addr: String, kind: String) -> R<String> { run(&app, move |a| a.aa_template(&addr, &kind)).await }
#[tauri::command]
async fn code_list(app: St<'_>) -> R<Vec<CodeRow>> { run(&app, |a| a.code_list()).await }
#[tauri::command]
async fn code_add(app: St<'_>, addr: String, description: String) -> R<usize> { run(&app, move |a| a.code_add(&addr, &description)).await }
#[tauri::command]
async fn code_remove(app: St<'_>, index: usize) -> R<()> { run(&app, move |a| a.code_remove(index)).await }
#[tauri::command]
async fn code_nop(app: St<'_>, index: usize) -> R<()> { run(&app, move |a| a.code_nop(index)).await }
#[tauri::command]
async fn code_restore(app: St<'_>, index: usize, force: bool) -> R<()> { run(&app, move |a| a.code_restore(index, force)).await }
#[tauri::command]
async fn debug_set_condition(app: St<'_>, id: u32, condition: String) -> R<()> { run(&app, move |a| a.debug_set_condition(id, &condition)).await }
#[tauri::command]
async fn debug_signals() -> R<Vec<(u32, &'static str, &'static str)>> { Ok(heaphook::debug::SIGNALS.to_vec()) }
#[tauri::command]
async fn ptr_sort(app: St<'_>, key: String, column: usize, desc: bool, vtype: VType, fmt: Option<Fmt>) -> R<PtrInfo> {
    run(&app, move |a| a.ptr_sort(&key, column, desc, vtype, &fmt.unwrap_or_default())).await
}

#[tauri::command]
async fn process_create(app: St<'_>, req: heaphook::inject::CreateReq) -> R<Opened> { run(&app, move |a| a.process_create(&req)).await }
#[tauri::command]
async fn speed_get(app: St<'_>) -> R<Option<hh_inject::SpeedhackStatus>> { run(&app, |a| a.speed_get()).await }
#[tauri::command]
async fn speed_set(app: St<'_>, speed: f64) -> R<hh_inject::SpeedhackStatus> { run(&app, move |a| a.speed_set(speed)).await }

/// Native open/save dialog; `None` when the user cancels. `filters`: `[[name, [ext, ..]], ..]`.
#[tauri::command]
async fn pick_path(handle: tauri::AppHandle, save: bool, title: String, filters: Vec<(String, Vec<String>)>, default: Option<String>) -> R<Option<String>> {
    tauri::async_runtime::spawn_blocking(move || {
        let mut d = handle.dialog().file().set_title(title);
        for (name, exts) in &filters {
            d = d.add_filter(name, &exts.iter().map(String::as_str).collect::<Vec<_>>());
        }
        if let Some(p) = default.as_deref().map(std::path::Path::new) {
            if let Some(dir) = p.parent().filter(|d| d.is_dir()) {
                d = d.set_directory(dir);
            }
            if let Some(name) = p.file_name() {
                d = d.set_file_name(name.to_string_lossy());
            }
        }
        let p = if save { d.blocking_save_file() } else { d.blocking_pick_file() };
        p.map(|p| p.into_path().map(|p| p.to_string_lossy().into_owned()).map_err(|e| e.to_string())).transpose()
    })
    .await
    .map_err(|e| format!("dialog failed: {e}"))?
}

fn main() {
    // Registered shortcut id -> its CE key combo.
    let combos: Arc<Mutex<HashMap<u32, Vec<u32>>>> = Arc::default();
    let pressed = combos.clone();
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(
            tauri_plugin_global_shortcut::Builder::new()
                .with_handler(move |h, sc, ev| {
                    if ev.state() != ShortcutState::Pressed {
                        return;
                    }
                    let keys = pressed.lock().unwrap_or_else(|e| e.into_inner()).get(&sc.id()).cloned();
                    if let Some(keys) = keys {
                        let app = h.state::<App>().inner().clone();
                        // Off the event-loop thread: hotkeys may run Lua and Auto Assembler.
                        std::thread::spawn(move || app.hotkey_press(&keys));
                    }
                })
                .build(),
        )
        .manage(App::default())
        .setup(move |tapp| {
            let app = tapp.state::<App>().inner().clone();
            if let Ok(dir) = tapp.path().app_config_dir() {
                app.set_config_dir(&dir);
            }
            let h = tapp.handle().clone();
            app.set_hotkey_registrar(Box::new(move |list: &[Vec<u32>]| {
                let gs = h.global_shortcut();
                let _ = gs.unregister_all();
                let mut m = combos.lock().unwrap_or_else(|e| e.into_inner());
                m.clear();
                list.iter()
                    .map(|keys| match shortcut_of(keys) {
                        Some(sc) if gs.register(sc).is_ok() => {
                            m.insert(sc.id(), keys.clone());
                            true
                        }
                        _ => false,
                    })
                    .collect()
            }));
            app.start_driver();
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            list_processes, open_process, regions, modules, read_memory, write_bytes, read_values,
            write_value, resolve_address, scan_first, scan_next, scan_undo, scan_new, scan_cancel,
            scan_progress, scan_results, set_frozen, disassemble, assemble, aa_check, aa_execute,
            table_load, table_save, debug_attach, debug_detach, debug_status, debug_add_breakpoint,
            debug_remove_breakpoint, debug_set_enabled, debug_breakpoints, debug_records, debug_clear_records,
            debug_trace, debug_threads, debug_suspend_thread, debug_context, debug_set_register, debug_stack,
            debug_continue, debug_pause, debug_step, debug_run_to, nop_instruction, ptr_scan, ptr_rescan,
            ptr_progress, ptr_cancel, ptr_results, ptr_entry, ptr_save_map, ptr_save_results, ptr_open_results,
            pick_path, table_get, table_put, table_open, table_export, table_set_active, table_set_value,
            table_hotkey, table_run_script, hotkey_press, lua_exec, lua_interrupt, lua_poll, lua_dialog_reply,
            settings_get, settings_set, close_process, table_undo, table_redo, tools_progress, tools_cancel,
            struct_get, struct_set, struct_guess, struct_eval, struct_expand, struct_entries, struct_spider,
            dissect_run, dissect_summary, dissect_list, dissect_xrefs, regions_info, mem_protect, mem_save, mem_load,
            mem_fill, mem_copy, snapshot_take, snapshot_list, snapshot_delete, snapshot_diff, find_pointers,
            module_header, aob_signature, aa_template, code_list, code_add, code_remove, code_nop, code_restore,
            debug_set_condition, debug_signals, ptr_sort, process_create, speed_get, speed_set
        ])
        .run(tauri::generate_context!())
        .expect("failed to start HeapHook");
}
