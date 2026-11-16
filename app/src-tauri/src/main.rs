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

use heaphook::tools::{CodeRow, EvalReq, JobProgress, Page, SigOut, SnapInfo, XRefOut};
use hh_tools::dissect::{DissectOptions, DissectSummary};
use hh_tools::headers::HeaderSummary;
use hh_tools::memory::{DiffRange, FileSummary, PointerHit, PointerQuery, Range, RegionInfo, RestoreSummary};
use hh_tools::structure::{FieldValue, SpiderHit, SpiderOptions, Structure};

#[cfg(feature = "dev-bridge")]
mod bridge;
use tauri_plugin_dialog::DialogExt;
use tauri_plugin_global_shortcut::{Code, GlobalShortcutExt, Modifiers, Shortcut, ShortcutState};

/// Runs command logic on the blocking pool so scans and big reads never stall IPC or the UI.
async fn run<T: Send + 'static>(app: &App, f: impl FnOnce(&App) -> R<T> + Send + 'static) -> R<T> {
    let app = app.clone();
    tauri::async_runtime::spawn_blocking(move || f(&app)).await.map_err(|e| format!("command failed: {e}"))?
}

type St<'a> = State<'a, App>;

/// Tauri command body: `run` goes to the blocking pool, `now` answers on the IPC thread.
macro_rules! tauri_body {
    (run, $app:ident, $a:ident, $body:expr) => {
        run(&$app, move |$a: &App| $body).await
    };
    (now, $app:ident, $a:ident, $body:expr) => {{
        let $a: &App = &$app;
        $body
    }};
}

/// The one command table. Each line becomes a `#[tauri::command]` (argument names are the
/// Tauri parameter names, camelCased on the wire by Tauri) and, with the `dev-bridge`
/// feature, a case of [`dispatch`] that decodes the same arguments the same way.
macro_rules! commands {
    ($( $mode:ident $name:ident ( $($arg:ident : $ty:ty),* ) -> $ret:ty = |$a:ident| $body:expr ; )*) => {
        $(
            #[tauri::command]
            #[allow(clippy::too_many_arguments)]
            async fn $name(app: St<'_>, $($arg: $ty),*) -> R<$ret> { tauri_body!($mode, app, $a, $body) }
        )*

        fn handler() -> impl Fn(tauri::ipc::Invoke) -> bool + Send + Sync + 'static {
            tauri::generate_handler![pick_path $(, $name)*]
        }

        /// Runs command `cmd` with Tauri-style `args` (a JSON object keyed by camelCase
        /// parameter name); `None` for an unknown command.
        #[cfg(feature = "dev-bridge")]
        fn dispatch(app: &App, cmd: &str, args: &Value) -> Option<R<Value>> {
            match cmd {
                $( stringify!($name) => Some((|| {
                    $( let $arg: $ty = bridge::arg(args, stringify!($name), stringify!($arg))?; )*
                    let $a: &App = app;
                    let r: R<$ret> = $body;
                    serde_json::to_value(r?).map_err(|e| e.to_string())
                })()), )*
                _ => None,
            }
        }
    };
}

commands! {
    run list_processes() -> Vec<ProcessInfo> = |a| a.list_processes();
    run open_process(pid: u32) -> Opened = |a| a.open_process(pid);
    run regions() -> Vec<RegionOut> = |a| a.regions();
    run modules() -> Vec<ModuleOut> = |a| a.modules();
    run read_memory(addr: String, len: usize) -> String = |a| a.read_memory(&addr, len);
    run write_bytes(addr: String, hex: String) -> () = |a| a.write_bytes(&addr, &hex);
    run read_values(reqs: Vec<ValueRef>) -> Vec<Option<String>> = |a| a.read_values(reqs);
    run write_value(addr: String, vtype: VType, value: String, len: Option<usize>, utf16: Option<bool>, signed: Option<bool>, hex: Option<bool>) -> () = |a| { let fmt = Fmt { len: len.filter(|&l| l > 0), utf16: utf16.unwrap_or(false), signed: signed.unwrap_or(false), hex: hex.unwrap_or(false) }; a.write_value(&addr, vtype, &value, &fmt) };
    run resolve_address(expr: String) -> String = |a| a.resolve_address(&expr);
    run scan_first(req: FirstScan) -> ScanCount = |a| a.scan_first(&req);
    run scan_next(req: NextScan) -> ScanCount = |a| a.scan_next(&req);
    run scan_undo() -> () = |a| a.scan_undo();
    run scan_new() -> () = |a| a.scan_new();
    now scan_cancel() -> () = |a| a.scan_cancel();
    now scan_progress() -> ScanProgress = |a| a.scan_progress();
    run scan_results(offset: u64, limit: usize) -> Vec<ResultRow> = |a| a.scan_results(offset, limit);
    run set_frozen(entries: Vec<FrozenEntry>) -> () = |a| a.set_frozen(&entries);
    run disassemble(addr: String, count: usize) -> Vec<DisasmOut> = |a| a.disassemble(&addr, count);
    run assemble(addr: String, text: String) -> String = |a| a.assemble(&addr, &text);
    run aa_check(script: String) -> Option<AaError> = |a| a.aa_check(&script);
    run aa_execute(script: String, enable: bool, state: Option<AaState>) -> AaState = |a| a.aa_execute(&script, enable, state.as_ref());
    run table_load(path: String) -> Table = |a| a.table_load(&path);
    run table_save(path: String, table: TableIn) -> () = |a| a.table_save(&path, table);
    now table_get() -> TableState = |a| a.table_get();
    run table_put(table: Table, base: u64) -> u64 = |a| a.table_put(table, base);
    run table_open(path: String, force: Option<bool>) -> TableState = |a| a.table_open(&path, force.unwrap_or(false));
    run table_trust(trust: bool) -> () = |a| a.table_trust(trust);
    run table_export(path: String) -> () = |a| a.table_export(&path);
    run table_set_active(ids: Vec<i64>, active: bool) -> () = |a| a.table_set_active(&ids, active);
    run table_set_value(ids: Vec<i64>, value: String) -> () = |a| a.table_set_value(&ids, &value);
    run table_hotkey(id: i64, index: usize) -> () = |a| a.table_hotkey(id, index);
    run table_run_script() -> () = |a| a.table_run_script();
    run hotkey_press(keys: Vec<u32>) -> usize = |a| a.hotkey_press(&keys);
    run lua_exec(code: String) -> () = |a| a.lua_exec(&code);
    now lua_interrupt() -> () = |a| a.lua_interrupt();
    now lua_poll(since: u64) -> LuaPoll = |a| a.lua_poll(since);
    now lua_dialog_reply(id: u64, value: Value) -> () = |a| a.lua_dialog_reply(DialogReply { id, value });
    now settings_get() -> Settings = |a| a.settings_get();
    run settings_set(settings: Settings) -> Settings = |a| a.settings_set(settings);
    run debug_attach() -> DebugStatus = |a| a.debug_attach();
    run debug_detach() -> () = |a| a.debug_detach();
    run debug_status() -> DebugStatus = |a| a.debug_status();
    run debug_add_breakpoint(req: BpReq) -> u32 = |a| a.debug_add_breakpoint(&req);
    run debug_remove_breakpoint(id: u32) -> () = |a| a.debug_remove_breakpoint(id);
    run debug_set_enabled(id: u32, enabled: bool) -> () = |a| a.debug_set_enabled(id, enabled);
    run debug_breakpoints() -> Vec<BpOut> = |a| a.debug_breakpoints();
    run debug_records(id: u32) -> Vec<RecordOut> = |a| a.debug_records(id);
    run debug_clear_records(id: u32) -> () = |a| a.debug_clear_records(id);
    run debug_trace(id: u32) -> Vec<TraceOut> = |a| a.debug_trace(id);
    run debug_threads() -> Vec<ThreadInfo> = |a| a.debug_threads();
    run debug_suspend_thread(tid: u32, suspend: bool) -> () = |a| a.debug_suspend_thread(tid, suspend);
    run debug_context(tid: u32) -> Value = |a| a.debug_context(tid);
    run debug_set_register(tid: u32, name: String, value: String) -> () = |a| a.debug_set_register(tid, &name, &value);
    run debug_stack(tid: u32, count: usize) -> Vec<StackOut> = |a| a.debug_stack(tid, count);
    run debug_continue(pass_signal: bool) -> () = |a| a.debug_continue(pass_signal);
    run debug_pause() -> () = |a| a.debug_pause();
    run debug_step(tid: u32, kind: String) -> () = |a| a.debug_step(tid, &kind);
    run debug_run_to(addr: String) -> () = |a| a.debug_run_to(&addr);
    run nop_instruction(addr: String) -> String = |a| a.nop_instruction(&addr);
    run ptr_scan(req: PtrScanReq) -> PtrInfo = |a| a.ptr_scan(&req);
    run ptr_rescan(req: PtrRescanReq) -> PtrInfo = |a| a.ptr_rescan(&req);
    now ptr_progress() -> PtrProgress = |a| a.ptr_progress();
    now ptr_cancel() -> () = |a| a.ptr_cancel();
    run ptr_results(offset: u64, limit: usize, vtype: VType, fmt: Option<Fmt>) -> Vec<PtrRow> = |a| a.ptr_results(offset, limit, vtype, &fmt.unwrap_or_default());
    run ptr_entry(index: u64, vtype: String, description: String) -> Value = |a| a.ptr_entry(index, &vtype, &description);
    run ptr_save_map(path: String) -> () = |a| a.ptr_save_map(&path);
    run ptr_save_results(path: String) -> () = |a| a.ptr_save_results(&path);
    run ptr_open_results(path: String) -> PtrInfo = |a| a.ptr_open_results(&path);
    run close_process() -> () = |a| a.close_process();
    run table_undo() -> TableState = |a| a.table_history(false);
    run table_redo() -> TableState = |a| a.table_history(true);
    now tools_progress() -> JobProgress = |a| a.tools_progress();
    now tools_cancel() -> () = |a| a.tools_cancel();
    now struct_get() -> Vec<Structure> = |a| a.struct_get();
    run struct_set(structs: Vec<Structure>) -> () = |a| a.struct_set(structs);
    run struct_guess(name: String, addr: String, size: usize) -> Structure = |a| a.struct_guess(&name, &addr, size);
    run struct_eval(reqs: Vec<EvalReq>) -> Vec<Result<Vec<FieldValue>, String>> = |a| a.struct_eval(&reqs);
    run struct_expand(owner: String, index: usize, field_addr: String, size: usize) -> EvalReq = |a| a.struct_expand(&owner, index, &field_addr, size);
    run struct_entries(name: String, root: String, path: Vec<u64>, only: Option<Vec<usize>>) -> Vec<heaphook::table::Entry> = |a| a.struct_entries(&name, &root, &path, only);
    run struct_spider(groups: Vec<Vec<String>>, opts: SpiderOptions) -> Vec<SpiderHit> = |a| a.struct_spider(&groups, &opts);
    run dissect_run(modules: Vec<String>, opts: DissectOptions) -> DissectSummary = |a| a.dissect_run(&modules, &opts);
    now dissect_summary() -> Option<DissectSummary> = |a| a.dissect_summary();
    run dissect_list(kind: String, filter: String, offset: usize, limit: usize) -> Page<Value> = |a| a.dissect_list(&kind, &filter, offset, limit);
    run dissect_xrefs(addr: String, len: u64, offset: usize, limit: usize) -> Page<XRefOut> = |a| a.dissect_xrefs(&addr, len, offset, limit);
    run regions_info() -> Vec<RegionInfo> = |a| a.regions_info();
    run mem_protect(addr: String, size: u64, prot: hh_core::Prot) -> hh_core::Prot = |a| a.mem_protect(&addr, size, prot);
    run mem_save(ranges: Vec<Range>, path: String) -> FileSummary = |a| a.mem_save(&ranges, &path);
    run mem_load(path: String, relocate: Option<String>) -> RestoreSummary = |a| a.mem_load(&path, relocate.as_deref());
    run mem_fill(addr: String, len: u64, pattern: String) -> () = |a| a.mem_fill(&addr, len, &pattern);
    run mem_copy(src: String, dst: String, len: u64) -> () = |a| a.mem_copy(&src, &dst, len);
    run snapshot_take(ranges: Vec<Range>, label: String) -> SnapInfo = |a| a.snapshot_take(&ranges, &label);
    now snapshot_list() -> Vec<SnapInfo> = |a| a.snapshot_list();
    now snapshot_delete(id: u64) -> () = |a| a.snapshot_delete(id);
    run snapshot_diff(id: u64, max: usize) -> Vec<DiffRange> = |a| a.snapshot_diff(id, max);
    run find_pointers(query: PointerQuery) -> Vec<PointerHit> = |a| a.find_pointers(&query);
    run module_header(name: String) -> HeaderSummary = |a| a.module_header(&name);
    run aob_signature(addr: String) -> SigOut = |a| a.aob_signature(&addr);
    run aa_template(addr: String, kind: String) -> String = |a| a.aa_template(&addr, &kind);
    run code_list() -> Vec<CodeRow> = |a| a.code_list();
    run code_add(addr: String, description: String) -> usize = |a| a.code_add(&addr, &description);
    run code_remove(index: usize) -> () = |a| a.code_remove(index);
    run code_nop(index: usize) -> () = |a| a.code_nop(index);
    run code_restore(index: usize, force: bool) -> () = |a| a.code_restore(index, force);
    run debug_set_condition(id: u32, condition: String) -> () = |a| a.debug_set_condition(id, &condition);
    now debug_signals() -> Vec<(u32, &'static str, &'static str)> = |_a| Ok(heaphook::debug::SIGNALS.to_vec());
    run ptr_sort(key: String, column: usize, desc: bool, vtype: VType, fmt: Option<Fmt>) -> PtrInfo = |a| a.ptr_sort(&key, column, desc, vtype, &fmt.unwrap_or_default());
    run process_create(req: heaphook::inject::CreateReq) -> Opened = |a| a.process_create(&req);
    run speed_get() -> Option<hh_inject::SpeedhackStatus> = |a| a.speed_get();
    run speed_set(speed: f64) -> hh_inject::SpeedhackStatus = |a| a.speed_set(speed);
}

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
    #[cfg(feature = "dev-bridge")]
    if let Some(port) = bridge::port_arg() {
        return bridge::serve(port, dispatch);
    }
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
        .invoke_handler(handler())
        .build(tauri::generate_context!())
        .expect("failed to start HeapHook")
        .run(|h, ev| {
            // Quitting with the process still running: undo active scripts, stop freezing.
            if let tauri::RunEvent::Exit = ev {
                let _ = h.state::<App>().close_process();
            }
        });
}
