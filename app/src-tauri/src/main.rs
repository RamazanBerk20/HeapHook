// No console window on Windows release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use heaphook::cheat::TableState;
use heaphook::commands::{App, DisasmOut, ModuleOut, Opened, ProgressOut, R, RegionOut, ResultOut, SavedScan};
use heaphook::lua::{DialogReply, LuaPoll, UiPoll};
use heaphook::settings::Settings;
use heaphook::debug::{BpOut, BpReq, DebugLog, DebugStatus, FrameOut, RangeReq, RecordOut, StackOut, TraceOut};
use heaphook::ptr::{PtrInfo, PtrProgress, PtrRescanReq, PtrRow, PtrScanReq};
use heaphook::table::{Table, TableIn};
use hh_asm::{AaError, AaState};
use hh_core::ProcessInfo;
use hh_debug::ThreadInfo;
use hh_scan::{CustomType, FirstScan, Fmt, FrozenEntryEx, NextScanEx, ScanCount, VType, ValueRefEx};
use serde_json::Value;
use tauri::{Manager, State};

use heaphook::tools::{CodeRow, EvalReq, JobProgress, Page, SigOut, SnapInfo, XRefOut};
use hh_tools::dissect::{DissectOptions, DissectSummary};
use hh_tools::headers::HeaderSummary;
use hh_tools::memory::{ChangeMap, DiffRange, FileSummary, LoadPlan, PlanBlock, PointerHit, PointerQuery, Range, RegionInfo, RegionStats, RestoreSummary};
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
            tauri::generate_handler![pick_path, app_quit $(, $name)*]
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
    run read_values(reqs: Vec<ValueRefEx>) -> Vec<Option<String>> = |a| a.read_values(reqs);
    run write_value(addr: String, vtype: VType, value: String, len: Option<usize>, utf16: Option<bool>, signed: Option<bool>, hex: Option<bool>, custom: Option<CustomType>) -> () = |a| { let fmt = Fmt { len: len.filter(|&l| l > 0), utf16: utf16.unwrap_or(false), signed: signed.unwrap_or(false), hex: hex.unwrap_or(false) }; a.write_value(&addr, vtype, &value, &fmt, custom.as_ref()) };
    run resolve_address(expr: String) -> String = |a| a.resolve_address(&expr);
    run scan_first(req: FirstScan) -> ScanCount = |a| a.scan_first(&req);
    run scan_next(req: NextScanEx) -> ScanCount = |a| a.scan_next(&req);
    run scan_undo() -> () = |a| a.scan_undo();
    run scan_new() -> () = |a| a.scan_new();
    now scan_cancel() -> () = |a| a.scan_cancel();
    now scan_progress() -> ProgressOut = |a| a.scan_progress();
    run scan_results(offset: u64, limit: usize, saved: Option<String>) -> Vec<ResultOut> = |a| a.scan_results(offset, limit, saved.as_deref());
    run set_frozen(entries: Vec<FrozenEntryEx>) -> () = |a| a.set_frozen(&entries);
    run disassemble(addr: String, count: usize, opts: Option<heaphook::commands::DisasmOpts>) -> Vec<DisasmOut> = |a| a.disassemble_ex(&addr, count, &opts.unwrap_or_default());
    run assemble(addr: String, text: String) -> String = |a| a.assemble(&addr, &text);
    run aa_check(script: String, session: Option<u64>, entry: Option<i64>) -> Option<AaError> = |a| a.aa_check(&script, session, entry);
    run aa_execute(script: String, enable: bool, state: Option<AaState>, session: Option<u64>) -> AaState = |a| a.aa_execute(&script, enable, state.as_ref(), session);
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
    run debug_step(tid: u32, kind: String, skip_breakpoints: Option<bool>) -> () = |a| a.debug_step(tid, &kind, skip_breakpoints.unwrap_or(false));
    run debug_run_to(addr: String, tid: Option<u32>, count: Option<u64>) -> () = |a| a.debug_run_to(&addr, tid, count.unwrap_or(1));
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
    run mem_load_plan(path: String, relocate: Option<String>) -> LoadPlan = |a| a.mem_load_plan(&path, relocate.as_deref());
    run mem_load_approved(path: String, relocate: Option<String>, blocks: Vec<PlanBlock>) -> RestoreSummary = |a| a.mem_load_approved(&path, relocate.as_deref(), &blocks);
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
    run debug_signals() -> Vec<heaphook::debug::SignalRow> = |a| a.debug_signals();
    run debug_set_options(id: u32, options: hh_debug::BpOptions) -> () = |a| a.debug_set_options(id, options);
    run debug_watch_range(req: RangeReq) -> u32 = |a| a.debug_watch_range(&req);
    run debug_backtrace(tid: u32, max: usize) -> Vec<FrameOut> = |a| a.debug_backtrace(tid, max);
    run debug_log(since: u64) -> DebugLog = |a| a.debug_log(since);
    now ui_poll(since: u64) -> UiPoll = |a| a.ui_poll(since);
    run ui_event(id: u32, event: String, args: Option<Vec<hh_lua::Prop>>) -> Vec<hh_lua::Prop> = |a| a.ui_event(id, &event, args.unwrap_or_default());
    run ui_input(id: u32, prop: String, value: hh_lua::Prop) -> () = |a| a.ui_input(id, &prop, value);
    run ui_image(path: String) -> String = |a| a.ui_image(&path);
    now key_state(keys: Vec<u32>) -> () = |a| a.key_state(&keys);
    now table_select(ids: Vec<i64>) -> () = |a| a.table_select(ids);
    run trainer_script(req: heaphook::trainer::TrainerReq) -> String = |a| a.trainer_script(&req);
    run ptr_sort(key: String, column: usize, desc: bool, vtype: VType, fmt: Option<Fmt>) -> PtrInfo = |a| a.ptr_sort(&key, column, desc, vtype, &fmt.unwrap_or_default());
    run process_create(req: heaphook::inject::CreateReq) -> Opened = |a| a.process_create(&req);
    run speed_get() -> Option<hh_inject::SpeedhackStatus> = |a| a.speed_get();
    run speed_set(speed: f64) -> hh_inject::SpeedhackStatus = |a| a.speed_set(speed);
    run scan_save(name: String) -> () = |a| a.scan_save(&name);
    run scan_saved() -> Vec<SavedScan> = |a| a.scan_saved();
    run scan_delete_saved(name: String) -> () = |a| a.scan_delete_saved(&name);
    now scan_pause() -> () = |a| a.scan_pause(true);
    now scan_resume() -> () = |a| a.scan_pause(false);
    now custom_presets() -> Vec<Value> = |a| a.custom_presets();
    now custom_validate(custom: CustomType) -> Option<String> = |a| a.custom_validate(&custom);
    run resolve_many(exprs: Vec<String>) -> Vec<Option<String>> = |a| a.resolve_many(&exprs);
    run remote_saved() -> heaphook::remote::SavedOut = |a| a.remote_saved();
    run remote_forget() -> () = |a| a.remote_forget();
    run remote_connect(addr: String, token: String, remember: bool) -> heaphook::remote::Status = |a| a.remote_connect(&addr, &token, remember);
    run remote_status() -> Option<heaphook::remote::Status> = |a| a.remote_status();
    run remote_processes() -> Vec<ProcessInfo> = |a| a.remote_processes();
    run remote_open(pid: u32) -> Opened = |a| a.remote_open(pid);
    run remote_disconnect() -> () = |a| a.remote_disconnect();
    run code_function(addr: String) -> heaphook::tools::FuncOut = |a| a.code_function(&addr);
    run code_targets(addr: String) -> heaphook::tools::Targets = |a| a.code_targets(&addr);
    run mem_compare(path: String, max: usize) -> Vec<DiffRange> = |a| a.mem_compare(&path, max);
    run struct_export(path: String, names: Vec<String>) -> () = |a| a.struct_export(&path, &names);
    run struct_import(path: String) -> Vec<String> = |a| a.struct_import(&path);
    now app_info() -> Value = |a| a.app_info();
    run mem_search(req: heaphook::search::SearchReq) -> Vec<String> = |a| a.mem_search(&req);
    run disasm_search(req: heaphook::search::DisasmSearchReq) -> Vec<heaphook::search::DisasmHit> = |a| a.disasm_search(&req);
    run mem_alloc(size: u64, prot: hh_core::Prot) -> String = |a| a.mem_alloc(size, prot);
    run mem_free(addr: String, size: u64) -> () = |a| a.mem_free(&addr, size);
    run process_pause(pause: bool) -> () = |a| a.process_pause(pause);
    run trace_save(path: String, trace: Value) -> () = |a| a.trace_save(&path, &trace);
    run trace_load(path: String) -> Value = |a| a.trace_load(&path);
    run table_export_text(path: String) -> () = |a| a.table_export_text(&path);
    run table_merge(path: String) -> TableState = |a| a.table_merge(&path);
    run table_paste(entries: Vec<heaphook::table::Entry>, after: Option<i64>, base: Option<u64>) -> heaphook::cheat::PasteOut = |a| a.table_paste(entries, after, base);
    run table_trust_entries(ids: Vec<i64>) -> () = |a| a.table_trust_entries(&ids);
    run table_dirty() -> bool = |a| a.table_dirty();
    run table_open_data(name: String, data: String, force: Option<bool>) -> TableState = |a| a.table_open_data(&name, &data, force.unwrap_or(false));
    run aa_load_file(path: String, session: u64) -> String = |a| a.aa_load_file(&path, session);
    run aa_trust(session: u64) -> () = |a| a.aa_trust(session);
    now aa_session() -> u64 = |a| a.aa_session();
    run aa_assign(session: u64, script: String, description: String, after: Option<i64>, base: Option<u64>) -> heaphook::cheat::PasteOut = |a| a.aa_assign(session, &script, &description, after, base);
    run table_add_template(addr: String, kind: String, description: String, after: Option<i64>, base: Option<u64>) -> heaphook::cheat::PasteOut = |a| a.table_add_template(&addr, &kind, &description, after, base);
    run table_resolve(ids: Vec<i64>) -> Vec<Option<String>> = |a| a.table_resolve(&ids);
    now app_args() -> Option<heaphook::cli::StartArgs> = |a| a.app_args();
    // 1.0 release candidate: engine features of the last wave.
    run scan_sort(key: hh_scan::SortKey, desc: bool) -> () = |a| a.scan_sort(key, desc);
    run scan_remove(addrs: Vec<String>) -> u64 = |a| a.scan_remove(&addrs);
    run scan_export_addresses(path: String) -> u64 = |a| a.scan_export_addresses(&path);
    run scan_copy_addresses() -> String = |a| a.scan_copy_addresses();
    run scan_stats() -> Vec<hh_scan::ResultStat> = |a| a.scan_stats();
    run scan_pointer(req: hh_scan::PointerScan) -> ScanCount = |a| a.scan_pointer(&req);
    now ptr_pause() -> () = |a| a.ptr_pause(true);
    now ptr_resume() -> () = |a| a.ptr_pause(false);
    run mem_file_search(req: heaphook::tools::FileSearchReq) -> Vec<String> = |a| a.mem_file_search(&req);
    run region_stats() -> RegionStats = |a| a.region_stats();
    run snapshot_change_map(old: u64, new: u64, start: Option<String>, end: Option<String>, cells: usize) -> ChangeMap = |a| a.snapshot_change_map(old, new, start.as_deref().unwrap_or(""), end.as_deref().unwrap_or(""), cells);
    run struct_view(reqs: Vec<EvalReq>) -> Vec<Result<heaphook::tools::StructView, String>> = |a| a.struct_view(&reqs);
    run struct_lock(name: String, addr: String, on: bool) -> () = |a| a.struct_lock(&name, &addr, on);
    run struct_write(name: String, addr: String, leaf: usize, value: String) -> () = |a| a.struct_write(&name, &addr, leaf, &value);
    run struct_code(names: Vec<String>, lang: String, path: Option<String>) -> String = |a| { let t = a.struct_code(&names, &lang)?; if let Some(p) = path.as_deref().filter(|p| !p.trim().is_empty()) { std::fs::write(p, &t).map_err(|e| format!("{p}: {e}"))?; } Ok(t) };
    run struct_field_entry(name: String, root: String, path: Vec<usize>) -> heaphook::table::Entry = |a| a.struct_field_entry(&name, &root, &path);
    run dissect_add(modules: Vec<String>, opts: DissectOptions) -> DissectSummary = |a| a.dissect_add(&modules, &opts);
    run dissect_save(path: String) -> () = |a| a.dissect_save(&path);
    run dissect_load(path: String) -> DissectSummary = |a| a.dissect_load(&path);
    run code_filter_start() -> heaphook::tools::FilterState = |a| a.code_filter_start();
    run code_filter_stop(ran: bool) -> heaphook::tools::FilterState = |a| a.code_filter_stop(ran);
    run code_filter_state() -> heaphook::tools::FilterState = |a| a.code_filter_state();
    run code_filter_reset() -> () = |a| a.code_filter_reset();
    run code_filter_list(offset: usize, limit: usize) -> Page<hh_tools::dissect::Function> = |a| a.code_filter_list(offset, limit);
    run asm_scan(req: heaphook::tools::AsmScanReq) -> heaphook::tools::AsmPageOut = |a| a.asm_scan(&req);
    run find_reference(from: String, target: String, forward: bool, max_bytes: Option<u64>) -> Option<String> = |a| a.find_reference(&from, &target, forward, max_bytes.unwrap_or(0));
    run symbol_list(module: Option<String>, filter: String, offset: usize, limit: usize) -> Page<heaphook::tools::SymbolOut> = |a| a.symbol_list(module.as_deref(), &filter, offset, limit);
    run debug_launch(req: heaphook::debug::LaunchReq) -> Opened = |a| a.debug_launch(&req);
    run debug_set_break_on(on: hh_debug::BreakOn) -> () = |a| a.debug_set_break_on(on);
    run debug_break_on() -> hh_debug::BreakOn = |a| a.debug_break_on();
    run debug_set_ip(tid: u32, addr: String) -> () = |a| a.debug_set_ip(tid, &addr);
    run debug_run_until_return(tid: u32, frame: usize) -> () = |a| a.debug_run_until_return(tid, frame);
}

/// The UI's answer to a close request with unsaved changes (`lua_poll.window.close_seq`):
/// quit, or keep the window open.
#[tauri::command]
async fn app_quit(handle: tauri::AppHandle, app: St<'_>, quit: bool) -> R<()> {
    if app.app_close_answer(quit) {
        handle.exit(0);
    }
    Ok(())
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
    // Never a plain key system-wide (the backend filters these out too).
    if mods.is_empty() {
        return None;
    }
    Some(Shortcut::new(Some(mods), code?))
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

/// Window size and position from the last run (`window.json` in the config dir).
#[derive(serde::Serialize, serde::Deserialize)]
struct WinState {
    x: i32,
    y: i32,
    w: u32,
    h: u32,
    maximized: bool,
}

fn restore_window(w: &tauri::WebviewWindow, path: &std::path::Path) {
    let Some(s) = std::fs::read_to_string(path).ok().and_then(|t| serde_json::from_str::<WinState>(&t).ok()) else { return };
    // Never restore a size below the window's minimum or one too big to be sane.
    if !(900..=16384).contains(&s.w) || !(600..=16384).contains(&s.h) {
        return;
    }
    let _ = w.set_size(tauri::PhysicalSize::new(s.w, s.h));
    // Only a position that lands on a monitor that exists now.
    let on_screen = w.available_monitors().unwrap_or_default().iter().any(|m| {
        let (p, z) = (m.position(), m.size());
        s.x + 100 >= p.x && s.y >= p.y && s.x + 100 <= p.x + z.width as i32 && s.y + 40 <= p.y + z.height as i32
    });
    if on_screen {
        let _ = w.set_position(tauri::PhysicalPosition::new(s.x, s.y));
    }
    if s.maximized {
        let _ = w.maximize();
    }
}

fn save_window(w: &tauri::Window, path: &std::path::Path) {
    let maximized = w.is_maximized().unwrap_or(false);
    let (Ok(p), Ok(z)) = (w.outer_position(), w.inner_size()) else { return };
    let s = WinState { x: p.x, y: p.y, w: z.width, h: z.height, maximized };
    if let Some(d) = path.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    let _ = serde_json::to_string(&s).map(|t| std::fs::write(path, t));
}

fn main() {
    #[cfg(feature = "dev-bridge")]
    if let Some(port) = bridge::port_arg() {
        return bridge::serve(port, dispatch);
    }
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let start = match heaphook::cli::parse(&argv) {
        Ok(Some(a)) => a,
        Ok(None) => {
            println!("{}", heaphook::cli::USAGE);
            return;
        }
        Err(e) => {
            eprintln!("heaphook: {e}");
            std::process::exit(2);
        }
    };
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
                    if std::env::var_os("HEAPHOOK_HOTKEY_LOG").is_some() {
                        eprintln!("heaphook: global hotkey pressed: {keys:?}");
                    }
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
            app.set_args(start);
            if let Ok(dir) = tapp.path().app_config_dir() {
                app.set_config_dir(&dir);
                if let Some(w) = tapp.get_webview_window("main") {
                    restore_window(&w, &dir.join("window.json"));
                }
            }
            let h = tapp.handle().clone();
            app.set_hotkey_registrar(Box::new(move |list: &[Vec<u32>]| {
                let gs = h.global_shortcut();
                let _ = gs.unregister_all();
                let mut m = combos.lock().unwrap_or_else(|e| e.into_inner());
                m.clear();
                // HEAPHOOK_HOTKEY_LOG=1: report each registration on stderr (diagnosing a desktop).
                let log = std::env::var_os("HEAPHOOK_HOTKEY_LOG").is_some();
                list.iter()
                    .map(|keys| {
                        let r = shortcut_of(keys).ok_or_else(|| "not a combination with one key".to_string()).and_then(|sc| gs.register(sc).map(|_| sc).map_err(|e| e.to_string()));
                        if log {
                            eprintln!("heaphook: global hotkey {keys:?}: {}", r.as_ref().map_or_else(|e| format!("not registered: {e}"), |_| "registered".into()));
                        }
                        match r {
                            Ok(sc) => {
                                m.insert(sc.id(), keys.clone());
                                true
                            }
                            Err(_) => false,
                        }
                    })
                    .collect()
            }));
            app.start_driver();
            Ok(())
        })
        .on_window_event(|w, ev| match ev {
            tauri::WindowEvent::CloseRequested { api, .. } => {
                // Unsaved table changes: the UI asks first (and calls app_quit).
                if !w.app_handle().state::<App>().window_close_requested() {
                    api.prevent_close();
                    return;
                }
                if let Ok(dir) = w.app_handle().path().app_config_dir() {
                    save_window(w, &dir.join("window.json"));
                }
            }
            tauri::WindowEvent::DragDrop(tauri::DragDropEvent::Drop { paths, .. }) => {
                let paths = paths.iter().map(|p| p.to_string_lossy().into_owned()).collect();
                w.app_handle().state::<App>().window_dropped(paths);
            }
            _ => {}
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
