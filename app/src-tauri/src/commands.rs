//! Command logic behind every IPC command, as plain functions over [`App`]. No Tauri types:
//! `main.rs` wraps each in a one-line `#[tauri::command]`.
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, MutexGuard, RwLock, Weak};
use std::time::Duration;

use hh_asm::{AaError, AaState, SymbolTable};
use hh_core::{Addr, Memory, Module, Pid, Process, ProcessInfo, Prot, Region, RegionKind};
use hh_scan::{CustomType, FirstScan, Fmt, Freezer, FrozenEntryEx, NextScanEx, ResultRow, ScanCount, ScanProgress, Scanner, VType, ValueRefEx};
use serde::{Deserialize, Serialize};

use crate::cheat::Live;
use crate::lua::{HotkeyState, LuaCtx};
use crate::settings::Settings;
use crate::table::{self, Table, TableIn};

pub type R<T> = Result<T, String>;

const MAX_READ: usize = 1 << 20;
const MAX_DISASM: usize = 4096;

pub(crate) fn s<E: ToString>(e: E) -> String {
    e.to_string()
}

pub fn hex_addr(a: Addr) -> String {
    format!("{a:#x}")
}

/// `"0x1A2B"`, `"1A2B"` (hex like everywhere in CE) or `"#123"` decimal.
pub fn parse_addr(t: &str) -> R<Addr> {
    hh_asm::parse_num(t.trim()).ok_or_else(|| format!("bad address {t:?}"))
}

/// Everything tied to the attached process; replaced as a whole on `open_process`.
pub struct Session {
    /// What every command reads and writes through: the plain process, or the debugger's
    /// process while it is attached (Linux allows one tracer, see hh-debug).
    pub proc: Arc<dyn Process>,
    pub(crate) switch: Arc<Switch>,
    pub(crate) raw: Arc<dyn Process>,
    pub info: Opened,
    /// Shared with Lua's `getCurrentMemscan()`.
    pub scanner: Arc<Scanner>,
    pub(crate) freezer: Freezer,
    /// Shared with the Lua engine (`registerSymbol`, AA `registersymbol` from either side).
    pub(crate) syms: Arc<Mutex<SymbolTable>>,
    pub(crate) dbg: Mutex<Option<crate::debug::Dbg>>,
    pub(crate) ptr: crate::ptr::Ptr,
    pub(crate) tools: crate::tools::Tools,
    /// Saved scan name -> its result count.
    pub(crate) saved: Mutex<HashMap<String, u64>>,
    /// Suspended with `process_pause`.
    pub(crate) paused: std::sync::atomic::AtomicBool,
}

/// A `Process` whose backend can be swapped while scanner, freezer and friends hold it.
pub struct Switch(RwLock<Arc<dyn Process>>);

impl Switch {
    pub(crate) fn get(&self) -> Arc<dyn Process> {
        self.0.read().unwrap_or_else(|e| e.into_inner()).clone()
    }
    pub(crate) fn set(&self, p: Arc<dyn Process>) {
        *self.0.write().unwrap_or_else(|e| e.into_inner()) = p;
    }
}

impl Memory for Switch {
    fn read(&self, addr: Addr, buf: &mut [u8]) -> hh_core::Result<usize> {
        self.get().read(addr, buf)
    }
    fn write(&self, addr: Addr, data: &[u8]) -> hh_core::Result<()> {
        self.get().write(addr, data)
    }
    fn pointer_size(&self) -> usize {
        self.get().pointer_size()
    }
}

impl Process for Switch {
    fn pid(&self) -> Pid {
        self.get().pid()
    }
    fn is_alive(&self) -> bool {
        self.get().is_alive()
    }
    fn regions(&self) -> hh_core::Result<Vec<Region>> {
        self.get().regions()
    }
    fn modules(&self) -> hh_core::Result<Vec<Module>> {
        self.get().modules()
    }
    fn threads(&self) -> hh_core::Result<Vec<u32>> {
        self.get().threads()
    }
    fn alloc(&self, size: u64, prot: Prot, near: Option<Addr>) -> hh_core::Result<Addr> {
        self.get().alloc(size, prot, near)
    }
    fn free(&self, addr: Addr, size: u64) -> hh_core::Result<()> {
        self.get().free(addr, size)
    }
    fn protect(&self, addr: Addr, size: u64, prot: Prot) -> hh_core::Result<Prot> {
        self.get().protect(addr, size, prot)
    }
    fn suspend(&self) -> hh_core::Result<()> {
        self.get().suspend()
    }
    fn resume(&self) -> hh_core::Result<()> {
        self.get().resume()
    }
}

/// Command state. Cheap to clone; every clone is the same app.
#[derive(Clone)]
pub struct App {
    sess: Arc<Mutex<Option<Arc<Session>>>>,
    pub(crate) x: Arc<Shared>,
}

impl Default for App {
    fn default() -> Self {
        let app = App { sess: Arc::default(), x: Arc::default() };
        // The Lua hosts call back into the app (create process, load table, debugger).
        let _ = app.x.lua.console.app.set(app.downgrade());
        app
    }
}

/// App-wide state that outlives process switches.
pub struct Shared {
    pub(crate) live: Arc<Live>,
    pub(crate) lua: LuaCtx,
    pub(crate) settings: Mutex<Settings>,
    config: Mutex<Option<PathBuf>>,
    pub(crate) hk: Mutex<HotkeyState>,
    pub(crate) driver: AtomicBool,
    /// Processes started by `process_create`, reaped when they exit.
    pub(crate) children: Mutex<Vec<std::process::Child>>,
    /// Last liveness check of a remote target (see `lua_poll`).
    pub(crate) remote_alive: Mutex<crate::lua::RemoteAlive>,
    /// The connected hh-server, if any.
    pub(crate) remote: Mutex<Option<crate::remote::Conn>>,
    /// User-defined symbols registered from the table: (table version, session, names).
    pub(crate) user_syms: Mutex<(u64, usize, Vec<String>)>,
    /// (address, entry id) of what the freezer holds, to name its failures.
    pub(crate) freeze_ids: Mutex<Vec<(Addr, i64)>>,
    /// Processes started under the debugger (`debug_launch`): reaped by pid once untraced.
    pub(crate) launched: Mutex<Vec<u32>>,
    /// Command-line arguments, until the UI took them (`app_args`).
    pub(crate) args: Mutex<Option<crate::cli::StartArgs>>,
    /// Window events the UI picks up with `lua_poll`.
    pub(crate) win: Mutex<WinEvents>,
}

/// Close requests and dropped files of the window, for the UI's poll.
#[derive(Debug, Clone, Default, Serialize)]
pub struct WinEvents {
    /// Moves when the user closes the window with unsaved table changes (the UI asks).
    pub close_seq: u64,
    /// A close request is waiting for the UI's answer.
    #[serde(skip)]
    pub close_pending: bool,
    /// Moves when files are dropped on the window; `drops` are the latest ones.
    pub drop_seq: u64,
    pub drops: Vec<String>,
}

impl Default for Shared {
    fn default() -> Self {
        let live = Arc::new(Live::default());
        Shared {
            lua: LuaCtx::new(live.clone()),
            live,
            settings: Mutex::default(),
            config: Mutex::default(),
            hk: Mutex::default(),
            driver: AtomicBool::new(false),
            children: Mutex::default(),
            remote_alive: Mutex::default(),
            remote: Mutex::default(),
            user_syms: Mutex::default(),
            freeze_ids: Mutex::default(),
            launched: Mutex::default(),
            args: Mutex::default(),
            win: Mutex::default(),
        }
    }
}

pub(crate) struct WeakApp(Weak<Mutex<Option<Arc<Session>>>>, Weak<Shared>);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Opened {
    pub pid: u32,
    pub name: String,
    pub is_64bit: bool,
    /// Server address when the process is on an hh-server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote: Option<String>,
}

/// A saved scan as the UI lists it.
#[derive(Debug, Clone, Serialize)]
pub struct SavedScan {
    pub name: String,
    pub count: u64,
    /// Rows of it the results' `saved` column can show (all of them).
    pub kept: u64,
}

/// A result row plus the value of a saved scan at its address.
#[derive(Debug, Clone, Serialize)]
pub struct ResultOut {
    #[serde(flatten)]
    pub row: ResultRow,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub saved: Option<Option<String>>,
}

/// `scan_progress` plus where result data spills to.
#[derive(Debug, Clone, Serialize)]
pub struct ProgressOut {
    #[serde(flatten)]
    pub p: ScanProgress,
    pub spilled: u64,
    pub spill_dir: String,
}

impl std::ops::Deref for ResultOut {
    type Target = ResultRow;
    fn deref(&self) -> &ResultRow {
        &self.row
    }
}

impl std::ops::Deref for ProgressOut {
    type Target = ScanProgress;
    fn deref(&self) -> &ScanProgress {
        &self.p
    }
}

/// Most addresses `scan_copy_addresses` puts on the clipboard (export writes any number).
const MAX_COPY: u64 = 1_000_000;

#[derive(Debug, Clone, Serialize)]
pub struct RegionOut {
    pub start: String,
    pub size: u64,
    pub prot: Prot,
    pub kind: RegionKind,
    pub path: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ModuleOut {
    pub name: String,
    pub path: String,
    pub base: String,
    pub size: u64,
}

/// Disassembler display options.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct DisasmOpts {
    /// AT&T syntax (display only; the assembler reads Intel).
    pub att: bool,
    /// Comments show memory operands by guessed type (`(float)1.5`, `->name`, `'text'`).
    pub typed: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct DisasmOut {
    pub addr: String,
    /// `"48 89 E5"`, or `"??"` when unreadable.
    pub bytes: String,
    pub text: String,
    pub comment: String,
    /// Incoming references from the last code dissection (when there is one).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xrefs: Option<crate::tools::XRefCounts>,
}

pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

pub(crate) fn hex_bytes(b: &[u8], sep: &str) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect::<Vec<_>>().join(sep)
}

impl App {
    pub fn session(&self) -> R<Arc<Session>> {
        lock(&self.sess).clone().ok_or_else(|| "no process opened".into())
    }

    pub(crate) fn downgrade(&self) -> WeakApp {
        WeakApp(Arc::downgrade(&self.sess), Arc::downgrade(&self.x))
    }

    pub(crate) fn upgrade(w: &WeakApp) -> Option<App> {
        Some(App { sess: w.0.upgrade()?, x: w.1.upgrade()? })
    }

    /// Where `settings.json` lives; loads and applies it.
    pub fn set_config_dir(&self, dir: &Path) {
        let s = Settings::load(&dir.join("settings.json"));
        *lock(&self.x.config) = Some(dir.to_path_buf());
        // Before anything touches the engine: it is built with this on first use.
        self.x.lua.engine.set_allow_os(s.lua_allow_os);
        self.apply_settings(&s);
        *lock(&self.x.settings) = s;
    }

    pub(crate) fn config_dir(&self) -> Option<PathBuf> {
        lock(&self.x.config).clone()
    }

    pub fn set_args(&self, a: crate::cli::StartArgs) {
        *lock(&self.x.args) = Some(a);
    }

    /// The command-line arguments, once (a reload of the UI does not act on them again).
    pub fn app_args(&self) -> R<Option<crate::cli::StartArgs>> {
        Ok(lock(&self.x.args).take())
    }

    /// The window is being closed: `true` when it may close now. With unsaved table changes the
    /// UI is asked first (`close_seq`); closing again while that question is open closes.
    pub fn window_close_requested(&self) -> bool {
        let mut w = lock(&self.x.win);
        if !self.x.live.dirty() || w.close_pending {
            return true;
        }
        w.close_pending = true;
        w.close_seq += 1;
        false
    }

    /// The UI's answer to a close request: `quit` false keeps the window open.
    pub fn app_close_answer(&self, quit: bool) -> bool {
        let mut w = lock(&self.x.win);
        w.close_pending = false;
        quit
    }

    pub fn window_dropped(&self, paths: Vec<String>) {
        let mut w = lock(&self.x.win);
        w.drop_seq += 1;
        w.drops = paths;
    }

    pub fn settings_get(&self) -> R<Settings> {
        Ok(lock(&self.x.settings).clone())
    }

    /// Normalizes, applies and persists (when a config dir is set); returns what was stored.
    pub fn settings_set(&self, s: Settings) -> R<Settings> {
        let s = s.normalized();
        self.apply_settings(&s);
        *lock(&self.x.settings) = s.clone();
        self.apply_signal_settings();
        if let Some(dir) = lock(&self.x.config).clone() {
            s.save(&dir.join("settings.json"))?;
        }
        Ok(s)
    }

    /// The settings the backend enforces itself; the UI applies the rest.
    fn apply_settings(&self, s: &Settings) {
        // "Never" withdraws every consent given, and stops what it started.
        if self.x.live.set_never(s.table_script == "never") {
            self.stop_table_lua();
        }
        self.x.lua.engine.set_budget((s.lua_budget_ms > 0).then(|| Duration::from_millis(s.lua_budget_ms)));
        {
            let _g = self.x.lua.enter();
            // 0 = no limit; kept for the states a reset builds.
            let _ = self.x.lua.engine.set_memory_limit((s.lua_memory_mb > 0).then_some((s.lua_memory_mb as usize) << 20));
        }
        if let Ok(sess) = self.session() {
            sess.freezer.set_interval(Duration::from_millis(s.freeze_interval_ms));
            sess.scanner.set_spill_dir(spill_dir(s));
        }
    }

    pub fn list_processes(&self) -> R<Vec<ProcessInfo>> {
        hh_core::list_processes().map_err(s)
    }

    /// Attaches to `pid`; the previous process's scan, frozen set and symbols are dropped.
    pub fn open_process(&self, pid: u32) -> R<Opened> {
        let raw = hh_core::open(pid).map_err(s)?;
        let name = hh_core::list_processes()
            .ok()
            .and_then(|l| l.into_iter().find(|p| p.pid == pid))
            .map_or_else(|| pid.to_string(), |p| p.name);
        self.install_process(raw, pid, name, None)
    }

    /// Makes `raw` the target (local or remote).
    pub(crate) fn install_process(&self, raw: Arc<dyn Process>, pid: u32, name: String, remote: Option<String>) -> R<Opened> {
        let switch = Arc::new(Switch(RwLock::new(raw.clone())));
        let proc: Arc<dyn Process> = switch.clone();
        let info = Opened { pid, name, is_64bit: proc.pointer_size() == 8, remote };
        let mem: Arc<dyn Memory> = proc.clone();
        let freezer = Freezer::new(mem).map_err(s)?;
        freezer.set_interval(Duration::from_millis(lock(&self.x.settings).freeze_interval_ms));
        let syms = self.x.lua.engine.symbols();
        *lock(&syms) = SymbolTable::default();
        let scanner = Arc::new(Scanner::new(proc.clone()));
        // A remote target's pid names a process on the other machine, never a local /proc.
        scanner.set_local(info.remote.is_none());
        scanner.set_spill_dir(spill_dir(&lock(&self.x.settings)));
        let sess = Session {
            paused: Default::default(),
            saved: Mutex::default(),
            scanner,
            freezer,
            proc: proc.clone(),
            switch,
            raw,
            info: info.clone(),
            syms,
            dbg: Mutex::default(),
            ptr: crate::ptr::Ptr::new(),
            tools: crate::tools::Tools::default(),
        };
        // A remote target's module paths name files on the other machine: symbols come from
        // its memory, never from a same-named local file.
        if info.remote.is_some() {
            hh_asm::set_module_files_local(pid, false);
        }
        if let Some(old) = lock(&self.sess).replace(Arc::new(sess)) {
            old.scanner.cancel();
            if old.info.remote.is_some() && (info.remote.is_none() || old.info.pid != pid) {
                hh_asm::set_module_files_local(old.info.pid, true);
            }
        }
        *lock(&self.x.lua.console.speedhack) = None;
        // The engine follows the Switch, so debugger attach/detach needs no rebind.
        self.x.lua.engine.set_process(Some(proc)).map_err(s)?;
        self.x.live.scripts_off();
        Ok(info)
    }

    /// Detaches the debugger (breakpoints removed), turns active scripts off in the table's
    /// view (their patches stay in the process, like closing Cheat Engine), stops scans,
    /// the freezer and the Lua engine's process access.
    pub fn close_process(&self) -> R<()> {
        if self.session().is_err() {
            return Ok(());
        }
        // Undo the scripts' patches while the process is still there; a failure is logged and
        // the process closed anyway (it must stay closable).
        for (_, e) in self.disable_active_scripts() {
            self.x.lua.console.push("err", &format!("{e}\nstill patched: the script could not be disabled"));
        }
        let _ = self.debug_detach();
        let Some(sess) = lock(&self.sess).take() else { return Ok(()) };
        // Never leave the target stopped behind.
        if sess.paused.swap(false, std::sync::atomic::Ordering::SeqCst) {
            let _ = sess.raw.resume();
        }
        sess.scanner.cancel();
        let _ = sess.freezer.set(&[]);
        if sess.info.remote.is_some() {
            hh_asm::set_module_files_local(sess.info.pid, true);
        }
        *lock(&self.x.lua.console.speedhack) = None;
        self.x.lua.engine.set_process(None).map_err(s)?;
        self.x.live.scripts_off();
        Ok(())
    }

    pub fn regions(&self) -> R<Vec<RegionOut>> {
        let rs: Vec<Region> = self.session()?.proc.regions().map_err(s)?;
        Ok(rs
            .into_iter()
            .map(|r| RegionOut { start: hex_addr(r.start), size: r.size, prot: r.prot, kind: r.kind, path: r.path })
            .collect())
    }

    pub fn modules(&self) -> R<Vec<ModuleOut>> {
        let ms: Vec<Module> = self.session()?.proc.modules().map_err(s)?;
        Ok(ms
            .into_iter()
            .map(|m| ModuleOut { name: m.name, path: m.path, base: hex_addr(m.base), size: m.size })
            .collect())
    }

    /// Lowercase hex, two characters per byte, `??` for unreadable bytes.
    pub fn read_memory(&self, addr: &str, len: usize) -> R<String> {
        if len > MAX_READ {
            return Err(format!("len {len} is above the {MAX_READ} byte limit"));
        }
        let (p, a) = (self.session()?.proc.clone(), parse_addr(addr)?);
        let mut buf = vec![0u8; len];
        let mut out = String::with_capacity(len * 2);
        let mut pos = 0;
        while pos < len {
            let at = a.wrapping_add(pos as u64);
            match p.read(at, &mut buf[pos..]) {
                Ok(n) if n > 0 => {
                    buf[pos..pos + n].iter().for_each(|b| out.push_str(&format!("{b:02x}")));
                    pos += n;
                }
                Err(hh_core::Error::Io(e)) if e.kind() == std::io::ErrorKind::ConnectionAborted => return Err(s(e)),
                _ => {
                    let skip = ((4096 - at % 4096) as usize).min(len - pos);
                    out.push_str(&"??".repeat(skip));
                    pos += skip;
                }
            }
        }
        Ok(out)
    }

    pub fn write_bytes(&self, addr: &str, hex: &str) -> R<()> {
        let h: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
        if !h.bytes().all(|c| c.is_ascii_hexdigit()) || !h.len().is_multiple_of(2) {
            return Err(format!("bad hex bytes {hex:?}"));
        }
        let data: Vec<u8> = (0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap_or(0)).collect();
        hh_asm::write_code(&*self.session()?.proc, parse_addr(addr)?, &data).map_err(s)
    }

    pub fn read_values(&self, mut reqs: Vec<ValueRefEx>) -> R<Vec<Option<String>>> {
        // The UI sends len 0 for "default length".
        reqs.iter_mut().filter(|r| r.r.fmt.len == Some(0)).for_each(|r| r.r.fmt.len = None);
        Ok(hh_scan::read_values_ex(&*self.session()?.proc, &reqs))
    }

    /// Integers accept a `0x` prefix (hex-displayed entries); `fmt` carries the entry's
    /// `utf16` / `hex` / `signed` / `len` flags; see `hh_scan::parse_value`. `custom`
    /// overrides `vtype`.
    pub fn write_value(&self, addr: &str, vtype: VType, value: &str, fmt: &Fmt, custom: Option<&CustomType>) -> R<()> {
        let p = self.session()?.proc.clone();
        match custom {
            Some(ct) => hh_scan::write_custom(&*p, parse_addr(addr)?, ct, value, fmt),
            None => hh_scan::write_value(&*p, parse_addr(addr)?, vtype, value, fmt),
        }
        .map_err(s)
    }

    /// One call for many expressions (table rows); `None` where one does not resolve.
    pub fn resolve_many(&self, exprs: &[String]) -> R<Vec<Option<String>>> {
        self.session()?;
        Ok(exprs.iter().map(|e| self.resolve_address(e).ok()).collect())
    }

    pub fn custom_presets(&self) -> R<Vec<serde_json::Value>> {
        Ok(CUSTOM_PRESETS
            .iter()
            .filter_map(|n| {
                let mut v = serde_json::to_value(CustomType::preset(n)?).ok()?;
                v["name"] = (*n).into();
                Some(v)
            })
            .collect())
    }

    pub fn custom_validate(&self, ct: &CustomType) -> R<Option<String>> {
        Ok(ct.validate().err().map(s))
    }

    pub fn app_info(&self) -> R<serde_json::Value> {
        // `lua_allow_os`: what the running Lua engine allows (a changed setting applies after a restart).
        Ok(serde_json::json!({"version": env!("CARGO_PKG_VERSION"), "license": "Apache-2.0", "platform": std::env::consts::OS,
            "lua_allow_os": self.x.lua.engine.allow_os(),
            // Withdrawn interpreters kept in memory (see hh_lua::Engine::reset).
            "lua_parked": hh_lua::parked_stats().0, "lua_parked_bytes": hh_lua::parked_stats().1}))
    }

    pub fn resolve_address(&self, expr: &str) -> R<String> {
        self.resolve_with(expr, self.lua_hooks_ok())
    }

    /// [`App::resolve_address`]; `lookups`: ask the symbol lookup callbacks Lua registered.
    pub(crate) fn resolve_with(&self, expr: &str, lookups: bool) -> R<String> {
        let sess = self.session()?;
        self.sync_user_symbols(&sess);
        let syms = lock(&sess.syms).clone();
        let extra = if lookups { self.x.lua.engine.symbol_lookup() } else { None };
        let r = match &extra {
            Some(f) => hh_asm::resolve_address_with(&*sess.proc, &syms, expr, &|n: &str| f(n)),
            None => hh_asm::resolve_address(&*sess.proc, &syms, expr),
        };
        match r {
            Ok(a) => Ok(hex_addr(a)),
            // hh-asm does not know THREADSTACK<n> bases; pointer-scan paths do.
            // Only THREADSTACK paths report the pointer-path error; anything else keeps
            // hh-asm's message (the fallback's would be `unknown base Some("name")`).
            Err(e) => match expr.parse::<hh_ptr::PointerPath>() {
                Ok(p) => hh_ptr::resolve(&*sess.proc, &p).map(hex_addr).map_err(|pe| {
                    if expr.to_ascii_uppercase().contains("THREADSTACK") { s(pe) } else { s(&e) }
                }),
                Err(_) => Err(s(e)),
            },
        }
    }

    /// Callbacks a table's Lua registered (address names, symbol lookups, structure
    /// overrides) are only used while that table is trusted (`own` / `agreed`).
    pub(crate) fn lua_hooks_ok(&self) -> bool {
        self.x.live.trust().allows() && lock(&self.x.settings).table_script != "never"
    }

    /// Blocks until the scan ends; call it off the UI thread.
    pub fn scan_first(&self, req: &FirstScan) -> R<ScanCount> {
        self.session()?.scanner.first_scan(req).map_err(s)
    }

    pub fn scan_next(&self, req: &NextScanEx) -> R<ScanCount> {
        self.session()?.scanner.next_scan_ex(req).map_err(s)
    }

    pub fn scan_save(&self, name: &str) -> R<()> {
        let sess = self.session()?;
        sess.scanner.save_scan(name).map_err(s)?;
        lock(&sess.saved).insert(name.trim().to_string(), sess.scanner.count());
        Ok(())
    }

    pub fn scan_saved(&self) -> R<Vec<SavedScan>> {
        let sess = self.session()?;
        let mut kept = lock(&sess.saved);
        let names = sess.scanner.saved_scans();
        // The scanner drops saved scans on a new or first scan; follow it.
        kept.retain(|k, _| names.contains(k));
        Ok(names.into_iter().map(|n| SavedScan { count: kept.get(&n).copied().unwrap_or(0), kept: kept.get(&n).copied().unwrap_or(0), name: n }).collect())
    }

    /// Orders the results by address or value (at most `hh_scan::MAX_SORT`; more is an error
    /// naming the cap).
    pub fn scan_sort(&self, key: hh_scan::SortKey, desc: bool) -> R<()> {
        let sess = self.session()?;
        let n = sess.scanner.count();
        if key == hh_scan::SortKey::Value && n > hh_scan::MAX_SORT {
            return Err(format!("{n} results are too many to sort by value (at most {}): narrow them down with a next scan first", hh_scan::MAX_SORT));
        }
        sess.scanner.sort(key, desc).map_err(s)
    }

    /// Removes these results (undo brings them back); returns how many went.
    pub fn scan_remove(&self, addrs: &[String]) -> R<u64> {
        let a = addrs.iter().map(|x| parse_addr(x)).collect::<R<Vec<_>>>()?;
        self.session()?.scanner.remove(&a).map_err(s)
    }

    /// Every result address, one per line (upper-case hex), into `path`; returns the count.
    pub fn scan_export_addresses(&self, path: &str) -> R<u64> {
        let sess = self.session()?;
        let mut f = std::io::BufWriter::new(std::fs::File::create(path).map_err(|e| format!("{path}: {e}"))?);
        let n = sess.scanner.export_addresses(&mut f).map_err(s)?;
        std::io::Write::flush(&mut f).map_err(|e| format!("{path}: {e}"))?;
        Ok(n)
    }

    /// Every result address as text for the clipboard (at most [`MAX_COPY`]).
    pub fn scan_copy_addresses(&self) -> R<String> {
        let sess = self.session()?;
        let n = sess.scanner.count();
        if n > MAX_COPY {
            return Err(format!("{n} addresses are too many for the clipboard (at most {MAX_COPY}): export them to a file instead"));
        }
        let mut b = Vec::new();
        sess.scanner.export_addresses(&mut b).map_err(s)?;
        String::from_utf8(b).map_err(s)
    }

    /// Result counts per region (with its module).
    pub fn scan_stats(&self) -> R<Vec<hh_scan::ResultStat>> {
        self.session()?.scanner.result_stats().map_err(s)
    }

    /// Pointer-value scan: pointer-sized values that point into readable memory (or only
    /// into the given modules / ranges). Starts a new scan.
    pub fn scan_pointer(&self, req: &hh_scan::PointerScan) -> R<ScanCount> {
        self.session()?.scanner.pointer_scan(req).map_err(s)
    }

    pub fn scan_delete_saved(&self, name: &str) -> R<()> {
        let sess = self.session()?;
        lock(&sess.saved).remove(name.trim());
        sess.scanner.delete_saved_scan(name).map_err(s)
    }

    pub fn scan_pause(&self, pause: bool) -> R<()> {
        let sess = self.session()?;
        if pause { sess.scanner.pause() } else { sess.scanner.resume() }
        Ok(())
    }

    pub fn scan_undo(&self) -> R<()> {
        self.session()?.scanner.undo().map_err(s)
    }

    pub fn scan_new(&self) -> R<()> {
        self.session()?.scanner.new_scan();
        Ok(())
    }

    pub fn scan_cancel(&self) -> R<()> {
        if let Ok(sess) = self.session() {
            sess.scanner.cancel();
        }
        Ok(())
    }

    pub fn scan_progress(&self) -> R<ProgressOut> {
        let sess = self.session().ok();
        Ok(ProgressOut {
            p: sess.as_ref().map(|s| s.scanner.progress()).unwrap_or_default(),
            spilled: sess.as_ref().map_or(0, |s| s.scanner.spilled_bytes()),
            spill_dir: match &sess {
                Some(s) => s.scanner.effective_spill_dir(),
                None => hh_scan::spill_dir(spill_dir(&lock(&self.x.settings)).as_deref()),
            }
            .display()
            .to_string(),
        })
    }

    pub fn scan_results(&self, offset: u64, limit: usize, saved: Option<&str>) -> R<Vec<ResultOut>> {
        let sess = self.session()?;
        let rows = sess.scanner.results(offset, limit).map_err(s)?;
        let vals = match saved.map(str::trim).filter(|n| !n.is_empty()) {
            Some(n) => Some(sess.scanner.saved_values(n, &rows.iter().map(|r| r.addr).collect::<Vec<_>>()).map_err(s)?),
            None => None,
        };
        let mut vals = vals.map(Vec::into_iter);
        Ok(rows.into_iter().map(|row| ResultOut { saved: vals.as_mut().map(|v| v.next().flatten()), row }).collect())
    }

    pub fn set_frozen(&self, entries: &[FrozenEntryEx]) -> R<()> {
        self.session()?.freezer.set_ex(entries).map_err(s)
    }

    pub fn disassemble(&self, addr: &str, count: usize) -> R<Vec<DisasmOut>> {
        self.disassemble_ex(addr, count, &DisasmOpts::default())
    }

    /// [`App::disassemble`] in AT&T syntax and / or with typed operand comments.
    pub fn disassemble_ex(&self, addr: &str, count: usize, o: &DisasmOpts) -> R<Vec<DisasmOut>> {
        let sess = self.session()?;
        self.sync_user_symbols(&sess);
        let syms = lock(&sess.syms).clone();
        let opts = hh_asm::DisasmOptions {
            syntax: if o.att { hh_asm::Syntax::Att } else { hh_asm::Syntax::Intel },
            guess_types: o.typed,
            address_name: if self.lua_hooks_ok() { self.x.lua.engine.address_name() } else { None },
            ..Default::default()
        };
        let lines = hh_asm::disassemble_with(&*sess.proc, &syms, parse_addr(addr)?, count.min(MAX_DISASM), &opts).map_err(s)?;
        let mut xr = self.xref_counts(&lines.iter().map(|l| l.addr).collect::<Vec<_>>()).map(Vec::into_iter);
        Ok(lines
            .into_iter()
            .map(|l| DisasmOut {
                addr: hex_addr(l.addr),
                bytes: if l.bytes.is_empty() { "??".into() } else { hex_bytes(&l.bytes, " ") },
                text: l.text,
                comment: l.comment,
                xrefs: xr.as_mut().and_then(Iterator::next),
            })
            .collect())
    }

    /// Lowercase hex without separators.
    pub fn assemble(&self, addr: &str, text: &str) -> R<String> {
        let sess = self.session()?;
        let syms = lock(&sess.syms).clone();
        let b = hh_asm::assemble(&*sess.proc, &syms, parse_addr(addr)?, text).map_err(s)?;
        Ok(hex_bytes(&b, "").to_lowercase())
    }

    /// Never runs code (the editor checks on every keystroke). The script has the
    /// capabilities of where it is being edited: table entry `entry`, Auto Assemble session
    /// `session`, else none. With them `{$lua}` blocks count as producing no text; without
    /// them each directive that needs one is an error naming `hh_asm::NOT_AVAILABLE`.
    pub fn aa_check(&self, script: &str, session: Option<u64>, entry: Option<i64>) -> R<Option<AaError>> {
        let sess = self.session()?;
        let syms = lock(&sess.syms).clone();
        let caps = match entry {
            Some(id) => self.x.live.caps(id),
            None => self.x.live.aa_caps(session),
        };
        let r = hh_asm::aa_check(&*sess.proc, &syms, script, &mut self.x.lua.engine.aa_hooks_check_only_with(caps));
        Ok(r.map(|mut e| {
            if caps == hh_lua::Caps::None && !e.message.contains(hh_asm::NOT_AVAILABLE) && self.x.lua.engine.has_symbol_lookup() {
                e.message.push_str(" (needs your consent: the symbol lookup callbacks Lua registered are not asked for this script)");
            }
            e
        }))
    }

    /// A new Auto Assemble window session: its text is the user's own until a file is loaded
    /// into it (`aa_load_file`).
    pub fn aa_session(&self) -> R<u64> {
        Ok(self.x.live.aa_new())
    }

    /// Runs the Auto Assemble window's script. It gets Lua and file access only as session
    /// `session`'s own typed text or after consent to what was loaded into it (`aa_trust`);
    /// without a session nothing proves the user typed it, so it gets neither. A script
    /// refused for want of them answers with the consent question. Symbols the script
    /// registers stay registered for later expressions. `{$lua}` blocks run in the app's
    /// engine (so they cannot hold the symbol lock: work on a copy, merge).
    pub fn aa_execute(&self, script: &str, enable: bool, state: Option<&AaState>, session: Option<u64>) -> R<AaState> {
        let sess = self.session()?;
        let caps = self.x.live.aa_caps(session);
        let (unique, files) = {
            let st = lock(&self.x.settings);
            let u = match st.aob_unique.as_str() {
                "warn" => hh_asm::AobUnique::Warn,
                "fail" => hh_asm::AobUnique::Fail,
                _ => hh_asm::AobUnique::Off,
            };
            (u, st.lua_allow_os && self.x.lua.engine.allow_os())
        };
        let before = lock(&sess.syms).clone();
        let mut work = before.clone();
        let r = {
            let _g = self.x.lua.enter();
            // A file the user agreed to: its code runs in the interpreter from now on.
            if let Some(o) = self.x.live.aa_owner(session) {
                self.x.lua.engine.add_owners(&[o]);
            }
            let mut hooks = self.x.lua.engine.aa_hooks_with(None, false, caps);
            hooks.aob_unique = unique;
            // With capabilities: file reads as Settings allow them.
            if caps == hh_lua::Caps::Full {
                hooks.read_file = Some(if files {
                    Box::new(|p: String| crate::table::read_capped(Path::new(p.trim()), hh_asm::MAX_ASSEMBLED_BYTES as u64).map_err(hh_core::Error::Other))
                } else {
                    Box::new(|_: String| Err(hh_core::Error::Other("loadbinary reads a file, and Settings do not allow Lua and scripts to access files".into())))
                });
            }
            hh_asm::aa_execute(&*sess.proc, &mut work, script, enable, state, &mut hooks)
        };
        let mut cur = lock(&sess.syms);
        for (n, a) in work.iter() {
            if before.get(n) != Some(a) {
                cur.register(n, a);
            }
        }
        for (n, _) in before.iter().filter(|(n, _)| work.get(n).is_none()) {
            cur.unregister(n);
        }
        drop(cur);
        self.lua_settle();
        r.map_err(|e| {
            let e = e.to_string();
            if caps == hh_lua::Caps::None && (e.contains(hh_asm::NOT_AVAILABLE) || self.x.lua.engine.has_symbol_lookup()) {
                let why = if lock(&self.x.settings).table_script == "never" {
                    "this script: not run: it was loaded from a file, needs Lua or file access, and Settings say never to run a table's Lua".to_string()
                } else {
                    format!("{} this script: it was loaded from a file and needs Lua or file access, which can use your files and the process", crate::cheat::NEEDS_CONSENT)
                };
                format!("{why}\n{e}")
            } else {
                e
            }
        })
    }

    /// An Auto Assembler script file loaded into session `session`: the session's content is
    /// untrusted from now on (whatever is typed into it later) until `aa_trust`.
    pub fn aa_load_file(&self, path: &str, session: u64) -> R<String> {
        self.aa_load(path, session).map(|l| l.script)
    }

    /// The user's yes for what was loaded into session `session` (refused while Settings say
    /// never; "never" withdraws it again).
    pub fn aa_trust(&self, session: u64) -> R<()> {
        self.x.live.grant(crate::cheat::Grant::AaSession(session))
    }

    /// [`App::aa_trust`] for file load `load` (what `aa_load` returned): refused when another
    /// file was loaded into the session since (IPC).
    pub fn aa_trust_at(&self, session: u64, load: u64) -> R<()> {
        self.x.live.grant_at(crate::cheat::Grant::AaSession(session), Some(load))
    }

    /// [`App::aa_load_file`] with the number of the load, for the consent answer (IPC).
    pub fn aa_load(&self, path: &str, session: u64) -> R<AaLoaded> {
        let load = self.x.live.aa_loaded(session)?;
        let b = table::read_capped(Path::new(path), table::MAX_FILE)?;
        let script = String::from_utf8(b).map_err(|e| format!("{path}: {e}"))?;
        Ok(AaLoaded { script, load })
    }

    /// "Assign to table": the session's script as a new entry after `after`, keeping the
    /// session's origin (a loaded file stays untrusted, agreed or not as the session is).
    pub fn aa_assign(&self, session: u64, script: &str, description: &str, after: Option<i64>, base: Option<u64>) -> R<crate::cheat::PasteOut> {
        let (origin, agreed) = self.x.live.aa_origin(session)?;
        let e = table::Entry { description: description.into(), script: Some(script.into()), ..table::Entry::default() };
        let (version, ids) = self.x.live.insert(vec![e], after, base, origin, agreed)?;
        Ok(crate::cheat::PasteOut { version, ids })
    }

    /// Registers the table's user-defined symbols (CE `UserdefinedSymbols`) in the session's
    /// symbol table when the table or the process changed; names it registered before and
    /// the table dropped are unregistered.
    pub(crate) fn sync_user_symbols(&self, sess: &Arc<Session>) {
        let ver = self.x.live.version();
        let key = Arc::as_ptr(sess) as usize;
        let mut g = lock(&self.x.user_syms);
        if g.0 == ver && g.1 == key {
            return;
        }
        let syms = self.x.live.state().table.symbols;
        let mut work = lock(&sess.syms).clone();
        if g.1 == key {
            for n in &g.2 {
                work.unregister(n);
            }
        }
        let mut names = Vec::new();
        // Later symbols may use earlier ones.
        let mods = sess.proc.modules().unwrap_or_default();
        for u in syms {
            // A label may not shadow a module (module names win anyway; say why it is unused).
            if hh_asm::names_module(&mods, &u.name) {
                self.x.lua.console.push("err", &format!("label {}: not used: it is the name of a loaded module", u.name));
                continue;
            }
            if let Ok(a) = hh_asm::resolve_address(&*sess.proc, &work, &u.address) {
                work.register(&u.name, a);
                names.push(u.name);
            }
        }
        *lock(&sess.syms) = work;
        *g = (ver, key, names);
    }

    pub fn table_load(&self, path: &str) -> R<Table> {
        table::load(Path::new(path))
    }

    /// Writes a table the UI built: like any JSON input, it may not carry raw `.CT` fragments.
    pub fn table_save(&self, path: &str, table: TableIn) -> R<()> {
        let mut t: Table = table.into();
        table::clean_json(&mut t);
        table::save(Path::new(path), &t)
    }
}

/// `aa_load_file` answer: the script and the number of this load.
#[derive(Debug, Clone, Serialize)]
pub struct AaLoaded {
    pub script: String,
    pub load: u64,
}

/// Cheat Engine's stock custom type names, as `CustomType::preset` knows them.
const CUSTOM_PRESETS: &[&str] = &["2 Byte Big Endian", "4 Byte Big Endian", "8 Byte Big Endian", "Float Big Endian", "Double Big Endian", "3 Byte", "3 Byte Big Endian"];

fn spill_dir(s: &Settings) -> Option<PathBuf> {
    (!s.scan_spill_dir.is_empty()).then(|| PathBuf::from(&s.scan_spill_dir))
}

