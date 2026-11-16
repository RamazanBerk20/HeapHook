//! Command logic behind every IPC command, as plain functions over [`App`]. No Tauri types:
//! `main.rs` wraps each in a one-line `#[tauri::command]`.
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, MutexGuard, RwLock, Weak};
use std::time::Duration;

use hh_asm::{AaError, AaState, SymbolTable};
use hh_core::{Addr, Memory, Module, Pid, Process, ProcessInfo, Prot, Region, RegionKind};
use hh_scan::{FirstScan, Fmt, Freezer, FrozenEntry, NextScan, ResultRow, ScanCount, ScanProgress, Scanner, VType, ValueRef};
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
    pub scanner: Scanner,
    pub(crate) freezer: Freezer,
    /// Shared with the Lua engine (`registerSymbol`, AA `registersymbol` from either side).
    pub(crate) syms: Arc<Mutex<SymbolTable>>,
    pub(crate) dbg: Mutex<Option<crate::debug::Dbg>>,
    pub(crate) ptr: crate::ptr::Ptr,
    pub(crate) tools: crate::tools::Tools,
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
#[derive(Clone, Default)]
pub struct App {
    sess: Arc<Mutex<Option<Arc<Session>>>>,
    pub(crate) x: Arc<Shared>,
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
    /// Whether `{$lua}` in the table's scripts may run (a loaded table must be agreed to).
    pub(crate) trust: Mutex<crate::cheat::Trust>,
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
            trust: Mutex::default(),
        }
    }
}

pub(crate) struct WeakApp(Weak<Mutex<Option<Arc<Session>>>>, Weak<Shared>);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Opened {
    pub pid: u32,
    pub name: String,
    pub is_64bit: bool,
}

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
        self.apply_settings(&s);
        *lock(&self.x.settings) = s;
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
        self.x.lua.engine.set_budget((s.lua_budget_ms > 0).then(|| Duration::from_millis(s.lua_budget_ms)));
        if let Ok(sess) = self.session() {
            sess.freezer.set_interval(Duration::from_millis(s.freeze_interval_ms));
        }
    }

    pub fn list_processes(&self) -> R<Vec<ProcessInfo>> {
        hh_core::list_processes().map_err(s)
    }

    /// Attaches to `pid`; the previous process's scan, frozen set and symbols are dropped.
    pub fn open_process(&self, pid: u32) -> R<Opened> {
        let raw = hh_core::open(pid).map_err(s)?;
        let switch = Arc::new(Switch(RwLock::new(raw.clone())));
        let proc: Arc<dyn Process> = switch.clone();
        let name = hh_core::list_processes()
            .ok()
            .and_then(|l| l.into_iter().find(|p| p.pid == pid))
            .map_or_else(|| pid.to_string(), |p| p.name);
        let info = Opened { pid, name, is_64bit: proc.pointer_size() == 8 };
        let mem: Arc<dyn Memory> = proc.clone();
        let freezer = Freezer::new(mem).map_err(s)?;
        freezer.set_interval(Duration::from_millis(lock(&self.x.settings).freeze_interval_ms));
        let syms = self.x.lua.engine.symbols();
        *lock(&syms) = SymbolTable::default();
        let sess = Session {
            scanner: Scanner::new(proc.clone()),
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
        if let Some(old) = lock(&self.sess).replace(Arc::new(sess)) {
            old.scanner.cancel();
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
        sess.scanner.cancel();
        let _ = sess.freezer.set(&[]);
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

    pub fn read_values(&self, mut reqs: Vec<ValueRef>) -> R<Vec<Option<String>>> {
        // The UI sends len 0 for "default length".
        reqs.iter_mut().filter(|r| r.fmt.len == Some(0)).for_each(|r| r.fmt.len = None);
        Ok(hh_scan::read_values(&*self.session()?.proc, &reqs))
    }

    /// Integers accept a `0x` prefix (hex-displayed entries); `fmt` carries the entry's
    /// `utf16` / `hex` / `signed` / `len` flags; see `hh_scan::parse_value`.
    pub fn write_value(&self, addr: &str, vtype: VType, value: &str, fmt: &Fmt) -> R<()> {
        hh_scan::write_value(&*self.session()?.proc, parse_addr(addr)?, vtype, value, fmt).map_err(s)
    }

    pub fn resolve_address(&self, expr: &str) -> R<String> {
        let sess = self.session()?;
        let syms = lock(&sess.syms).clone();
        match hh_asm::resolve_address(&*sess.proc, &syms, expr) {
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

    /// Blocks until the scan ends; call it off the UI thread.
    pub fn scan_first(&self, req: &FirstScan) -> R<ScanCount> {
        self.session()?.scanner.first_scan(req).map_err(s)
    }

    pub fn scan_next(&self, req: &NextScan) -> R<ScanCount> {
        self.session()?.scanner.next_scan(req).map_err(s)
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

    pub fn scan_progress(&self) -> R<ScanProgress> {
        Ok(self.session().map(|s| s.scanner.progress()).unwrap_or_default())
    }

    pub fn scan_results(&self, offset: u64, limit: usize) -> R<Vec<ResultRow>> {
        self.session()?.scanner.results(offset, limit).map_err(s)
    }

    pub fn set_frozen(&self, entries: &[FrozenEntry]) -> R<()> {
        self.session()?.freezer.set(entries).map_err(s)
    }

    pub fn disassemble(&self, addr: &str, count: usize) -> R<Vec<DisasmOut>> {
        let sess = self.session()?;
        let syms = lock(&sess.syms).clone();
        let lines = hh_asm::disassemble(&*sess.proc, &syms, parse_addr(addr)?, count.min(MAX_DISASM)).map_err(s)?;
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

    /// Never runs code: the editor checks on every keystroke and the script may come from an
    /// untrusted table, so `{$lua}` blocks count as producing no text here.
    pub fn aa_check(&self, script: &str) -> R<Option<AaError>> {
        let sess = self.session()?;
        let syms = lock(&sess.syms).clone();
        Ok(hh_asm::aa_check(&*sess.proc, &syms, script, &mut self.x.lua.engine.aa_hooks_check_only()))
    }

    /// Symbols the script registers stay registered for later expressions. `{$lua}` blocks
    /// run in the app's engine (so they cannot hold the symbol lock: work on a copy, merge).
    pub fn aa_execute(&self, script: &str, enable: bool, state: Option<&AaState>) -> R<AaState> {
        let sess = self.session()?;
        let before = lock(&sess.syms).clone();
        let mut work = before.clone();
        let r = {
            let _g = self.x.lua.enter();
            hh_asm::aa_execute(&*sess.proc, &mut work, script, enable, state, &mut self.x.lua.engine.aa_hooks(None, false))
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
        r.map_err(s)
    }

    pub fn table_load(&self, path: &str) -> R<Table> {
        table::load(Path::new(path))
    }

    pub fn table_save(&self, path: &str, table: TableIn) -> R<()> {
        table::save(Path::new(path), &table.into())
    }
}
