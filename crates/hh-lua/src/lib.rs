//! HeapHook Lua engine: an embedded Lua 5.3 with Cheat Engine compatible globals
//! (`readInteger`, `AOBScan`, `autoAssemble`, `getAddressList`, `createTimer`, ...).
//!
//! One [`Engine`] owns one Lua state bound to an (optional) opened process. All Lua runs on
//! whichever thread calls into the engine; the state is behind a lock (mlua `send`), so two
//! threads can never run Lua at the same time. Timers and `createThread` functions are
//! cooperative: they run inside [`Engine::tick`], which the host calls periodically (CE runs
//! them on its GUI thread the same way).
//!
//! OS access: `io`, `os.execute`, `os.remove`, `os.rename`, `os.getenv`, `os.tmpname`,
//! `dofile`, `loadfile` and file-based `require` are available like in Cheat Engine unless
//! [`EngineOptions::allow_os`] is false. `os.exit` is always disabled (it would kill the
//! host); loading C modules is never possible.
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant};

use hh_asm::{AaHooks, SymbolTable};
use hh_core::{Addr, Error, Process, Result};
use hh_scan::Scanner;
use mlua::{Function, HookTriggers, Lua, MultiValue, Value, VmState};

mod api;
mod table;

pub use table::{MemTable, RecId, Record, TableHost};

/// Cheat Engine functions that exist as names but are not implemented: calling one raises
/// a Lua error naming it. Grouped by area so later waves can fill them in.
pub const STUBS: &[(&str, &[&str])] = &[
    (
        "forms",
        &[
            "createForm", "createFormFromFile", "createButton", "createLabel", "createEdit",
            "createMemo", "createCheckBox", "createRadioGroup", "createListBox", "createComboBox",
            "createPanel", "createGroupBox", "createImage", "createProgressBar", "createTrackBar",
            "createListView", "createTreeView", "createMainMenu", "createMenuItem", "createPopupMenu",
            "createSplitter", "createToggleBox", "createTabControl", "createPageControl",
            "createScrollBox", "createBitmap", "createPicture", "createPNG", "createFont",
            "createOpenDialog", "createSaveDialog", "createSelectDirectoryDialog", "createColorDialog",
            "getMainForm", "getMemoryViewForm", "getFormCount", "getForm", "getSettings",
            "getApplication", "getLuaEngine", "getVisibleDisassembler",
        ],
    ),
    (
        "debugger",
        &[
            "debugProcess", "debug_isDebugging", "debug_getCurrentDebuggerInterface",
            "debug_setBreakpoint", "debug_removeBreakpoint", "debug_continueFromBreakpoint",
            "debug_getBreakpointList", "debug_breakThread", "debug_getContext", "debug_setContext",
            "debug_updateGUI", "debug_isBroken", "debug_canBreak", "debug_setLastBranchRecording",
            "debug_getXMMPointer",
        ],
    ),
    (
        "mono",
        &[
            "LaunchMonoDataCollector", "mono_initialize", "mono_enumDomains", "mono_enumAssemblies",
            "mono_findClass", "mono_findMethod", "mono_invoke_method", "mono_compile_method",
            "mono_object_getClass", "mono_class_getName", "mono_class_enumFields",
            "mono_class_enumMethods", "mono_image_enumClasses", "mono_getJitInfo",
            "getDotNetDataCollector",
        ],
    ),
    (
        "dbk",
        &[
            "dbk_initialize", "dbk_useKernelmodeOpenProcess", "dbk_useKernelmodeProcessMemoryAccess",
            "dbk_useKernelmodeQueryMemoryRegions", "dbk_getPEProcess", "dbk_getPEThread",
            "dbk_executeKernelMemory", "dbk_readMSR", "dbk_writeMSR", "dbk_getCR0", "dbk_getCR3",
            "dbk_getCR4", "dbk_getPhysicalAddress", "dbk_writesIgnoreWriteProtection",
        ],
    ),
    (
        "dbvm",
        &[
            "dbvm_initialize", "dbvm_getCR3", "dbvm_getCR4", "dbvm_readMSR", "dbvm_writeMSR",
            "dbvm_readPhysicalMemory", "dbvm_writePhysicalMemory", "dbvm_watch_writes",
            "dbvm_watch_reads", "dbvm_watch_executes", "dbvm_watch_retrievelog", "dbvm_watch_disable",
            "dbvm_cloak_activate", "dbvm_cloak_deactivate", "dbvm_changeregonbp",
            "dbvm_removechangeregonbp", "dbvm_speedhack_setSpeed",
        ],
    ),
    (
        "structures",
        &[
            "createStructure", "getStructureCount", "getStructure", "registerStructureDissectOverride",
            "unregisterStructureDissectOverride", "registerStructureNameLookup",
            "unregisterStructureNameLookup",
        ],
    ),
    ("d3d", &["createD3DHook"]),
    (
        "other",
        &[
            "injectDll", "executeCode", "executeCodeEx", "executeCodeLocal", "loadPlugin",
            "createProcess", "getCurrentMemscan", "registerCustomTypeLua",
            "registerCustomTypeAutoAssembler", "registerAutoAssemblerCommand", "registerAssembler",
            "loadTable", "saveTable", "connectToCEServer", "compile", "compileTCC", "compileCS",
            "createMemoryStream", "createFileStream", "createStringStream",
        ],
    ),
];

/// The error message a stub raises.
pub fn stub_message(category: &str, name: &str) -> String {
    match category {
        "dbk" | "dbvm" => format!("not supported: {name} (HeapHook has no kernel driver or hypervisor)"),
        _ => format!("not supported yet: {name}"),
    }
}

/// Things only the host application can do. Every method has a headless default.
pub trait Host: Send + Sync {
    /// `print(...)` output (the Lua console). Default: dropped.
    fn print(&self, _text: &str) {}
    /// `showMessage`. Default: forwarded to [`Host::print`].
    fn show_message(&self, text: &str) {
        self.print(text)
    }
    /// Errors from timers, threads, hotkeys or record activation nobody else sees.
    fn error(&self, text: &str) {
        self.print(text)
    }
    /// `messageDialog`: `buttons` are CE `mb*` values; returns an `mr*` value. Default: the
    /// first button's result.
    fn message_dialog(&self, _title: &str, _text: &str, _kind: i64, buttons: &[i64]) -> i64 {
        api::button_result(buttons.first().copied().unwrap_or(2))
    }
    /// `inputQuery`: `None` = cancelled. Default: accepts the initial value.
    fn input_query(&self, _caption: &str, _prompt: &str, initial: &str) -> Option<String> {
        Some(initial.to_string())
    }
    fn set_speed(&self, _speed: f64) -> Result<()> {
        Err(Error::Unsupported("speedhack"))
    }
    /// `createHotkey`: the host calls [`Engine::fire_hotkey`] with `id` when `keys` (CE
    /// virtual-key codes) are pressed.
    fn register_hotkey(&self, _id: u32, _keys: &[i64]) -> Result<()> {
        Ok(())
    }
    fn unregister_hotkey(&self, _id: u32) {}
    /// `playSound` with a file name or table file, or `beep()` when `None`.
    fn play_sound(&self, _what: Option<&str>) {}
}

struct NullHost;
impl Host for NullHost {}

#[derive(Debug, Clone)]
pub struct EngineOptions {
    /// Keep `io`, `os.execute`, `dofile`, ... (Cheat Engine allows them). Default true.
    pub allow_os: bool,
    /// Wall-clock limit for one [`Engine::exec`] / [`Engine::tick`] / activation. `None` =
    /// unlimited. Default 30 s.
    pub budget: Option<Duration>,
}

impl Default for EngineOptions {
    fn default() -> Self {
        EngineOptions {
            allow_os: true,
            budget: Some(Duration::from_secs(30)),
        }
    }
}

/// Stops the script currently running in an [`Engine`]; callable from any thread.
#[derive(Clone)]
pub struct Interrupt(Arc<AtomicBool>);

impl Interrupt {
    pub fn interrupt(&self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

pub(crate) struct State {
    proc: RwLock<Option<Arc<dyn Process>>>,
    local: OnceLock<Option<Arc<dyn Process>>>,
    syms: Arc<Mutex<SymbolTable>>,
    allocs: Mutex<HashMap<Addr, u64>>,
    host: RwLock<Arc<dyn Host>>,
    table: RwLock<Arc<dyn TableHost>>,
    scans: Mutex<HashMap<i64, Arc<Scanner>>>,
    next_id: AtomicI64,
    start: Instant,
    interrupt: Arc<AtomicBool>,
    depth: AtomicUsize,
    deadline: Mutex<Option<Instant>>,
    budget: Mutex<Option<Duration>>,
    speed: Mutex<f64>,
}

impl State {
    fn proc(&self) -> Option<Arc<dyn Process>> {
        self.proc.read().unwrap().clone()
    }
    /// The opened process, or Cheat Engine's own ("Local" functions, `targetself`).
    fn target(&self, local: bool) -> Option<Arc<dyn Process>> {
        if local {
            self.local.get_or_init(|| hh_core::open(std::process::id()).ok()).clone()
        } else {
            self.proc()
        }
    }
    fn host(&self) -> Arc<dyn Host> {
        self.host.read().unwrap().clone()
    }
    fn table(&self) -> Arc<dyn TableHost> {
        self.table.read().unwrap().clone()
    }
    /// Checked by the instruction hook, `sleep` and long Rust loops.
    fn check(&self) -> mlua::Result<()> {
        if self.interrupt.load(Ordering::SeqCst) {
            return Err(mlua::Error::runtime("script interrupted"));
        }
        if self.deadline.lock().unwrap().is_some_and(|d| Instant::now() >= d) {
            let b = self.budget.lock().unwrap().unwrap_or_default();
            return Err(mlua::Error::runtime(format!("script exceeded its time budget ({b:?})")));
        }
        Ok(())
    }
}

/// Arms the budget for the outermost entry into Lua; nested entries share it.
pub(crate) struct Guard(Arc<State>);

pub(crate) fn guard(st: &Arc<State>) -> Guard {
    if st.depth.fetch_add(1, Ordering::SeqCst) == 0 {
        st.interrupt.store(false, Ordering::SeqCst);
        *st.deadline.lock().unwrap() = st.budget.lock().unwrap().map(|b| Instant::now() + b);
    }
    Guard(st.clone())
}

impl Drop for Guard {
    fn drop(&mut self) {
        if self.0.depth.fetch_sub(1, Ordering::SeqCst) == 1 {
            *self.0.deadline.lock().unwrap() = None;
        }
    }
}

/// Lua functions the prelude hands back to Rust.
struct Internals {
    xcall: Function,
    tick: Function,
    setactive: Function,
    hotkey: Function,
}

/// A Lua state with the Cheat Engine API. Cheap to clone (shared state).
#[derive(Clone)]
pub struct Engine {
    lua: Lua,
    st: Arc<State>,
    i: Arc<Internals>,
}

fn lua_err(e: mlua::Error) -> Error {
    match e {
        mlua::Error::SyntaxError { message, .. } => Error::Parse(message),
        e => Error::Other(api::err_text(&e)),
    }
}

impl Engine {
    pub fn new(opts: EngineOptions) -> Result<Engine> {
        let lua = Lua::new();
        let st = Arc::new(State {
            proc: RwLock::new(None),
            local: OnceLock::new(),
            syms: Arc::new(Mutex::new(SymbolTable::default())),
            allocs: Mutex::new(HashMap::new()),
            host: RwLock::new(Arc::new(NullHost)),
            table: RwLock::new(Arc::new(MemTable::new())),
            scans: Mutex::new(HashMap::new()),
            next_id: AtomicI64::new(1),
            start: Instant::now(),
            interrupt: Arc::new(AtomicBool::new(false)),
            depth: AtomicUsize::new(0),
            deadline: Mutex::new(None),
            budget: Mutex::new(opts.budget),
            speed: Mutex::new(1.0),
        });
        let hook_st = st.clone();
        lua.set_global_hook(HookTriggers::new().every_nth_instruction(1000), move |_, _| {
            hook_st.check().map(|_| VmState::Continue)
        })
        .map_err(lua_err)?;
        let i = api::install(&lua, &st, opts.allow_os).map_err(lua_err)?;
        Ok(Engine {
            lua,
            st,
            i: Arc::new(i),
        })
    }

    /// The underlying Lua state, for host-specific extensions.
    pub fn lua(&self) -> &Lua {
        &self.lua
    }

    /// Binds the engine to a process (or detaches with `None`); updates the `process` global.
    pub fn set_process(&self, p: Option<Arc<dyn Process>>) -> Result<()> {
        api::set_process(&self.lua, &self.st, p).map_err(lua_err)
    }

    pub fn process(&self) -> Option<Arc<dyn Process>> {
        self.st.proc()
    }

    /// Symbols from `registerSymbol` and Auto Assembler `registersymbol`; share it with the
    /// app's own address resolution.
    pub fn symbols(&self) -> Arc<Mutex<SymbolTable>> {
        self.st.syms.clone()
    }

    pub fn set_host(&self, host: Arc<dyn Host>) {
        *self.st.host.write().unwrap() = host;
    }

    pub fn set_table(&self, table: Arc<dyn TableHost>) {
        *self.st.table.write().unwrap() = table;
    }

    pub fn set_budget(&self, budget: Option<Duration>) {
        *self.st.budget.lock().unwrap() = budget;
    }

    pub fn interrupt_handle(&self) -> Interrupt {
        Interrupt(self.st.interrupt.clone())
    }

    /// Runs a chunk (table script, console line). Returns its results converted with
    /// `tostring`. Errors carry the message, `name:line:` position and a traceback.
    pub fn exec(&self, src: &str, name: &str) -> Result<Vec<String>> {
        let _g = guard(&self.st);
        let f = self.lua.load(src).set_name(format!("={name}")).into_function().map_err(lua_err)?;
        let r = self.call(f, MultiValue::new())?;
        let tostring: Function = self.lua.globals().get("tostring").map_err(lua_err)?;
        r.into_iter().map(|v| tostring.call::<String>(v).map_err(lua_err)).collect()
    }

    /// Calls `f` under the traceback handler; Err holds the formatted Lua error.
    fn call(&self, f: Function, args: MultiValue) -> Result<MultiValue> {
        let mut r = self.i.xcall.call::<MultiValue>((f, args)).map_err(lua_err)?;
        match r.pop_front() {
            Some(Value::Boolean(true)) => Ok(r),
            _ => {
                let msg = r.pop_front().map(|v| api::value_text(&self.lua, &v)).unwrap_or_default();
                Err(Error::Other(msg))
            }
        }
    }

    /// Runs due timers and resumes due `createThread` functions. Call it every ~10-50 ms from
    /// the thread that owns the engine. Errors of individual callbacks are joined into Err
    /// (the timers stay enabled, like in CE).
    pub fn tick(&self) -> Result<()> {
        let _g = guard(&self.st);
        let errs: Vec<String> = self.i.tick.call(()).map_err(lua_err)?;
        if errs.is_empty() { Ok(()) } else { Err(Error::Other(errs.join("\n"))) }
    }

    /// Activates/deactivates a memory record like setting `memrec.Active` from Lua:
    /// OnActivate/OnDeactivate callbacks, Auto Assembler for script entries, freeze for value
    /// entries.
    pub fn set_active(&self, id: RecId, active: bool) -> Result<()> {
        let _g = guard(&self.st);
        let (ok, err): (bool, Option<String>) =
            self.i.setactive.call((id, active)).map_err(lua_err)?;
        if ok { Ok(()) } else { Err(Error::Other(err.unwrap_or_else(|| "activation failed".into()))) }
    }

    /// Runs the `createHotkey` function registered under `id`.
    pub fn fire_hotkey(&self, id: u32) -> Result<()> {
        let _g = guard(&self.st);
        let f = self.i.hotkey.clone();
        let wrapped = self.lua.create_function(move |_, ()| f.call::<()>(id)).map_err(lua_err)?;
        self.call(wrapped, MultiValue::new()).map(|_| ())
    }

    /// Hooks for `hh_asm::aa_execute` / `aa_check` so `{$lua}` blocks run in this engine,
    /// with the `syntaxcheck` and `memrec` globals set like Cheat Engine does.
    pub fn aa_hooks(&self, memrec: Option<RecId>, syntax_check: bool) -> AaHooks {
        AaHooks {
            lua: Some(api::lua_block_hook(self.lua.clone(), self.st.clone(), memrec, syntax_check)),
            ..Default::default()
        }
    }
}
