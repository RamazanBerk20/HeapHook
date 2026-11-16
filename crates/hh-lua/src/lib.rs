//! HeapHook Lua engine: an embedded Lua 5.3 with Cheat Engine compatible globals
//! (`readInteger`, `AOBScan`, `autoAssemble`, `getAddressList`, `createTimer`, `createForm`,
//! `debug_setBreakpoint`, ...).
//!
//! One [`Engine`] owns one Lua state bound to an (optional) opened process. All Lua runs on
//! whichever thread calls into the engine. Every entry point ([`Engine::exec`],
//! [`Engine::tick`], [`Engine::set_active`], [`Engine::fire_event`], ...) passes one gate: a
//! lock that admits one thread at a time and lets that thread re-enter (nested entries). The
//! outermost entry of a thread arms the time budget and clears the interrupt flag, so
//! callers on different threads never share a deadline and the host does not need its own
//! lock around the engine. Timers and `createThread` functions are cooperative: they run
//! inside [`Engine::tick`], which the host calls periodically (CE runs them on its GUI thread
//! the same way).
//!
//! Once a script exceeds its budget or is interrupted it is aborted for good: `pcall`,
//! `xpcall` and `coroutine.resume` re-raise the abort, so a script cannot catch it in a loop
//! and keep running.
//!
//! Subsystems the host can plug in, all with headless defaults: [`Host`] (console, dialogs,
//! hotkeys, process creation, table files), [`TableHost`] (the address list), [`UiHost`]
//! (forms built by scripts, kept as a retained control tree here) and [`DebugHost`]
//! (breakpoints).
//!
//! OS access: `io`, `os.execute`, `os.remove`, `os.rename`, `os.getenv`, `os.tmpname`,
//! `dofile`, `loadfile`, file-based `require`, `shellExecute`, `readRegionFromFile` /
//! `writeRegionToFile` and `md5file` are available like in Cheat Engine unless
//! [`EngineOptions::allow_os`] is false. `os.exit` is always disabled (it would kill the
//! host); loading C modules is never possible.
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock, RwLock};
use std::thread::ThreadId;
use std::time::{Duration, Instant};

use hh_asm::{AaHooks, SymbolTable};
use hh_core::{Addr, Error, Process, Result};
use hh_scan::Scanner;
use mlua::chunk::ChunkMode;
use mlua::{Function, HookTriggers, IntoLua, IntoLuaMulti, Lua, MultiValue, Value, VmState};

mod api;
mod debug;
mod ext;
mod table;
mod ui;

pub use api::button_result;
pub use debug::{BpMethod, BpTrigger, BreakEvent, BreakResult, BreakpointSpec, ContinueMode, DebugHost, RegContext};
pub use table::{MemTable, RecId, Record, RecordHotkey, TableHost};
pub use ui::{Control, ControlId, ControlNode, Prop, UiChange, UiHost, UiSnapshot};

/// Cheat Engine functions that exist as names but are not available: calling one raises a
/// Lua error naming it (see [`stub_message`]). Categories in [`UNSUPPORTED`] can never work
/// in HeapHook; the others are not implemented yet.
pub const STUBS: &[(&str, &[&str])] = &[
    (
        "forms",
        &[
            "createFormFromFile", "createListView", "createTreeView", "createBitmap", "createPicture",
            "createPNG", "createFont", "createOpenDialog", "createSaveDialog", "createSelectDirectoryDialog",
            "createColorDialog", "getMemoryViewForm", "getSettings", "getLuaEngine", "getVisibleDisassembler",
        ],
    ),
    (
        "debugger",
        &[
            "debug_getCurrentDebuggerInterface", "debug_setLastBranchRecording", "debug_getXMMPointer",
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
            "registerStructureDissectOverride", "unregisterStructureDissectOverride",
            "registerStructureNameLookup", "unregisterStructureNameLookup",
        ],
    ),
    ("d3d", &["createD3DHook"]),
    (
        "injection",
        &[
            "injectDll", "executeCode", "executeCodeEx", "executeCodeLocal", "loadPlugin", "compile",
            "compileTCC", "compileCS",
        ],
    ),
    (
        "other",
        &[
            "registerCustomTypeLua", "registerCustomTypeAutoAssembler", "registerAutoAssemblerCommand",
            "registerAssembler", "connectToCEServer", "createMemoryStream", "createFileStream",
            "createStringStream",
        ],
    ),
];

/// Stub categories that can never work in HeapHook, with the reason.
pub const UNSUPPORTED: &[(&str, &str)] = &[
    ("mono", "mono/.NET inspection needs an injected data collector"),
    ("dbk", "HeapHook has no kernel driver"),
    ("dbvm", "HeapHook has no hypervisor"),
    ("d3d", "Direct3D hooking needs library injection"),
    ("injection", "library and code injection is not available in HeapHook"),
];

/// The error message a stub raises: `not supported in HeapHook: NAME (reason)` for the
/// [`UNSUPPORTED`] categories, `not implemented yet: NAME` otherwise.
pub fn stub_message(category: &str, name: &str) -> String {
    match UNSUPPORTED.iter().find(|u| u.0 == category) {
        Some((_, why)) => format!("not supported in HeapHook: {name} ({why})"),
        None => format!("not implemented yet: {name}"),
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
        button_result(buttons.first().copied().unwrap_or(2))
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
    /// `createProcess(path, parameters, debug, breakOnEntry)`: start the program and make it
    /// the opened process (the host calls [`Engine::set_process`]). Returns the pid.
    fn create_process(&self, _path: &str, _params: &str, _debug: bool, _break_on_entry: bool) -> Result<u32> {
        Err(Error::Unsupported("createProcess: no host process launcher"))
    }
    /// `getCurrentMemscan()`: the scanner of the main window's scan. Default: none.
    fn current_memscan(&self) -> Option<Arc<Scanner>> {
        None
    }
    /// `loadTable(file, merge)`. The host replaces (or merges into) its table and should call
    /// [`Engine::clear_table_state`] when it replaced it.
    fn load_table(&self, _path: &str, _merge: bool) -> Result<()> {
        Err(Error::Unsupported("loadTable: no host table loader"))
    }
    /// `saveTable(file, protect)`.
    fn save_table(&self, _path: &str, _protect: bool) -> Result<()> {
        Err(Error::Unsupported("saveTable: no host table writer"))
    }
    /// `isKeyPressed(vk)`. Default: false.
    fn is_key_pressed(&self, _vk: i64) -> bool {
        false
    }
}

struct NullHost;
impl Host for NullHost {}

#[derive(Debug, Clone)]
pub struct EngineOptions {
    /// Keep `io`, `os.execute`, `dofile`, `shellExecute`, ... (Cheat Engine allows them).
    /// Default true. False also turns off access to HeapHook's own memory (the `*Local`
    /// functions, `autoAssemble(script, true)`, local `copyMemory` modes).
    ///
    /// `allow_os = false` is a restriction for scripts the user chose to run, not a hardened
    /// sandbox: scripts still read and write the target process, run Auto Assembler there and
    /// can use as much CPU and memory as the budget and [`EngineOptions::memory_limit`] allow.
    pub allow_os: bool,
    /// Wall-clock limit for one outermost entry ([`Engine::exec`], [`Engine::tick`], an
    /// activation, an event). `None` = unlimited. Default 30 s.
    pub budget: Option<Duration>,
    /// Most memory the Lua state may allocate, in bytes; exceeding it is an ordinary script
    /// error ("not enough memory"). `None` = unlimited. Default 1 GiB.
    pub memory_limit: Option<usize>,
}

impl Default for EngineOptions {
    fn default() -> Self {
        EngineOptions {
            allow_os: true,
            budget: Some(Duration::from_secs(30)),
            memory_limit: Some(1 << 30),
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

/// Which thread is inside the engine and how deeply.
#[derive(Default)]
struct GateState {
    owner: Option<ThreadId>,
    depth: usize,
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
    gate: Mutex<GateState>,
    gate_cv: Condvar,
    /// Set when the running script hit its budget or was interrupted; sticky until the
    /// outermost entry returns.
    abort: Mutex<Option<String>>,
    deadline: Mutex<Option<Instant>>,
    budget: Mutex<Option<Duration>>,
    speed: Mutex<f64>,
    allow_os: bool,
    pub(crate) ui: ui::UiState,
    pub(crate) dbg: debug::DebugState,
    pub(crate) ext: ext::ExtState,
}

impl State {
    fn proc(&self) -> Option<Arc<dyn Process>> {
        self.proc.read().unwrap().clone()
    }
    /// The opened process, or Cheat Engine's own ("Local" functions, `targetself`).
    fn target(&self, local: bool) -> Option<Arc<dyn Process>> {
        if local && !self.allow_os {
            return None;
        }
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
    fn aborted(&self) -> Option<String> {
        self.abort.lock().unwrap().clone()
    }
    /// Checked by the instruction hook, `sleep` and long Rust loops.
    fn check(&self) -> mlua::Result<()> {
        let mut a = self.abort.lock().unwrap();
        if a.is_none() {
            if self.interrupt.load(Ordering::SeqCst) {
                *a = Some("script interrupted".into());
            } else if self.deadline.lock().unwrap().is_some_and(|d| Instant::now() >= d) {
                let b = self.budget.lock().unwrap().unwrap_or_default();
                *a = Some(format!("script exceeded its time budget ({b:?})"));
            }
        }
        match &*a {
            Some(m) => Err(mlua::Error::runtime(m.clone())),
            None => Ok(()),
        }
    }
}

/// One entry into the engine. The outermost entry of a thread waits for other threads to
/// leave, then arms the budget; nested entries on the same thread share it.
pub(crate) struct Guard(Arc<State>);

pub(crate) fn guard(st: &Arc<State>) -> Guard {
    let me = std::thread::current().id();
    let mut g = st.gate.lock().unwrap();
    if g.owner == Some(me) {
        g.depth += 1;
    } else {
        while g.owner.is_some() {
            g = st.gate_cv.wait(g).unwrap();
        }
        g.owner = Some(me);
        g.depth = 1;
        st.interrupt.store(false, Ordering::SeqCst);
        *st.abort.lock().unwrap() = None;
        *st.deadline.lock().unwrap() = st.budget.lock().unwrap().map(|b| Instant::now() + b);
    }
    Guard(st.clone())
}

impl Drop for Guard {
    fn drop(&mut self) {
        let mut g = self.0.gate.lock().unwrap();
        g.depth -= 1;
        if g.depth == 0 {
            g.owner = None;
            *self.0.deadline.lock().unwrap() = None;
            drop(g);
            self.0.gate_cv.notify_one();
        }
    }
}

/// Lua functions the prelude hands back to Rust.
struct Internals {
    xcall: Function,
    tick: Function,
    setactive: Function,
    hotkey: Function,
    rechotkey: Function,
    clear: Function,
    uievent: Function,
    uiinput: Function,
    breakpoint: Function,
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
        if let Some(m) = opts.memory_limit {
            lua.set_memory_limit(m).map_err(lua_err)?;
        }
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
            gate: Mutex::new(GateState::default()),
            gate_cv: Condvar::new(),
            abort: Mutex::new(None),
            deadline: Mutex::new(None),
            budget: Mutex::new(opts.budget),
            speed: Mutex::new(1.0),
            allow_os: opts.allow_os,
            ui: ui::UiState::default(),
            dbg: debug::DebugState::default(),
            ext: ext::ExtState::default(),
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

    /// Where forms built by scripts are rendered. Default: headless (the tree is kept and
    /// scripts run; nothing is shown). The new host gets the current tree as `Create` events.
    pub fn set_ui_host(&self, host: Arc<dyn UiHost>) {
        ui::set_host(&self.st, host);
    }

    /// The debugger the `debug_*` functions drive. Default: none (they report that no
    /// debugger is available).
    pub fn set_debug_host(&self, host: Arc<dyn DebugHost>) {
        *self.st.dbg.host.write().unwrap() = host;
    }

    pub fn set_budget(&self, budget: Option<Duration>) {
        *self.st.budget.lock().unwrap() = budget;
    }

    pub fn interrupt_handle(&self) -> Interrupt {
        Interrupt(self.st.interrupt.clone())
    }

    /// Runs `f` as one guarded entry; an abort the script swallowed still fails the call.
    fn entry<T>(&self, f: impl FnOnce() -> Result<T>) -> Result<T> {
        let _g = guard(&self.st);
        let r = f();
        match self.st.aborted() {
            Some(m) if r.is_ok() => Err(Error::Other(m)),
            _ => r,
        }
    }

    /// Runs a chunk (table script, console line). Returns its results converted with
    /// `tostring`. Errors carry the message, `name:line:` position and a traceback.
    pub fn exec(&self, src: &str, name: &str) -> Result<Vec<String>> {
        self.entry(|| {
            let f = self.lua.load(src).set_name(format!("={name}")).set_mode(ChunkMode::Text).into_function().map_err(lua_err)?;
            let r = self.call(f, MultiValue::new())?;
            let tostring: Function = self.lua.globals().get("tostring").map_err(lua_err)?;
            r.into_iter().map(|v| tostring.call::<String>(v).map_err(lua_err)).collect()
        })
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

    /// Runs due timers, resumes due `createThread` functions and fires `OnValueChanged` of
    /// memory records. Call it every ~10-50 ms. Errors of individual callbacks are joined
    /// into Err (the timers stay enabled, like in CE).
    pub fn tick(&self) -> Result<()> {
        self.entry(|| {
            let errs: Vec<String> = self.i.tick.call(()).map_err(lua_err)?;
            if errs.is_empty() { Ok(()) } else { Err(Error::Other(errs.join("\n"))) }
        })
    }

    /// Activates/deactivates a memory record like setting `memrec.Active` from Lua:
    /// OnActivate/OnDeactivate callbacks, Auto Assembler for script entries, freeze for value
    /// entries, nothing for group headers, then the group options (children activated or
    /// deactivated as well).
    pub fn set_active(&self, id: RecId, active: bool) -> Result<()> {
        self.entry(|| {
            let (ok, err): (bool, Option<String>) = self.i.setactive.call((id, active)).map_err(lua_err)?;
            if ok { Ok(()) } else { Err(Error::Other(err.unwrap_or_else(|| "activation failed".into()))) }
        })
    }

    /// Runs the `createHotkey` function registered under `id`.
    pub fn fire_hotkey(&self, id: u32) -> Result<()> {
        self.call_internal(&self.i.hotkey, id).map(|_| ())
    }

    /// Performs the action of hotkey `hotkey` of record `rec` (toggle, activate, set /
    /// increase / decrease value) with its OnHotkey / OnPostHotkey callbacks.
    pub fn fire_record_hotkey(&self, rec: RecId, hotkey: u32) -> Result<()> {
        self.call_internal(&self.i.rechotkey, (rec, hotkey)).map(|_| ())
    }

    /// Forgets everything the previous table's scripts left behind: memory record callbacks
    /// and cached record objects (OnDestroy runs first), record hotkey callbacks, timers,
    /// `createThread` threads, `createHotkey` hotkeys (unregistered with the host), forms
    /// (destroyed, the UI host is told), breakpoints set from Lua (removed through the debug
    /// host) and memscans. Call it after replacing the table. Globals stay.
    ///
    /// Ownership is by time: everything created since the previous clear belongs to the
    /// current table, including objects created from the console.
    pub fn clear_table_state(&self) -> Result<()> {
        self.call_internal(&self.i.clear, ()).map(|_| ())
    }

    /// Delivers a user event to control `id` (`OnClick`, `OnClose`, `OnKeyPress`, `OnChange`,
    /// `OnDblClick`, `OnMouseDown`, ...): runs the script's handler with the control as the
    /// first argument followed by `args`, and returns what it returned. `OnClose` also applies
    /// the close action (hide or free). A control without a handler is not an error.
    pub fn fire_event(&self, id: ControlId, event: &str, args: &[Prop]) -> Result<Vec<Prop>> {
        let mut a = MultiValue::new();
        a.push_back(Value::Integer(id as i64));
        a.push_back(event.into_lua(&self.lua).map_err(lua_err)?);
        for p in args {
            a.push_back(p.clone().into_lua(&self.lua).map_err(lua_err)?);
        }
        let r = self.call_internal(&self.i.uievent, a)?;
        Ok(r.iter().map(Prop::from_lua_value).collect())
    }

    /// The user changed a control (`Text` of an edit or memo, `Checked`, `ItemIndex`,
    /// `Position`, ...): stores the value without echoing it back to the UI host and fires the
    /// control's `OnChange` (checkboxes also `OnClick`) when it changed.
    pub fn ui_input(&self, id: ControlId, prop: &str, value: Prop) -> Result<()> {
        let v = value.into_lua(&self.lua).map_err(lua_err)?;
        self.call_internal(&self.i.uiinput, (id, prop.to_string(), v)).map(|_| ())
    }

    /// The whole control tree (forms and their children), for a UI that attaches late.
    pub fn ui_snapshot(&self) -> UiSnapshot {
        ui::snapshot(&self.st)
    }

    /// The host's debugger stopped a thread on a breakpoint set through `debug_setBreakpoint`
    /// (or any breakpoint, when `debugger_onBreakpoint` is defined). Sets the register
    /// globals (`RAX`, `EAX`, `RIP`, ...), runs the breakpoint's function (or
    /// `debugger_onBreakpoint`) and returns whether to resume (CE: the function returns
    /// non-zero to continue) and the registers the script changed. When not resumed the
    /// thread counts as broken (`debug_isBroken`) until `debug_continueFromBreakpoint` or
    /// [`Engine::debug_resumed`].
    pub fn on_breakpoint(&self, ev: &BreakEvent) -> Result<BreakResult> {
        self.entry(|| {
            *self.st.dbg.broken.lock().unwrap() = Some(ev.clone());
            *self.st.dbg.known.lock().unwrap() = Some(ev.context);
            debug::write_context(&self.lua, &ev.context).map_err(lua_err)?;
            let r = self.call(self.i.breakpoint.clone(), (ev.address as i64, ev.thread_id).into_lua_multi(&self.lua).map_err(lua_err)?);
            let resume = match r.as_ref().ok().and_then(|v| v.front()) {
                Some(Value::Boolean(b)) => *b,
                Some(Value::Integer(i)) => *i != 0,
                Some(Value::Number(n)) => *n != 0.0,
                _ => false,
            };
            let ctx = debug::read_context(&self.lua, &ev.context);
            let changed = (ctx != ev.context).then_some(ctx);
            let mut b = self.st.dbg.broken.lock().unwrap();
            // The function may have continued (or re-broken) the thread itself.
            if b.as_ref().is_some_and(|b| b.thread_id == ev.thread_id) {
                if resume {
                    *b = None;
                } else if let Some(b) = b.as_mut() {
                    b.context = ctx;
                    *self.st.dbg.known.lock().unwrap() = Some(ctx);
                }
            }
            drop(b);
            r.map(|_| BreakResult { resume, context: changed })
        })
    }

    /// The host resumed the broken thread itself (debugger UI): `debug_isBroken` turns false.
    pub fn debug_resumed(&self) {
        *self.st.dbg.broken.lock().unwrap() = None;
    }

    fn call_internal(&self, f: &Function, args: impl mlua::IntoLuaMulti) -> Result<MultiValue> {
        self.entry(|| {
            let args = args.into_lua_multi(&self.lua).map_err(lua_err)?;
            self.call(f.clone(), args)
        })
    }

    /// Hooks for `hh_asm::aa_check` that do NOT run `{$lua}` blocks: each block yields an
    /// empty string. For live syntax checks while the user types, which must not execute
    /// table code.
    pub fn aa_hooks_check_only(&self) -> AaHooks {
        AaHooks {
            lua: Some(Box::new(|_src: String| Ok(String::new()))),
            ..Default::default()
        }
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
