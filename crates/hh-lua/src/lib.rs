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
//! Scripts can extend the Auto Assembler and the symbol handler (`registerAutoAssemblerCommand`,
//! `registerAutoAssemblerPrologue`, `registerSymbolLookupCallback`,
//! `registerAddressLookupCallback`, `registerStructureDissectOverride`,
//! `registerStructureNameLookup`); [`Engine::aa_hooks`], [`Engine::address_name`],
//! [`Engine::symbol_lookup`] and [`Engine::structure_override`] hand them to the host.
//! HeapHook's own additions are prefixed `hh` (`hhCreatePointerScan`, `hhAssemblyScan`, ...).
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

use hh_asm::{AaHooks, AddressName, SymbolLookup, SymbolTable};
use hh_core::{Addr, Error, Process, Result};
use hh_scan::Scanner;
use mlua::chunk::ChunkMode;
use mlua::{Function, HookTriggers, IntoLua, IntoLuaMulti, Lua, MultiValue, Value, VmState};

mod api;
mod debug;
mod ext;
mod hooks;
mod ptrscan;
mod table;
mod ui;

pub use api::button_result;
pub use debug::{BpMethod, BpTrigger, BreakEvent, BreakResult, BreakpointSpec, ContinueMode, DebugHost, RegContext};
pub use table::{Caps, MemTable, Owner, RecId, Record, RecordHotkey, TableHost};
pub use ui::{ChangeLog, Control, ControlId, ControlNode, MAX_CONTROLS, MAX_DEPTH, MAX_PROP_BYTES, MAX_UI_BYTES, Prop, UiChange, UiHost, UiSnapshot, change_size};

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
            "registerCustomTypeLua", "registerCustomTypeAutoAssembler", "registerAssembler",
            "unregisterAssembler", "connectToCEServer", "createMemoryStream", "createFileStream",
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
    /// Asked before Auto Assembler `loadbinary(address, file)` reads `path` (only when
    /// [`EngineOptions::allow_os`] is on; the file must also be a regular file of at most
    /// `hh_asm::MAX_ASSEMBLED_BYTES`). Default: denied.
    fn allow_aa_file(&self, _path: &str) -> bool {
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
    /// Most discarded interpreters kept (see [`Engine::reset`]); the oldest is closed beyond
    /// it. Default 16.
    pub max_parked: usize,
    /// Most Lua memory all kept interpreters may hold together (each counted as its used
    /// memory when it was kept); the oldest are closed beyond it. Default 512 MiB.
    pub max_parked_bytes: usize,
}

impl Default for EngineOptions {
    fn default() -> Self {
        EngineOptions {
            allow_os: true,
            budget: Some(Duration::from_secs(30)),
            memory_limit: Some(1 << 30),
            max_parked: 16,
            max_parked_bytes: 512 << 20,
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
    /// What scripts registered as AA / symbol / structure hooks (see `hooks`).
    hooks: Mutex<hooks::Regs>,
    /// Set while a symbol lookup callback runs (no recursion into the callbacks).
    in_symlookup: AtomicBool,
    /// Records refused for want of capabilities since the host last asked
    /// ([`Engine::take_denied`]): (record, message).
    denied: Mutex<Vec<(RecId, String)>>,
    /// Script texts Lua read from records without capabilities (`memrec.Script`): an
    /// `autoAssemble` of text containing one runs without capabilities too.
    tainted: Mutex<std::collections::VecDeque<String>>,
    /// The engine's Lua state, for address resolution deep inside Rust helpers (weak: the
    /// state owns closures holding this struct). Replaced by [`Engine::reset`].
    weak: RwLock<Option<mlua::WeakLua>>,
    /// [`Engine::reset`] was asked for: every script is aborted and every host function
    /// refused until the outermost entry performs it.
    reset_pending: AtomicBool,
    /// Ids of the `createHotkey` hotkeys registered with the host (released by a reset).
    lua_hotkeys: Mutex<std::collections::HashSet<u32>>,
    /// The Lua state's memory limit (a reset applies it to the new state).
    memory_limit: Mutex<Option<usize>>,
    /// The engine's interpreter slot, for a reset performed when the outermost guard drops.
    core: OnceLock<std::sync::Weak<Mutex<Core>>>,
    /// The consent principals whose code has run in this interpreter (see [`Owner`]); only a
    /// reset clears it.
    contam: Mutex<std::collections::BTreeSet<Owner>>,
    /// Caps for kept interpreters (see [`EngineOptions::max_parked`]).
    max_parked: usize,
    max_parked_bytes: usize,
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
            if self.reset_pending.load(Ordering::SeqCst) {
                *a = Some("the table's Lua was stopped".into());
            } else if self.interrupt.load(Ordering::SeqCst) {
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
            // A reset asked for from inside happens at the outermost exit, whichever entry
            // that was (also a `{$lua}` block or lookup callback reached from the host).
            if self.0.reset_pending.load(Ordering::SeqCst)
                && let Some(slot) = self.0.core.get().and_then(std::sync::Weak::upgrade)
            {
                let _ = do_reset(&self.0, &slot);
            }
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

/// One Lua interpreter: the state and the prelude functions it handed back.
#[derive(Clone)]
struct Core {
    lua: Lua,
    i: Arc<Internals>,
    /// Set when the interpreter is discarded (its host functions refuse from then on).
    dead: Arc<AtomicBool>,
}

/// A discarded interpreter in which table or foreign code ran, kept instead of closed.
struct Parked {
    lua: Lua,
    /// Its used memory when it was kept.
    bytes: usize,
}

/// Discarded interpreters in which code of a consent principal ran: closing a Lua state runs
/// every pending `__gc` finalizer, and Lua 5.3 runs finalizers with hooks off, so such code's
/// finalizer would run exactly when its consent is withdrawn. So they are kept, collector
/// stopped, host functions refusing, an error hook on every call and instruction. A clean
/// interpreter (only the user's own code ran) is closed at once.
///
/// Bounded ([`EngineOptions::max_parked`], [`EngineOptions::max_parked_bytes`]): beyond the
/// cap the oldest kept state is closed. Residual risk, stated: closing runs its pending
/// finalizers. Scripts cannot install `__gc` (the prelude's `setmetatable` refuses it, host
/// userdata metatables are locked, there is no `debug.setmetatable`), host functions refuse
/// on a dead state, and its allocator is capped at what it already uses, so a finalizer that
/// slipped through could run plain Lua only, without HeapHook's API and without allocating.
static PARKED: Mutex<std::collections::VecDeque<Parked>> = Mutex::new(std::collections::VecDeque::new());

static RESETS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Interpreters discarded by [`Engine::reset`] in this process (diagnostics).
pub fn reset_count() -> usize {
    RESETS.load(Ordering::SeqCst)
}

/// (kept interpreters, Lua bytes they held when kept), over every engine of the process.
pub fn parked_stats() -> (usize, usize) {
    let p = PARKED.lock().unwrap();
    (p.len(), p.iter().map(|x| x.bytes).sum())
}

/// Keeps `lua` (see [`PARKED`]) and closes the oldest kept ones beyond the caps.
fn park(lua: Lua, max: usize, max_bytes: usize) {
    let bytes = lua.used_memory();
    let mut gone = Vec::new();
    {
        let mut p = PARKED.lock().unwrap();
        p.push_back(Parked { lua, bytes });
        while p.len() > max.max(1) || (p.len() > 1 && p.iter().map(|x| x.bytes).sum::<usize>() > max_bytes) {
            gone.extend(p.pop_front());
        }
    }
    for old in gone {
        // Nothing may grow: a finalizer that slipped through cannot allocate.
        let _ = old.lua.set_memory_limit(old.lua.used_memory().max(1));
        drop(old);
    }
}

/// A Lua state with the Cheat Engine API. Cheap to clone (shared state; every clone sees a
/// [`Engine::reset`]).
#[derive(Clone)]
pub struct Engine {
    core: Arc<Mutex<Core>>,
    st: Arc<State>,
}

/// Replaces the interpreter of `slot` (see [`Engine::reset`]).
fn do_reset(st: &Arc<State>, slot: &Arc<Mutex<Core>>) -> Result<()> {
    let _g = guard(st);
    if !st.reset_pending.load(Ordering::SeqCst) {
        return Ok(()); // another thread did it meanwhile
    }
    let old = slot.lock().unwrap().clone();
    // From now on nothing of the old interpreter runs: its host functions refuse, every call
    // and instruction errors, and its collector never runs (no finalizer, ever).
    old.dead.store(true, Ordering::SeqCst);
    let _ = old.lua.set_global_hook(HookTriggers { on_calls: true, every_nth_instruction: Some(1), ..Default::default() }, |_, _| {
        Err(mlua::Error::runtime("this Lua state was discarded"))
    });
    old.lua.gc_stop();
    for id in std::mem::take(&mut *st.lua_hotkeys.lock().unwrap()) {
        st.host().unregister_hotkey(id);
    }
    for id in st.ui.children(None) {
        st.ui.destroy(id);
    }
    debug::clear(st);
    *st.dbg.broken.lock().unwrap() = None;
    ext::release(st);
    st.scans.lock().unwrap().clear();
    *st.hooks.lock().unwrap() = hooks::Regs::default();
    st.in_symlookup.store(false, Ordering::SeqCst);
    st.denied.lock().unwrap().clear();
    st.tainted.lock().unwrap().clear();
    st.allocs.lock().unwrap().clear();
    let clean = std::mem::take(&mut *st.contam.lock().unwrap()).is_empty();
    RESETS.fetch_add(1, Ordering::SeqCst);
    *st.speed.lock().unwrap() = 1.0;
    st.reset_pending.store(false, Ordering::SeqCst);
    let core = build_core(st)?;
    let replaced = std::mem::replace(&mut *slot.lock().unwrap(), core);
    drop(replaced);
    // Only the Lua handle is kept: the prelude's functions and every Rust-side handle go now.
    let Core { lua, i, dead: _ } = old;
    drop(i);
    if clean {
        // Only the user's own code ran in it: closed like any state.
        drop(lua);
    } else {
        // Kept, not closed: closing would run its finalizers.
        park(lua, st.max_parked, st.max_parked_bytes);
    }
    *st.abort.lock().unwrap() = None;
    Ok(())
}

/// A fresh interpreter for `st`: memory limit, instruction hook, the API and the prelude, the
/// `process` global.
fn build_core(st: &Arc<State>) -> Result<Core> {
    let lua = Lua::new();
    if let Some(m) = *st.memory_limit.lock().unwrap() {
        lua.set_memory_limit(m).map_err(lua_err)?;
    }
    *st.weak.write().unwrap() = Some(lua.weak());
    let hook_st = Arc::downgrade(st);
    lua.set_global_hook(HookTriggers::new().every_nth_instruction(1000), move |_, _| match hook_st.upgrade() {
        Some(st) => st.check().map(|_| VmState::Continue),
        None => Err(mlua::Error::runtime("this Lua state was discarded")),
    })
        .map_err(lua_err)?;
    let dead = Arc::new(AtomicBool::new(false));
    let i = api::install(&lua, st, st.allow_os, &dead).map_err(lua_err)?;
    let name = st.proc().and_then(|p| {
        let pid = p.pid();
        hh_core::list_processes().ok()?.into_iter().find(|i| i.pid == pid).map(|i| i.name)
    });
    lua.globals().set("process", name).map_err(lua_err)?;
    Ok(Core { lua, i: Arc::new(i), dead })
}

fn lua_err(e: mlua::Error) -> Error {
    match e {
        mlua::Error::SyntaxError { message, .. } => Error::Parse(message),
        e => Error::Other(api::err_text(&e)),
    }
}

impl Engine {
    pub fn new(opts: EngineOptions) -> Result<Engine> {
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
            hooks: Mutex::new(hooks::Regs::default()),
            in_symlookup: AtomicBool::new(false),
            denied: Mutex::new(Vec::new()),
            tainted: Mutex::new(Default::default()),
            weak: RwLock::new(None),
            reset_pending: AtomicBool::new(false),
            lua_hotkeys: Mutex::new(Default::default()),
            memory_limit: Mutex::new(opts.memory_limit),
            core: OnceLock::new(),
            contam: Mutex::new(Default::default()),
            max_parked: opts.max_parked,
            max_parked_bytes: opts.max_parked_bytes,
            ui: ui::UiState::default(),
            dbg: debug::DebugState::default(),
            ext: ext::ExtState::default(),
        });
        let core = Arc::new(Mutex::new(build_core(&st)?));
        let _ = st.core.set(Arc::downgrade(&core));
        Ok(Engine { core, st })
    }

    fn core(&self) -> Core {
        self.core.lock().unwrap().clone()
    }

    fn i(&self) -> Arc<Internals> {
        self.core().i
    }

    /// The underlying Lua state, for host-specific extensions (a handle to the current one:
    /// after [`Engine::reset`] it is a different state).
    pub fn lua(&self) -> Lua {
        self.core().lua
    }

    /// The Lua state's memory limit (`None` = unlimited); kept for the states a reset builds.
    pub fn set_memory_limit(&self, limit: Option<usize>) -> Result<()> {
        *self.st.memory_limit.lock().unwrap() = limit;
        self.lua().set_memory_limit(limit.unwrap_or(0)).map(|_| ()).map_err(lua_err)
    }

    /// Discards the Lua state and builds a new one: consent for a table's Lua was withdrawn
    /// (or another table replaces it), so nothing that table's code defined may survive —
    /// globals, replaced library functions and metatables, `package.loaded`, coroutines,
    /// upvalues, registry entries. First every external resource it held is released: forms
    /// (the UI host hears they are gone), `createHotkey` hotkeys (unregistered with the host),
    /// Lua breakpoints (removed through the debug host), pointer scans (cancelled, their files
    /// deleted), memscans, HeapHook-side buffers, AA / symbol / structure registrations, taint
    /// and refusal records. The old state is neutered before it is dropped, so finalizers
    /// (`__gc`) it holds run no code. Hosts, process, budget, memory limit and the symbol
    /// table (addresses, not code) stay.
    ///
    /// Any running script is interrupted. Called from inside the engine (a Lua callback on
    /// this thread, e.g. `loadTable`), it is deferred: the running script is aborted, every
    /// host function is refused, and the outermost entry performs the reset when it returns.
    /// Another thread inside the engine is waited for (it is interrupted first).
    pub fn reset(&self) -> Result<()> {
        self.st.reset_pending.store(true, Ordering::SeqCst);
        self.st.interrupt.store(true, Ordering::SeqCst);
        if self.inside() {
            return Ok(());
        }
        self.do_reset()
    }

    /// Whether this thread is inside the engine.
    fn inside(&self) -> bool {
        self.st.gate.lock().unwrap().owner == Some(std::thread::current().id())
    }

    fn do_reset(&self) -> Result<()> {
        do_reset(&self.st, &self.core)
    }

    /// Performs a pending reset when this thread is not inside the engine.
    fn reset_if_pending(&self) -> Result<()> {
        if self.st.reset_pending.load(Ordering::SeqCst) && !self.inside() {
            self.do_reset()?;
        }
        Ok(())
    }

    /// Binds the engine to a process (or detaches with `None`); updates the `process` global.
    pub fn set_process(&self, p: Option<Arc<dyn Process>>) -> Result<()> {
        api::set_process(&self.lua(), &self.st, p).map_err(lua_err)
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
        self.reset_if_pending()?;
        let r = {
            let _g = guard(&self.st);
            let r = f();
            match self.st.aborted() {
                Some(m) if r.is_ok() => Err(Error::Other(m)),
                _ => r,
            }
        };
        // A reset asked for from inside (e.g. `loadTable`) happens here, at the outermost exit.
        self.reset_if_pending()?;
        r
    }

    /// Runs a chunk (table script, console line). Returns its results converted with
    /// `tostring`. Errors carry the message, `name:line:` position and a traceback.
    pub fn exec(&self, src: &str, name: &str) -> Result<Vec<String>> {
        self.entry(|| {
            let lua = self.lua();
            let f = lua.load(src).set_name(format!("={name}")).set_mode(ChunkMode::Text).into_function().map_err(lua_err)?;
            let r = self.call(f, MultiValue::new())?;
            // The engine's own `tostring`, captured at init (a script may replace the global).
            let tostring: Function = lua.named_registry_value("hh_tostring").map_err(lua_err)?;
            r.into_iter().map(|v| tostring.call::<String>(v).map_err(lua_err)).collect()
        })
    }

    /// Calls `f` under the traceback handler; Err holds the formatted Lua error.
    fn call(&self, f: Function, args: MultiValue) -> Result<MultiValue> {
        let mut r = self.i().xcall.call::<MultiValue>((f, args)).map_err(lua_err)?;
        match r.pop_front() {
            Some(Value::Boolean(true)) => Ok(r),
            _ => {
                let msg = r.pop_front().map(|v| api::value_text(&self.lua(), &v)).unwrap_or_default();
                Err(Error::Other(msg))
            }
        }
    }

    /// Runs due timers, resumes due `createThread` functions and fires `OnValueChanged` of
    /// memory records. Call it every ~10-50 ms. Errors of individual callbacks are joined
    /// into Err (the timers stay enabled, like in CE).
    pub fn tick(&self) -> Result<()> {
        self.entry(|| {
            let errs: Vec<String> = self.i().tick.call(()).map_err(lua_err)?;
            if errs.is_empty() { Ok(()) } else { Err(Error::Other(errs.join("\n"))) }
        })
    }

    /// Activates/deactivates a memory record like setting `memrec.Active` from Lua:
    /// OnActivate/OnDeactivate callbacks, Auto Assembler for script entries, freeze for value
    /// entries, nothing for group headers, then the group options (children activated or
    /// deactivated as well).
    pub fn set_active(&self, id: RecId, active: bool) -> Result<()> {
        self.entry(|| {
            let (ok, err): (bool, Option<String>) = self.i().setactive.call((id, active)).map_err(lua_err)?;
            if ok { Ok(()) } else { Err(Error::Other(err.unwrap_or_else(|| "activation failed".into()))) }
        })
    }

    /// Runs the `createHotkey` function registered under `id`.
    pub fn fire_hotkey(&self, id: u32) -> Result<()> {
        self.call_internal(|i| &i.hotkey, id).map(|_| ())
    }

    /// Performs the action of hotkey `hotkey` of record `rec` (toggle, activate, set /
    /// increase / decrease value) with its OnHotkey / OnPostHotkey callbacks.
    pub fn fire_record_hotkey(&self, rec: RecId, hotkey: u32) -> Result<()> {
        self.call_internal(|i| &i.rechotkey, (rec, hotkey)).map(|_| ())
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
        self.call_internal(|i| &i.clear, false).map(|_| ())
    }

    /// Like [`Engine::clear_table_state`], for consent the user withdrew: everything goes
    /// without running any of it once more (no `OnDestroy` of records or forms), and a script
    /// running on another thread is interrupted first.
    pub fn stop_table_state(&self) -> Result<()> {
        self.st.interrupt.store(true, Ordering::SeqCst);
        self.call_internal(|i| &i.clear, true).map(|_| ())
    }

    /// Records refused since the last call because they lack the capabilities their script
    /// or callbacks need (see [`Caps`]): (record, message). Activation routes report these
    /// to the host this way, also when the refusal happened deep inside a group cascade,
    /// a hotkey or a script's `memrec.Active = true`.
    pub fn take_denied(&self) -> Vec<(RecId, String)> {
        std::mem::take(&mut *self.st.denied.lock().unwrap())
    }

    /// Delivers a user event to control `id` (`OnClick`, `OnClose`, `OnKeyPress`, `OnChange`,
    /// `OnDblClick`, `OnMouseDown`, ...): runs the script's handler with the control as the
    /// first argument followed by `args`, and returns what it returned. `OnClose` also applies
    /// the close action (hide or free). A control without a handler is not an error.
    pub fn fire_event(&self, id: ControlId, event: &str, args: &[Prop]) -> Result<Vec<Prop>> {
        self.reset_if_pending()?;
        let lua = self.lua();
        let mut a = MultiValue::new();
        a.push_back(Value::Integer(id as i64));
        a.push_back(event.into_lua(&lua).map_err(lua_err)?);
        for p in args {
            a.push_back(p.clone().into_lua(&lua).map_err(lua_err)?);
        }
        let r = self.call_internal(|i| &i.uievent, a)?;
        Ok(r.iter().map(Prop::from_lua_value).collect())
    }

    /// The user changed a control (`Text` of an edit or memo, `Checked`, `ItemIndex`,
    /// `Position`, ...): stores the value without echoing it back to the UI host and fires the
    /// control's `OnChange` (checkboxes also `OnClick`) when it changed.
    pub fn ui_input(&self, id: ControlId, prop: &str, value: Prop) -> Result<()> {
        self.reset_if_pending()?;
        let v = value.into_lua(&self.lua()).map_err(lua_err)?;
        self.call_internal(|i| &i.uiinput, (id, prop.to_string(), v)).map(|_| ())
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
            let lua = self.lua();
            debug::write_context(&lua, &ev.context).map_err(lua_err)?;
            let r = self.call(self.i().breakpoint.clone(), (ev.address as i64, ev.thread_id).into_lua_multi(&lua).map_err(lua_err)?);
            let resume = match r.as_ref().ok().and_then(|v| v.front()) {
                Some(Value::Boolean(b)) => *b,
                Some(Value::Integer(i)) => *i != 0,
                Some(Value::Number(n)) => *n != 0.0,
                _ => false,
            };
            let ctx = debug::read_context(&lua, &ev.context);
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

    /// Calls an internal prelude function of the CURRENT state (`which` picks it once a
    /// pending reset is done).
    fn call_internal(&self, which: impl FnOnce(&Internals) -> &Function, args: impl mlua::IntoLuaMulti) -> Result<MultiValue> {
        self.entry(|| {
            let core = self.core();
            let args = args.into_lua_multi(&core.lua).map_err(lua_err)?;
            self.call(which(&core.i).clone(), args)
        })
    }

    /// [`Engine::aa_hooks_check_only_with`] without capabilities (the safe default: the
    /// caller did not say the script is trusted).
    pub fn aa_hooks_check_only(&self) -> AaHooks {
        self.aa_hooks_check_only_with(Caps::None)
    }

    /// Hooks for `hh_asm::aa_check` that run NO Lua at all, for live syntax checks while the
    /// user types. With [`Caps::Full`]: `{$lua}` blocks yield an empty string, custom
    /// commands registered with `registerAutoAssemblerCommand` expand to nothing, prologues
    /// are skipped, and while a `registerSymbolLookupCallback` is registered an otherwise
    /// unknown symbol resolves to a placeholder address; `loadbinary` is accepted when OS
    /// access is on (checking never reads the file). With [`Caps::None`] each of those is an
    /// error naming `hh_asm::NOT_AVAILABLE`.
    pub fn aa_hooks_check_only_with(&self, caps: Caps) -> AaHooks {
        hooks::for_caps(&self.lua(), &self.st, None, hooks::Mode::CheckNoLua, caps)
    }

    /// Hooks for `hh_asm::aa_execute` / `aa_check` so `{$lua}` blocks and `luacall` run in
    /// this engine, with the `syntaxcheck` and `memrec` globals set like Cheat Engine does,
    /// plus what scripts registered: `registerAutoAssemblerCommand` commands,
    /// `registerAutoAssemblerPrologue` prologues and `registerSymbolLookupCallback` lookups
    /// (all of them told `syntax_check`). `loadbinary` reads files only with
    /// [`EngineOptions::allow_os`] and when [`Host::allow_aa_file`] agrees. `aob_unique` is
    /// left at its default for the host to set.
    ///
    /// Capabilities: those [`TableHost::caps`] gives `memrec`, and none without a record
    /// (the safe default). Say what the script may do with [`Engine::aa_hooks_with`].
    pub fn aa_hooks(&self, memrec: Option<RecId>, syntax_check: bool) -> AaHooks {
        let caps = memrec.map_or(Caps::None, |id| self.st.table().caps(id));
        self.aa_hooks_with(memrec, syntax_check, caps)
    }

    /// [`Engine::aa_hooks`] with the capabilities stated: `Caps::Full` only for a script the
    /// host knows the user typed or agreed to.
    pub fn aa_hooks_with(&self, memrec: Option<RecId>, syntax_check: bool, caps: Caps) -> AaHooks {
        let mode = if syntax_check { hooks::Mode::Check } else { hooks::Mode::Run };
        hooks::for_caps(&self.lua(), &self.st, memrec, mode, caps)
    }

    /// Code of `owners` is about to run in this interpreter (the host runs a table script or a
    /// record's Lua with capabilities): it joins the contamination set before it runs.
    pub fn add_owners(&self, owners: &[Owner]) {
        self.st.contam.lock().unwrap().extend(owners.iter().copied());
    }

    /// The consent principals whose code has run in this interpreter since it was created (or
    /// reset), sorted. Everything Lua creates or scripts here depends on all of them.
    pub fn contamination(&self) -> Vec<Owner> {
        self.st.contam.lock().unwrap().iter().copied().collect()
    }

    /// Whether `registerSymbolLookupCallback` functions are registered: a script run without
    /// capabilities that failed may have needed them (they were not asked).
    pub fn has_symbol_lookup(&self) -> bool {
        hooks::has_symbol_lookup(&self.st)
    }

    /// The `registerAddressLookupCallback` functions as a disassembler naming hook (put it in
    /// `hh_asm::DisasmOptions::address_name`); `None` while none is registered. Each call
    /// enters the engine (waits for a running script).
    pub fn address_name(&self) -> Option<AddressName> {
        hooks::address_name(&self.lua(), &self.st)
    }

    /// The `registerSymbolLookupCallback` functions as a lookup for
    /// `hh_asm::resolve_address_with`; `None` while none is registered. Each call enters the
    /// engine.
    pub fn symbol_lookup(&self) -> Option<SymbolLookup> {
        hooks::symbol_lookup_opt(&self.lua(), &self.st)
    }

    /// `registerStructureDissectOverride`: the structure the first override that took care
    /// of `addr` filled (for `hh_tools::structure::StructOverride`, e.g.
    /// `|a, s| engine.structure_override(a, s)`). An unnamed one is named by
    /// [`Engine::structure_name`], else `Structure_<addr>`. `None`: guess as usual.
    pub fn structure_override(&self, addr: Addr, size: usize) -> Option<hh_tools::structure::Structure> {
        hooks::structure_override(&self.lua(), &self.st, addr, size)
    }

    /// `registerStructureNameLookup`: the name the first callback gives for a structure at
    /// `addr`, and the base address it suggests instead of `addr` (if any).
    pub fn structure_name(&self, addr: Addr) -> Option<(String, Option<Addr>)> {
        hooks::structure_name(&self.lua(), &self.st, addr)
    }
}
