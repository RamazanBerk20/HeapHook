//! `Engine::reset`: withdrawing consent discards the interpreter. Nothing a script defined
//! survives, every external resource it held is released, the hosts stay bound, and a reset
//! asked for from inside the engine (or while another thread runs Lua) neither deadlocks nor
//! frees a state in use.
mod common;

use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use common::*;
use hh_core::{Addr, Result};
use hh_lua::{BreakpointSpec, DebugHost, Engine, EngineOptions, Host, UiChange, UiHost};

#[derive(Default)]
struct Rec {
    out: Mutex<Vec<String>>,
    hotkeys: Mutex<Vec<u32>>,
    unregistered: Mutex<Vec<u32>>,
    engine: OnceLock<Engine>,
}
impl Host for Rec {
    fn print(&self, t: &str) {
        self.out.lock().unwrap().push(t.into());
    }
    fn register_hotkey(&self, id: u32, _keys: &[i64]) -> Result<()> {
        self.hotkeys.lock().unwrap().push(id);
        Ok(())
    }
    fn unregister_hotkey(&self, id: u32) {
        self.unregistered.lock().unwrap().push(id);
    }
    /// Stands in for the app: `loadTable(f)` replaces the table, so it resets the engine
    /// from inside a script.
    fn load_table(&self, _path: &str, _merge: bool) -> Result<()> {
        self.engine.get().unwrap().reset()
    }
}
#[derive(Default)]
struct Ui(Mutex<Vec<UiChange>>);
impl UiHost for Ui {
    fn changed(&self, c: &UiChange) {
        self.0.lock().unwrap().push(c.clone());
    }
}
#[derive(Default)]
struct Dbg(Mutex<Vec<Addr>>);
impl DebugHost for Dbg {
    fn is_debugging(&self) -> bool {
        true
    }
    fn set_breakpoint(&self, _bp: &BreakpointSpec) -> Result<()> {
        Ok(())
    }
    fn remove_breakpoint(&self, a: Addr) -> Result<()> {
        self.0.lock().unwrap().push(a);
        Ok(())
    }
}

fn setup() -> (Engine, Arc<TestProc>, Arc<Rec>, Arc<Ui>, Arc<Dbg>) {
    let e = Engine::new(EngineOptions::default()).unwrap();
    let p = game();
    e.set_process(Some(p.clone())).unwrap();
    let rec = Arc::new(Rec::default());
    let _ = rec.engine.set(e.clone());
    e.set_host(rec.clone());
    let ui = Arc::new(Ui::default());
    e.set_ui_host(ui.clone());
    let dbg = Arc::new(Dbg::default());
    e.set_debug_host(dbg.clone());
    (e, p, rec, ui, dbg)
}

/// What a once-trusted table leaves behind to run later, by name or by trap.
const POISON: &str = r#"
marks = 0
local rawprint = print
local function mark() marks = marks + 1 rawprint('poison') end
local raw_tostring = tostring
tostring = function(...) mark() return raw_tostring(...) end
getmetatable('').__index = function(s, k) mark() return string[k] end
function debugger_onBreakpoint() mark() return 1 end
function onOpenProcess() mark() end
package.loaded.string = { format = function() mark() return '' end }
setmetatable(_G, { __index = function(_, k) mark() end, __newindex = function(t, k, v) mark() rawset(t, k, v) end })
print = function(...) mark() end
pcall = function(f, ...) mark() return true end
parked = coroutine.create(function() while true do coroutine.yield(mark()) end end)
coroutine.resume(parked)
createThread(function(t) while true do mark() sleep(1) end end)
tm = createTimer(nil) tm.Interval = 1 tm.OnTimer = mark
hk = createHotkey(mark, VK_CONTROL, VK_F9)
f = createForm() f.OnDestroy = mark
debug_setBreakpoint(0x1234, mark)
registerAutoAssemblerCommand('mycmd', function() mark() return '' end)
"#;

#[test]
fn reset_discards_everything_the_script_defined_and_releases_its_resources() {
    let (e, _p, rec, ui, dbg) = setup();
    e.exec(POISON, "table").unwrap();
    assert!(!rec.hotkeys.lock().unwrap().is_empty());
    rec.out.lock().unwrap().clear();
    e.reset().unwrap();
    // Released: hotkeys unregistered, forms destroyed (the UI host heard), breakpoints removed.
    assert_eq!(*rec.unregistered.lock().unwrap(), *rec.hotkeys.lock().unwrap());
    assert!(ui.0.lock().unwrap().iter().any(|c| matches!(c, UiChange::Destroy { .. })), "forms not destroyed");
    assert!(e.ui_snapshot().roots.is_empty());
    assert_eq!(*dbg.0.lock().unwrap(), [0x1234]);
    assert!(!e.has_symbol_lookup());
    // Gone: nothing of it runs on any by-name or trap route.
    std::thread::sleep(Duration::from_millis(20));
    e.tick().unwrap();
    assert_eq!(e.exec("return 1 + 1, ('x'):upper(), string.format('%d', 7)", "console").unwrap(), ["2", "X", "7"]);
    assert_eq!(e.exec("return marks, debugger_onBreakpoint, onOpenProcess, parked, getmetatable(_G)", "console").unwrap(), ["nil", "nil", "nil", "nil", "nil"]);
    let r = e.on_breakpoint(&hh_lua::BreakEvent { address: 0x1234, thread_id: 1, context: Default::default() }).unwrap();
    assert!(!r.resume);
    e.exec("print('fresh')", "console").unwrap();
    assert_eq!(*rec.out.lock().unwrap(), ["fresh"], "only the new state printed; the old one's finalizers ran nothing");
}

#[test]
fn reset_keeps_the_hosts_and_the_process() {
    let (e, p, rec, _ui, _dbg) = setup();
    e.exec("x = 1", "c").unwrap();
    e.reset().unwrap();
    assert_eq!(e.exec(&format!("return x, readInteger({:#x}), process", GAME + 0x3020), "c").unwrap()[..2], ["nil", "42"]);
    e.exec("print('hi')", "c").unwrap();
    assert_eq!(rec.out.lock().unwrap().last().unwrap(), "hi");
    let _ = p;
}

/// `loadTable` inside a script resets from inside the engine: deferred to the outermost
/// exit; the rest of that script does nothing.
#[test]
fn reset_from_inside_a_script_is_deferred_and_refuses_the_rest() {
    let (e, _p, rec, _ui, _dbg) = setup();
    let r = e.exec("left = 1 loadTable('next.CT') print('after') left = 2", "c");
    let err = r.unwrap_err().to_string();
    assert!(err.contains("stopped"), "{err}");
    assert!(!rec.out.lock().unwrap().iter().any(|l| l == "after"));
    assert_eq!(e.exec("return left", "c").unwrap(), ["nil"], "the state was not replaced");
}

/// Another thread is running Lua: it is interrupted, then the reset happens.
#[test]
fn reset_while_another_thread_runs_lua() {
    let (e, _p, _rec, _ui, _dbg) = setup();
    e.set_budget(None);
    let e2 = e.clone();
    let t = std::thread::spawn(move || e2.exec("busy = true while true do end", "loop"));
    std::thread::sleep(Duration::from_millis(100));
    e.reset().unwrap();
    let r = t.join().unwrap();
    assert!(r.is_err());
    assert_eq!(e.exec("return busy", "c").unwrap(), ["nil"]);
}

/// No finalizer of a discarded interpreter ever runs: the state is never closed (finalizers run
/// on close, with hooks off) and its collector is stopped. Objects with `__gc` are made from
/// Rust here (scripts cannot make them, see below), kept alive in a global, in an upvalue of a
/// registered callback and in the registry, then the engine is reset and the old handles go.
#[test]
fn finalizers_of_a_discarded_state_never_run() {
    let (e, _p, rec, _ui, _dbg) = setup();
    let lua = e.lua();
    // Not a host function (those refuse once discarded): like a captured `io.open`.
    let ran = Arc::new(Mutex::new(0));
    let r2 = ran.clone();
    let fin = lua.create_function(move |_, ()| {
        *r2.lock().unwrap() += 1;
        Ok(())
    }).unwrap();
    let make = || {
        let t = lua.create_table().unwrap();
        let mt = lua.create_table().unwrap();
        mt.set("__gc", fin.clone()).unwrap();
        t.set_metatable(Some(mt)).unwrap();
        t
    };
    lua.globals().set("held", make()).unwrap();
    lua.globals().set("keep", make()).unwrap();
    e.exec("local k = keep keep = nil tm = createTimer(nil) tm.OnTimer = function() return k end", "table").unwrap();
    lua.set_named_registry_value("hh_test_held", make()).unwrap();
    drop(make());
    drop(lua);
    rec.out.lock().unwrap().clear();
    // A table's code ran in it: it is kept, not closed.
    e.add_owners(&[hh_lua::Owner::Table(1)]);
    e.reset().unwrap();
    e.exec("collectgarbage() collectgarbage()", "console").unwrap();
    assert!(rec.out.lock().unwrap().is_empty(), "{:?}", rec.out.lock().unwrap());
    assert_eq!(*ran.lock().unwrap(), 0, "a finalizer of the discarded state ran");
}

/// Scripts cannot install finalizers: `setmetatable` refuses `__gc`, adding it to a metatable
/// later does not register one (Lua 5.3), host userdata metatables are protected, and there
/// is no `debug.setmetatable`.
#[test]
fn scripts_cannot_install_finalizers() {
    let (e, _p, rec, _ui, _dbg) = setup();
    let err = e.exec("setmetatable({}, { __gc = function() print('gc') end })", "c").unwrap_err().to_string();
    assert!(err.contains("__gc finalizers are not available"), "{err}");
    e.exec("local mt = {} x = setmetatable({}, mt) mt.__gc = function() print('gc') end x = nil collectgarbage() collectgarbage()", "c").unwrap();
    assert_eq!(e.exec("local ok, t = autoAssemble('[ENABLE]\\n[DISABLE]\\n') return getmetatable(t.__state), debug.setmetatable, debug.getregistry", "c").unwrap(), ["false", "nil", "nil"]);
    assert!(!rec.out.lock().unwrap().iter().any(|l| l == "gc"));
}

/// A clean interpreter (only the user's own code ran) is closed (in the background), not kept.
#[test]
fn a_clean_reset_keeps_nothing() {
    let e = Engine::new(EngineOptions { max_parked: 1000, ..EngineOptions::default() }).unwrap();
    let marker = Arc::new(Mutex::new(0));
    let m2 = marker.clone();
    let lua = e.lua();
    // A finalizer from Rust in a clean state runs at close: proof it was closed.
    let fin = lua.create_function(move |_, ()| {
        *m2.lock().unwrap() += 1;
        Ok(())
    }).unwrap();
    let t = lua.create_table().unwrap();
    let mt = lua.create_table().unwrap();
    mt.set("__gc", fin).unwrap();
    t.set_metatable(Some(mt)).unwrap();
    lua.globals().set("x", t).unwrap();
    drop(lua);
    e.exec("y = 1", "console").unwrap();
    e.reset().unwrap();
    // Closed on the reaper thread, off the reset path.
    let t = std::time::Instant::now();
    while *marker.lock().unwrap() == 0 && t.elapsed() < std::time::Duration::from_secs(3) {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert_eq!(*marker.lock().unwrap(), 1, "the clean state was not closed");
}

/// Beyond the cap the oldest kept interpreter is closed; even then its host functions refuse
/// (a finalizer that slipped through reaches nothing of HeapHook).
#[test]
fn the_cap_closes_the_oldest_and_its_host_functions_refuse() {
    let (_, _p, rec, _ui, _dbg) = setup();
    let e = Engine::new(EngineOptions { max_parked: 3, ..EngineOptions::default() }).unwrap();
    e.set_host(rec.clone());
    let lua = e.lua();
    // The prelude's `print` (a host function) as a finalizer, put there from Rust.
    let t = lua.create_table().unwrap();
    let mt = lua.create_table().unwrap();
    mt.set("__gc", lua.globals().get::<mlua::Function>("print").unwrap()).unwrap();
    t.set_metatable(Some(mt)).unwrap();
    lua.globals().set("held", t).unwrap();
    drop(lua);
    rec.out.lock().unwrap().clear();
    for i in 0..6 {
        e.add_owners(&[hh_lua::Owner::Table(i)]);
        e.reset().unwrap();
        assert!(hh_lua::parked_stats().0 <= 3 + 3, "{:?}", hh_lua::parked_stats());
    }
    e.add_owners(&[hh_lua::Owner::Table(9)]);
    e.reset().unwrap();
    // (+1: a test running alongside may have kept one since)
    assert!(hh_lua::parked_stats().0 <= 4, "the cap: {:?}", hh_lua::parked_stats());
    // Closes run on the reaper thread: give them time before looking.
    std::thread::sleep(std::time::Duration::from_millis(300));
    assert!(rec.out.lock().unwrap().is_empty(), "a closed state's finalizer reached the host: {:?}", rec.out.lock().unwrap());
}
