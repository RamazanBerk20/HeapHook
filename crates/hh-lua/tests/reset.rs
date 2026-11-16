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
-- The string metatable is locked: replacing its __index is refused.
assert(not pcall(function() getmetatable('').__index = function(s, k) mark() return string[k] end end))
string.upper = function(s) mark() return s end
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

/// No metatable a script can reach is handed out: library values (files, strings, every
/// other type, host userdata and errors) give false or nil from `getmetatable`, the `FILE*`
/// metatable is not reachable through `__index` either, and a finalizer cannot be put on it.
#[test]
fn library_metatables_are_locked() {
    let (e, _p, _rec, _ui, _dbg) = setup();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("f.txt");
    let marker = dir.path().join("fin");
    let code = format!(
        r#"
        local f = io.open({path:?}, 'w')
        local p = io.popen('true')
        local okaa, aa = autoAssemble('[ENABLE]\n[DISABLE]\n')
        local _, herr = pcall(readInteger, {{}})
        local vals = {{ io.stdout, io.stdin, io.stderr, f, p, '', 'x', 1, 1.5, true, false, nil, print, readInteger,
          coroutine.create(function() end), coroutine.running(), string, io, os, table, math, coroutine, package, utf8,
          package.loaded, type(aa) == 'table' and rawget(aa, '__state') or nil, herr, io.lines }}
        local bad = {{}}
        for i = 1, 28 do
          local m = getmetatable(vals[i])
          if type(m) == 'table' then bad[#bad + 1] = i .. ':' .. type(vals[i]) end
        end
        -- The FILE* metatable is not the files' __index any more; nothing to write a __gc into.
        local idx = {{ type(io.stdout.__index), type(f.__index), type(f.__gc), type(f.__metatable), type(('').__index) }}
        local w = function() local h = io.open({marker:?}, 'a') h:write('ran') h:close() end
        local r = {{}}
        r[#r + 1] = tostring(pcall(function() getmetatable(io.stdout).__gc = w end))
        r[#r + 1] = tostring(pcall(function() rawset(getmetatable(io.stdout), '__gc', w) end))
        r[#r + 1] = tostring(pcall(function() io.stdout.__index.__gc = w end))
        r[#r + 1] = tostring(pcall(function() io.stdout.__gc = w end))
        r[#r + 1] = tostring(pcall(function() getmetatable('').__index = {{}} end))
        r[#r + 1] = tostring(pcall(function() getmetatable('').__gc = w end))
        r[#r + 1] = tostring(pcall(setmetatable, io.stdout, {{}}))
        r[#r + 1] = tostring(pcall(setmetatable, '', {{}}))
        r[#r + 1] = tostring(debug.setmetatable) .. tostring(debug.getmetatable) .. tostring(debug.getregistry) .. tostring(debug.getuservalue)
        f:close() p:close()
        for _ = 1, 3 do io.open({path:?}, 'r') end
        collectgarbage('collect') collectgarbage('collect')
        return table.concat(bad, ','), table.concat(idx, ','), table.concat(r, ','), okaa
        "#
    );
    let out = e.exec(&code, "probe").unwrap();
    assert_eq!(out[0], "", "values with a reachable metatable: {}", out[0]);
    assert_eq!(out[1], "nil,nil,nil,nil,nil", "__index / __gc / __metatable reachable through a value");
    assert_eq!(out[2], "false,false,false,false,false,false,false,false,nilnilnilnil", "{out:?}");
    assert_eq!(out[3], "true");
    assert!(!marker.exists(), "a Lua finalizer ran");
    // And across a reset (the old state's files are closed then).
    e.add_owners(&[hh_lua::Owner::Table(77)]);
    e.reset().unwrap();
    e.reset().unwrap();
    std::thread::sleep(Duration::from_millis(200));
    assert!(!marker.exists(), "a Lua finalizer ran at the reset");
}

/// Locking changes nothing for scripts: string methods and file I/O work as before.
#[test]
fn string_methods_and_file_io_still_work() {
    let (e, _p, _rec, _ui, _dbg) = setup();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("io.txt");
    let code = format!(
        r#"
        local f = assert(io.open({path:?}, 'w')) f:write('a\nb\n') f:close()
        local g = assert(io.open({path:?}, 'r')) local all = g:read('a') g:close()
        local n = 0 local h = io.open({path:?}) for l in h:lines() do n = n + 1 end h:close()
        local m = 0 for l in io.lines({path:?}) do m = m + #l end
        local p = io.popen('echo hi') local o = p:read('l') local st = p:close()
        local s = ('x'):upper() .. ('%d'):format(7) .. ('abc'):sub(2) .. #('xyz'):rep(2) .. string.format('%s', 'q')
        return s, all, n, m, o, tostring(st), io.type(f), io.type(io.stdout), tostring(io.stdout):sub(1, 4)
        "#
    );
    let out = e.exec(&code, "io").unwrap();
    assert_eq!(out, ["X7bc6q", "a\nb\n", "2", "2", "hi", "true", "closed file", "file", "file"]);
}
