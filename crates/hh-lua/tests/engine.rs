//! Engine-level behaviour: the execution budget (per entry, across threads, not catchable),
//! clearing per-table state on a table switch, and debugger callbacks through a fake
//! `DebugHost`.
mod common;

use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use common::*;
use hh_core::{Addr, Result};
use hh_lua::{
    BreakEvent, BreakpointSpec, BpMethod, BpTrigger, ContinueMode, DebugHost, Engine, EngineOptions, Host, MemTable, RegContext,
    TableHost, UiChange, UiHost,
};

#[test]
fn budget_cannot_be_caught() {
    let (e, _, _) = engine();
    e.set_budget(Some(Duration::from_millis(150)));
    for (name, src) in [
        ("pcall", "while true do pcall(function() while true do end end) end"),
        ("xpcall", "while true do xpcall(function() while true do end end, function(m) return m end) end"),
        ("coroutine", "while true do coroutine.resume(coroutine.create(function() while true do end end)) end"),
        ("coroutine.wrap", "while true do pcall(coroutine.wrap(function() while true do end end)) end"),
        ("nested coroutine", "while true do coroutine.resume(coroutine.create(function() while true do pcall(function() while true do end end) end end)) end"),
        ("pcall sleep", "while true do pcall(sleep, 10000) end"),
        ("swallow", "local ok = pcall(function() while true do end end) return 'escaped'"),
        ("error handler", "while true do pcall(error, setmetatable({}, {__tostring = function() while true do end end})) end"),
    ] {
        let t = Instant::now();
        let err = e.exec(src, name).unwrap_err().to_string();
        assert!(err.contains("time budget"), "{name}: {err}");
        assert!(t.elapsed() < Duration::from_secs(3), "{name} ran {:?}", t.elapsed());
    }
    // a timer catching the abort in a loop is stopped as well
    run(&e, "t = createTimer() t.Interval = 1 t.OnTimer = function() while true do pcall(function() while true do end end) end end");
    std::thread::sleep(Duration::from_millis(5));
    assert!(e.tick().unwrap_err().to_string().contains("time budget"));
    run(&e, "t.destroy()");
    // interrupts cannot be caught either
    e.set_budget(None);
    let h = e.interrupt_handle();
    let stopper = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        h.interrupt();
    });
    let err = e.exec("while true do pcall(function() while true do end end) end", "int").unwrap_err().to_string();
    stopper.join().unwrap();
    assert!(err.contains("interrupted"), "{err}");
    assert_eq!(run(&e, "return pcall(error, 'normal errors are still caught')"), ["false", "normal errors are still caught"]);
}

#[test]
fn budget_is_per_entry_across_threads() {
    let (e, _, _) = engine();
    e.set_budget(Some(Duration::from_millis(400)));
    let e2 = e.clone();
    let a = std::thread::spawn(move || e2.exec("sleep(300)", "a"));
    std::thread::sleep(Duration::from_millis(150));
    // B queues behind A; with a shared deadline its own 300 ms would overrun A's budget.
    let b = e.exec("sleep(300) return 'b ok'", "b");
    assert!(a.join().unwrap().is_ok());
    assert_eq!(b.unwrap(), ["b ok"]);
    // An interrupt aimed at A does not leak into B.
    let e3 = e.clone();
    let h = e.interrupt_handle();
    let a = std::thread::spawn(move || e3.exec("while true do end", "spin"));
    std::thread::sleep(Duration::from_millis(50));
    h.interrupt();
    assert!(a.join().unwrap().unwrap_err().to_string().contains("interrupted"));
    assert_eq!(run(&e, "return 1"), ["1"]);
}

/// A host whose `print` re-enters the engine (nested entry on the same thread).
#[derive(Default)]
struct Reenter {
    engine: OnceLock<Engine>,
    out: Mutex<Vec<String>>,
}
impl Host for Reenter {
    fn print(&self, text: &str) {
        if text == "nest" {
            let r = self.engine.get().unwrap().exec("return depth_marker", "inner").unwrap();
            self.out.lock().unwrap().push(r.join(","));
        }
    }
}

#[test]
fn nested_entries_share_the_outer_budget() {
    let e = Engine::new(EngineOptions { budget: Some(Duration::from_millis(300)), ..Default::default() }).unwrap();
    let h = Arc::new(Reenter::default());
    h.engine.set(e.clone()).ok();
    e.set_host(h.clone());
    run(&e, "depth_marker = 'inner ran' print('nest')");
    assert_eq!(*h.out.lock().unwrap(), ["inner ran"]);
    // The inner entry does not re-arm the budget: outer work plus inner work is limited.
    let t = Instant::now();
    let err = e.exec("sleep(200) print('nest') sleep(200)", "outer").unwrap_err().to_string();
    assert!(err.contains("time budget") && t.elapsed() < Duration::from_millis(1500), "{err}");
}

#[derive(Default)]
struct Hk {
    reg: Mutex<Vec<u32>>,
    unreg: Mutex<Vec<u32>>,
}
impl Host for Hk {
    fn register_hotkey(&self, id: u32, _keys: &[i64]) -> Result<()> {
        self.reg.lock().unwrap().push(id);
        Ok(())
    }
    fn unregister_hotkey(&self, id: u32) {
        self.unreg.lock().unwrap().push(id);
    }
}

#[derive(Default)]
struct UiLog(Mutex<Vec<UiChange>>);
impl UiHost for UiLog {
    fn changed(&self, c: &UiChange) {
        self.0.lock().unwrap().push(c.clone());
    }
}

#[derive(Default)]
struct FakeDebug {
    set: Mutex<Vec<BreakpointSpec>>,
    removed: Mutex<Vec<Addr>>,
    continued: Mutex<Vec<(u32, ContinueMode, Option<RegContext>)>>,
    started: Mutex<Option<i64>>,
}
impl DebugHost for FakeDebug {
    fn start(&self, i: i64) -> Result<()> {
        *self.started.lock().unwrap() = Some(i);
        Ok(())
    }
    fn is_debugging(&self) -> bool {
        self.started.lock().unwrap().is_some() || !self.set.lock().unwrap().is_empty()
    }
    fn set_breakpoint(&self, bp: &BreakpointSpec) -> Result<()> {
        self.set.lock().unwrap().push(bp.clone());
        Ok(())
    }
    fn remove_breakpoint(&self, a: Addr) -> Result<()> {
        self.removed.lock().unwrap().push(a);
        Ok(())
    }
    fn continue_from_breakpoint(&self, tid: u32, mode: ContinueMode, ctx: Option<&RegContext>) -> Result<()> {
        self.continued.lock().unwrap().push((tid, mode, ctx.copied()));
        Ok(())
    }
}

#[test]
fn table_switch_clears_per_table_state() {
    let (e, _, _) = engine();
    let hk = Arc::new(Hk::default());
    e.set_host(hk.clone());
    let ui = Arc::new(UiLog::default());
    e.set_ui_host(ui.clone());
    let dbg = Arc::new(FakeDebug::default());
    e.set_debug_host(dbg.clone());
    let t1 = Arc::new(MemTable::new());
    e.set_table(t1.clone());
    run(
        &e,
        r#"
        ticks, activations, destroyed, threadsteps = 0, 0, 0, 0
        local r = getAddressList().createMemoryRecord()
        r.Address = 'game.exe+3020'
        r.OnActivate = function() activations = activations + 1 end
        r.OnDestroy = function() destroyed = destroyed + 1 end
        t = createTimer() t.Interval = 1 t.OnTimer = function() ticks = ticks + 1 end
        createThread(function() while true do threadsteps = threadsteps + 1 sleep(1) end end)
        createHotkey(function() end, VK_F5)
        f = createForm()
        createButton(f).Caption = 'old'
        debug_setBreakpoint('game.exe+1005', function() return 1 end)
        ms = createMemScan()
    "#,
    );
    std::thread::sleep(Duration::from_millis(5));
    e.tick().unwrap();
    assert_eq!(run(&e, "return ticks > 0, threadsteps > 0"), ["true", "true"]);

    // Switch tables: the new one reuses record id 1.
    let t2 = Arc::new(MemTable::new());
    let id = t2.create(None);
    let mut r = t2.get(id).unwrap();
    r.address = "game.exe+3020".into();
    t2.set(r).unwrap();
    e.set_table(t2.clone());
    e.clear_table_state().unwrap();

    assert_eq!(*hk.unreg.lock().unwrap(), *hk.reg.lock().unwrap(), "hotkeys unregistered");
    assert_eq!(*dbg.removed.lock().unwrap(), [GAME + 0x1005]);
    assert!(e.ui_snapshot().roots.is_empty());
    assert!(ui.0.lock().unwrap().iter().any(|c| matches!(c, UiChange::Destroy { .. })));
    run(&e, "ticks, threadsteps = 0, 0");
    std::thread::sleep(Duration::from_millis(5));
    e.tick().unwrap();
    e.set_active(id, true).unwrap();
    assert_eq!(
        run(&e, "return ticks, threadsteps, activations, destroyed, debug_getBreakpointList()[1], getFormCount()"),
        ["0", "0", "0", "1", "nil", "0"]
    );
    assert!(e.exec("ms.firstScan(soExactValue, vtDword, rtRounded, '1')", "x").unwrap_err().to_string().contains("destroyed"));
    // Globals stay.
    assert_eq!(run(&e, "return type(f)"), ["table"]);
}

#[test]
fn debugger_callbacks_through_fake_host() {
    let (e, _, _) = engine();
    // Without a debug host: clear errors.
    let err = e.exec("debugProcess()", "x").unwrap_err().to_string();
    assert!(err.contains("no debugger"), "{err}");
    assert_eq!(run(&e, "return debug_isDebugging(), debug_isBroken(), #debug_getBreakpointList()"), ["false", "false", "0"]);

    let dbg = Arc::new(FakeDebug::default());
    e.set_debug_host(dbg.clone());
    run(
        &e,
        r#"
        assert(debugProcess(2))
        assert(debug_isDebugging())
        hits = {}
        debug_setBreakpoint('game.exe+1005', function()
          hits[#hits + 1] = string.format('%X', RIP)
          RAX = RAX + 1   -- 64-bit name wins
          EBX = 0x12345678 -- 32-bit name replaces (zero-extends)
          return 1
        end)
        debug_setBreakpoint(0x20000088, 4, bptWrite, function() hits[#hits + 1] = 'write ' .. EAX; return 0 end)
        debug_setBreakpoint('game.exe+1011', 1, bptExecute, bpmInt3)
        local l = debug_getBreakpointList()
        assert(#l == 3)
    "#,
    );
    let set = dbg.set.lock().unwrap().clone();
    assert_eq!(set[0], BreakpointSpec { address: GAME + 0x1005, size: 1, trigger: BpTrigger::Execute, method: BpMethod::DebugRegister });
    assert_eq!(set[1].trigger, BpTrigger::Write);
    assert_eq!(set[1].size, 4);
    assert_eq!(set[2].method, BpMethod::Int3);

    let ctx = RegContext { rax: 0xFFFF_FFFF_0000_0001, rbx: 0xAAAA_AAAA_BBBB_BBBB, rip: GAME + 0x1005, ..Default::default() };
    let r = e.on_breakpoint(&BreakEvent { thread_id: 7, address: GAME + 0x1005, context: ctx }).unwrap();
    assert!(r.resume);
    let c = r.context.unwrap();
    assert_eq!((c.rax, c.rbx), (0xFFFF_FFFF_0000_0002, 0x1234_5678));
    assert_eq!(run(&e, "return hits[1], debug_isBroken()"), ["140001005", "false"]);

    // Returning 0 keeps the thread broken; the script continues it later.
    let ctx = RegContext { rax: 5, rip: GAME + 0x1011, ..Default::default() };
    let r = e.on_breakpoint(&BreakEvent { thread_id: 9, address: 0x2000_0088, context: ctx }).unwrap();
    assert!(!r.resume && r.context.is_none());
    run(
        &e,
        r#"
        assert(hits[2] == 'write 5' and debug_isBroken())
        RCX = 99          -- not applied until debug_setContext
        debug_getContext()
        assert(RCX == 0 and RAX == 5)
        RCX = 0x77
        debug_setContext()
        assert(debug_continueFromBreakpoint(co_stepover))
        assert(not debug_isBroken())
        assert(debug_continueFromBreakpoint() == false, 'nothing to continue')
    "#,
    );
    let cont = dbg.continued.lock().unwrap().clone();
    assert_eq!(cont.len(), 1);
    assert_eq!((cont[0].0, cont[0].1), (9, ContinueMode::StepOver));
    assert_eq!(cont[0].2.unwrap().rcx, 0x77);

    // No function: debugger_onBreakpoint decides; without it the thread breaks.
    let ev = BreakEvent { thread_id: 1, address: GAME + 0x1011, context: RegContext::default() };
    assert!(!e.on_breakpoint(&ev).unwrap().resume);
    e.debug_resumed();
    run(&e, "function debugger_onBreakpoint() seen = RIP return 1 end");
    let ev = BreakEvent { thread_id: 1, address: GAME + 0x1011, context: RegContext { rip: 0x42, ..Default::default() } };
    assert!(e.on_breakpoint(&ev).unwrap().resume);
    assert_eq!(run(&e, "return seen"), ["66"]);
    // A failing function reports the error and does not resume.
    run(&e, "debug_setBreakpoint(0x1234, function() error('bp boom') end)");
    let ev = BreakEvent { thread_id: 1, address: 0x1234, context: RegContext::default() };
    assert!(e.on_breakpoint(&ev).unwrap_err().to_string().contains("bp boom"));
    e.debug_resumed();

    run(&e, "assert(debug_removeBreakpoint('game.exe+1005')) assert(#debug_getBreakpointList() == 3)");
    assert_eq!(*dbg.removed.lock().unwrap(), [GAME + 0x1005]);
}

#[test]
fn hardening() {
    let (e, _, _) = engine();
    // Text chunks only, no string.dump.
    run(
        &e,
        r#"
        assert(string.dump == nil)
        local f, err = load('\27Lua\83\0\25\147\r\n\26\n')
        assert(f == nil and err:find('binary'), err)
        assert(load('return 1 + 1')() == 2)
        assert(load('return x', 'n', 'b', { x = 5 })() == 5, 'env kept, mode forced to text')
        y = 7
        assert(load('return y')() == 7, 'no env = globals')
        local ok, lerr = pcall(load('return x', 'n', 't', nil))
        assert(not ok, 'explicit nil env still means no globals')
    "#,
    );
    assert!(e.exec("\x1bLua\x53\x00", "bin").is_err());
    let dir = std::env::temp_dir().join(format!("hh-lua-bin-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("evilmod.lua"), b"\x1bLua\x53\x00\x19\x93\r\n\x1a\n").unwrap();
    std::fs::write(dir.join("goodmod.lua"), b"return { v = 3 }").unwrap();
    e.lua().globals().set("DIR", dir.display().to_string()).unwrap();
    run(
        &e,
        r#"
        package.path = DIR .. '/?.lua'
        assert(require('goodmod').v == 3)
        local ok, err = pcall(require, 'evilmod')
        assert(not ok and err:find('binary'), err)
        local f, lerr = loadfile(DIR .. '/evilmod.lua')
        assert(f == nil and lerr:find('binary'))
        assert(not pcall(dofile, DIR .. '/evilmod.lua'))
        assert(dofile(DIR .. '/goodmod.lua').v == 3)
        assert(package.loadlib == nil and #package.searchers == 2)
    "#,
    );
    std::fs::remove_dir_all(&dir).unwrap();

    // Multi-return cap; the table form has none.
    run(
        &e,
        r#"
        local ok, err = pcall(readBytes, 'game.exe', 9000)
        assert(not ok and err:find('table'), err)
        assert(#readBytes('game.exe', 9000, true) == 9000)
        assert(select('#', readBytes('game.exe', 8000)) == 8000)
    "#,
    );

    // sleep: no overflow or panic on odd values.
    e.set_budget(Some(Duration::from_millis(100)));
    assert!(e.exec("sleep(math.huge)", "s").unwrap_err().to_string().contains("time budget"));
    assert!(e.exec("sleep(1e300)", "s").unwrap_err().to_string().contains("time budget"));
    run(&e, "sleep(0/0) sleep(-math.huge) sleep(-5)");
}

#[test]
fn allow_os_false_blocks_own_memory() {
    let e = Engine::new(EngineOptions { allow_os: false, ..Default::default() }).unwrap();
    e.set_process(Some(game())).unwrap();
    let cell: &'static mut u32 = Box::leak(Box::new(5u32));
    let a = cell as *mut u32 as u64;
    run(
        &e,
        &format!(
            r#"
            assert(readIntegerLocal({a}) == nil and writeIntegerLocal({a}, 9) == false)
            assert(readBytesLocal({a}, 4) == nil and writeBytesLocal({a}, 1) == false)
            local ok, err = autoAssemble('[ENABLE]\n{a:X}:\ndd 9\n[DISABLE]\n', true)
            assert(ok == false and err:find('disabled'), err)
            local ok2, err2 = pcall(copyMemory, 'game.exe', 4, nil, 1)
            assert(not ok2 and err2:find('disabled'), err2)
            assert(readInteger('game.exe+3020') == 42, 'the target is still accessible')
        "#
        ),
    );
    assert_eq!(unsafe { std::ptr::read_volatile(a as *const u32) }, 5);
}

#[test]
fn memory_limit_is_a_script_error() {
    // Small limit: the test never allocates more than ~32 MiB.
    let e = Engine::new(EngineOptions { memory_limit: Some(32 << 20), ..Default::default() }).unwrap();
    let err = e.exec("local s = string.rep('x', 2^26)", "big").unwrap_err().to_string();
    assert!(err.contains("memory"), "{err}");
    let err = e.exec("local t = {} for i = 1, 1e8 do t[i] = i end", "grow").unwrap_err().to_string();
    assert!(err.contains("memory"), "{err}");
    assert_eq!(run(&e, "return pcall(string.rep, 'x', 2^26)")[0], "false");
    assert_eq!(run(&e, "collectgarbage() return 1 + 1"), ["2"]);
}

#[test]
fn check_only_hooks_do_not_run_lua() {
    let (e, p, _) = engine();
    let syms = e.symbols().lock().unwrap().clone();
    let script = "[ENABLE]\n{$lua}\nran = true\n{$asm}\n[DISABLE]\n";
    assert_eq!(hh_asm::aa_check(&*p, &syms, script, &mut e.aa_hooks_check_only_with(hh_lua::Caps::Full)), None);
    assert_eq!(run(&e, "return ran"), ["nil"]);
    // the executing hooks still run it
    assert_eq!(hh_asm::aa_check(&*p, &syms, script, &mut e.aa_hooks_with(None, true, hh_lua::Caps::Full)), None);
    assert_eq!(run(&e, "return ran"), ["true"]);
}
