//! The app's Lua engine (hh-lua): one per app, bound to the current process through the
//! session's `Switch` (so it follows debugger attach/detach), with the console log, the
//! dialogs scripts open, `createHotkey` registrations, and the background driver that calls
//! `tick()`, applies group cascades, re-syncs the freezer and keeps global hotkeys registered.
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::SeqCst};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use hh_core::Result as HResult;
use hh_lua::{Engine, EngineOptions, Host};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::cheat::Live;
use crate::commands::{App, R, lock};

const LOG_CAP: usize = 2000;
const TICK: Duration = Duration::from_millis(20);
/// Pointer entries can move; the frozen set is re-resolved this often even without changes.
const FREEZE_RESYNC: Duration = Duration::from_secs(1);
/// A combo firing twice within this window (global grab plus in-app key event) fires once.
const HOTKEY_DEDUPE: Duration = Duration::from_millis(150);

#[derive(Debug, Clone, Serialize)]
pub struct LogLine {
    pub seq: u64,
    /// `in` (echoed input), `out` (print), `result`, `err`, `info`.
    pub kind: &'static str,
    pub text: String,
}

/// A dialog a script is blocked on until the UI answers with `lua_dialog_reply`.
#[derive(Debug, Clone, Serialize)]
pub struct DialogReq {
    pub id: u64,
    /// `message` (showMessage), `dialog` (messageDialog), `input` (inputQuery).
    pub kind: &'static str,
    pub title: String,
    pub text: String,
    /// CE `mt*` dialog type (messageDialog).
    pub dlg_type: i64,
    /// CE `mb*` buttons (messageDialog).
    pub buttons: Vec<i64>,
    pub initial: String,
}

#[derive(Default)]
struct DialogSlot {
    next: u64,
    pending: Option<DialogReq>,
    answer: Option<(u64, Value)>,
}

/// `Host` for the engine: everything a script shows or registers goes through here.
#[derive(Default)]
pub struct Console {
    log: Mutex<(VecDeque<LogLine>, u64)>,
    dialog: Mutex<DialogSlot>,
    cv: Condvar,
    /// Bumped per beep (hotkey sound, Lua `beep()`); the UI plays one tone per step.
    pub(crate) sound: AtomicU64,
    /// `createHotkey` id -> CE virtual-key codes, plus a version bumped on every change.
    pub(crate) hotkeys: Mutex<(HashMap<u32, Vec<u32>>, u64)>,
    /// The opened process's speedhack, when it was launched with one (`speedhack_setSpeed`).
    pub(crate) speedhack: Mutex<Option<Arc<hh_inject::Speedhack>>>,
}

impl Console {
    pub(crate) fn push(&self, kind: &'static str, text: &str) {
        let mut g = lock(&self.log);
        g.1 += 1;
        let seq = g.1;
        g.0.push_back(LogLine { seq, kind, text: text.to_string() });
        while g.0.len() > LOG_CAP {
            g.0.pop_front();
        }
    }

    fn since(&self, seq: u64) -> (Vec<LogLine>, u64) {
        let g = lock(&self.log);
        (g.0.iter().filter(|l| l.seq > seq).cloned().collect(), g.1)
    }

    /// Blocks the calling (Lua) thread until the UI answers; `Null` when cancelled.
    fn ask(&self, mut req: DialogReq) -> Value {
        let mut g = lock(&self.dialog);
        g.next += 1;
        let id = g.next;
        req.id = id;
        g.pending = Some(req);
        g.answer = None;
        loop {
            if let Some((aid, v)) = g.answer.take()
                && aid == id
            {
                g.pending = None;
                return v;
            }
            g = self.cv.wait(g).unwrap_or_else(|e| e.into_inner());
        }
    }

    fn reply(&self, id: u64, v: Value) {
        let mut g = lock(&self.dialog);
        if g.pending.as_ref().is_some_and(|p| p.id == id) {
            g.answer = Some((id, v));
            self.cv.notify_all();
        }
    }

    /// Answers whatever dialog is open with "cancelled" (interrupt).
    fn cancel(&self) {
        let mut g = lock(&self.dialog);
        if let Some(id) = g.pending.as_ref().map(|p| p.id) {
            g.answer = Some((id, Value::Null));
            self.cv.notify_all();
        }
    }
}

/// CE `mb*` button -> the `mr*` result clicking it gives (same table as hh-lua's default).
fn button_result(mb: i64) -> i64 {
    match mb {
        0 => 6,
        1 => 7,
        2 => 1,
        3 => 2,
        4 => 3,
        5 => 4,
        6 => 5,
        7 => 8,
        8 => 9,
        9 => 10,
        11 => 11,
        _ => 0,
    }
}

impl Host for Console {
    fn print(&self, text: &str) {
        self.push("out", text);
    }
    fn show_message(&self, text: &str) {
        self.ask(DialogReq { id: 0, kind: "message", title: String::new(), text: text.into(), dlg_type: 2, buttons: vec![2], initial: String::new() });
    }
    fn error(&self, text: &str) {
        self.push("err", text);
    }
    fn message_dialog(&self, title: &str, text: &str, kind: i64, buttons: &[i64]) -> i64 {
        let req = DialogReq { id: 0, kind: "dialog", title: title.into(), text: text.into(), dlg_type: kind, buttons: buttons.to_vec(), initial: String::new() };
        // The UI answers with the clicked `mb*` button; closing the dialog = cancel.
        match self.ask(req).as_i64() {
            Some(mb) => button_result(mb),
            None => 2,
        }
    }
    fn input_query(&self, caption: &str, prompt: &str, initial: &str) -> Option<String> {
        let req = DialogReq { id: 0, kind: "input", title: caption.into(), text: prompt.into(), dlg_type: 0, buttons: Vec::new(), initial: initial.into() };
        self.ask(req).as_str().map(str::to_string)
    }
    fn register_hotkey(&self, id: u32, keys: &[i64]) -> HResult<()> {
        let mut g = lock(&self.hotkeys);
        g.0.insert(id, keys.iter().map(|&k| k as u32).collect());
        g.1 += 1;
        Ok(())
    }
    fn unregister_hotkey(&self, id: u32) {
        let mut g = lock(&self.hotkeys);
        g.0.remove(&id);
        g.1 += 1;
    }
    fn play_sound(&self, what: Option<&str>) {
        match what {
            None => {
                self.sound.fetch_add(1, SeqCst);
            }
            Some(f) => self.push("info", &format!("playSound({f}): sound files are not available yet")),
        }
    }
    fn set_speed(&self, speed: f64) -> HResult<()> {
        let s = lock(&self.speedhack).clone();
        match s {
            Some(s) => s.set_speed(speed),
            None => Err(hh_core::Error::Unsupported("speedhack: launch the process with \"Create process\" and the speedhack option")),
        }
    }
}

/// The engine plus the lock that admits one caller at a time (hh-lua's budget guard counts
/// nesting across threads, so concurrent entries would share one deadline).
pub struct LuaCtx {
    pub(crate) engine: Engine,
    run: Mutex<()>,
    pub(crate) console: Arc<Console>,
    busy: AtomicBool,
}

impl LuaCtx {
    pub(crate) fn new(live: Arc<Live>) -> LuaCtx {
        // Lua::new and the API install only fail on hh-lua bugs.
        let engine = Engine::new(EngineOptions::default()).expect("Lua engine init");
        let console = Arc::new(Console::default());
        engine.set_host(console.clone());
        engine.set_table(live);
        LuaCtx { engine, run: Mutex::new(()), console, busy: AtomicBool::new(false) }
    }

    pub(crate) fn enter(&self) -> MutexGuard<'_, ()> {
        lock(&self.run)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct LuaPoll {
    pub log: Vec<LogLine>,
    /// Pass back as `since`.
    pub next: u64,
    pub dialog: Option<DialogReq>,
    pub table_version: u64,
    /// Every bound hotkey combo (table entries and `createHotkey`), CE virtual-key codes.
    pub hotkeys: Vec<Vec<u32>>,
    /// A console run or table script is executing (the interrupt button applies).
    pub busy: bool,
    pub sound: u64,
}

/// Who a hotkey belongs to.
#[derive(Debug, Clone, PartialEq)]
pub enum Target {
    /// Entry id and index into its `hotkeys`.
    Entry(i64, usize),
    Lua(u32),
}

/// Registers the given combos with the OS; returns which succeeded. Set by `main.rs`.
pub type Registrar = Box<dyn Fn(&[Vec<u32>]) -> Vec<bool> + Send + Sync>;

#[derive(Default)]
pub struct HotkeyState {
    pub(crate) registrar: Option<Registrar>,
    registered: Vec<Vec<u32>>,
    last: HashMap<Vec<u32>, Instant>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DialogReply {
    pub id: u64,
    #[serde(default)]
    pub value: Value,
}

impl App {
    /// Runs console input; its echo, prints, results and error (with traceback) go to the log.
    pub fn lua_exec(&self, code: &str) -> R<()> {
        self.lua_run(code, "console", true)
    }

    fn lua_run(&self, code: &str, name: &str, echo: bool) -> R<()> {
        let l = &self.x.lua;
        if echo {
            l.console.push("in", code);
        }
        let _g = l.enter();
        l.busy.store(true, SeqCst);
        let r = l.engine.exec(code, name);
        l.busy.store(false, SeqCst);
        drop(_g);
        self.drain_cascades();
        match r {
            Ok(vals) => {
                if !vals.is_empty() {
                    l.console.push("result", &vals.join("\t"));
                }
                Ok(())
            }
            Err(e) => {
                let t = e.to_string();
                l.console.push("err", &t);
                Err(t)
            }
        }
    }

    /// Runs the table's `<LuaScript>`. The UI only calls this after the user agreed.
    pub fn table_run_script(&self) -> R<()> {
        let src = self.x.live.state().table.lua_script;
        if src.trim().is_empty() {
            return Ok(());
        }
        self.x.lua.console.push("info", "-- running the table's Lua script");
        self.lua_run(&src, "table script", false)
    }

    /// Stops the running script (and answers its open dialog with "cancel"); any thread.
    pub fn lua_interrupt(&self) -> R<()> {
        self.x.lua.engine.interrupt_handle().interrupt();
        self.x.lua.console.cancel();
        Ok(())
    }

    pub fn lua_poll(&self, since: u64) -> R<LuaPoll> {
        let c = &self.x.lua.console;
        let (log, next) = c.since(since);
        let mut hotkeys: Vec<Vec<u32>> = self.bindings().into_iter().map(|b| b.0).collect();
        hotkeys.sort();
        hotkeys.dedup();
        Ok(LuaPoll {
            log,
            next,
            dialog: lock(&c.dialog).pending.clone(),
            table_version: self.x.live.version(),
            hotkeys,
            busy: self.x.lua.busy.load(SeqCst),
            sound: c.sound.load(SeqCst),
        })
    }

    pub fn lua_dialog_reply(&self, r: DialogReply) -> R<()> {
        self.x.lua.console.reply(r.id, r.value);
        Ok(())
    }

    // ---------------------------------------------------------------- hotkeys

    /// Every hotkey binding, keys sorted (order of pressing does not matter).
    pub(crate) fn bindings(&self) -> Vec<(Vec<u32>, Target)> {
        let mut out: Vec<(Vec<u32>, Target)> = self.x.live.hotkeys().into_iter().map(|(k, id, i)| (k, Target::Entry(id, i))).collect();
        out.extend(lock(&self.x.lua.console.hotkeys).0.iter().map(|(&id, k)| (k.clone(), Target::Lua(id))));
        for b in &mut out {
            b.0.sort_unstable();
            b.0.dedup();
        }
        out.retain(|b| !b.0.is_empty());
        out
    }

    pub fn set_hotkey_registrar(&self, f: Registrar) {
        lock(&self.x.hk).registrar = Some(f);
    }

    /// A key combo was pressed (globally or in the app window): fires every hotkey bound to
    /// it. Returns how many fired; errors are logged to the console and returned.
    pub fn hotkey_press(&self, keys: &[u32]) -> R<usize> {
        let mut k = keys.to_vec();
        k.sort_unstable();
        k.dedup();
        {
            let mut g = lock(&self.x.hk);
            let now = Instant::now();
            if g.last.get(&k).is_some_and(|t| now.duration_since(*t) < HOTKEY_DEDUPE) {
                return Ok(0);
            }
            g.last.insert(k.clone(), now);
        }
        let hits: Vec<Target> = self.bindings().into_iter().filter(|b| b.0 == k).map(|b| b.1).collect();
        let mut errs = Vec::new();
        for t in &hits {
            let r = match t {
                Target::Entry(id, i) => self.table_hotkey(*id, *i),
                Target::Lua(id) => {
                    let r = {
                        let _g = self.x.lua.enter();
                        self.x.lua.engine.fire_hotkey(*id).map_err(|e| e.to_string())
                    };
                    self.drain_cascades();
                    r
                }
            };
            if let Err(e) = r {
                self.x.lua.console.push("err", &format!("hotkey: {e}"));
                errs.push(e);
            }
        }
        if !hits.is_empty() && lock(&self.x.settings).hotkey_sound {
            self.x.lua.console.sound.fetch_add(1, SeqCst);
        }
        if errs.is_empty() { Ok(hits.len()) } else { Err(errs.join("\n")) }
    }

    /// Registers the current combos with the OS when they changed.
    fn sync_global_hotkeys(&self) {
        let mut combos: Vec<Vec<u32>> = self.bindings().into_iter().map(|b| b.0).collect();
        combos.sort();
        combos.dedup();
        let mut g = lock(&self.x.hk);
        if g.registrar.is_none() || g.registered == combos {
            return;
        }
        let ok = (g.registrar.as_ref().unwrap())(&combos);
        let failed: Vec<String> = combos.iter().zip(&ok).filter(|(_, ok)| !**ok).map(|(c, _)| format!("{c:?}")).collect();
        g.registered = combos;
        drop(g);
        if !failed.is_empty() {
            self.x.lua.console.push("info", &format!("hotkeys {} work only while HeapHook has focus (no global registration)", failed.join(", ")));
        }
    }

    // ---------------------------------------------------------------- driver

    /// Starts the background driver once: Lua timers/threads (`tick`), group cascades, the
    /// frozen set, global hotkeys. It ends when the last `App` clone is dropped.
    pub fn start_driver(&self) {
        if self.x.driver.swap(true, SeqCst) {
            return;
        }
        let weak = self.downgrade();
        std::thread::Builder::new()
            .name("hh-lua-driver".into())
            .spawn(move || {
                let mut last_sync = Instant::now();
                loop {
                    std::thread::sleep(TICK);
                    let Some(app) = App::upgrade(&weak) else { break };
                    let l = &app.x.lua;
                    // Skip the tick while a console run holds the engine.
                    if let Ok(_g) = l.run.try_lock()
                        && let Err(e) = l.engine.tick()
                    {
                        l.console.push("err", &e.to_string());
                    }
                    app.drain_cascades();
                    if app.x.live.take_dirty() || last_sync.elapsed() >= FREEZE_RESYNC {
                        app.sync_freeze();
                        last_sync = Instant::now();
                    }
                    app.sync_global_hotkeys();
                }
            })
            .expect("spawn driver thread");
    }
}
