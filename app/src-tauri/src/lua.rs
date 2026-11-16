//! The app's Lua engine (hh-lua): one per app, bound to the current process through the
//! session's `Switch` (so it follows debugger attach/detach), with the console log, the
//! dialogs scripts open, `createHotkey` registrations, the forms scripts build (`UiHost`,
//! mirrored to the UI through `ui_poll`), the debugger behind `debug_*` (`DebugHost`), and
//! the background driver that calls `tick()`, runs Lua breakpoint functions, re-syncs the
//! freezer and keeps global hotkeys registered.
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::SeqCst};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::thread::ThreadId;
use std::time::{Duration, Instant};

use hh_core::{Error as HError, Result as HResult};
use hh_lua::{DebugHost, Engine, EngineOptions, Host, Prop, UiChange, UiHost, UiSnapshot};
use hh_scan::Scanner;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::cheat::Live;
use crate::commands::{App, R, WeakApp, lock};

const LOG_CAP: usize = 2000;
const TICK: Duration = Duration::from_millis(20);
/// Pointer entries can move; the frozen set is re-resolved this often even without changes.
const FREEZE_RESYNC: Duration = Duration::from_secs(1);
/// A combo firing twice within this window (global grab plus in-app key event) fires once.
const HOTKEY_DEDUPE: Duration = Duration::from_millis(150);
/// Form changes kept for `ui_poll`; a UI further behind gets a snapshot instead.
const UI_CAP: usize = 20_000;
/// Bytes of queued form changes kept for `ui_poll` before the UI must take a snapshot.
const UI_BYTES: usize = 8 << 20;
/// Largest image file a form may show (`Picture.loadFromFile`).
const MAX_IMAGE: u64 = 8 << 20;

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
    /// The app, for hosts that call back into it (create process, tables, debugger).
    pub(crate) app: OnceLock<WeakApp>,
    /// Keys held down in the app window (`isKeyPressed`), CE virtual-key codes.
    keys: Mutex<HashSet<u32>>,
    /// Form changes with their sequence numbers, for `ui_poll`.
    ui: Mutex<UiLog>,
}

/// Form changes for `ui_poll`: hh-lua's bounded log (updates coalesce per property; capped by
/// count and bytes; a UI that fell behind takes a snapshot).
struct UiLog(hh_lua::ChangeLog);

impl Default for UiLog {
    fn default() -> Self {
        UiLog(hh_lua::ChangeLog::new(UI_CAP, UI_BYTES))
    }
}

/// `ui_poll` answer: the changes after `since`, or the whole tree when the UI is too far
/// behind (or asks with `since` 0).
#[derive(Debug, Clone, Serialize)]
pub struct UiPoll {
    pub next: u64,
    pub changes: Vec<UiSeqChange>,
    pub snapshot: Option<UiSnapshot>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UiSeqChange {
    pub seq: u64,
    #[serde(flatten)]
    pub change: UiChange,
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
    fn create_process(&self, path: &str, params: &str, debug: bool, _break_on_entry: bool) -> HResult<u32> {
        let app = self.app_os("createProcess")?;
        let req = crate::inject::CreateReq { program: path.into(), args: params.into(), ..Default::default() };
        let o = app.process_create(&req).map_err(HError::Other)?;
        if debug {
            app.debug_attach().map_err(HError::Other)?;
        }
        Ok(o.pid)
    }
    fn current_memscan(&self) -> Option<Arc<Scanner>> {
        Some(self.app().ok()?.session().ok()?.scanner.clone())
    }
    fn load_table(&self, path: &str, merge: bool) -> HResult<()> {
        let app = self.app_os("loadTable")?;
        if merge { app.table_merge(path).map(|_| ()) } else { app.table_open(path, false).map(|_| ()) }.map_err(HError::Other)
    }
    fn save_table(&self, path: &str, _protect: bool) -> HResult<()> {
        self.app_os("saveTable")?.table_export(path).map_err(HError::Other)
    }
    fn is_key_pressed(&self, vk: i64) -> bool {
        let k = lock(&self.keys);
        // CE: VK_SHIFT/CONTROL/MENU also match the left/right variants.
        let alias = match vk {
            160 | 161 => 16,
            162 | 163 => 17,
            164 | 165 => 18,
            v => v,
        };
        k.contains(&(alias as u32))
    }
}

impl Console {
    fn app(&self) -> HResult<App> {
        self.app.get().and_then(App::upgrade).ok_or_else(|| HError::Other("HeapHook is shutting down".into()))
    }

    /// The app, for a host function that uses files or starts programs: refused like hh-lua's
    /// own `io` / `os` when Settings turn that off.
    fn app_os(&self, what: &str) -> HResult<App> {
        let app = self.app()?;
        if !app.x.lua.engine.allow_os() {
            return Err(HError::Other(format!("{what}: Settings do not allow Lua scripts to access files and run programs")));
        }
        Ok(app)
    }
}

/// `debug_*` from Lua drive the app's debugger; breakpoints set this way are listed in
/// the UI as script-owned.
impl DebugHost for Console {
    fn start(&self, _interface: i64) -> HResult<()> {
        self.app()?.debug_attach().map(|_| ()).map_err(HError::Other)
    }
    fn is_debugging(&self) -> bool {
        self.app().is_ok_and(|a| a.lua_debugging())
    }
    fn set_breakpoint(&self, bp: &hh_lua::BreakpointSpec) -> HResult<()> {
        self.app()?.lua_set_breakpoint(bp).map(|_| ()).map_err(HError::Other)
    }
    fn remove_breakpoint(&self, address: hh_core::Addr) -> HResult<()> {
        self.app()?.lua_remove_breakpoint(address).map_err(HError::Other)
    }
    fn continue_from_breakpoint(&self, tid: u32, mode: hh_lua::ContinueMode, ctx: Option<&hh_lua::RegContext>) -> HResult<()> {
        self.app()?.lua_continue(tid, mode, ctx).map_err(HError::Other)
    }
    fn break_thread(&self, _tid: u32) -> HResult<()> {
        self.app()?.debug_pause().map_err(HError::Other)
    }
}

/// Forms built by scripts: every change is queued for the UI (`ui_poll`); never calls back
/// into the engine.
impl UiHost for Console {
    fn changed(&self, change: &UiChange) {
        lock(&self.ui).0.push(change);
    }
}

/// A lock one thread holds at a time and may take again (Lua calls hosts that call back
/// into app commands that take it too: `loadTable`, `createProcess`, debugger functions).
#[derive(Default)]
pub(crate) struct ReLock {
    /// Owner, depth, and since when it is held.
    m: Mutex<(Option<ThreadId>, usize, Option<Instant>)>,
    cv: Condvar,
}

pub(crate) struct ReGuard<'a>(&'a ReLock);

impl ReLock {
    fn enter(&self) -> ReGuard<'_> {
        let me = std::thread::current().id();
        let mut g = lock(&self.m);
        while g.0.is_some_and(|t| t != me) {
            g = self.cv.wait(g).unwrap_or_else(|e| e.into_inner());
        }
        if g.0.is_none() {
            g.2 = Some(Instant::now());
        }
        g.0 = Some(me);
        g.1 += 1;
        ReGuard(self)
    }

    /// How long the current holder has had it.
    fn held_for(&self) -> Option<Duration> {
        lock(&self.m).2.map(|t| t.elapsed())
    }

    /// `None` while another thread holds it.
    fn try_enter(&self) -> Option<ReGuard<'_>> {
        let me = std::thread::current().id();
        let mut g = lock(&self.m);
        if g.0.is_some_and(|t| t != me) {
            return None;
        }
        if g.0.is_none() {
            g.2 = Some(Instant::now());
        }
        g.0 = Some(me);
        g.1 += 1;
        Some(ReGuard(self))
    }
}

impl Drop for ReGuard<'_> {
    fn drop(&mut self) {
        let mut g = lock(&self.0.m);
        g.1 -= 1;
        if g.1 == 0 {
            g.0 = None;
            g.2 = None;
            self.0.cv.notify_one();
        }
    }
}

/// The engine, built on first use: `EngineOptions::allow_os` is fixed when it is built, so
/// the setting is read then (`set_config_dir` sets it before anything uses the engine).
pub(crate) struct LazyEngine {
    cell: OnceLock<Engine>,
    allow_os: AtomicBool,
    live: Arc<Live>,
    console: Arc<Console>,
}

impl LazyEngine {
    /// Takes effect only if the engine was not built yet.
    pub(crate) fn set_allow_os(&self, v: bool) {
        if self.cell.get().is_none() {
            self.allow_os.store(v, SeqCst);
        }
    }

    /// What the (running or next) engine allows.
    pub(crate) fn allow_os(&self) -> bool {
        self.allow_os.load(SeqCst)
    }
}

impl std::ops::Deref for LazyEngine {
    type Target = Engine;
    fn deref(&self) -> &Engine {
        self.cell.get_or_init(|| {
            // Lua::new and the API install only fail on hh-lua bugs.
            let engine = Engine::new(EngineOptions { allow_os: self.allow_os.load(SeqCst), ..EngineOptions::default() }).expect("Lua engine init");
            engine.set_host(self.console.clone());
            engine.set_table(self.live.clone());
            engine.set_ui_host(self.console.clone());
            engine.set_debug_host(self.console.clone());
            engine
        })
    }
}

/// The engine plus the app's lock around it: one thread runs Lua and the table changes it
/// makes at a time (hh-lua has its own gate; this one also covers the app-side steps).
pub struct LuaCtx {
    pub(crate) engine: LazyEngine,
    run: ReLock,
    pub(crate) console: Arc<Console>,
    busy: AtomicBool,
    /// The script defines `debugger_onBreakpoint`: every breakpoint hit goes to Lua first.
    pub(crate) onbp: AtomicBool,
}

impl LuaCtx {
    pub(crate) fn new(live: Arc<Live>) -> LuaCtx {
        let console = Arc::new(Console::default());
        let engine = LazyEngine { cell: OnceLock::new(), allow_os: AtomicBool::new(EngineOptions::default().allow_os), live, console: console.clone() };
        LuaCtx { engine, run: ReLock::default(), console, busy: AtomicBool::new(false), onbp: AtomicBool::new(false) }
    }

    pub(crate) fn enter(&self) -> ReGuard<'_> {
        self.run.enter()
    }

    /// Re-reads whether `debugger_onBreakpoint` is defined; call with the lock held.
    pub(crate) fn refresh_onbp(&self) {
        let f = self.engine.lua().globals().raw_get::<mlua::Value>("debugger_onBreakpoint").is_ok_and(|v| v.is_function());
        self.onbp.store(f, SeqCst);
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
    /// The opened process (`null` when none), so the UI notices an exit and can recover
    /// its state after a reload.
    pub process: Option<ProcessState>,
    /// Table selection a script set (`SelectedRecords`); `seq` moves on each change.
    pub selection: crate::cheat::Selection,
    /// Sequence number of the last form change (call `ui_poll` when it moves).
    pub ui_seq: u64,
    /// Close requests and dropped files of the window.
    pub window: crate::commands::WinEvents,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProcessState {
    #[serde(flatten)]
    pub info: crate::commands::Opened,
    pub alive: bool,
    /// Remote target whose connection dropped: why.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lost: Option<String>,
    /// Suspended with `process_pause`.
    pub paused: bool,
}

/// Who a hotkey belongs to.
#[derive(Debug, Clone, PartialEq)]
pub enum Target {
    /// Entry id and index into its `hotkeys`.
    Entry(i64, usize),
    Lua(u32),
    /// Index into the settings' `app_hotkeys`.
    App(usize),
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
        l.refresh_onbp();
        drop(_g);
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

    /// Runs the table's `<LuaScript>`: the user's own table, or a loaded one the user agreed
    /// to (`table_trust`); otherwise refused with the consent error.
    pub fn table_run_script(&self) -> R<()> {
        let src = self.x.live.state().table.lua_script;
        if src.trim().is_empty() {
            return Ok(());
        }
        if !self.x.live.trust().allows() {
            return Err(self.consent_error("The table's Lua script"));
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
            // A console run or table script, or anything else (timer, form event, hotkey,
            // activation) holding the engine long enough to look stuck: Esc and Stop apply.
            busy: self.x.lua.busy.load(SeqCst) || self.x.lua.run.held_for().is_some_and(|d| d >= BUSY_AFTER),
            sound: c.sound.load(SeqCst),
            process: self.session().ok().map(|s| {
                // A local check is a cheap syscall; a remote one is a network round trip that
                // can hang for the connection timeout, so the poll reads what the liveness
                // thread found last (see `start_driver`).
                let (alive, lost) = if s.info.remote.is_none() {
                    (s.raw.is_alive(), None)
                } else {
                    let r = lock(&self.x.remote_alive);
                    if r.sess == session_key(&s) { (r.alive, r.lost.clone()) } else { (true, None) }
                };
                ProcessState { info: s.info.clone(), alive, lost, paused: s.paused.load(SeqCst) }
            }),
            selection: self.x.live.selection(),
            ui_seq: lock(&c.ui).0.seq(),
            window: lock(&self.x.win).clone(),
        })
    }

    // ---------------------------------------------------------------- forms

    /// Form changes after `since` (`since` 0, or too far behind: the whole tree instead).
    pub fn ui_poll(&self, since: u64) -> R<UiPoll> {
        let g = lock(&self.x.lua.console.ui);
        let next = g.0.seq();
        let changes = if since > next { None } else { g.0.since(since) };
        drop(g);
        match changes {
            Some(c) => Ok(UiPoll { next, changes: c.into_iter().map(|(seq, change)| UiSeqChange { seq, change }).collect(), snapshot: None }),
            // `since` 0, too far behind (changes were dropped for room) or from an older
            // engine: the whole tree. Changes made while it is taken are in it and also
            // replayed; the UI applies them idempotently.
            None => Ok(UiPoll { next, changes: Vec::new(), snapshot: Some(self.x.lua.engine.ui_snapshot()) }),
        }
    }

    /// A user event on a form control (`OnClick`, `OnClose`, ...); returns the handler's results.
    pub fn ui_event(&self, id: u32, event: &str, args: Vec<Prop>) -> R<Vec<Prop>> {
        let _g = self.x.lua.enter();
        let r = self.x.lua.engine.fire_event(id, event, &args).map_err(|e| e.to_string());
        self.x.lua.refresh_onbp();
        if let Err(e) = &r {
            self.x.lua.console.push("err", e);
        }
        r
    }

    /// The user changed a control's value (`Text`, `Checked`, `ItemIndex`, `Position`).
    pub fn ui_input(&self, id: u32, prop: &str, value: Prop) -> R<()> {
        let _g = self.x.lua.enter();
        let r = self.x.lua.engine.ui_input(id, prop, value).map_err(|e| e.to_string());
        if let Err(e) = &r {
            self.x.lua.console.push("err", e);
        }
        r
    }

    /// An image file a form shows (`TImage.Picture.loadFromFile`) as a `data:` URL.
    pub fn ui_image(&self, path: &str) -> R<String> {
        // The path is the script's (`Picture.loadFromFile`): a file read on its behalf.
        if !self.x.lua.engine.allow_os() {
            return Err(format!("{path}: Settings do not allow Lua scripts to access files"));
        }
        let mime = match std::path::Path::new(path).extension().and_then(|e| e.to_str()).map(str::to_ascii_lowercase).as_deref() {
            Some("png") => "image/png",
            Some("jpg" | "jpeg") => "image/jpeg",
            Some("gif") => "image/gif",
            Some("bmp") => "image/bmp",
            Some("webp") => "image/webp",
            Some("svg") => "image/svg+xml",
            _ => return Err(format!("{path}: not an image HeapHook can show (png, jpg, gif, bmp, webp, svg)")),
        };
        let b = crate::table::read_capped(std::path::Path::new(path), MAX_IMAGE)?;
        Ok(format!("data:{mime};base64,{}", base64(&b)))
    }

    /// Keys currently held in the app window (`isKeyPressed`). Ignored (cleared) while the
    /// table is not trusted: only Lua the user agreed to may watch the keyboard.
    pub fn key_state(&self, keys: &[u32]) -> R<()> {
        let ok = self.x.live.trust().allows();
        *lock(&self.x.lua.console.keys) = if ok { keys.iter().copied().collect() } else { HashSet::new() };
        Ok(())
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
        out.extend(lock(&self.x.settings).app_hotkeys.iter().enumerate().map(|(i, h)| (h.keys.clone(), Target::App(i))));
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
        let gap = HOTKEY_DEDUPE.max(Duration::from_millis(lock(&self.x.settings).hotkey_delay_ms));
        {
            let mut g = lock(&self.x.hk);
            let now = Instant::now();
            if g.last.get(&k).is_some_and(|t| now.duration_since(*t) < gap) {
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
                    let _g = self.x.lua.enter();
                    self.x.lua.engine.fire_hotkey(*id).map_err(|e| e.to_string())
                }
                Target::App(i) => self.app_hotkey(*i),
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

    /// Runs HeapHook's own hotkey `i` (Settings): a speedhack preset or pause / resume.
    fn app_hotkey(&self, i: usize) -> R<()> {
        let h = lock(&self.x.settings).app_hotkeys.get(i).cloned().ok_or("no such hotkey")?;
        match h.action.as_str() {
            "speed" => self.speed_set(h.value).map(|_| ()),
            "pause" => {
                let paused = self.session()?.paused.load(SeqCst);
                self.process_pause(!paused)
            }
            a => Err(format!("unknown hotkey action {a:?}")),
        }
    }

    /// The combos registered with the OS (system-wide): only with a modifier key (a plain key
    /// would be taken from every other program), and a table's entry hotkeys only once the
    /// table is trusted. The rest work while HeapHook has focus.
    pub fn global_combos(&self) -> Vec<Vec<u32>> {
        let trusted = self.x.live.trust().allows();
        // An entry pasted or merged from another table: not system-wide before its consent either.
        let ok = |t: &Target| match t {
            Target::Lua(_) | Target::App(_) => true,
            Target::Entry(id, _) => trusted && !self.x.live.is_foreign_ask(*id),
        };
        let mut combos: Vec<Vec<u32>> = self.bindings().into_iter().filter(|(k, t)| has_modifier(k) && ok(t)).map(|b| b.0).collect();
        combos.sort();
        combos.dedup();
        combos
    }

    /// Registers the current combos with the OS when they changed.
    fn sync_global_hotkeys(&self) {
        let combos = self.global_combos();
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

    /// Starts the background driver once: Lua timers/threads (`tick`), Lua breakpoint
    /// functions, the frozen set, global hotkeys. It ends when the last `App` clone is dropped.
    pub fn start_driver(&self) {
        if self.x.driver.swap(true, SeqCst) {
            return;
        }
        // Remote liveness on its own thread: a server that stops answering blocks this one for
        // the connection timeout, never the driver or the UI poll.
        let weak = self.downgrade();
        std::thread::Builder::new()
            .name("hh-liveness".into())
            .spawn(move || {
                loop {
                    std::thread::sleep(LIVENESS);
                    let Some(app) = App::upgrade(&weak) else { break };
                    let Ok(s) = app.session() else { continue };
                    if s.info.remote.is_none() {
                        continue;
                    }
                    let alive = s.raw.is_alive();
                    let lost = if alive { None } else { app.remote_lost() };
                    *lock(&app.x.remote_alive) = RemoteAlive { sess: session_key(&s), alive, lost };
                }
            })
            .expect("spawn liveness thread");
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
                    if let Some(_g) = l.run.try_enter() {
                        if let Err(e) = l.engine.tick() {
                            l.console.push("err", &e.to_string());
                        }
                        l.refresh_onbp();
                    }
                    app.dispatch_lua_break();
                    if app.x.live.take_dirty() || last_sync.elapsed() >= FREEZE_RESYNC {
                        app.sync_freeze();
                        last_sync = Instant::now();
                        // Reap launched processes that exited, so none lingers as a zombie.
                        app.reap_children();
                    }
                    app.sync_global_hotkeys();
                }
            })
            .expect("spawn driver thread");
    }
}

/// Lua holding the engine this long counts as busy (the UI offers Stop).
const BUSY_AFTER: Duration = Duration::from_millis(300);

/// How often the liveness thread checks a remote target.
const LIVENESS: Duration = Duration::from_millis(500);

/// The last liveness check of a remote target, for the session it was made on.
#[derive(Default)]
pub(crate) struct RemoteAlive {
    sess: usize,
    alive: bool,
    lost: Option<String>,
}

fn session_key(s: &Arc<crate::commands::Session>) -> usize {
    Arc::as_ptr(s) as usize
}

/// A combo with Shift, Ctrl, Alt or the Windows key in it.
fn has_modifier(keys: &[u32]) -> bool {
    keys.iter().any(|k| matches!(k, 16..=18 | 91 | 92 | 160..=165))
}

/// Standard base64 with padding.
fn base64(b: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(b.len().div_ceil(3) * 4);
    for c in b.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            out.push(if i <= c.len() { A[(n >> (18 - 6 * i)) as usize & 63] as char } else { '=' });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn only_combos_with_a_modifier_are_system_wide() {
        assert!(super::has_modifier(&[17, 112]) && super::has_modifier(&[65, 164]));
        assert!(!super::has_modifier(&[112]) && !super::has_modifier(&[32]) && !super::has_modifier(&[65, 66]));
    }

    #[test]
    fn base64_matches_rfc4648() {
        let t = |s: &str| super::base64(s.as_bytes());
        assert_eq!([t(""), t("f"), t("fo"), t("foo"), t("foob"), t("fooba"), t("foobar")], ["", "Zg==", "Zm8=", "Zm9v", "Zm9vYg==", "Zm9vYmE=", "Zm9vYmFy"]);
    }
}
