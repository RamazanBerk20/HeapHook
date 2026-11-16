//! Forms built by scripts (`createForm`, `createButton`, ...) as a retained control tree.
//!
//! The tree lives here; the Lua objects in the prelude are views onto it. Every mutation is
//! sent to the [`UiHost`] as a [`UiChange`], so a UI can mirror the tree (or rebuild it from
//! [`UiSnapshot`] when it attaches late) and render it any way it likes. User input comes back
//! through [`crate::Engine::fire_event`] and [`crate::Engine::ui_input`].
//!
//! Property names are Cheat Engine's (`Caption`, `Left`, `Checked`, `Items`, `Font.Size`,
//! ...). Properties a script sets that HeapHook does not know are stored and read back like
//! any other; values the tree cannot hold (tables that are not string lists) stay on the Lua
//! side. A property holding another control (`PopupMenu`, `Menu`) holds its id.
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use mlua::{IntoLua, Lua, Value};
use serde::{Deserialize, Serialize};

use crate::State;

pub type ControlId = u32;

/// A property value.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(untagged)]
pub enum Prop {
    #[default]
    Nil,
    Bool(bool),
    Int(i64),
    Num(f64),
    Str(String),
    /// String lists (`Items`, `Lines`).
    List(Vec<String>),
}

impl Prop {
    /// Lua value -> property (`None` for values a property cannot hold: functions, tables
    /// that are not lists of strings/numbers, userdata, values over [`MAX_PROP_BYTES`]).
    pub(crate) fn from_lua(v: &Value) -> Option<Prop> {
        Prop::checked(v).ok().flatten()
    }

    /// Like [`Prop::from_lua`], but a value over [`MAX_PROP_BYTES`] is an error.
    pub(crate) fn checked(v: &Value) -> mlua::Result<Option<Prop>> {
        let too_big = || mlua::Error::runtime(format!("property value larger than {MAX_PROP_BYTES} bytes"));
        Ok(Some(match v {
            Value::Nil => Prop::Nil,
            Value::Boolean(b) => Prop::Bool(*b),
            Value::Integer(i) => Prop::Int(*i),
            Value::Number(n) => Prop::Num(*n),
            Value::String(s) => {
                if s.as_bytes().len() > MAX_PROP_BYTES {
                    return Err(too_big());
                }
                Prop::Str(s.to_string_lossy())
            }
            Value::Table(t) => {
                if t.raw_len().saturating_mul(LIST_ITEM) > MAX_PROP_BYTES {
                    return Err(too_big());
                }
                if t.pairs::<Value, Value>().count() != t.raw_len() {
                    return Ok(None);
                }
                let (mut out, mut bytes) = (Vec::new(), 0);
                for x in t.sequence_values::<Value>() {
                    let s = match x? {
                        Value::String(s) => s.to_string_lossy(),
                        Value::Integer(i) => i.to_string(),
                        Value::Number(n) => n.to_string(),
                        _ => return Ok(None),
                    };
                    bytes += s.len() + LIST_ITEM;
                    if bytes > MAX_PROP_BYTES {
                        return Err(too_big());
                    }
                    out.push(s);
                }
                Prop::List(out)
            }
            _ => return Ok(None),
        }))
    }

    /// Lossy (event handler results).
    pub(crate) fn from_lua_value(v: &Value) -> Prop {
        Prop::from_lua(v).unwrap_or(Prop::Nil)
    }

    /// Bytes this value holds, for the UI budgets.
    pub fn size(&self) -> usize {
        16 + match self {
            Prop::Str(s) => s.len(),
            Prop::List(l) => l.iter().map(|s| s.len() + LIST_ITEM).sum(),
            _ => 0,
        }
    }
}

impl IntoLua for Prop {
    fn into_lua(self, lua: &Lua) -> mlua::Result<Value> {
        Ok(match self {
            Prop::Nil => Value::Nil,
            Prop::Bool(b) => Value::Boolean(b),
            Prop::Int(i) => Value::Integer(i),
            Prop::Num(n) => Value::Number(n),
            Prop::Str(s) => Value::String(lua.create_string(&s)?),
            Prop::List(l) => Value::Table(lua.create_sequence_from(l)?),
        })
    }
}

/// One control.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Control {
    pub id: ControlId,
    /// CE class name: `TCEForm`, `TMainForm` (HeapHook's main window as scripts see it),
    /// `TButton`, `TLabel`, `TEdit`, `TMemo`, `TCheckBox`, `TToggleBox`, `TRadioGroup`,
    /// `TListBox`, `TComboBox`, `TPanel`, `TGroupBox`, `TImage`, `TProgressBar`, `TTrackBar`,
    /// `TSplitter`, `TScrollBox`, `TTabControl`, `TPageControl`, `TTabSheet`, `TMainMenu`,
    /// `TPopupMenu`, `TMenuItem`.
    pub class: String,
    pub parent: Option<ControlId>,
    pub props: BTreeMap<String, Prop>,
    /// Events the script handles (`OnClick`, `OnClose`, ...).
    pub events: BTreeSet<String>,
}

/// A control with its children, in creation order.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ControlNode {
    #[serde(flatten)]
    pub control: Control,
    pub children: Vec<ControlNode>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct UiSnapshot {
    /// Forms, menus and other controls without a parent.
    pub roots: Vec<ControlNode>,
}

/// A mutation of the tree, in the order it happened.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum UiChange {
    Create { control: Control },
    Update { id: ControlId, prop: String, value: Prop },
    /// A handler for `event` was set (`set` true) or cleared.
    Event { id: ControlId, event: String, set: bool },
    Reparent { id: ControlId, parent: Option<ControlId> },
    /// The control and all its children are gone.
    Destroy { id: ControlId },
    /// A method with no state of its own: `bringToFront`, `sendToBack`, `setFocus`,
    /// `repaint`, `showModal`, `popup`.
    Call { id: ControlId, method: String, args: Vec<Prop> },
}

/// Renders the control tree. Every method has a headless default, so scripts run the same
/// with no UI attached.
pub trait UiHost: Send + Sync {
    /// Called after each change, outside the engine's tree lock (but inside the engine call
    /// that made it: do not call back into the engine from here).
    fn changed(&self, _change: &UiChange) {}
    /// `getScreenWidth` / `getScreenHeight`, `centerScreen`.
    fn screen_size(&self) -> (i64, i64) {
        (1920, 1080)
    }
}

struct NullUi;
impl UiHost for NullUi {}

/// Most controls a script may create (all forms together).
pub const MAX_CONTROLS: usize = 10_000;
/// Deepest nesting of controls (a form is level 1).
pub const MAX_DEPTH: usize = 64;
/// Largest single property value (a string, or a string list in total), also the largest
/// argument list of a control method call.
pub const MAX_PROP_BYTES: usize = 1 << 20;
/// Most bytes the whole control tree may hold.
pub const MAX_UI_BYTES: usize = 64 << 20;
/// Bookkeeping counted per string-list item.
const LIST_ITEM: usize = 24;

fn control_size(c: &Control) -> usize {
    64 + c.class.len()
        + c.props.iter().map(|(k, v)| k.len() + v.size()).sum::<usize>()
        + c.events.iter().map(|e| e.len() + 16).sum::<usize>()
}

/// Approximate bytes a change holds (for [`ChangeLog`]).
pub fn change_size(c: &UiChange) -> usize {
    32 + match c {
        UiChange::Create { control } => control_size(control),
        UiChange::Update { prop, value, .. } => prop.len() + value.size(),
        UiChange::Event { event, .. } => event.len(),
        UiChange::Call { method, args, .. } => method.len() + args.iter().map(Prop::size).sum::<usize>(),
        UiChange::Reparent { .. } | UiChange::Destroy { .. } => 0,
    }
}

fn ui_err(m: String) -> mlua::Error {
    mlua::Error::runtime(m)
}

#[derive(Default)]
struct Tree {
    c: BTreeMap<ControlId, Control>,
    /// `control_size` of every control.
    bytes: usize,
}

impl Tree {
    /// Children of every control (and the roots under `None`), in creation (id) order.
    fn kids(&self) -> HashMap<Option<ControlId>, Vec<ControlId>> {
        let mut k: HashMap<Option<ControlId>, Vec<ControlId>> = HashMap::new();
        for c in self.c.values() {
            k.entry(c.parent).or_default().push(c.id);
        }
        k
    }

    /// `from` and everything below it, parents before children.
    fn subtree(&self, kids: &HashMap<Option<ControlId>, Vec<ControlId>>, from: Option<ControlId>) -> Vec<ControlId> {
        let mut out: Vec<ControlId> = from.into_iter().collect();
        if from.is_none() {
            out.extend(kids.get(&None).into_iter().flatten());
        }
        let mut i = 0;
        while i < out.len() {
            out.extend(kids.get(&Some(out[i])).into_iter().flatten());
            i += 1;
        }
        out
    }

    /// Level of `id` (a control without a parent is level 1).
    fn depth(&self, id: ControlId) -> usize {
        let (mut d, mut cur) = (0, Some(id));
        while let Some(c) = cur.and_then(|c| self.c.get(&c)) {
            d += 1;
            cur = c.parent;
        }
        d
    }

    fn grow(&mut self, by: usize, shrink: usize) -> mlua::Result<()> {
        let new = self.bytes.saturating_sub(shrink).saturating_add(by);
        if by > shrink && new > MAX_UI_BYTES {
            return Err(ui_err(format!("forms hold more than {MAX_UI_BYTES} bytes")));
        }
        self.bytes = new;
        Ok(())
    }
}

pub(crate) struct UiState {
    tree: Mutex<Tree>,
    next: AtomicU32,
    host: RwLock<Arc<dyn UiHost>>,
}

impl Default for UiState {
    fn default() -> Self {
        UiState { tree: Mutex::new(Tree::default()), next: AtomicU32::new(1), host: RwLock::new(Arc::new(NullUi)) }
    }
}

impl UiState {
    fn notify(&self, c: UiChange) {
        let h = self.host.read().unwrap().clone();
        h.changed(&c);
    }

    pub(crate) fn screen(&self) -> (i64, i64) {
        self.host.read().unwrap().screen_size()
    }

    pub(crate) fn create(&self, class: &str, parent: Option<ControlId>, props: BTreeMap<String, Prop>) -> mlua::Result<ControlId> {
        let c = {
            let mut t = self.tree.lock().unwrap();
            if t.c.len() >= MAX_CONTROLS {
                return Err(ui_err(format!("too many controls (at most {MAX_CONTROLS})")));
            }
            let parent = parent.filter(|p| t.c.contains_key(p));
            if parent.is_some_and(|p| t.depth(p) >= MAX_DEPTH) {
                return Err(ui_err(format!("controls nested deeper than {MAX_DEPTH} levels")));
            }
            let id = self.next.fetch_add(1, Ordering::SeqCst);
            let c = Control { id, class: class.into(), parent, props, events: BTreeSet::new() };
            t.grow(control_size(&c), 0)?;
            t.c.insert(id, c.clone());
            c
        };
        let id = c.id;
        self.notify(UiChange::Create { control: c });
        Ok(id)
    }

    pub(crate) fn get(&self, id: ControlId, key: &str) -> Option<Prop> {
        self.tree.lock().unwrap().c.get(&id)?.props.get(key).cloned()
    }

    pub(crate) fn exists(&self, id: ControlId) -> bool {
        self.tree.lock().unwrap().c.contains_key(&id)
    }

    /// Returns whether the value changed; `echo` false = user input (not sent back).
    pub(crate) fn set(&self, id: ControlId, key: &str, v: Prop, echo: bool) -> mlua::Result<bool> {
        {
            let mut t = self.tree.lock().unwrap();
            let Some(c) = t.c.get(&id) else { return Ok(false) };
            let old = c.props.get(key);
            if old == Some(&v) || (v == Prop::Nil && old.is_none()) {
                return Ok(false);
            }
            let shrink = old.map_or(0, |o| key.len() + o.size());
            let by = if v == Prop::Nil { 0 } else { key.len() + v.size() };
            t.grow(by, shrink)?;
            let c = t.c.get_mut(&id).unwrap();
            if v == Prop::Nil {
                c.props.remove(key);
            } else {
                c.props.insert(key.into(), v.clone());
            }
        }
        if echo {
            self.notify(UiChange::Update { id, prop: key.into(), value: v });
        }
        Ok(true)
    }

    pub(crate) fn set_event(&self, id: ControlId, event: &str, set: bool) -> mlua::Result<()> {
        {
            let mut t = self.tree.lock().unwrap();
            let Some(c) = t.c.get(&id) else { return Ok(()) };
            if c.events.contains(event) == set {
                return Ok(());
            }
            let n = event.len() + 16;
            match set {
                true => t.grow(n, 0)?,
                false => t.grow(0, n)?,
            }
            let c = t.c.get_mut(&id).unwrap();
            if set { c.events.insert(event.into()) } else { c.events.remove(event) };
        }
        self.notify(UiChange::Event { id, event: event.into(), set });
        Ok(())
    }

    pub(crate) fn reparent(&self, id: ControlId, parent: Option<ControlId>) -> mlua::Result<()> {
        {
            let mut t = self.tree.lock().unwrap();
            // Refuse cycles and unknown parents.
            if let Some(p) = parent {
                let mut cur = Some(p);
                while let Some(c) = cur {
                    if c == id || !t.c.contains_key(&c) {
                        return Ok(());
                    }
                    cur = t.c[&c].parent;
                }
            }
            let Some(c) = t.c.get(&id) else { return Ok(()) };
            if c.parent == parent {
                return Ok(());
            }
            if let Some(p) = parent {
                // Levels below `id`, itself included.
                let kids = t.kids();
                let (mut height, mut level) = (0, vec![id]);
                while !level.is_empty() {
                    height += 1;
                    level = level.iter().flat_map(|x| kids.get(&Some(*x)).into_iter().flatten().copied()).collect();
                }
                if t.depth(p) + height > MAX_DEPTH {
                    return Err(ui_err(format!("controls nested deeper than {MAX_DEPTH} levels")));
                }
            }
            t.c.get_mut(&id).unwrap().parent = parent;
        }
        self.notify(UiChange::Reparent { id, parent });
        Ok(())
    }

    pub(crate) fn children(&self, id: Option<ControlId>) -> Vec<ControlId> {
        self.tree.lock().unwrap().c.values().filter(|c| c.parent == id).map(|c| c.id).collect()
    }

    pub(crate) fn class(&self, id: ControlId) -> Option<String> {
        self.tree.lock().unwrap().c.get(&id).map(|c| c.class.clone())
    }

    pub(crate) fn parent(&self, id: ControlId) -> Option<ControlId> {
        self.tree.lock().unwrap().c.get(&id)?.parent
    }

    /// Removes the control and its subtree; returns every removed id.
    pub(crate) fn destroy(&self, id: ControlId) -> Vec<ControlId> {
        let gone = {
            let mut t = self.tree.lock().unwrap();
            if !t.c.contains_key(&id) {
                return Vec::new();
            }
            let gone = t.subtree(&t.kids(), Some(id));
            for g in &gone {
                if let Some(c) = t.c.remove(g) {
                    let n = control_size(&c);
                    let _ = t.grow(0, n);
                }
            }
            gone
        };
        self.notify(UiChange::Destroy { id });
        gone
    }

    pub(crate) fn call(&self, id: ControlId, method: &str, args: Vec<Prop>) -> mlua::Result<()> {
        if method.len() + args.iter().map(Prop::size).sum::<usize>() > MAX_PROP_BYTES {
            return Err(ui_err(format!("{method}: arguments larger than {MAX_PROP_BYTES} bytes")));
        }
        if self.exists(id) {
            self.notify(UiChange::Call { id, method: method.into(), args });
        }
        Ok(())
    }
}

pub(crate) fn set_host(st: &State, host: Arc<dyn UiHost>) {
    *st.ui.host.write().unwrap() = host.clone();
    // Parents before children (a reparented child can have a lower id than its parent).
    let creates: Vec<Control> = {
        let t = st.ui.tree.lock().unwrap();
        t.subtree(&t.kids(), None).iter().map(|id| t.c[id].clone()).collect()
    };
    for c in creates {
        host.changed(&UiChange::Create { control: c });
    }
}

pub(crate) fn snapshot(st: &State) -> UiSnapshot {
    let t = st.ui.tree.lock().unwrap();
    let kids = t.kids();
    // Built bottom-up without recursion: every child is finished before its parent.
    let mut done: HashMap<ControlId, ControlNode> = HashMap::new();
    for id in t.subtree(&kids, None).into_iter().rev() {
        let children = kids.get(&Some(id)).into_iter().flatten().filter_map(|k| done.remove(k)).collect();
        done.insert(id, ControlNode { control: t.c[&id].clone(), children });
    }
    UiSnapshot { roots: kids.get(&None).into_iter().flatten().filter_map(|r| done.remove(r)).collect() }
}

/// A bounded log of changes for a UI that polls with the last sequence number it saw.
/// Updates of the same property coalesce (only the newest stays queued); past `max_changes`
/// entries or `max_bytes` (see [`change_size`]) the oldest are dropped and a UI that missed
/// them must take a snapshot ([`ChangeLog::since`] returns `None`).
pub struct ChangeLog {
    changes: VecDeque<(u64, UiChange, usize)>,
    seq: u64,
    bytes: usize,
    /// Highest sequence number dropped for room (not coalesced).
    dropped: u64,
    max_changes: usize,
    max_bytes: usize,
}

impl ChangeLog {
    pub fn new(max_changes: usize, max_bytes: usize) -> Self {
        ChangeLog { changes: VecDeque::new(), seq: 0, bytes: 0, dropped: 0, max_changes, max_bytes }
    }

    /// Queues a change; returns its sequence number.
    pub fn push(&mut self, c: &UiChange) -> u64 {
        if let UiChange::Update { id, prop, .. } = c
            && let Some(i) = self.changes.iter().position(|(_, o, _)| matches!(o, UiChange::Update { id: oid, prop: op, .. } if oid == id && op == prop))
        {
            let (_, _, n) = self.changes.remove(i).unwrap_or_else(|| unreachable!());
            self.bytes -= n;
        }
        self.seq += 1;
        let n = change_size(c);
        self.changes.push_back((self.seq, c.clone(), n));
        self.bytes += n;
        while self.changes.len() > self.max_changes || (self.bytes > self.max_bytes && self.changes.len() > 1) {
            let Some((s, _, n)) = self.changes.pop_front() else { break };
            self.bytes -= n;
            self.dropped = s;
        }
        self.seq
    }

    /// Sequence number of the newest change (0 before the first).
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// Bytes queued.
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// The changes after `since`, oldest first, or `None` when some were dropped (or `since`
    /// is 0): take a snapshot then.
    pub fn since(&self, since: u64) -> Option<Vec<(u64, UiChange)>> {
        if since == 0 || since < self.dropped {
            return None;
        }
        Some(self.changes.iter().filter(|c| c.0 > since).map(|(s, c, _)| (*s, c.clone())).collect())
    }
}

pub(crate) fn install(h: &crate::api::B) -> mlua::Result<()> {
    use mlua::{Table, Variadic};
    h.f("ui_create", |_, st, (class, parent, props): (String, Option<ControlId>, Option<Table>)| {
        let mut p = BTreeMap::new();
        if let Some(t) = props {
            for kv in t.pairs::<mlua::LuaString, Value>() {
                let (k, v) = kv?;
                if k.as_bytes().len() > MAX_PROP_BYTES {
                    return Err(ui_err("property name too long".into()));
                }
                if let Some(v) = Prop::checked(&v)? {
                    p.insert(k.to_string_lossy(), v);
                }
            }
        }
        st.ui.create(&class, parent, p)
    })?;
    h.f("ui_exists", |_, st, id: ControlId| Ok(st.ui.exists(id)))?;
    h.f("ui_get", |_, st, (id, key): (ControlId, String)| Ok(st.ui.get(id, &key).unwrap_or(Prop::Nil)))?;
    // (id, key, value, echo) -> changed; error when the value cannot be a property
    h.f("ui_set", |_, st, (id, key, v, echo): (ControlId, mlua::LuaString, Value, Option<bool>)| {
        if key.as_bytes().len() > MAX_PROP_BYTES {
            return Err(ui_err("property name too long".into()));
        }
        let key = key.to_string_lossy();
        let p = Prop::checked(&v)
            .map_err(|e| ui_err(format!("{key}: {}", crate::api::err_text(&e))))?
            .ok_or_else(|| mlua::Error::runtime(format!("{key}: unsupported value type")))?;
        st.ui.set(id, &key, p, echo.unwrap_or(true))
    })?;
    h.f("ui_event", |_, st, (id, name, set): (ControlId, mlua::LuaString, bool)| {
        if name.as_bytes().len() > 256 {
            return Err(ui_err("event name too long".into()));
        }
        st.ui.set_event(id, &name.to_string_lossy(), set)
    })?;
    h.f("ui_parent", |_, st, (id, parent): (ControlId, Option<ControlId>)| {
        st.ui.reparent(id, parent)?;
        Ok(st.ui.parent(id))
    })?;
    h.f("ui_parentof", |_, st, id: ControlId| Ok(st.ui.parent(id)))?;
    h.f("ui_class", |_, st, id: ControlId| Ok(st.ui.class(id)))?;
    h.f("ui_children", |_, st, id: Option<ControlId>| Ok(st.ui.children(id)))?;
    h.f("ui_destroy", |_, st, id: ControlId| Ok(st.ui.destroy(id)))?;
    h.f("ui_call", |_, st, a: Variadic<Value>| {
        let id = a.first().and_then(crate::api::int_of).unwrap_or(0) as ControlId;
        let m = a.get(1).and_then(crate::api::str_of).unwrap_or_default();
        let args = a.iter().skip(2).map(|v| Ok(Prop::checked(v)?.unwrap_or(Prop::Nil))).collect::<mlua::Result<_>>()?;
        st.ui.call(id, &m, args)
    })?;
    h.f("ui_screen", |_, st, ()| Ok(st.ui.screen()))?;
    Ok(())
}
