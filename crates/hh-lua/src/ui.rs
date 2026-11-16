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
use std::collections::{BTreeMap, BTreeSet};
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
    /// that are not lists of strings/numbers, userdata).
    pub(crate) fn from_lua(v: &Value) -> Option<Prop> {
        Some(match v {
            Value::Nil => Prop::Nil,
            Value::Boolean(b) => Prop::Bool(*b),
            Value::Integer(i) => Prop::Int(*i),
            Value::Number(n) => Prop::Num(*n),
            Value::String(s) => Prop::Str(s.to_string_lossy()),
            Value::Table(t) => {
                if t.pairs::<Value, Value>().count() != t.raw_len() {
                    return None;
                }
                let mut out = Vec::new();
                for x in t.sequence_values::<Value>() {
                    match x.ok()? {
                        Value::String(s) => out.push(s.to_string_lossy()),
                        Value::Integer(i) => out.push(i.to_string()),
                        Value::Number(n) => out.push(n.to_string()),
                        _ => return None,
                    }
                }
                Prop::List(out)
            }
            _ => return None,
        })
    }

    /// Any Lua value, lossy (event handler results).
    pub(crate) fn from_lua_value(v: &Value) -> Prop {
        Prop::from_lua(v).unwrap_or(Prop::Nil)
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

pub(crate) struct UiState {
    tree: Mutex<BTreeMap<ControlId, Control>>,
    next: AtomicU32,
    host: RwLock<Arc<dyn UiHost>>,
}

impl Default for UiState {
    fn default() -> Self {
        UiState { tree: Mutex::new(BTreeMap::new()), next: AtomicU32::new(1), host: RwLock::new(Arc::new(NullUi)) }
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

    pub(crate) fn create(&self, class: &str, parent: Option<ControlId>, props: BTreeMap<String, Prop>) -> ControlId {
        let id = self.next.fetch_add(1, Ordering::SeqCst);
        let parent = parent.filter(|p| self.tree.lock().unwrap().contains_key(p));
        let c = Control { id, class: class.into(), parent, props, events: BTreeSet::new() };
        self.tree.lock().unwrap().insert(id, c.clone());
        self.notify(UiChange::Create { control: c });
        id
    }

    pub(crate) fn get(&self, id: ControlId, key: &str) -> Option<Prop> {
        self.tree.lock().unwrap().get(&id)?.props.get(key).cloned()
    }

    pub(crate) fn exists(&self, id: ControlId) -> bool {
        self.tree.lock().unwrap().contains_key(&id)
    }

    /// Returns whether the value changed; `echo` false = user input (not sent back).
    pub(crate) fn set(&self, id: ControlId, key: &str, v: Prop, echo: bool) -> bool {
        {
            let mut t = self.tree.lock().unwrap();
            let Some(c) = t.get_mut(&id) else { return false };
            if c.props.get(key) == Some(&v) || (v == Prop::Nil && !c.props.contains_key(key)) {
                return false;
            }
            if v == Prop::Nil {
                c.props.remove(key);
            } else {
                c.props.insert(key.into(), v.clone());
            }
        }
        if echo {
            self.notify(UiChange::Update { id, prop: key.into(), value: v });
        }
        true
    }

    pub(crate) fn set_event(&self, id: ControlId, event: &str, set: bool) {
        {
            let mut t = self.tree.lock().unwrap();
            let Some(c) = t.get_mut(&id) else { return };
            let changed = if set { c.events.insert(event.into()) } else { c.events.remove(event) };
            if !changed {
                return;
            }
        }
        self.notify(UiChange::Event { id, event: event.into(), set });
    }

    pub(crate) fn reparent(&self, id: ControlId, parent: Option<ControlId>) {
        {
            let mut t = self.tree.lock().unwrap();
            // Refuse cycles and unknown parents.
            if let Some(p) = parent {
                let mut cur = Some(p);
                while let Some(c) = cur {
                    if c == id || !t.contains_key(&c) {
                        return;
                    }
                    cur = t[&c].parent;
                }
            }
            let Some(c) = t.get_mut(&id) else { return };
            if c.parent == parent {
                return;
            }
            c.parent = parent;
        }
        self.notify(UiChange::Reparent { id, parent });
    }

    pub(crate) fn children(&self, id: Option<ControlId>) -> Vec<ControlId> {
        self.tree.lock().unwrap().values().filter(|c| c.parent == id).map(|c| c.id).collect()
    }

    pub(crate) fn class(&self, id: ControlId) -> Option<String> {
        self.tree.lock().unwrap().get(&id).map(|c| c.class.clone())
    }

    pub(crate) fn parent(&self, id: ControlId) -> Option<ControlId> {
        self.tree.lock().unwrap().get(&id)?.parent
    }

    /// Removes the control and its subtree; returns every removed id.
    pub(crate) fn destroy(&self, id: ControlId) -> Vec<ControlId> {
        let gone = {
            let mut t = self.tree.lock().unwrap();
            if !t.contains_key(&id) {
                return Vec::new();
            }
            let mut gone = vec![id];
            let mut i = 0;
            while i < gone.len() {
                let p = gone[i];
                gone.extend(t.values().filter(|c| c.parent == Some(p)).map(|c| c.id));
                i += 1;
            }
            for g in &gone {
                t.remove(g);
            }
            gone
        };
        self.notify(UiChange::Destroy { id });
        gone
    }

    pub(crate) fn call(&self, id: ControlId, method: &str, args: Vec<Prop>) {
        if self.exists(id) {
            self.notify(UiChange::Call { id, method: method.into(), args });
        }
    }
}

pub(crate) fn set_host(st: &State, host: Arc<dyn UiHost>) {
    *st.ui.host.write().unwrap() = host.clone();
    // Parents before children (a reparented child can have a lower id than its parent).
    fn walk(host: &dyn UiHost, n: ControlNode) {
        host.changed(&UiChange::Create { control: n.control });
        for c in n.children {
            walk(host, c);
        }
    }
    for n in snapshot(st).roots {
        walk(&*host, n);
    }
}

pub(crate) fn snapshot(st: &State) -> UiSnapshot {
    let t = st.ui.tree.lock().unwrap();
    fn node(t: &BTreeMap<ControlId, Control>, c: &Control) -> ControlNode {
        let children = t.values().filter(|x| x.parent == Some(c.id)).map(|x| node(t, x)).collect();
        ControlNode { control: c.clone(), children }
    }
    UiSnapshot { roots: t.values().filter(|c| c.parent.is_none()).map(|c| node(&t, c)).collect() }
}

pub(crate) fn install(h: &crate::api::B) -> mlua::Result<()> {
    use mlua::{Table, Variadic};
    h.f("ui_create", |_, st, (class, parent, props): (String, Option<ControlId>, Option<Table>)| {
        let mut p = BTreeMap::new();
        if let Some(t) = props {
            for kv in t.pairs::<String, Value>() {
                let (k, v) = kv?;
                if let Some(v) = Prop::from_lua(&v) {
                    p.insert(k, v);
                }
            }
        }
        Ok(st.ui.create(&class, parent, p))
    })?;
    h.f("ui_exists", |_, st, id: ControlId| Ok(st.ui.exists(id)))?;
    h.f("ui_get", |_, st, (id, key): (ControlId, String)| Ok(st.ui.get(id, &key).unwrap_or(Prop::Nil)))?;
    // (id, key, value, echo) -> changed; error when the value cannot be a property
    h.f("ui_set", |_, st, (id, key, v, echo): (ControlId, String, Value, Option<bool>)| {
        let p = Prop::from_lua(&v).ok_or_else(|| mlua::Error::runtime(format!("{key}: unsupported value type")))?;
        Ok(st.ui.set(id, &key, p, echo.unwrap_or(true)))
    })?;
    h.f("ui_event", |_, st, (id, name, set): (ControlId, String, bool)| {
        st.ui.set_event(id, &name, set);
        Ok(())
    })?;
    h.f("ui_parent", |_, st, (id, parent): (ControlId, Option<ControlId>)| {
        st.ui.reparent(id, parent);
        Ok(st.ui.parent(id))
    })?;
    h.f("ui_parentof", |_, st, id: ControlId| Ok(st.ui.parent(id)))?;
    h.f("ui_class", |_, st, id: ControlId| Ok(st.ui.class(id)))?;
    h.f("ui_children", |_, st, id: Option<ControlId>| Ok(st.ui.children(id)))?;
    h.f("ui_destroy", |_, st, id: ControlId| Ok(st.ui.destroy(id)))?;
    h.f("ui_call", |_, st, a: Variadic<Value>| {
        let id = a.first().and_then(crate::api::int_of).unwrap_or(0) as ControlId;
        let m = a.get(1).and_then(crate::api::str_of).unwrap_or_default();
        st.ui.call(id, &m, a.iter().skip(2).map(Prop::from_lua_value).collect());
        Ok(())
    })?;
    h.f("ui_screen", |_, st, ()| Ok(st.ui.screen()))?;
    Ok(())
}
