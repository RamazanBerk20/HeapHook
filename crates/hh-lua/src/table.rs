//! Memory records (cheat table entries) as the Lua engine sees them, and the seam the app
//! implements to own them.
use std::sync::Mutex;

use hh_asm::AaState;
use hh_core::{Error, Result};
use hh_scan::{Fmt, VType};
use hh_tools::structure::Structure;

pub type RecId = u32;

/// One cheat table entry. The engine reads/writes these through [`TableHost`]; everything
/// the engine computes (current value, address) is derived from these fields.
#[derive(Debug, Clone)]
pub struct Record {
    pub id: RecId,
    pub parent: Option<RecId>,
    pub description: String,
    /// Base address expression (`"game.exe+1234"`, `"[player]+8"`, symbol, hex).
    pub address: String,
    /// Pointer offsets in the order they are applied: `[[base]+o0]+o1 ...`.
    pub offsets: Vec<i64>,
    pub vtype: VType,
    /// `len` = characters for strings, bytes for array of byte.
    pub fmt: Fmt,
    /// Auto Assembler script: makes this a script entry (CE type vtAutoAssembler).
    pub script: Option<String>,
    /// 0xBBGGRR like CE.
    pub color: u32,
    pub active: bool,
    /// Value captured when a value entry was activated (frozen). The host enforces the freeze
    /// (the app's `Freezer`); the engine only records what to freeze to.
    pub frozen_value: Option<String>,
    /// What the last enable of `script` did; needed to disable it.
    pub aa_state: Option<AaState>,
    /// CE `IsGroupHeader`: activating it runs nothing and reads nothing (children follow the
    /// group options).
    pub group_header: bool,
    /// CE memory record options (`moHideChildren`, `moActivateChildrenAsWell`,
    /// `moDeactivateChildrenAsWell`, `moRecursiveSetValue`, `moAllowManualCollapseAndExpand`,
    /// `moManualExpandCollapse`, `moAlwaysHideChildren`). The engine applies the activation
    /// cascade and recursive set value itself.
    pub options: Vec<String>,
    pub collapsed: bool,
    /// CE `DropDownList` lines, `value:description`.
    pub dropdown: Vec<String>,
    pub dropdown_readonly: bool,
    pub dropdown_description_only: bool,
    pub dropdown_display_as_item: bool,
    /// Hotkeys of this record. The host owns triggering them: when one is pressed it calls
    /// [`crate::Engine::fire_record_hotkey`].
    pub hotkeys: Vec<RecordHotkey>,
}

/// A memory record hotkey (CE `MemoryRecordHotkey`).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct RecordHotkey {
    /// Unique within its record.
    pub id: u32,
    /// CE virtual-key codes.
    pub keys: Vec<i64>,
    /// CE `mrh*`: 0 toggle, 1 toggle (allow increase), 2 toggle (allow decrease), 3 activate,
    /// 4 deactivate, 5 set value, 6 increase value, 7 decrease value.
    pub action: i64,
    pub value: String,
    pub description: String,
}

impl Record {
    pub fn new(id: RecId, parent: Option<RecId>) -> Self {
        Record {
            id,
            parent,
            description: "No description".into(),
            address: "0".into(),
            offsets: Vec::new(),
            vtype: VType::Bytes4,
            fmt: Fmt::default(),
            script: None,
            color: 0,
            active: false,
            frozen_value: None,
            aa_state: None,
            group_header: false,
            options: Vec::new(),
            collapsed: false,
            dropdown: Vec::new(),
            dropdown_readonly: false,
            dropdown_description_only: false,
            dropdown_display_as_item: false,
            hotkeys: Vec::new(),
        }
    }
}

/// The address list the engine scripts against. The app implements this over its table.
pub trait TableHost: Send + Sync {
    /// Every record id in display order (parents before their children).
    fn ids(&self) -> Vec<RecId>;
    fn get(&self, id: RecId) -> Option<Record>;
    /// Replaces the record with the same id.
    fn set(&self, rec: Record) -> Result<()>;
    /// Adds a default record (see [`Record::new`]) under `parent` and returns its id.
    fn create(&self, parent: Option<RecId>) -> RecId;
    /// Removes the record and its children.
    fn delete(&self, id: RecId);
    /// Selected records (address list selection). Default: none.
    fn selected(&self) -> Vec<RecId> {
        Vec::new()
    }
    /// Changes the selection. Default: ignored.
    fn set_selected(&self, _ids: &[RecId]) {}
    /// The global structure list (CE `getStructureCount`/`getStructure`), when the host owns
    /// one. Default `None`: the engine keeps its own list.
    fn structures(&self) -> Option<Vec<Structure>> {
        None
    }
    /// Replaces the host's structure list; return false if the host has none (the engine
    /// then keeps it). Default false.
    fn set_structures(&self, _s: Vec<Structure>) -> bool {
        false
    }
}

/// In-memory [`TableHost`] for headless use and tests.
#[derive(Default)]
pub struct MemTable {
    inner: Mutex<(Vec<Record>, RecId)>,
    selection: Mutex<Vec<RecId>>,
}

impl MemTable {
    pub fn new() -> Self {
        Self::default()
    }
}

impl TableHost for MemTable {
    fn ids(&self) -> Vec<RecId> {
        let g = self.inner.lock().unwrap();
        // Depth-first so children follow their parent.
        fn walk(recs: &[Record], parent: Option<RecId>, out: &mut Vec<RecId>) {
            for r in recs.iter().filter(|r| r.parent == parent) {
                out.push(r.id);
                walk(recs, Some(r.id), out);
            }
        }
        let mut out = Vec::new();
        walk(&g.0, None, &mut out);
        out
    }
    fn get(&self, id: RecId) -> Option<Record> {
        self.inner.lock().unwrap().0.iter().find(|r| r.id == id).cloned()
    }
    fn set(&self, rec: Record) -> Result<()> {
        let mut g = self.inner.lock().unwrap();
        let slot = g.0.iter_mut().find(|r| r.id == rec.id).ok_or_else(|| Error::Other(format!("no record {}", rec.id)))?;
        *slot = rec;
        Ok(())
    }
    fn create(&self, parent: Option<RecId>) -> RecId {
        let mut g = self.inner.lock().unwrap();
        g.1 += 1;
        let id = g.1;
        g.0.push(Record::new(id, parent));
        id
    }
    fn delete(&self, id: RecId) {
        let mut g = self.inner.lock().unwrap();
        let mut gone = vec![id];
        while let Some(p) = gone.pop() {
            g.0.retain(|r| r.id != p);
            gone.extend(g.0.iter().filter(|r| r.parent == Some(p)).map(|r| r.id));
        }
    }
    fn selected(&self) -> Vec<RecId> {
        let ids = self.ids();
        self.selection.lock().unwrap().iter().copied().filter(|i| ids.contains(i)).collect()
    }
    fn set_selected(&self, ids: &[RecId]) {
        *self.selection.lock().unwrap() = ids.to_vec();
    }
}
