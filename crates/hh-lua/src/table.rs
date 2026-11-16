//! Memory records (cheat table entries) as the Lua engine sees them, and the seam the app
//! implements to own them.
use std::sync::Mutex;

use hh_asm::AaState;
use hh_core::{Error, Result};
use hh_scan::{Fmt, VType};

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
}

/// In-memory [`TableHost`] for headless use and tests.
#[derive(Default)]
pub struct MemTable {
    inner: Mutex<(Vec<Record>, RecId)>,
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
}
