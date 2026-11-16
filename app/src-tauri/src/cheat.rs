//! The live cheat table: the single source of truth for entries and their activation.
//!
//! The backend owns it because the Lua engine reads and writes memory records synchronously
//! from any thread (`TableHost`) and the freezer and hotkeys must work while the UI is busy
//! or hidden. The UI keeps a mirror: it fetches `{version, table}` when the version moves and
//! sends whole-table edits with the version it based them on (`table_put` rejects stale
//! ones; the UI refetches and replays its edit). Activation (`frozen`), the frozen value and
//! Auto Assembler state are runtime-owned here and never taken from a put.
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Mutex;

use hh_asm::AaState;
use hh_core::{Addr, Error, Result as HResult};
use hh_lua::{RecId, Record, TableHost};
use hh_scan::{Fmt, FreezeMode, FrozenEntry, VType, ValueRef};
use serde::Serialize;

use crate::commands::{App, R, lock, parse_addr};
use crate::table::{self, Entry, Table};

/// CE `clWindowText`: "default color" for records whose entry has no color.
const DEFAULT_COLOR: u32 = 0x8000_0008;

#[derive(Default)]
struct Rt {
    aa_state: Option<AaState>,
    frozen_value: Option<String>,
}

#[derive(Default)]
struct Inner {
    table: Table,
    version: u64,
    rt: HashMap<i64, Rt>,
    /// (id, active) of records with children whose activation changed; the group options
    /// decide what happens to the children (`App::drain_cascades`).
    cascade: Vec<(i64, bool)>,
    freeze_dirty: bool,
    /// Earlier / undone tables of user edits (puts, structure and code-list changes).
    undo: Vec<Table>,
    redo: Vec<Table>,
}

/// Table versions kept for undo.
const MAX_UNDO: usize = 100;

impl Inner {
    fn bump(&mut self) {
        self.version += 1;
        self.freeze_dirty = true;
    }

    /// Installs `t` keeping activation (runtime-owned); `history` records the old table.
    fn install(&mut self, mut t: Table, history: bool) {
        let active: HashMap<i64, bool> = all(&self.table.entries).into_iter().map(|(e, _)| (e.id, e.frozen)).collect();
        for_each_mut(&mut t.entries, &mut |e| e.frozen = active.get(&e.id).copied().unwrap_or(false));
        let ids: HashSet<i64> = all(&t.entries).into_iter().map(|(e, _)| e.id).collect();
        self.rt.retain(|id, _| ids.contains(id));
        let old = std::mem::replace(&mut self.table, t);
        if history && old != self.table {
            self.undo.push(old);
            if self.undo.len() > MAX_UNDO {
                self.undo.remove(0);
            }
            self.redo.clear();
        }
        self.bump();
    }
}

/// Ids of active script entries in `old` that `new` no longer has (they must be disabled
/// before the edit lands, or their patches stay in the game with nothing to undo them).
pub(crate) fn removed_active_scripts(old: &Table, new: &Table) -> Vec<i64> {
    let keep: HashSet<i64> = all(&new.entries).into_iter().map(|(e, _)| e.id).collect();
    all(&old.entries).into_iter().filter(|(e, _)| e.frozen && e.script.is_some() && !keep.contains(&e.id)).map(|(e, _)| e.id).collect()
}

#[derive(Default)]
pub struct Live(Mutex<Inner>);

#[derive(Debug, Clone, Serialize)]
pub struct TableState {
    pub version: u64,
    pub table: Table,
}

pub fn is_group(e: &Entry) -> bool {
    e.script.is_none() && e.addr.trim().is_empty()
}

fn has_opt(e: &Entry, o: &str) -> bool {
    e.options.iter().any(|x| x == o)
}

fn walk<'a>(list: &'a [Entry], parent: Option<i64>, out: &mut Vec<(&'a Entry, Option<i64>)>) {
    for e in list {
        out.push((e, parent));
        walk(&e.children, Some(e.id), out);
    }
}

fn all(list: &[Entry]) -> Vec<(&Entry, Option<i64>)> {
    let mut out = Vec::new();
    walk(list, None, &mut out);
    out
}

fn find_mut(list: &mut [Entry], id: i64) -> Option<&mut Entry> {
    for e in list {
        if e.id == id {
            return Some(e);
        }
        if let Some(x) = find_mut(&mut e.children, id) {
            return Some(x);
        }
    }
    None
}

fn for_each_mut(list: &mut [Entry], f: &mut impl FnMut(&mut Entry)) {
    for e in list {
        f(e);
        for_each_mut(&mut e.children, f);
    }
}

/// Removes the entry (with its children) wherever it is.
fn take(list: &mut Vec<Entry>, id: i64) -> Option<Entry> {
    if let Some(i) = list.iter().position(|e| e.id == id) {
        return Some(list.remove(i));
    }
    list.iter_mut().find_map(|e| take(&mut e.children, id))
}

pub fn fmt_of(e: &Entry) -> Fmt {
    Fmt { len: (e.len > 0).then_some(e.len), signed: e.signed, hex: e.hex, utf16: e.utf16 }
}

/// `"1C"`, `"-8"`, `"0x10"` -> number; unparsable offsets read as 0.
fn parse_off(o: &str) -> i64 {
    let t = o.trim();
    let (neg, b) = t.strip_prefix('-').map_or((false, t), |r| (true, r));
    let v = i64::from_str_radix(b.trim_start_matches("0x").trim_start_matches("0X"), 16).unwrap_or(0);
    if neg { -v } else { v }
}

fn fmt_off(o: i64) -> String {
    if o < 0 { format!("-{:X}", o.unsigned_abs()) } else { format!("{o:X}") }
}

/// `#RRGGBB` <-> CE 0xBBGGRR (high byte set = system default color).
fn color_in(c: Option<&str>) -> u32 {
    c.and_then(|s| u32::from_str_radix(s.trim_start_matches('#'), 16).ok().filter(|_| s.len() == 7))
        .map_or(DEFAULT_COLOR, |v| ((v & 0xff) << 16) | (v & 0xff00) | (v >> 16))
}

fn color_out(c: u32) -> Option<String> {
    (c >> 24 == 0).then(|| format!("#{:02X}{:02X}{:02X}", c & 0xff, (c >> 8) & 0xff, (c >> 16) & 0xff))
}

fn record(e: &Entry, parent: Option<i64>, rt: Option<&Rt>) -> Record {
    let mut r = Record::new(e.id as RecId, parent.map(|p| p as RecId));
    r.description = e.description.clone();
    r.address = e.addr.clone();
    r.offsets = e.offsets.iter().map(|o| parse_off(o)).collect();
    r.vtype = e.vtype;
    r.fmt = fmt_of(e);
    // shortcut: hh-lua activates a record either as a script or by reading its value; a group
    // header is handed over as an empty script (enabling it runs nothing), so Lua sees Type 11
    // for headers. Upgrade when hh-lua knows group records.
    r.script = if is_group(e) { Some(String::new()) } else { e.script.clone() };
    r.color = color_in(e.color.as_deref());
    r.active = e.frozen;
    if let Some(rt) = rt {
        r.aa_state = rt.aa_state.clone();
        r.frozen_value = rt.frozen_value.clone();
    }
    r
}

impl Live {
    pub fn state(&self) -> TableState {
        let g = lock(&self.0);
        TableState { version: g.version, table: g.table.clone() }
    }

    pub fn version(&self) -> u64 {
        lock(&self.0).version
    }

    pub(crate) fn entry(&self, id: i64) -> Option<Entry> {
        all(&lock(&self.0).table.entries).into_iter().find(|(e, _)| e.id == id).map(|(e, _)| e.clone())
    }

    /// Replaces the table with a UI edit based on `base`. Activation stays as it is here.
    pub fn put(&self, t: Table, base: u64) -> R<u64> {
        let mut g = lock(&self.0);
        if base != g.version {
            return Err(format!("stale table version {base} (current {})", g.version));
        }
        let mut seen = HashSet::new();
        for (e, _) in all(&t.entries) {
            if e.id <= 0 || e.id > u32::MAX as i64 || !seen.insert(e.id) {
                return Err(format!("bad or duplicate entry id {}", e.id));
            }
        }
        g.install(t, true);
        Ok(g.version)
    }

    pub(crate) fn set_structures(&self, s: Vec<hh_tools::structure::Structure>) {
        let mut g = lock(&self.0);
        let t = Table { structures: s, ..g.table.clone() };
        g.install(t, true);
    }

    pub(crate) fn set_codes(&self, c: Vec<table::CodeEntry>) {
        let mut g = lock(&self.0);
        let t = Table { codes: c, ..g.table.clone() };
        g.install(t, true);
    }

    /// The table one undo (`redo` false) or redo step away, if any.
    pub(crate) fn peek_history(&self, redo: bool) -> Option<Table> {
        let g = lock(&self.0);
        if redo { g.redo.last().cloned() } else { g.undo.last().cloned() }
    }

    /// Steps back (or forward) through edits; activation is kept as it is now.
    pub(crate) fn step_history(&self, redo: bool) -> R<TableState> {
        let mut g = lock(&self.0);
        let t = if redo { g.redo.pop() } else { g.undo.pop() }.ok_or(if redo { "nothing to redo" } else { "nothing to undo" })?;
        let cur = g.table.clone();
        g.install(t, false);
        if redo { g.undo.push(cur) } else { g.redo.push(cur) }
        Ok(TableState { version: g.version, table: g.table.clone() })
    }

    /// (undo steps, redo steps) available.
    pub fn history_len(&self) -> (usize, usize) {
        let g = lock(&self.0);
        (g.undo.len(), g.redo.len())
    }

    /// A freshly loaded table: everything inactive.
    pub fn replace(&self, mut t: Table) -> TableState {
        for_each_mut(&mut t.entries, &mut |e| e.frozen = false);
        let mut g = lock(&self.0);
        g.table = t;
        g.rt.clear();
        g.cascade.clear();
        g.undo.clear();
        g.redo.clear();
        g.bump();
        TableState { version: g.version, table: g.table.clone() }
    }

    /// Process changed: scripts patched the old process, so they are off; value entries stay
    /// frozen to the same values.
    pub(crate) fn scripts_off(&self) {
        let mut g = lock(&self.0);
        let mut off = Vec::new();
        for_each_mut(&mut g.table.entries, &mut |e| {
            if e.frozen && e.script.is_some() {
                e.frozen = false;
                off.push(e.id);
            }
        });
        for id in off {
            g.rt.remove(&id);
        }
        g.bump();
    }

    /// Active value entries and the value each is frozen to.
    pub(crate) fn frozen(&self) -> Vec<(Entry, String)> {
        let g = lock(&self.0);
        all(&g.table.entries)
            .into_iter()
            .filter(|(e, _)| e.frozen && e.script.is_none() && !is_group(e))
            .filter_map(|(e, _)| Some((e.clone(), g.rt.get(&e.id)?.frozen_value.clone()?)))
            .collect()
    }

    pub(crate) fn set_frozen_value(&self, id: i64, v: &str) {
        let mut g = lock(&self.0);
        let active = all(&g.table.entries).iter().any(|(e, _)| e.id == id && e.frozen);
        if active {
            g.rt.entry(id).or_default().frozen_value = Some(v.to_string());
            g.freeze_dirty = true;
        }
    }

    pub(crate) fn set_mode(&self, id: i64, m: FreezeMode) {
        let mut g = lock(&self.0);
        if let Some(e) = find_mut(&mut g.table.entries, id).filter(|e| e.freeze_mode != m) {
            e.freeze_mode = m;
            g.bump();
        }
    }

    pub(crate) fn take_cascade(&self) -> Vec<(i64, bool)> {
        std::mem::take(&mut lock(&self.0).cascade)
    }

    pub(crate) fn take_dirty(&self) -> bool {
        std::mem::take(&mut lock(&self.0).freeze_dirty)
    }

    /// (keys, entry id, hotkey index) of every entry hotkey.
    pub(crate) fn hotkeys(&self) -> Vec<(Vec<u32>, i64, usize)> {
        let g = lock(&self.0);
        all(&g.table.entries)
            .into_iter()
            .flat_map(|(e, _)| e.hotkeys.iter().enumerate().map(move |(i, h)| (h.keys.clone(), e.id, i)))
            .collect()
    }
}

impl TableHost for Live {
    fn ids(&self) -> Vec<RecId> {
        all(&lock(&self.0).table.entries).into_iter().map(|(e, _)| e.id as RecId).collect()
    }

    fn get(&self, id: RecId) -> Option<Record> {
        let g = lock(&self.0);
        all(&g.table.entries).into_iter().find(|(e, _)| e.id == id as i64).map(|(e, p)| record(e, p, g.rt.get(&e.id)))
    }

    fn set(&self, rec: Record) -> HResult<()> {
        let mut g = lock(&self.0);
        let id = rec.id as i64;
        let (old, parent) = all(&g.table.entries)
            .into_iter()
            .find(|(e, _)| e.id == id)
            .map(|(e, p)| (record(e, p, None), p))
            .ok_or_else(|| Error::Other(format!("no record {id}")))?;
        let e = find_mut(&mut g.table.entries, id).expect("found above");
        let group = is_group(e);
        e.description = rec.description.clone();
        if !group {
            e.addr = rec.address.clone();
            e.script = rec.script.clone();
            e.vtype = rec.vtype;
        }
        if old.offsets != rec.offsets {
            e.offsets = rec.offsets.iter().map(|&o| fmt_off(o)).collect();
        }
        e.len = rec.fmt.len.unwrap_or(0);
        e.signed = rec.fmt.signed;
        e.hex = rec.fmt.hex;
        e.utf16 = rec.fmt.utf16;
        if old.color != rec.color {
            e.color = color_out(rec.color);
        }
        let toggled = e.frozen != rec.active;
        e.frozen = rec.active;
        let has_kids = !e.children.is_empty();
        let rt = g.rt.entry(id).or_default();
        rt.aa_state = rec.aa_state.clone();
        rt.frozen_value = rec.frozen_value.clone();
        if toggled && has_kids {
            g.cascade.push((id, rec.active));
        }
        let new_parent = rec.parent.map(|p| p as i64);
        if new_parent != parent {
            let moved = take(&mut g.table.entries, id).expect("found above");
            match new_parent {
                None => g.table.entries.push(moved),
                Some(p) => match find_mut(&mut g.table.entries, p) {
                    Some(pe) => pe.children.push(moved),
                    // The new parent is gone or inside the moved subtree: put it back on top.
                    None => g.table.entries.push(moved),
                },
            }
        }
        g.bump();
        Ok(())
    }

    fn create(&self, parent: Option<RecId>) -> RecId {
        let mut g = lock(&self.0);
        let id = all(&g.table.entries).iter().map(|(e, _)| e.id).max().unwrap_or(0) + 1;
        let e = Entry { id, description: "No description".into(), addr: "0".into(), ..Entry::default() };
        match parent.and_then(|p| find_mut(&mut g.table.entries, p as i64)) {
            Some(p) => p.children.push(e),
            None => g.table.entries.push(e),
        }
        g.bump();
        id as RecId
    }

    fn delete(&self, id: RecId) {
        let mut g = lock(&self.0);
        if let Some(e) = take(&mut g.table.entries, id as i64) {
            for (x, _) in all(std::slice::from_ref(&e)) {
                g.rt.remove(&x.id);
            }
            g.bump();
        }
    }
}

/// `[[addr]+o0]+o1`: the expression `resolve_address` understands.
pub fn expr_of(e: &Entry) -> String {
    e.offsets.iter().fold(e.addr.trim().to_string(), |x, o| format!("[{x}]+{}", o.trim()))
}

/// Adds `delta` to a displayed value (`hex` = both are hex); `None` when not numeric.
fn add_value(vtype: VType, cur: &str, delta: &str, hex: bool, sign: i128) -> Option<String> {
    if matches!(vtype, VType::Float | VType::Double) {
        let v = cur.trim().parse::<f64>().ok()? + sign as f64 * delta.trim().parse::<f64>().ok()?;
        return Some(v.to_string());
    }
    let int = |s: &str| {
        let t = s.trim();
        let (neg, b) = t.strip_prefix('-').map_or((false, t), |r| (true, r));
        let b = b.trim_start_matches("0x").trim_start_matches("0X");
        let v = if hex { i128::from_str_radix(b, 16).ok()? } else { b.parse::<i128>().ok()? };
        Some(if neg { -v } else { v })
    };
    let width = match vtype {
        VType::Byte => 8,
        VType::Bytes2 => 16,
        VType::Bytes4 => 32,
        VType::Bytes8 => 64,
        _ => return None,
    };
    let v = int(cur)? + sign * int(delta)?;
    // Wrap like the game's integer would (CE does the same).
    let mask = (1i128 << width) - 1;
    let u = v & mask;
    Some(if hex { format!("0x{u:X}") } else { u.to_string() })
}

impl App {
    pub fn table_get(&self) -> R<TableState> {
        Ok(self.x.live.state())
    }

    /// A UI edit. Active script entries the edit removes are disabled first (their
    /// `[DISABLE]` section runs); if that fails the edit is refused and the entry stays.
    pub fn table_put(&self, t: Table, base: u64) -> R<u64> {
        let cur = self.x.live.state();
        if base != cur.version {
            return Err(format!("stale table version {base} (current {})", cur.version));
        }
        let gone = removed_active_scripts(&cur.table, &t);
        if gone.is_empty() {
            return self.x.live.put(t, base);
        }
        self.table_set_active(&gone, false).map_err(|e| format!("{e}\nnot deleted: the script could not be disabled"))?;
        self.x.live.put(t, self.x.live.version())
    }

    /// Undo (`redo` false) or redo one table edit. Active scripts the step removes are
    /// disabled first, like a delete.
    pub fn table_history(&self, redo: bool) -> R<TableState> {
        let target = self.x.live.peek_history(redo).ok_or(if redo { "nothing to redo" } else { "nothing to undo" })?;
        let gone = removed_active_scripts(&self.x.live.state().table, &target);
        if !gone.is_empty() {
            self.table_set_active(&gone, false)?;
        }
        let st = self.x.live.step_history(redo)?;
        self.sync_freeze();
        Ok(st)
    }

    /// Loads a JSON or `.CT` file as the live table (everything inactive). Running its Lua
    /// script is a separate, user-confirmed step (`table_run_script`).
    pub fn table_open(&self, path: &str) -> R<TableState> {
        let t = table::load(Path::new(path))?;
        Ok(self.x.live.replace(t))
    }

    /// Writes the live table; JSON or `.CT` by extension.
    pub fn table_export(&self, path: &str) -> R<()> {
        table::save(Path::new(path), &self.x.live.state().table)
    }

    /// Resolved address of a value entry.
    pub(crate) fn entry_addr(&self, e: &Entry) -> R<Addr> {
        parse_addr(&self.resolve_address(&expr_of(e))?)
    }

    /// Activates/deactivates like CE: OnActivate/OnDeactivate, Auto Assembler (with `{$lua}`)
    /// for scripts, freeze for values, group options for children.
    pub fn table_set_active(&self, ids: &[i64], active: bool) -> R<()> {
        let mut errs = Vec::new();
        {
            let _g = self.x.lua.enter();
            for &id in ids {
                if let Err(e) = self.activate_locked(id, active) {
                    errs.push(e);
                }
            }
            errs.extend(self.cascade_locked());
        }
        if errs.is_empty() { Ok(()) } else { Err(errs.join("\n")) }
    }

    /// Caller holds the Lua lock.
    fn activate_locked(&self, id: i64, active: bool) -> R<()> {
        let e = self.x.live.entry(id).ok_or_else(|| format!("no table entry {id}"))?;
        // Group headers toggle without a process too (hh-lua needs one to "run" the header).
        if is_group(&e) && self.session().is_err() {
            let mut r = TableHost::get(&*self.x.live, id as RecId).ok_or("entry vanished")?;
            r.active = active;
            return TableHost::set(&*self.x.live, r).map_err(|e| e.to_string());
        }
        self.x.lua.engine.set_active(id as RecId, active).map_err(|err| {
            let t = err.to_string();
            if t.starts_with(&e.description) { t } else { format!("{}: {t}", e.description) }
        })
    }

    /// Applies queued group options: moActivateChildrenAsWell / moDeactivateChildrenAsWell.
    fn cascade_locked(&self) -> Vec<String> {
        let mut errs = Vec::new();
        loop {
            let q = self.x.live.take_cascade();
            if q.is_empty() {
                return errs;
            }
            for (id, on) in q {
                let Some(e) = self.x.live.entry(id) else { continue };
                let opt = if on { "moActivateChildrenAsWell" } else { "moDeactivateChildrenAsWell" };
                if !has_opt(&e, opt) {
                    continue;
                }
                for c in e.children.iter().filter(|c| c.frozen != on) {
                    if let Err(err) = self.activate_locked(c.id, on) {
                        errs.push(err);
                    }
                }
            }
        }
    }

    /// Cascades queued by Lua (`memrec.Active = ...`) outside `table_set_active`.
    pub(crate) fn drain_cascades(&self) {
        let errs = {
            let _g = self.x.lua.enter();
            self.cascade_locked()
        };
        for e in errs {
            self.x.lua.console.push("err", &e);
        }
    }

    /// Writes `value` to each entry (groups with moRecursiveSetValue: to their value
    /// children); a frozen entry freezes to the new value.
    pub fn table_set_value(&self, ids: &[i64], value: &str) -> R<()> {
        let mut errs = Vec::new();
        for &id in ids {
            let Some(e) = self.x.live.entry(id) else { continue };
            let targets: Vec<Entry> = if is_group(&e) || e.script.is_some() {
                if !has_opt(&e, "moRecursiveSetValue") {
                    continue;
                }
                all(&e.children).into_iter().filter(|(c, _)| c.script.is_none() && !is_group(c)).map(|(c, _)| c.clone()).collect()
            } else {
                vec![e]
            };
            for t in targets {
                if let Err(err) = self.write_entry(&t, value) {
                    errs.push(format!("{}: {err}", t.description));
                }
            }
        }
        self.x.live.take_dirty();
        self.sync_freeze();
        if errs.is_empty() { Ok(()) } else { Err(errs.join("\n")) }
    }

    fn write_entry(&self, e: &Entry, value: &str) -> R<()> {
        let a = self.entry_addr(e)?;
        hh_scan::write_value(&*self.session()?.proc, a, e.vtype, value, &fmt_of(e)).map_err(|x| x.to_string())?;
        self.x.live.set_frozen_value(e.id, value);
        Ok(())
    }

    fn read_entry(&self, e: &Entry) -> R<String> {
        let a = self.entry_addr(e)?;
        let r = ValueRef { addr: a, vtype: e.vtype, fmt: fmt_of(e) };
        hh_scan::read_values(&*self.session()?.proc, &[r]).pop().flatten().ok_or_else(|| format!("cannot read {a:#x}"))
    }

    /// Runs hotkey `index` of entry `id` (CE actions).
    pub fn table_hotkey(&self, id: i64, index: usize) -> R<()> {
        let e = self.x.live.entry(id).ok_or_else(|| format!("no table entry {id}"))?;
        let hk = e.hotkeys.get(index).ok_or_else(|| format!("{}: no hotkey {index}", e.description))?.clone();
        let val = hk.value.clone().unwrap_or_default();
        match hk.action.as_str() {
            "Toggle Activation" => self.table_set_active(&[id], !e.frozen),
            "Toggle Activation Allow Increase" | "Toggle Activation Allow Decrease" => {
                let m = if hk.action.ends_with("Increase") { FreezeMode::AllowIncrease } else { FreezeMode::AllowDecrease };
                self.x.live.set_mode(id, m);
                self.table_set_active(&[id], !e.frozen)
            }
            "Activate" => self.table_set_active(&[id], true),
            "Deactivate" => self.table_set_active(&[id], false),
            "Set Value" => self.table_set_value(&[id], &val),
            "Increase Value" | "Decrease Value" => {
                let sign = if hk.action.starts_with("Increase") { 1 } else { -1 };
                let cur = self.read_entry(&e)?;
                let next = add_value(e.vtype, &cur, &val, e.hex, sign).ok_or_else(|| format!("{}: {cur:?} {val:?} are not numbers", e.description))?;
                self.table_set_value(&[id], &next)
            }
            a => Err(format!("{}: unknown hotkey action {a:?}", e.description)),
        }
    }

    /// Hands the active value entries to the freezer (addresses re-resolved).
    pub(crate) fn sync_freeze(&self) {
        let Ok(sess) = self.session() else { return };
        let list: Vec<FrozenEntry> = self
            .x
            .live
            .frozen()
            .into_iter()
            .filter_map(|(e, value)| {
                let addr = self.entry_addr(&e).ok()?;
                Some(FrozenEntry { addr, vtype: e.vtype, value, mode: e.freeze_mode, fmt: fmt_of(&e) })
            })
            .collect();
        if let Err(e) = sess.freezer.set(&list) {
            self.x.lua.console.push("err", &format!("freeze: {e}"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_offsets_colors() {
        assert_eq!(add_value(VType::Bytes4, "10", "5", false, 1).as_deref(), Some("15"));
        assert_eq!(add_value(VType::Byte, "0", "1", false, -1).as_deref(), Some("255"));
        assert_eq!(add_value(VType::Bytes2, "FF", "1", true, 1).as_deref(), Some("0x100"));
        assert_eq!(add_value(VType::Float, "1.5", "0.25", false, 1).as_deref(), Some("1.75"));
        assert_eq!(add_value(VType::String, "a", "1", false, 1), None);
        assert_eq!((parse_off("1C"), parse_off("-8"), parse_off("0x10")), (0x1c, -8, 0x10));
        assert_eq!((fmt_off(0x1c), fmt_off(-8)), ("1C".to_string(), "-8".to_string()));
        assert_eq!(color_in(Some("#FF0000")), 0x0000FF);
        assert_eq!(color_out(0x0000FF).as_deref(), Some("#FF0000"));
        assert_eq!((color_in(None), color_out(DEFAULT_COLOR)), (DEFAULT_COLOR, None));
    }

    #[test]
    fn put_keeps_activation_and_rejects_stale() {
        let live = Live::default();
        let e = |id, kids| Entry { id, addr: "0x10".into(), children: kids, ..Entry::default() };
        let v = live.put(Table { entries: vec![e(1, vec![e(2, vec![])])], ..Table::default() }, 0).unwrap();
        let mut r = TableHost::get(&live, 2).unwrap();
        assert_eq!(r.parent, Some(1));
        r.active = true;
        r.frozen_value = Some("5".into());
        TableHost::set(&live, r).unwrap();
        assert!(live.put(Table::default(), v).unwrap_err().contains("stale"));
        let mut t = live.state().table;
        t.entries[0].children[0].frozen = false; // the UI cannot switch it off this way
        t.entries[0].description = "renamed".into();
        live.put(t, live.version()).unwrap();
        let s = live.state();
        assert!(s.table.entries[0].children[0].frozen && s.table.entries[0].description == "renamed");
        assert_eq!(live.frozen().len(), 1);
        // Lua: create under 1, re-parent to top, delete.
        let n = TableHost::create(&live, Some(1));
        assert_eq!(TableHost::ids(&live), [1, 2, n]);
        let mut r = TableHost::get(&live, n).unwrap();
        r.parent = None;
        TableHost::set(&live, r).unwrap();
        assert_eq!(live.state().table.entries.len(), 2);
        TableHost::delete(&live, 1);
        assert_eq!(TableHost::ids(&live), [n]);
        assert!(live.frozen().is_empty());
    }
}
