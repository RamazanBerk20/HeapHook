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
use hh_lua::{Caps, RecId, Record, RecordHotkey, TableHost};
use hh_scan::{Fmt, FreezeMode, FrozenEntry, FrozenEntryEx};
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

/// Where an entry's content came from. Trust is decided by this, never by the content. The
/// backend issues every entry id (ids only grow for the lifetime of a table, never reused) and
/// records its origin when it issues it; neither ever changes afterwards (a put, an undo or a
/// redo cannot touch them), and nothing is forgotten until another table is opened. Editing
/// an untrusted entry does not make it trusted: only consent does (`Live::grant`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// Made in this session by the user (`table_new`, a typed Auto Assemble window's "Assign
    /// to table", a local template) or by trusted Lua (`createMemoryRecord`).
    Own,
    /// Came with the table file that was opened (a dropped file, the command line, Lua's
    /// `loadTable(f)`): under the table's consent ([`Trust`]).
    Table,
    /// Came into this table from elsewhere (paste, merge, Lua's `loadTable(f, true)`, a
    /// script file assigned from the Auto Assemble window, a template that embeds a remote
    /// target's names): under its own consent.
    Foreign,
}

/// What an Auto Assemble window's content is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AaSess {
    /// Only typed (or pasted by the user) since the window opened.
    Typed,
    /// A file was loaded into it; `agreed`: the user consented since.
    File { agreed: bool },
}

/// Something the user can consent to.
pub(crate) enum Grant<'a> {
    Table,
    Entries(&'a [i64]),
    AaSession(u64),
}

#[derive(Default)]
struct Inner {
    table: Table,
    version: u64,
    rt: HashMap<i64, Rt>,
    freeze_dirty: bool,
    /// Earlier / undone tables of user edits (puts, structure and code-list changes).
    undo: Vec<Table>,
    redo: Vec<Table>,
    /// Consent for this table's Lua script and its [`Origin::Table`] entries.
    trust: Trust,
    /// Entry id -> origin, for every id issued since the table was opened (never pruned: an
    /// id that left the table may come back by undo / redo). An id without one was not
    /// issued by the backend: no capabilities, and a put may not bring it in.
    origin: HashMap<i64, Origin>,
    /// The last id issued; ids only grow until another table is opened.
    next_id: i64,
    /// [`Origin::Foreign`] entries the user consented to.
    agreed: HashSet<i64>,
    /// Settings say never to run a loaded table's Lua: nothing but the user's own runs Lua.
    never: bool,
    /// Auto Assemble window sessions (`aa_session`).
    aa: HashMap<u64, AaSess>,
    aa_next: u64,
    /// Content hash of the table when it was last opened or saved (`dirty`).
    saved: u64,
}

/// Hash of a script's text (session-local; never stored).
pub(crate) fn script_hash(s: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    s.hash(&mut h);
    h.finish()
}

/// The table without runtime state, hashed: what "unsaved changes" compares.
fn content_hash(t: &Table) -> u64 {
    let mut t = t.clone();
    for_each_mut(&mut t.entries, &mut |e| e.frozen = false);
    script_hash(&serde_json::to_string(&t).unwrap_or_default())
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

    /// Issues a new entry id with its origin.
    fn issue(&mut self, origin: Origin) -> i64 {
        self.next_id += 1;
        self.origin.insert(self.next_id, origin);
        self.next_id
    }

    /// THE capability decision for entry `id`: what its script and callbacks may do on every
    /// route (the engine asks through `TableHost::caps`, the app's own routes ask here).
    fn caps(&self, id: i64) -> Caps {
        let ok = match self.origin.get(&id) {
            None => false,
            Some(Origin::Own) => true,
            Some(Origin::Table) => self.trust.allows() && !self.never,
            Some(Origin::Foreign) => self.agreed.contains(&id) && !self.never,
        };
        if ok { Caps::Full } else { Caps::None }
    }

    fn st(&self) -> TableState {
        let mut untrusted: Vec<i64> = all(&self.table.entries)
            .into_iter()
            .filter(|(e, _)| self.origin.get(&e.id) == Some(&Origin::Foreign) && !self.agreed.contains(&e.id))
            .map(|(e, _)| e.id)
            .collect();
        untrusted.sort_unstable();
        TableState { version: self.version, table: self.table.clone(), trust: self.trust, untrusted }
    }
}

/// Ids of active script entries in `old` that `new` no longer has (they must be disabled
/// before the edit lands, or their patches stay in the game with nothing to undo them).
pub(crate) fn removed_active_scripts(old: &Table, new: &Table) -> Vec<i64> {
    let keep: HashSet<i64> = all(&new.entries).into_iter().map(|(e, _)| e.id).collect();
    all(&old.entries).into_iter().filter(|(e, _)| e.frozen && e.script.is_some() && !keep.contains(&e.id)).map(|(e, _)| e.id).collect()
}

#[derive(Default)]
pub struct Live(Mutex<Inner>, Mutex<Selection>);

/// The address list selection: the UI reports it (`table_select`); a script that sets it
/// bumps `seq` so the UI follows.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Selection {
    pub seq: u64,
    pub ids: Vec<i64>,
}

/// CE `mrh*` hotkey actions, in number order.
const HK_ACTIONS: [&str; 8] = [
    "Toggle Activation", "Toggle Activation Allow Increase", "Toggle Activation Allow Decrease", "Activate", "Deactivate", "Set Value",
    "Increase Value", "Decrease Value",
];

/// Ids for an entry's hotkeys: each kept id when unique, the rest numbered after the largest.
fn hotkey_ids(hks: &[table::Hotkey]) -> Vec<u32> {
    let mut seen = HashSet::new();
    let mut next = hks.iter().filter_map(|h| h.id).max().unwrap_or(0);
    hks.iter()
        .map(|h| match h.id.filter(|i| *i > 0 && seen.insert(*i)) {
            Some(i) => i,
            None => {
                next += 1;
                seen.insert(next);
                next
            }
        })
        .collect()
}

/// Consent for the Lua in a table: its table script and the `{$lua}` blocks of its entries.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Trust {
    /// Built in this session (no table file opened yet): the user's own.
    #[default]
    Own,
    /// Loaded from a file and the user agreed (Settings "never" withdraws it).
    Agreed,
    /// Loaded from a file (or by a script); not asked yet.
    Ask,
    Declined,
}

impl Trust {
    pub fn allows(self) -> bool {
        matches!(self, Trust::Own | Trust::Agreed)
    }
}

/// Error prefix the UI answers with a question and `table_trust`.
pub const NEEDS_CONSENT: &str = "needs consent:";
/// Error prefix for an entry that came from another table: the UI asks about the entries and
/// answers with `table_trust_entries` (it also starts with [`NEEDS_CONSENT`]).
pub const NEEDS_ENTRY_CONSENT: &str = "needs consent: entries:";

#[derive(Debug, Clone, Serialize)]
pub struct TableState {
    pub version: u64,
    pub table: Table,
    /// Consent for the table's Lua (`own`, `agreed`, `ask`, `declined`).
    pub trust: Trust,
    /// Entries that came from another table (paste, merge, ...) and still need the user's
    /// consent before their script gets Lua or file access, or their callbacks run.
    pub untrusted: Vec<i64>,
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

/// 1-based depth of entry `id` (0 when absent).
fn depth_of(list: &[Entry], id: i64) -> usize {
    let all = all(list);
    let parent: HashMap<i64, Option<i64>> = all.iter().map(|(e, p)| (e.id, *p)).collect();
    let (mut d, mut cur) = (0, parent.contains_key(&id).then_some(id));
    while let Some(c) = cur {
        d += 1;
        cur = parent.get(&c).copied().flatten();
    }
    d
}

/// Levels in the tree `list` (1 for a leaf list).
fn height(list: &[Entry]) -> usize {
    list.iter().map(|e| 1 + height(&e.children)).max().unwrap_or(0)
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
    // A custom type overrides `vtype`: `memrec.Value`, set value and hotkey increase /
    // decrease work in its converted units, and the frozen value is that converted text.
    (r.vtype, r.fmt, r.custom) = (e.vtype, fmt_of(e), e.custom);
    r.group_header = is_group(e);
    r.script = e.script.clone();
    r.color = color_in(e.color.as_deref());
    r.active = e.frozen;
    r.options = e.options.clone();
    if let Some(d) = &e.dropdown {
        r.dropdown = d.options.iter().map(|o| format!("{}:{}", o.value, o.text)).collect();
        (r.dropdown_readonly, r.dropdown_description_only, r.dropdown_display_as_item) = (d.read_only, d.description_only, d.display_value_as_item);
    }
    r.hotkeys = e
        .hotkeys
        .iter()
        .zip(hotkey_ids(&e.hotkeys))
        .map(|(h, id)| RecordHotkey {
            id,
            keys: h.keys.iter().map(|&k| k as i64).collect(),
            action: HK_ACTIONS.iter().position(|a| *a == h.action).unwrap_or(0) as i64,
            value: h.value.clone().unwrap_or_default(),
            description: h.description.clone().unwrap_or_default(),
        })
        .collect();
    if let Some(rt) = rt {
        r.aa_state = rt.aa_state.clone();
        r.frozen_value = rt.frozen_value.clone();
    }
    r
}

impl Live {
    pub fn state(&self) -> TableState {
        lock(&self.0).st()
    }

    pub fn trust(&self) -> Trust {
        lock(&self.0).trust
    }

    /// What entry `id` may do (see `Inner::caps`).
    pub(crate) fn caps(&self, id: i64) -> Caps {
        lock(&self.0).caps(id)
    }

    pub(crate) fn origin(&self, id: i64) -> Option<Origin> {
        lock(&self.0).origin.get(&id).copied()
    }

    /// The table's answer was no (or the open asks again): nothing is granted by it.
    pub(crate) fn decline(&self) -> bool {
        let mut g = lock(&self.0);
        let was = g.trust == Trust::Agreed;
        if g.trust != Trust::Own && g.trust != Trust::Declined {
            g.trust = Trust::Declined;
            g.bump();
        }
        was
    }

    /// THE one place trust is granted: the user consented to the table (its script and the
    /// entries that came with it), to entries from elsewhere, or to what was loaded into an
    /// Auto Assemble window. Refused while Settings say never. Editing never grants it.
    pub(crate) fn grant(&self, what: Grant) -> R<()> {
        let mut g = lock(&self.0);
        if g.never {
            return Err("Settings say never to run a table's Lua: change \"Lua script in a loaded table\" first".into());
        }
        match what {
            Grant::Table => {
                if g.trust != Trust::Own {
                    g.trust = Trust::Agreed;
                }
            }
            Grant::Entries(ids) => {
                let mut under = Vec::new();
                for (e, _) in all(&g.table.entries).into_iter().filter(|(e, _)| ids.contains(&e.id)) {
                    under.extend(all(std::slice::from_ref(e)).into_iter().map(|(c, _)| c.id).filter(|c| g.origin.get(c) == Some(&Origin::Foreign)));
                }
                g.agreed.extend(under);
            }
            Grant::AaSession(s) => match g.aa.get_mut(&s) {
                Some(x @ AaSess::File { .. }) => *x = AaSess::File { agreed: true },
                Some(AaSess::Typed) => {}
                None => return Err(format!("no Auto Assemble session {s}")),
            },
        }
        g.bump();
        Ok(())
    }

    /// Settings say never (`never` true) or no longer: with never, consent already given is
    /// withdrawn (the table's, every entry's, every Auto Assemble window's). True when
    /// something was withdrawn: what it started must be stopped.
    pub(crate) fn set_never(&self, never: bool) -> bool {
        let mut g = lock(&self.0);
        g.never = never;
        if !never {
            return false;
        }
        let mut was = g.trust == Trust::Agreed || !g.agreed.is_empty();
        if g.trust == Trust::Agreed {
            g.trust = Trust::Declined;
        }
        g.agreed.clear();
        for x in g.aa.values_mut() {
            if *x == (AaSess::File { agreed: true }) {
                *x = AaSess::File { agreed: false };
                was = true;
            }
        }
        g.bump();
        was
    }

    /// A merge brought a table script into a table without one: the table asks again; its
    /// entries that may run now keep running (they become agreed entries of their own).
    pub(crate) fn distrust_keeping_current(&self) {
        let mut g = lock(&self.0);
        if g.trust.allows() {
            let keep: Vec<i64> = g.origin.iter().filter(|(_, o)| **o == Origin::Table).map(|(id, _)| *id).collect();
            for id in keep {
                g.origin.insert(id, Origin::Foreign);
                g.agreed.insert(id);
            }
        }
        g.trust = Trust::Ask;
        g.bump();
    }

    /// A new Auto Assemble window session: what is typed into it is the user's own.
    pub(crate) fn aa_new(&self) -> u64 {
        let mut g = lock(&self.0);
        g.aa_next += 1;
        let id = g.aa_next;
        g.aa.insert(id, AaSess::Typed);
        id
    }

    /// A file was loaded into session `s`: its content is untrusted until consent, whatever
    /// is typed into it afterwards.
    pub(crate) fn aa_loaded(&self, s: u64) -> R<()> {
        let mut g = lock(&self.0);
        let x = g.aa.get_mut(&s).ok_or_else(|| format!("no Auto Assemble session {s}"))?;
        *x = AaSess::File { agreed: false };
        Ok(())
    }

    /// What session `s` may run; no (or an unknown) session: nothing (the backend cannot tell
    /// that the text was typed).
    pub(crate) fn aa_caps(&self, s: Option<u64>) -> Caps {
        let g = lock(&self.0);
        match s.and_then(|s| g.aa.get(&s)) {
            Some(AaSess::Typed) => Caps::Full,
            Some(AaSess::File { agreed: true }) if !g.never => Caps::Full,
            _ => Caps::None,
        }
    }

    /// The origin (and consent) an entry assigned from session `s` keeps.
    pub(crate) fn aa_origin(&self, s: u64) -> R<(Origin, bool)> {
        match lock(&self.0).aa.get(&s) {
            Some(AaSess::Typed) => Ok((Origin::Own, false)),
            Some(AaSess::File { agreed }) => Ok((Origin::Foreign, *agreed)),
            None => Err(format!("no Auto Assemble session {s}")),
        }
    }

    pub fn version(&self) -> u64 {
        lock(&self.0).version
    }

    pub(crate) fn entry(&self, id: i64) -> Option<Entry> {
        all(&lock(&self.0).table.entries).into_iter().find(|(e, _)| e.id == id).map(|(e, _)| e.clone())
    }

    /// Replaces the table with a UI edit based on `base`. Activation stays as it is here.
    pub fn put(&self, mut t: Table, base: u64) -> R<u64> {
        let mut g = lock(&self.0);
        if base != g.version {
            return Err(format!("stale table version {base} (current {})", g.version));
        }
        table::check_limits(&t.entries)?;
        table::check_structures(&t)?;
        let mut seen = HashSet::new();
        for (e, _) in all(&t.entries) {
            if e.id <= 0 || e.id > u32::MAX as i64 || !seen.insert(e.id) {
                return Err(format!("bad or duplicate entry id {}", e.id));
            }
            // New entries come from the backend commands that say where they came from
            // (`table_new`, `table_paste`, ...): a put only edits, moves and deletes.
            if !g.origin.contains_key(&e.id) {
                return Err(format!("entry id {} was not issued by HeapHook: add entries with table_new", e.id));
            }
        }
        // Raw `.CT` fragments only ever come from a `.CT` import: a put keeps one only when it
        // is exactly what this table already holds for that entry.
        {
            let held: HashMap<i64, &Vec<String>> = all(&g.table.entries).into_iter().map(|(e, _)| (e.id, &e.ct_extra)).collect();
            for_each_mut(&mut t.entries, &mut |e| {
                if !e.ct_extra.is_empty() && held.get(&e.id) != Some(&&e.ct_extra) {
                    e.ct_extra.clear();
                }
                table::clean_entry(e);
            });
            if t.ct_extra != g.table.ct_extra {
                t.ct_extra.clear();
            }
        }
        g.install(t, true);
        Ok(g.version)
    }

    /// Replaces the structure list; refused when it breaks the structure limits.
    pub(crate) fn set_structures(&self, s: Vec<hh_tools::structure::Structure>) -> R<()> {
        hh_tools::structure::validate_structures(&s).map_err(|e| e.to_string())?;
        let mut g = lock(&self.0);
        let t = Table { structures: s, ..g.table.clone() };
        g.install(t, true);
        Ok(())
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
        Ok(g.st())
    }

    /// (undo steps, redo steps) available.
    pub fn history_len(&self) -> (usize, usize) {
        let g = lock(&self.0);
        (g.undo.len(), g.redo.len())
    }

    /// A freshly loaded table: everything inactive, except the old entries `keep` (active
    /// scripts that could not be disabled), carried over into a group so they still can be.
    /// The new table is untrusted; the carried scripts stay runnable (they were before).
    pub fn replace(&self, mut t: Table, keep: &[i64]) -> TableState {
        for_each_mut(&mut t.entries, &mut |e| e.frozen = false);
        let mut g = lock(&self.0);
        let mut next = all(&t.entries).iter().map(|(e, _)| e.id).max().unwrap_or(0) + 1;
        let (mut rt, mut carried) = (HashMap::new(), Vec::new());
        // Every entry of the file is under the table's consent; carried ones keep theirs.
        let mut origin: HashMap<i64, Origin> = all(&t.entries).into_iter().map(|(e, _)| (e.id, Origin::Table)).collect();
        let mut agreed = HashSet::new();
        for &id in keep {
            let Some(mut e) = find_mut(&mut g.table.entries, id).map(|e| e.clone()) else { continue };
            e.children.clear();
            if g.origin.get(&id) == Some(&Origin::Own) {
                origin.insert(next, Origin::Own);
            } else {
                origin.insert(next, Origin::Foreign);
                if g.caps(id) == Caps::Full {
                    agreed.insert(next);
                }
            }
            e.id = next;
            if let Some(r) = g.rt.remove(&id) {
                rt.insert(next, r);
            }
            carried.push(e);
            next += 1;
        }
        if carried.is_empty() {
            next -= 1;
        } else {
            origin.insert(next, Origin::Own);
            t.entries.push(Entry { id: next, description: "Still active from the previous table".into(), children: carried, ..Entry::default() });
        }
        g.table = t;
        g.rt = rt;
        g.undo.clear();
        g.redo.clear();
        g.trust = Trust::Ask;
        g.origin = origin;
        g.agreed = agreed;
        g.next_id = next;
        g.saved = content_hash(&g.table);
        g.bump();
        g.st()
    }

    /// Inserts `entries` (new ids, inactive) after entry `after` (in its list) or at the end,
    /// all of them (children too) with fresh ids issued with `origin`, already agreed or not.
    /// A paste, a merge or a drop from another table never carries consent along. Returns
    /// the new version and the new top-level ids.
    pub(crate) fn insert(&self, mut entries: Vec<Entry>, after: Option<i64>, base: Option<u64>, origin: Origin, agreed: bool) -> R<(u64, Vec<i64>)> {
        let mut g = lock(&self.0);
        if let Some(b) = base.filter(|b| *b != g.version) {
            return Err(format!("stale table version {b} (current {})", g.version));
        }
        let mut n = 0;
        for_each_mut(&mut entries, &mut |_| n += 1);
        let (first, mut next) = (g.next_id + 1, g.next_id);
        if first.saturating_add(n) > u32::MAX as i64 {
            return Err("no entry ids left in this table".into());
        }
        for_each_mut(&mut entries, &mut |e| {
            next += 1;
            e.id = next;
            e.frozen = false;
            e.ct_extra.clear();
            table::clean_entry(e);
        });
        let mut t = g.table.clone();
        let ids: Vec<i64> = entries.iter().map(|e| e.id).collect();
        let mut place = Some(entries);
        if let Some(a) = after {
            fn put_after(list: &mut Vec<Entry>, a: i64, place: &mut Option<Vec<Entry>>) {
                if let Some(i) = list.iter().position(|e| e.id == a) {
                    let items = place.take().unwrap_or_default();
                    list.splice(i + 1..i + 1, items);
                    return;
                }
                for e in list.iter_mut() {
                    if place.is_none() {
                        return;
                    }
                    put_after(&mut e.children, a, place);
                }
            }
            put_after(&mut t.entries, a, &mut place);
        }
        if let Some(rest) = place {
            t.entries.extend(rest);
        }
        table::check_limits(&t.entries)?;
        // Issued only now that the insert cannot fail any more.
        for id in first..=next {
            let got = g.issue(origin);
            debug_assert_eq!(got, id);
            if agreed {
                g.agreed.insert(id);
            }
        }
        g.install(t, true);
        Ok((g.version, ids))
    }

    /// Whether the table changed since it was opened or saved (activation does not count).
    pub fn dirty(&self) -> bool {
        let g = lock(&self.0);
        let h = content_hash(&g.table);
        h != g.saved && !(g.saved == 0 && g.table == Table::default())
    }

    pub(crate) fn mark_saved(&self) {
        let mut g = lock(&self.0);
        g.saved = content_hash(&g.table);
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

    pub fn selection(&self) -> Selection {
        lock(&self.1).clone()
    }

    /// The UI's selection (does not bump `seq`: the UI already shows it).
    pub(crate) fn select(&self, ids: Vec<i64>) {
        lock(&self.1).ids = ids;
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
        e.description = rec.description.clone();
        if rec.group_header {
            // A header has no address and no script (CE `IsGroupHeader`).
            e.addr.clear();
            e.script = None;
        } else {
            // A header turned into a value entry needs an address to stay one.
            e.addr = if rec.address.trim().is_empty() && rec.script.is_none() { "0".into() } else { rec.address.clone() };
            e.script = rec.script.clone();
            e.custom = rec.custom;
            if e.custom.is_none() {
                e.vtype = rec.vtype;
            }
        }
        if old.options != rec.options {
            e.options = rec.options.clone();
        }
        if (&old.dropdown, old.dropdown_readonly, old.dropdown_description_only, old.dropdown_display_as_item)
            != (&rec.dropdown, rec.dropdown_readonly, rec.dropdown_description_only, rec.dropdown_display_as_item)
        {
            e.dropdown = (!rec.dropdown.is_empty()).then(|| table::Dropdown {
                options: rec
                    .dropdown
                    .iter()
                    .map(|l| match l.split_once(':') {
                        Some((v, t)) => table::DropdownItem { value: v.trim().into(), text: t.trim().into() },
                        None => table::DropdownItem { value: l.trim().into(), text: String::new() },
                    })
                    .collect(),
                read_only: rec.dropdown_readonly,
                description_only: rec.dropdown_description_only,
                display_value_as_item: rec.dropdown_display_as_item,
            });
        }
        if old.hotkeys != rec.hotkeys {
            e.hotkeys = rec
                .hotkeys
                .iter()
                .map(|h| table::Hotkey {
                    action: HK_ACTIONS.get(h.action.max(0) as usize).unwrap_or(&HK_ACTIONS[0]).to_string(),
                    keys: h.keys.iter().map(|&k| k as u32).collect(),
                    value: Some(h.value.clone()).filter(|v| !v.is_empty()),
                    description: Some(h.description.clone()).filter(|d| !d.is_empty()),
                    id: Some(h.id),
                })
                .collect();
        }
        if old.offsets != rec.offsets {
            e.offsets = rec.offsets.iter().map(|&o| fmt_off(o)).collect();
        }
        if e.custom.is_none() {
            e.len = rec.fmt.len.unwrap_or(0);
            e.signed = rec.fmt.signed;
            e.hex = rec.fmt.hex;
            e.utf16 = rec.fmt.utf16;
        }
        if old.color != rec.color {
            e.color = color_out(rec.color);
        }
        if old.options != rec.options {
            table::clean_entry(e);
        }
        e.frozen = rec.active;
        let rt = g.rt.entry(id).or_default();
        rt.aa_state = rec.aa_state.clone();
        rt.frozen_value = rec.frozen_value.clone();
        let new_parent = rec.parent.map(|p| p as i64);
        if new_parent != parent {
            let sub = find_mut(&mut g.table.entries, id).map_or(1, |e| height(std::slice::from_ref(e)));
            if new_parent.is_some_and(|p| depth_of(&g.table.entries, p) + sub > table::MAX_DEPTH) {
                return Err(Error::Other(format!("moving record {id} there would nest groups more than {} levels deep", table::MAX_DEPTH)));
            }
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
        // Only trusted Lua runs, so what it creates is the user's own.
        let id = g.issue(Origin::Own);
        let e = Entry { id, description: "No description".into(), addr: "0".into(), ..Entry::default() };
        // Past the depth limit the new record goes to the top level instead.
        let parent = parent.filter(|&p| depth_of(&g.table.entries, p as i64) < table::MAX_DEPTH);
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

    fn selected(&self) -> Vec<RecId> {
        let ids: HashSet<i64> = all(&lock(&self.0).table.entries).into_iter().map(|(e, _)| e.id).collect();
        lock(&self.1).ids.iter().filter(|i| ids.contains(i)).map(|&i| i as RecId).collect()
    }

    fn set_selected(&self, ids: &[RecId]) {
        let mut s = lock(&self.1);
        s.ids = ids.iter().map(|&i| i as i64).collect();
        s.seq += 1;
    }

    fn structures(&self) -> Option<Vec<hh_tools::structure::Structure>> {
        Some(lock(&self.0).table.structures.clone())
    }

    fn set_structures(&self, s: Vec<hh_tools::structure::Structure>) -> bool {
        // Refused (over the limits): not stored here, and not kept by the engine either.
        if let Err(e) = Live::set_structures(self, s) {
            eprintln!("structures from Lua refused: {e}");
        }
        true
    }

    fn caps(&self, id: RecId) -> Caps {
        Live::caps(self, id as i64)
    }
}

/// `[[addr]+o0]+o1`: the expression `resolve_address` understands.
pub fn expr_of(e: &Entry) -> String {
    e.offsets.iter().fold(e.addr.trim().to_string(), |x, o| format!("[{x}]+{}", o.trim()))
}

impl App {
    pub fn table_get(&self) -> R<TableState> {
        Ok(self.x.live.state())
    }

    /// The UI's address list selection (what Lua's `SelectedRecords` sees).
    pub fn table_select(&self, ids: Vec<i64>) -> R<()> {
        self.x.live.select(ids);
        Ok(())
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
    ///
    /// Active scripts of the current table are disabled first (their patches would stay in
    /// the game with nothing left to undo them). If one cannot be, the open is refused unless
    /// `force`, which carries those entries over (still active) so they can be disabled later.
    pub fn table_open(&self, path: &str, force: bool) -> R<TableState> {
        let t = table::load(Path::new(path))?;
        let failed = self.disable_active_scripts();
        if !failed.is_empty() && !force {
            let why: Vec<String> = failed.iter().map(|f| f.1.clone()).collect();
            return Err(format!("{}
the table was not opened: these active scripts could not be disabled (open anyway to keep them in the new table)", why.join("\n")));
        }
        let keep: Vec<i64> = failed.into_iter().map(|f| f.0).collect();
        let st = self.x.live.replace(t, &keep);
        self.x.live.select(Vec::new());
        // Record callbacks, timers, hotkeys and forms of the previous table go with it.
        {
            let _g = self.x.lua.enter();
            if let Err(e) = self.x.lua.engine.clear_table_state() {
                self.x.lua.console.push("err", &format!("clearing the previous table's Lua state: {e}"));
            }
        }
        self.sync_freeze();
        Ok(st)
    }

    /// Lua `loadTable(file, true)` and the UI's "Merge table": appends the file's entries
    /// (new ids, inactive, [`Origin::Foreign`]: each asks for its own consent) and keeps the
    /// current table, its scripts and their Lua state. A table script it brings into a table
    /// without one makes the table ask again (its current entries keep running).
    pub fn table_merge(&self, path: &str) -> R<TableState> {
        let add = table::load(Path::new(path))?;
        let script = self.x.live.state().table.lua_script.trim().is_empty() && !add.lua_script.trim().is_empty();
        if script {
            self.x.live.distrust_keeping_current();
        }
        self.x.live.insert(add.entries, None, None, Origin::Foreign, false)?;
        if script {
            let cur = self.x.live.state();
            let mut t = cur.table;
            t.lua_script = add.lua_script;
            self.x.live.put(t, cur.version)?;
        }
        Ok(self.x.live.state())
    }

    /// Runs `[DISABLE]` of every active script while the process lives; (id, error) of
    /// those that failed.
    pub(crate) fn disable_active_scripts(&self) -> Vec<(i64, String)> {
        if !self.session().is_ok_and(|s| s.raw.is_alive()) {
            return Vec::new();
        }
        let ids: Vec<i64> = all(&self.x.live.state().table.entries).into_iter().filter(|(e, _)| e.frozen && e.script.is_some()).map(|(e, _)| e.id).collect();
        ids.into_iter().filter_map(|id| self.table_set_active(&[id], false).err().map(|e| (id, e))).collect()
    }

    /// Writes the live table; JSON or `.CT` by extension.
    pub fn table_export(&self, path: &str) -> R<()> {
        table::save(Path::new(path), &self.x.live.state().table)?;
        self.x.live.mark_saved();
        Ok(())
    }

    /// A readable listing of the table (description, address, type, value; groups indented).
    pub fn table_export_text(&self, path: &str) -> R<()> {
        let t = self.x.live.state().table;
        let vals = self.session().ok();
        let mut out = String::new();
        fn go(app: &App, list: &[Entry], depth: usize, live: bool, out: &mut String) {
            for e in list {
                let pad = "  ".repeat(depth);
                let kind = if e.script.is_some() { "script".to_string() } else if is_group(e) { "group".to_string() } else { table::type_name(e) };
                let addr = if e.script.is_some() || is_group(e) { String::new() } else { expr_of(e) };
                let value = if live && e.script.is_none() && !is_group(e) { app.entry_value(e).unwrap_or_else(|| "??".into()) } else { String::new() };
                let line = [format!("{pad}{}", e.description), addr, kind, value].join("\t");
                out.push_str(line.trim_end());
                out.push('\n');
                go(app, &e.children, depth + 1, live, out);
            }
        }
        out.push_str("Description\tAddress\tType\tValue\n");
        go(self, &t.entries, 0, vals.is_some(), &mut out);
        std::fs::write(path, out).map_err(|e| format!("{path}: {e}"))
    }

    /// The live value of a value entry, formatted like the table shows it.
    fn entry_value(&self, e: &Entry) -> Option<String> {
        let addr = self.entry_addr(e).ok()?;
        let p = self.session().ok()?.proc.clone();
        let r = hh_scan::ValueRefEx { r: hh_scan::ValueRef { addr, vtype: e.vtype, fmt: fmt_of(e) }, custom: e.custom };
        hh_scan::read_values_ex(&*p, &[r]).pop().flatten()
    }

    /// A table file the user dropped on the window in a browser (the dev bridge): its text,
    /// opened like `table_open` (same consent; nothing runs).
    pub fn table_open_data(&self, name: &str, data: &str, force: bool) -> R<TableState> {
        if data.len() as u64 > table::MAX_FILE {
            return Err(format!("{name}: larger than {} MiB", table::MAX_FILE >> 20));
        }
        let dir = tempfile_dir()?;
        let ext = if name.to_ascii_lowercase().ends_with(".ct") { "CT" } else { "json" };
        let p = dir.join(format!("dropped.{ext}"));
        std::fs::write(&p, data).map_err(|e| format!("{}: {e}", p.display()))?;
        let r = self.table_open(&p.to_string_lossy(), force);
        let _ = std::fs::remove_dir_all(&dir);
        r
    }

    /// Resolved address of a value entry.
    pub(crate) fn entry_addr(&self, e: &Entry) -> R<Addr> {
        // A lookup callback a table registered never sees an untrusted entry's address.
        let lookups = self.lua_hooks_ok() && self.x.live.caps(e.id) == Caps::Full;
        parse_addr(&self.resolve_with(&expr_of(e), lookups)?)
    }

    /// Activates/deactivates like CE: OnActivate/OnDeactivate, Auto Assembler (with `{$lua}`)
    /// for scripts, freeze for values, group options for children. Each entry gets the
    /// capabilities its origin allows (`TableHost::caps`); one refused for want of them
    /// makes the whole call answer with the consent question ([`NEEDS_CONSENT`]).
    pub fn table_set_active(&self, ids: &[i64], active: bool) -> R<()> {
        let mut errs = Vec::new();
        self.consented(|| {
            for &id in ids {
                if let Err(e) = self.activate_locked(id, active) {
                    errs.push(e);
                }
            }
        })?;
        if errs.is_empty() { Ok(()) } else { Err(errs.join("\n")) }
    }

    /// Runs `f` under the Lua lock; if the engine refused an entry for want of capabilities
    /// meanwhile (also deep in a group cascade or a hotkey), the consent question for it.
    pub(crate) fn consented<T>(&self, f: impl FnOnce() -> T) -> R<T> {
        let (r, denied) = {
            let _g = self.x.lua.enter();
            self.x.lua.engine.take_denied();
            let r = f();
            (r, self.x.lua.engine.take_denied())
        };
        match denied.first() {
            Some((id, msg)) => Err(self.denied_error(*id as i64, msg)),
            None => Ok(r),
        }
    }

    /// The consent question (or the refusal under "never" / after a no) for entry `id`.
    pub(crate) fn denied_error(&self, id: i64, msg: &str) -> String {
        let what = self.x.live.entry(id).map_or_else(|| msg.to_string(), |e| e.description);
        match self.x.live.origin(id) {
            Some(Origin::Foreign) => self.entry_consent_error(&what),
            _ => self.consent_error(&what),
        }
    }

    /// Why `what` (an entry, the table script) does not run now: [`NEEDS_CONSENT`] when the
    /// user can still be asked.
    pub(crate) fn consent_error(&self, what: &str) -> String {
        if lock(&self.x.settings).table_script == "never" {
            return format!("{what}: not run: it needs Lua or file access from a loaded table and Settings say never to run a table's Lua");
        }
        match self.x.live.trust() {
            Trust::Declined => format!("{what}: not run: you chose not to run this table's Lua (open the table again to be asked again)"),
            _ => format!("{NEEDS_CONSENT} {what}: this table runs Lua code or reads files, which can use your files and the process"),
        }
    }

    /// Why an entry that came from another table does not get Lua or file access yet.
    pub(crate) fn entry_consent_error(&self, what: &str) -> String {
        if lock(&self.x.settings).table_script == "never" {
            return format!("{what}: not run: it needs Lua or file access, it came from another table and Settings say never to run a table's Lua");
        }
        format!("{NEEDS_ENTRY_CONSENT} {what}: this entry came from another table (pasted, merged or dropped in) and runs Lua code or reads files, which can use your files and the process")
    }

    /// The user's yes for the entries that came from another table (the subtrees of `ids`);
    /// refused while Settings say never.
    pub fn table_trust_entries(&self, ids: &[i64]) -> R<()> {
        self.x.live.grant(Grant::Entries(ids))
    }

    /// Pastes (or drops) entries after entry `after`: new ids, inactive, every one of them
    /// untrusted until its own consent. `base`: the table version the UI saw.
    pub fn table_paste(&self, entries: Vec<Entry>, after: Option<i64>, base: Option<u64>) -> R<PasteOut> {
        let (version, ids) = self.x.live.insert(entries, after, base, Origin::Foreign, false)?;
        Ok(PasteOut { version, ids })
    }

    /// New entries the user made (add address, new script, new group, from results, the
    /// structure dissector, a pointer scan, the disassembler ...): new ids after entry
    /// `after`, inactive, the user's own. The only way the frontend adds entries of its own;
    /// a put cannot bring in an id the backend did not issue.
    pub fn table_new(&self, entries: Vec<Entry>, after: Option<i64>, base: Option<u64>) -> R<PasteOut> {
        let (version, ids) = self.x.live.insert(entries, after, base, Origin::Own, false)?;
        Ok(PasteOut { version, ids })
    }

    /// What entry `id` may do now (diagnostics and tests): `Caps::Full` only for the user's
    /// own entries and those under consent in force.
    pub fn table_caps(&self, id: i64) -> Caps {
        self.x.live.caps(id)
    }

    /// An injection template at `addr` as a new script entry after `after`. A template for
    /// a remote target embeds names the server reported: untrusted like a pasted entry.
    pub fn table_add_template(&self, addr: &str, kind: &str, description: &str, after: Option<i64>, base: Option<u64>) -> R<PasteOut> {
        let script = self.aa_template(addr, kind)?;
        let remote = self.session()?.info.remote.is_some();
        let e = Entry { description: description.into(), script: Some(script), ..Entry::default() };
        let (version, ids) = self.x.live.insert(vec![e], after, base, if remote { Origin::Foreign } else { Origin::Own }, false)?;
        Ok(PasteOut { version, ids })
    }

    /// Resolved addresses of entries (the table's rows): each with the lookups its origin
    /// allows. `None` where one does not resolve.
    pub fn table_resolve(&self, ids: &[i64]) -> R<Vec<Option<String>>> {
        self.session()?;
        Ok(ids.iter().map(|&id| self.x.live.entry(id).and_then(|e| self.entry_addr(&e).ok()).map(crate::commands::hex_addr)).collect())
    }

    /// Whether the table has changes not yet saved (or not from the opened file).
    pub fn table_dirty(&self) -> R<bool> {
        Ok(self.x.live.dirty())
    }

    /// The user's answer to [`NEEDS_CONSENT`] (or to the question when the table was opened).
    /// Yes is the only way a loaded table's Lua becomes runnable; refused while Settings say
    /// never. No withdraws consent given before: what the table's Lua started is stopped.
    pub fn table_trust(&self, trust: bool) -> R<()> {
        if trust {
            return self.x.live.grant(Grant::Table);
        }
        if self.x.live.decline() {
            self.stop_table_lua();
        }
        Ok(())
    }

    /// Consent was withdrawn: interrupt what runs, then drop timers, forms, hotkeys,
    /// callbacks, registered AA hooks, Lua breakpoints and pointer scans without running any
    /// of them once more.
    pub(crate) fn stop_table_lua(&self) {
        self.x.lua.engine.interrupt_handle().interrupt();
        self.x.lua.console.cancel();
        let _g = self.x.lua.enter();
        if let Err(e) = self.x.lua.engine.stop_table_state() {
            self.x.lua.console.push("err", &format!("stopping the table's Lua: {e}"));
        }
        self.x.lua.console.push("info", "-- consent withdrawn: the table's Lua (timers, forms, hotkeys, callbacks) was stopped");
    }

    /// Caller holds the Lua lock. The engine applies the group options (children activated
    /// or deactivated as well).
    fn activate_locked(&self, id: i64, active: bool) -> R<()> {
        let e = self.x.live.entry(id).ok_or_else(|| format!("no table entry {id}"))?;
        self.x.lua.engine.set_active(id as RecId, active).map_err(|err| {
            let t = err.to_string();
            if t.starts_with(&e.description) { t } else { format!("{}: {t}", e.description) }
        })
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
        let p = self.session()?.proc.clone();
        match (&e.custom, &e.custom_name) {
            (Some(ct), _) => hh_scan::write_custom(&*p, a, ct, value, &fmt_of(e)),
            (None, Some(n)) => return Err(format!("custom type {n:?} is not supported by HeapHook")),
            _ => hh_scan::write_value(&*p, a, e.vtype, value, &fmt_of(e)),
        }
        .map_err(|x| x.to_string())?;
        self.x.live.set_frozen_value(e.id, value);
        Ok(())
    }

    /// Runs hotkey `index` of entry `id` through the engine: its CE action with the
    /// record's OnHotkey / OnPostHotkey callbacks.
    pub fn table_hotkey(&self, id: i64, index: usize) -> R<()> {
        let e = self.x.live.entry(id).ok_or_else(|| format!("no table entry {id}"))?;
        let hk = e.hotkeys.get(index).ok_or_else(|| format!("{}: no hotkey {index}", e.description))?;
        if !HK_ACTIONS.contains(&hk.action.as_str()) {
            return Err(format!("{}: unknown hotkey action {:?}", e.description, hk.action));
        };
        if hk.action.starts_with("Toggle Activation Allow") {
            let m = if hk.action.ends_with("Increase") { FreezeMode::AllowIncrease } else { FreezeMode::AllowDecrease };
            self.x.live.set_mode(id, m);
        }
        let hid = hotkey_ids(&e.hotkeys)[index];
        let r = self.consented(|| self.x.lua.engine.fire_record_hotkey(id as RecId, hid).map_err(|err| format!("{}: {err}", e.description)));
        self.sync_freeze();
        r?
    }

    /// Hands the active value entries to the freezer (addresses re-resolved).
    pub(crate) fn sync_freeze(&self) {
        let Ok(sess) = self.session() else { return };
        let active = self.x.live.frozen();
        // hh-lua formats record values by `vtype` only, so a custom entry's frozen value is
        // read here, with its type, when it turns active.
        let list = active
            .into_iter()
            // An unsupported custom type has nothing to write.
            .filter(|(e, _)| e.custom.is_some() || e.custom_name.is_none())
            .filter_map(|(e, value)| {
                let addr = self.entry_addr(&e).ok()?;
                Some((e.id, e.freeze_interval_ms, FrozenEntryEx { entry: FrozenEntry { addr, vtype: e.vtype, value, mode: e.freeze_mode, fmt: fmt_of(&e) }, custom: e.custom }))
            })
            .collect::<Vec<_>>();
        *lock(&self.x.freeze_ids) = list.iter().map(|(id, _, f)| (f.entry.addr, *id)).collect();
        let set: Vec<FrozenEntryEx> = list.iter().map(|x| x.2.clone()).collect();
        if let Err(e) = sess.freezer.set_ex(&set) {
            self.x.lua.console.push("err", &format!("freeze: {e}"));
        }
        // Entries with their own interval: updated in place (their state is kept).
        for (_, ms, f) in list.iter().filter(|x| x.1.is_some()) {
            if let Err(e) = sess.freezer.put(f, ms.map(std::time::Duration::from_millis)) {
                self.x.lua.console.push("err", &format!("freeze: {e}"));
            }
        }
    }

    /// Frozen table entries whose last write failed (freed or protected memory): id, address
    /// and why. The freezer keeps retrying them.
    pub(crate) fn freeze_failures(&self) -> Vec<FreezeFail> {
        let Ok(sess) = self.session() else { return Vec::new() };
        let fails = sess.freezer.failures();
        if fails.is_empty() {
            return Vec::new();
        }
        let ids = lock(&self.x.freeze_ids);
        fails
            .into_iter()
            .flat_map(|f| ids.iter().filter(move |(a, _)| *a == f.addr).map(move |(_, id)| FreezeFail { id: *id, addr: crate::commands::hex_addr(f.addr), error: f.error.clone() }))
            .collect()
    }
}

/// A frozen entry the freezer cannot write (`lua_poll.freeze_failures`).
#[derive(Debug, Clone, Serialize)]
pub struct FreezeFail {
    pub id: i64,
    pub addr: String,
    pub error: String,
}

/// `table_paste` answer.
#[derive(Debug, Clone, Serialize)]
pub struct PasteOut {
    pub version: u64,
    pub ids: Vec<i64>,
}

/// A private temporary directory (mode 0700 on Unix).
fn tempfile_dir() -> R<std::path::PathBuf> {
    let d = std::env::temp_dir().join(format!("heaphook-{}-{}", std::process::id(), script_hash(&format!("{:?}", std::time::Instant::now()))));
    let mut b = std::fs::DirBuilder::new();
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
    b.create(&d).map_err(|e| format!("{}: {e}", d.display()))?;
    Ok(d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hotkey_ids_stay_unique() {
        let hk = |id| table::Hotkey { id, ..Default::default() };
        assert_eq!(hotkey_ids(&[hk(None), hk(None)]), [1, 2]);
        assert_eq!(hotkey_ids(&[hk(Some(5)), hk(None), hk(Some(5)), hk(Some(2))]), [5, 6, 7, 2]);
    }

    #[test]
    fn offsets_colors() {
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
        // A put cannot bring in ids the backend did not issue.
        assert!(live.put(Table { entries: vec![e(1, vec![])], ..Table::default() }, 0).unwrap_err().contains("not issued"));
        let (v, ids) = live.insert(vec![e(7, vec![e(8, vec![])])], None, None, Origin::Own, false).unwrap();
        assert_eq!(ids, [1]);
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
        // Ids never come back: the next one is past every id issued.
        let (_, again) = live.insert(vec![e(1, vec![])], None, None, Origin::Foreign, false).unwrap();
        assert_eq!(again, [n as i64 + 1]);
        assert_eq!(live.caps(n as i64 + 1), Caps::None);
    }
}
