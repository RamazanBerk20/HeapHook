//! Auto Assembler and symbol hooks registered from Lua: custom AA commands, AA prologues,
//! symbol and address lookup callbacks, structure dissect overrides and name lookups.
//!
//! The Lua functions live in the prelude (`registerAutoAssemblerCommand`, ...); Rust keeps a
//! mirror of what is registered ([`Regs`]) so it can fill `hh_asm::AaHooks` without running
//! Lua (check-only mode) and skip hooks nobody registered. The prelude's dispatchers sit in
//! the named registry table `hh_hooks`.
use std::sync::Arc;
use std::sync::atomic::Ordering;

use hh_asm::{AaHooks, AddressName, SymbolLookup};
use hh_core::{Addr, Error, Result};
use mlua::{Function, IntoLuaMulti, Lua, Table, Value};

use crate::api::{err_text, int_of, lua_block_hook, str_of};
use crate::{Caps, RecId, State, guard};

/// What the scripts registered (names of AA commands in lowercase, counts of the others).
#[derive(Default, Clone)]
pub(crate) struct Regs {
    pub(crate) commands: Vec<String>,
    pub(crate) prologues: usize,
    pub(crate) symbol: usize,
    pub(crate) address: usize,
    pub(crate) struct_override: usize,
    pub(crate) struct_name: usize,
}

/// Address a symbol resolves to while checking a script when a lookup callback exists but
/// must not run.
const CHECK_PLACEHOLDER: Addr = 0x10000;

fn regs(st: &State) -> Regs {
    st.hooks.lock().unwrap().clone()
}

/// Calls dispatcher `name` of the prelude under the engine gate.
fn dispatch<R: mlua::FromLuaMulti>(lua: &Lua, st: &Arc<State>, name: &str, args: impl IntoLuaMulti) -> Result<R> {
    let _g = guard(st);
    let r = (|| {
        let t: Table = lua.named_registry_value("hh_hooks")?;
        t.get::<Function>(name)?.call::<R>(args)
    })();
    r.map_err(|e| Error::Other(err_text(&e)))
}

/// Asks the symbol lookup callbacks for `name`; the caller is inside the engine.
pub(crate) fn symbol_now(lua: &Lua, st: &State, name: &str) -> Option<Addr> {
    // A callback that resolves names itself must not recurse into the callbacks.
    if st.in_symlookup.swap(true, Ordering::SeqCst) {
        return None;
    }
    let r = (|| {
        let t: Table = lua.named_registry_value("hh_hooks")?;
        t.get::<Function>("symbol")?.call::<Value>(name)
    })();
    st.in_symlookup.store(false, Ordering::SeqCst);
    match r {
        Ok(v) => int_of(&v).map(|a| a as Addr),
        Err(e) => {
            st.host().error(&format!("symbol lookup callback: {}", err_text(&e)));
            None
        }
    }
}

/// The symbol lookup callbacks for `name` when any are registered and the engine's Lua state
/// still exists (for address resolution inside the engine).
pub(crate) fn symbol_lua(st: &State) -> Option<Lua> {
    if st.hooks.lock().unwrap().symbol == 0 {
        return None;
    }
    st.weak.get()?.try_upgrade()
}

fn symbol_lookup(lua: &Lua, st: &Arc<State>) -> SymbolLookup {
    let (lua, st) = (lua.clone(), st.clone());
    Arc::new(move |name: &str| {
        let _g = guard(&st);
        symbol_now(&lua, &st, name)
    })
}

/// The registered `registerSymbolLookupCallback` functions as a lookup, or `None` when there
/// are none.
pub(crate) fn symbol_lookup_opt(lua: &Lua, st: &Arc<State>) -> Option<SymbolLookup> {
    (regs(st).symbol > 0).then(|| symbol_lookup(lua, st))
}

/// The registered `registerAddressLookupCallback` functions, or `None` when there are none.
pub(crate) fn address_name(lua: &Lua, st: &Arc<State>) -> Option<AddressName> {
    if regs(st).address == 0 {
        return None;
    }
    let (lua, st) = (lua.clone(), st.clone());
    Some(Arc::new(move |a: Addr| match dispatch::<Value>(&lua, &st, "address", a as i64) {
        Ok(v) => str_of(&v),
        Err(e) => {
            st.host().error(&format!("address lookup callback: {e}"));
            None
        }
    }))
}

/// `loadbinary`: only with OS access, only regular files, at most
/// `hh_asm::MAX_ASSEMBLED_BYTES`, and only when the host allows that path.
type ReadFile = Box<dyn FnMut(String) -> Result<Vec<u8>>>;

fn read_file(st: &Arc<State>) -> Option<ReadFile> {
    if !st.allow_os {
        return None;
    }
    let st = st.clone();
    Some(Box::new(move |path: String| {
        if !st.host().allow_aa_file(&path) {
            return Err(Error::Other(format!("loadbinary: reading {path} was not allowed")));
        }
        let (f, len) = crate::ext::open_regular(&path).map_err(|e| Error::Other(err_text(&e)))?;
        let max = hh_asm::MAX_ASSEMBLED_BYTES as u64;
        if len > max {
            return Err(Error::Other(format!("loadbinary: {path} is larger than {max} bytes")));
        }
        let mut data = Vec::new();
        // The file may grow after the size check.
        std::io::Read::read_to_end(&mut std::io::Read::take(f, max + 1), &mut data)?;
        if data.len() as u64 > max {
            return Err(Error::Other(format!("loadbinary: {path} is larger than {max} bytes")));
        }
        Ok(data)
    }))
}

/// How a script is processed.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    /// Execute (hooks run Lua, `syntaxcheck` false).
    Run,
    /// Check with Lua running, told `syntaxcheck` (Cheat Engine's own check).
    Check,
    /// Check without running any Lua at all (live checks while typing).
    CheckNoLua,
}

/// THE way to build `AaHooks`: every place in hh-lua that hands a script to hh-asm (records,
/// `autoAssemble`, `autoAssembleCheck`, the host's [`crate::Engine::aa_hooks_with`]) comes
/// here with the capabilities it was given. `Caps::None` gets [`denied`]; only `Caps::Full`
/// reaches anything that runs Lua or reads a file.
pub(crate) fn for_caps(lua: &Lua, st: &Arc<State>, memrec: Option<RecId>, mode: Mode, caps: Caps) -> AaHooks {
    match (caps, mode) {
        (Caps::None, _) => denied(st),
        (Caps::Full, Mode::Run) => full(lua, st, memrec, false),
        (Caps::Full, Mode::Check) => full(lua, st, memrec, true),
        (Caps::Full, Mode::CheckNoLua) => check_only(st),
    }
}

/// Hooks for a script without capabilities: nothing that runs Lua, reads a local file or
/// hands the script's text to Lua a table registered. hh-asm fails `{$lua}`, `luacall`,
/// `loadbinary` and `include` with `hh_asm::NOT_AVAILABLE`; the two stubs below hold no Lua
/// and no state (a snapshot of names), they only make a registered custom command or
/// prologue fail the same way instead of the script being assembled without it.
pub(crate) fn denied(st: &State) -> AaHooks {
    let r = regs(st);
    let mut h = AaHooks::default();
    if !r.commands.is_empty() {
        let names = r.commands;
        h.command = Some(Box::new(move |(name, _, _): (String, String, bool)| {
            if names.contains(&name) {
                Err(Error::Other(format!("{name}: a command registered from Lua {}", hh_asm::NOT_AVAILABLE)))
            } else {
                Ok(None)
            }
        }));
    }
    if r.prologues > 0 {
        h.prologue = Some(Box::new(|_: (String, bool)| Err(Error::Other(format!("the prologue registered from Lua {}", hh_asm::NOT_AVAILABLE)))));
    }
    h
}

/// Whether a script without capabilities could have failed for want of the symbol lookup
/// callbacks (they are not asked for it, and an unknown name says nothing more).
pub(crate) fn has_symbol_lookup(st: &State) -> bool {
    regs(st).symbol > 0
}

/// Every hook, running Lua: `{$lua}` blocks, `luacall`, custom commands, prologues and the
/// symbol lookup callbacks, `loadbinary` (see [`read_file`]).
fn full(lua: &Lua, st: &Arc<State>, memrec: Option<RecId>, check: bool) -> AaHooks {
    let r = regs(st);
    let mut call = lua_block_hook(lua.clone(), st.clone(), memrec, check);
    let mut h = AaHooks {
        lua: Some(lua_block_hook(lua.clone(), st.clone(), memrec, check)),
        lua_call: Some(Box::new(move |code: String| call(code).map(|_| ()))),
        read_file: read_file(st),
        symbol_lookup: (r.symbol > 0).then(|| symbol_lookup(lua, st)),
        ..Default::default()
    };
    if !r.commands.is_empty() {
        let (lua, st) = (lua.clone(), st.clone());
        h.command = Some(Box::new(move |(name, args, dry): (String, String, bool)| {
            if !regs(&st).commands.contains(&name) {
                return Ok(None);
            }
            let v: Value = dispatch(&lua, &st, "command", (name, args, dry))?;
            Ok(Some(str_of(&v).unwrap_or_default()))
        }));
    }
    if r.prologues > 0 {
        let (lua, st) = (lua.clone(), st.clone());
        h.prologue = Some(Box::new(move |(script, dry): (String, bool)| dispatch(&lua, &st, "prologue", (script, dry))));
    }
    h
}

/// Hooks for live syntax checks that run no Lua at all: `{$lua}` blocks yield nothing,
/// registered custom commands expand to nothing, prologues are skipped, and when a symbol
/// lookup callback is registered every otherwise unknown name resolves to a placeholder
/// (the callback might know it).
fn check_only(st: &Arc<State>) -> AaHooks {
    let r = regs(st);
    let mut h = AaHooks {
        lua: Some(Box::new(|_src: String| Ok(String::new()))),
        read_file: read_file(st),
        ..Default::default()
    };
    if !r.commands.is_empty() {
        let names = r.commands.clone();
        h.command = Some(Box::new(move |(name, _, _): (String, String, bool)| Ok(names.contains(&name).then(String::new))));
    }
    if r.symbol > 0 {
        h.symbol_lookup = Some(Arc::new(|_: &str| Some(CHECK_PLACEHOLDER)));
    }
    h
}

/// Runs the structure dissect overrides for `addr`: the structure the first one that
/// returned true filled, named by the name lookup (or `Structure_ADDR`) if it left the
/// name empty.
pub(crate) fn structure_override(lua: &Lua, st: &Arc<State>, addr: Addr, size: usize) -> Option<hh_tools::structure::Structure> {
    if regs(st).struct_override == 0 {
        return None;
    }
    let sid = match dispatch::<Option<i64>>(lua, st, "structoverride", (addr as i64, size as i64)) {
        Ok(s) => s?,
        Err(e) => {
            st.host().error(&format!("structure dissect override: {e}"));
            return None;
        }
    };
    let mut s = crate::ext::take_structure(st, sid)?;
    if s.name.is_empty() {
        s.name = structure_name(lua, st, addr).map_or_else(|| format!("Structure_{addr:X}"), |n| n.0);
    }
    Some(s)
}

/// The first name a `registerStructureNameLookup` callback gives for `addr`, with the base
/// address it suggests (if any).
pub(crate) fn structure_name(lua: &Lua, st: &Arc<State>, addr: Addr) -> Option<(String, Option<Addr>)> {
    if regs(st).struct_name == 0 {
        return None;
    }
    match dispatch::<(Value, Value)>(lua, st, "structname", addr as i64) {
        Ok((n, a)) => Some((str_of(&n)?, int_of(&a).map(|a| a as Addr))),
        Err(e) => {
            st.host().error(&format!("structure name lookup: {e}"));
            None
        }
    }
}

pub(crate) fn install(h: &crate::api::B) -> mlua::Result<()> {
    // (commands, prologues, symbol, address, struct overrides, struct names)
    h.f("hooks_sync", |_, st, (cmds, p, s, a, so, sn): (Vec<String>, usize, usize, usize, usize, usize)| {
        *st.hooks.lock().unwrap() = Regs {
            commands: cmds.into_iter().map(|c| c.to_ascii_lowercase()).collect(),
            prologues: p,
            symbol: s,
            address: a,
            struct_override: so,
            struct_name: sn,
        };
        Ok(())
    })
}
