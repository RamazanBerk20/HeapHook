//! Capabilities per record (`TableHost::caps`): a record the host has not vouched for gets
//! hooks without anything that runs Lua or reads a file, on every route hh-lua has to its
//! script (activation, cascades, hotkeys, `autoAssemble` of its text) and its callbacks.
mod common;

use std::sync::Arc;

use common::*;
use hh_asm::{NOT_AVAILABLE, SymbolTable};
use hh_core::Memory;
use hh_lua::{Caps, MemTable, RecId, TableHost};

/// Registrations a trusted table script would make; every one leaves a trace in `ran`.
const TRUSTED: &str = r#"
ran = {}
registerAutoAssemblerCommand('mycmd', function(params) ran[#ran + 1] = 'cmd:' .. params return 'game.exe+3020:\ndb 63' end)
registerAutoAssemblerPrologue(function(script) ran[#ran + 1] = 'prologue' end)
registerSymbolLookupCallback(function(name) ran[#ran + 1] = 'sym:' .. name if name == 'magicsym' then return getAddress('game.exe+3020') end end, slFailure)
"#;

/// One script per capability; each leaves a trace in `ran` or writes 0x63 to game.exe+3020.
fn payloads(file: &str) -> Vec<(&'static str, String)> {
    vec![
        ("lua block", "[ENABLE]\n{$lua}\nran[#ran + 1] = 'lua'\nreturn ''\n{$asm}\n[DISABLE]\n".into()),
        ("luacall", "[ENABLE]\nluacall(ran[#ran + 1] = 'luacall')\n[DISABLE]\n".into()),
        ("loadbinary", format!("[ENABLE]\nloadbinary(game.exe+3020,{file})\n[DISABLE]\n")),
        ("load{{}}binary", format!("[ENABLE]\nload{{}}binary(game.exe+3020,{file})\n[DISABLE]\n")),
        ("command", "[ENABLE]\nMYCMD(attacker args)\n[DISABLE]\n".into()),
        ("symbol lookup", "[ENABLE]\nmagicsym:\ndb 63\n[DISABLE]\n".into()),
    ]
}

struct Files;
impl hh_lua::Host for Files {
    fn allow_aa_file(&self, _: &str) -> bool {
        true
    }
}

fn setup() -> (hh_lua::Engine, Arc<TestProc>, Arc<MemTable>, tempfile::TempDir) {
    let (e, p, _) = engine();
    e.set_host(Arc::new(Files));
    let t = Arc::new(MemTable::new());
    e.set_table(t.clone());
    run(&e, TRUSTED);
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("blob"), [0x63u8]).unwrap();
    (e, p, t, dir)
}

fn record(t: &MemTable, script: &str, caps: Caps) -> RecId {
    let id = t.create(None);
    let mut r = t.get(id).unwrap();
    r.description = format!("rec{id}");
    r.script = Some(script.into());
    t.set(r).unwrap();
    t.set_caps(id, caps);
    id
}

fn nothing_ran(e: &hh_lua::Engine, p: &TestProc, what: &str) {
    // The prologue runs for every script of a trusted record, so only look for the rest.
    let ran = run(e, "local o = {} for _, x in ipairs(ran) do if x ~= 'prologue' then o[#o + 1] = x end end return table.concat(o, ' ')");
    assert_eq!(ran, [""], "{what}: Lua ran");
    assert_eq!(read_u32(p, GAME + 0x3020), 0x2A, "{what}: memory written");
}

#[test]
fn records_without_caps_run_nothing_on_any_route() {
    let (e, p, t, dir) = setup();
    let file = dir.path().join("blob").display().to_string();
    for (name, script) in payloads(&file) {
        let id = record(&t, &script, Caps::None);
        // the host's activation, Lua's memrec.Active, a record hotkey, a group cascade
        let err = e.set_active(id, true).unwrap_err().to_string();
        assert!(err.contains("needs your consent"), "{name}: {err}");
        run(&e, &format!("getAddressList().getMemoryRecordByID({id}).Active = true"));
        let hk = run(&e, &format!("local r = getAddressList().getMemoryRecordByID({id}) return r.createHotkey({{1}}, 3).ID"))[0].parse().unwrap();
        e.fire_record_hotkey(id, hk).unwrap();
        let g = t.create(None);
        let mut gr = t.get(g).unwrap();
        gr.group_header = true;
        gr.options = vec!["moActivateChildrenAsWell".into()];
        t.set(gr).unwrap();
        let mut r = t.get(id).unwrap();
        r.parent = Some(g);
        t.set(r).unwrap();
        e.set_active(g, true).unwrap();
        // trusted Lua assembling the record's text
        run(&e, &format!("local ok, err = autoAssemble(getAddressList().getMemoryRecordByID({id}).Script) assert(not ok and err:find('{NOT_AVAILABLE}', 1, true), err)"));
        run(&e, &format!("local ok = autoAssembleCheck('// wrapped\\n' .. getAddressList().getMemoryRecordByID({id}).Script) assert(not ok)"));
        // the old host API: the record's capabilities, none without a record
        let mut syms = SymbolTable::default();
        assert!(hh_asm::aa_execute(&*p, &mut syms, &script, true, None, &mut e.aa_hooks(Some(id), false)).is_err(), "{name}");
        assert!(hh_asm::aa_execute(&*p, &mut syms, &script, true, None, &mut e.aa_hooks(None, false)).is_err(), "{name}");
        assert!(hh_asm::aa_check(&*p, &syms, &script, &mut e.aa_hooks_check_only()).is_some(), "{name}");
        assert!(!t.get(id).unwrap().active, "{name}");
        nothing_ran(&e, &p, name);
        let denied = e.take_denied();
        assert!(denied.iter().any(|d| d.0 == id), "{name}: no refusal reported: {denied:?}");
        // Granted: the same record runs.
        t.set_caps(id, Caps::Full);
        e.set_active(id, true).unwrap_or_else(|err| panic!("{name}: {err}"));
        e.set_active(id, false).unwrap();
        run(&e, "ran = {}");
        p.write(GAME + 0x3020, &0x2Au32.to_le_bytes()).unwrap();
    }
}

#[test]
fn callbacks_of_records_without_caps_do_not_run() {
    let (e, p, t, _dir) = setup();
    let id = record(&t, "[ENABLE]\n[DISABLE]\n", Caps::None);
    // A stale callback for the id (a trusted record that had it, deleted, the id reused).
    run(&e, &format!("local r = getAddressList().getMemoryRecordByID({id}) r.OnActivate = function() ran[#ran + 1] = 'onactivate' end r.OnDestroy = function() ran[#ran + 1] = 'ondestroy' end"));
    run(&e, &format!("local h = getAddressList().getMemoryRecordByID({id}).createHotkey({{1}}, 0) h.OnHotkey = function() ran[#ran + 1] = 'onhotkey' end"));
    assert!(e.set_active(id, true).unwrap_err().to_string().contains("OnActivate"));
    e.fire_record_hotkey(id, 1).unwrap();
    e.stop_table_state().unwrap();
    nothing_ran(&e, &p, "callbacks");
    assert!(e.take_denied().len() >= 2);
}

#[test]
fn record_address_never_reaches_a_lookup_callback() {
    let (e, p, t, _dir) = setup();
    let id = t.create(None);
    let mut r = t.get(id).unwrap();
    r.address = "attackername".into();
    t.set(r).unwrap();
    t.set_caps(id, Caps::None);
    assert_eq!(run(&e, &format!("return getAddressList().getMemoryRecordByID({id}).Value")), ["??"]);
    let err = e.set_active(id, true).unwrap_err().to_string();
    assert!(err.contains("needs your consent"), "{err}");
    nothing_ran(&e, &p, "address");
}

#[test]
fn stop_table_state_runs_no_more_lua() {
    let (e, p, _t, _dir) = setup();
    run(&e, "tm = createTimer(nil) tm.Interval = 1 tm.OnTimer = function() ran[#ran + 1] = 'timer' end\nf = createForm() f.OnDestroy = function() ran[#ran + 1] = 'formdestroy' end");
    e.stop_table_state().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(20));
    e.tick().unwrap();
    nothing_ran(&e, &p, "stop");
    assert!(!e.has_symbol_lookup(), "registrations are gone");
}
