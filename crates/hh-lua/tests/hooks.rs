//! The 1.0 feature pass: Auto Assembler extension from Lua (custom commands, prologues,
//! symbol / address lookup callbacks, luacall, loadbinary), custom-typed records, memscan
//! additions, HeapHook's pointer scan job, structure overrides / bit fields / arrays / RTTI,
//! dissect save / load / code filter and the disassembler helpers.
mod common;

use std::sync::Arc;

use common::*;
use hh_asm::SymbolTable;
use hh_core::{Memory, Result};
use hh_lua::{Engine, EngineOptions, Host};

const INJECT: &str = r#"
[ENABLE]
luacall(luacalled = (luacalled or 0) + 1)
alloc(newmem,$100,TARGETSYM)
label(return)
newmem:
  padnops(2)
  sub [rcx+000000E0],eax
  jmp return
TARGETSYM:
  jmp newmem
  nop
return:
[DISABLE]
TARGETSYM:
  db 29 81 E0 00 00 00
dealloc(newmem)
"#;

/// Registers a custom AA command, a prologue and a symbol lookup callback the way a table
/// script would.
const REGISTER: &str = r#"
calls = {}
registerAutoAssemblerCommand('padNops', function(params, check)
  calls[#calls + 1] = 'cmd:' .. tostring(check)
  local n = tonumber(params)
  if not n then return nil, 'padnops needs a count' end
  return string.rep('nop\n', n)
end)
prologue = registerAutoAssemblerPrologue(function(script, check)
  calls[#calls + 1] = 'prologue:' .. tostring(check)
  script.Text = script.Text:gsub('TARGETSYM', 'healthcode')
end)
lookup = registerSymbolLookupCallback(function(name)
  calls[#calls + 1] = 'sym:' .. name
  if name:lower() == 'healthcode' then return getAddress('game.exe+1005') end
end, slFailure)
"#;

#[test]
fn table_registers_aa_command_and_symbol_lookup() {
    let (e, p, _) = engine();
    let before = p.snapshot();
    e.lua().globals().set("INJECT", INJECT).unwrap();
    run(&e, REGISTER);
    run(
        &e,
        r#"
        -- the callback also serves getAddress
        assert(getAddress('healthcode') == getAddress('game.exe+1005'))
        local r = getAddressList().createMemoryRecord()
        r.Type = vtAutoAssembler
        r.Script = INJECT
        r.Active = true
        assert(r.Active, 'enabled')
        assert(readBytes('game.exe+1005') == 0xE9, 'jump written')
        local dest = getAddress('game.exe+1005') + 5 + readInteger('game.exe+1006', true)
        local b = readBytes(dest, 4, true)
        assert(b[1] == 0x90 and b[2] == 0x90 and b[3] == 0x29, 'command expanded to two nops')
        assert(luacalled == 1, 'luacall ran once')
        r.Active = false
        assert(not r.Active)
        local joined = table.concat(calls, ' ')
        assert(joined:find('cmd:false') and joined:find('prologue:false') and joined:find('sym:healthcode'), joined)
        -- an error the command returns fails the script
        local ok, err = autoAssemble('[ENABLE]\npadnops(x)\n[DISABLE]\n')
        assert(not ok and err:find('padnops needs a count'), err)
    "#,
    );
    assert_eq!(p.snapshot(), before, "disable restored memory and freed the allocation");

    // The app's route (Engine::aa_hooks) sees the same registrations.
    let script = INJECT.replace("luacall(luacalled = (luacalled or 0) + 1)\n", "");
    let mut syms = SymbolTable::default();
    let st = hh_asm::aa_execute(&*p, &mut syms, &script, true, None, &mut e.aa_hooks(None, false)).unwrap();
    assert_eq!(read_u32(&*p, GAME + 0x1005) & 0xFF, 0xE9);
    hh_asm::aa_execute(&*p, &mut syms, &script, false, Some(&st), &mut e.aa_hooks(None, false)).unwrap();
    assert_eq!(p.snapshot(), before);

    // clear_table_state forgets every registration.
    e.clear_table_state().unwrap();
    let err = hh_asm::aa_check(&*p, &SymbolTable::default(), &script, &mut e.aa_hooks(None, true)).expect("unknown now");
    assert!(err.message.to_lowercase().contains("targetsym") || err.message.contains("padnops"), "{err:?}");
    run(&e, "assert(getAddressSafe('healthcode') == nil)");
    run(&e, "assert(unregisterSymbolLookupCallback(lookup) == false)");
}

#[test]
fn check_only_runs_no_registered_callback() {
    let (e, p, _) = engine();
    e.lua().globals().set("INJECT", INJECT).unwrap();
    run(&e, REGISTER);
    let script = INJECT.replace("luacall(luacalled = (luacalled or 0) + 1)\n", "{$lua}\nluaran = true\n{$asm}\n");
    let r = hh_asm::aa_check(&*p, &SymbolTable::default(), &script, &mut e.aa_hooks_check_only());
    // The prologue cannot rename TARGETSYM without running; the placeholder lookup accepts it.
    assert!(r.is_none(), "{r:?}");
    run(&e, "assert(#calls == 0, table.concat(calls, ' ')) assert(luaran == nil)");
    // A syntax check through Engine::aa_hooks does run them (told it is a check).
    assert!(hh_asm::aa_check(&*p, &SymbolTable::default(), &script, &mut e.aa_hooks(None, true)).is_none());
    run(
        &e,
        "local j = table.concat(calls, ' ') assert(j:find('prologue:true') and j:find('cmd:true') and luaran, j)",
    );
    // Lua's autoAssembleCheck is a syntax check with callbacks too (Cheat Engine semantics).
    run(&e, "calls = {} assert(autoAssembleCheck(INJECT)) assert(#calls > 0)");
}

struct Files(bool);
impl Host for Files {
    fn allow_aa_file(&self, _path: &str) -> bool {
        self.0
    }
}

#[test]
fn loadbinary_needs_os_access_and_host_consent() {
    let dir = std::env::temp_dir().join(format!("hh-lua-loadbin-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("blob.bin");
    std::fs::write(&file, b"ABCD").unwrap();
    let script = |path: &std::path::Path| {
        format!("[ENABLE]\nalloc(buf,$100)\nregistersymbol(buf)\nloadbinary(buf,{})\n[DISABLE]\nunregistersymbol(buf)\ndealloc(buf)\n", path.display())
    };
    let go = |e: &Engine, s: &str| -> std::result::Result<(), String> {
        e.lua().globals().set("S", s).unwrap();
        let r = e.exec("local ok, err = autoAssemble(S) if not ok then error(err, 0) end return readString('buf')", "lb");
        match r {
            Ok(v) if v == ["ABCD"] => Ok(()),
            Ok(v) => Err(format!("read {v:?}")),
            Err(err) => Err(err.to_string()),
        }
    };
    let (e, _, _) = engine();
    let err = go(&e, &script(&file)).unwrap_err();
    assert!(err.contains("not allowed"), "default host denies: {err}");
    e.set_host(Arc::new(Files(true)));
    go(&e, &script(&file)).unwrap();
    // only regular files
    let err = go(&e, &script(&dir)).unwrap_err();
    assert!(err.contains("not a regular file"), "{err}");
    // the app's route consults the host the same way
    e.set_host(Arc::new(Files(false)));
    let (_, p, _) = engine();
    let mut syms = SymbolTable::default();
    let r = hh_asm::aa_execute(&*p, &mut syms, &script(&file), true, None, &mut e.aa_hooks(None, false));
    assert!(r.unwrap_err().to_string().contains("not allowed"));
    // no OS access: no file reads at all, whatever the host says
    let e = Engine::new(EngineOptions { allow_os: false, ..Default::default() }).unwrap();
    e.set_process(Some(game())).unwrap();
    e.set_host(Arc::new(Files(true)));
    let err = go(&e, &script(&file)).unwrap_err();
    assert!(err.contains("file access is not enabled"), "{err}");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn custom_typed_record_in_converted_units() {
    let (e, p, _) = engine();
    p.write(0x2000_0040, &1234u32.to_le_bytes()).unwrap();
    run(
        &e,
        r#"
        local r = getAddressList().createMemoryRecord()
        r.Address = '20000040'
        r.Type = vtCustom
        r.CustomTypeName = { size = 4, signed = true, scale = 0.01 }
        assert(r.Type == vtCustom)
        assert(r.Value == '12.34', r.Value)
        r.Value = '20.5'
        assert(readInteger(0x20000040) == 2050)
        local inc = r.createHotkey({ VK_F1 }, mrhIncreaseValue, '1.5')
        inc.doHotkey()
        assert(readInteger(0x20000040) == 2200 and r.Value == '22', r.Value)
        r.createHotkey({ VK_F2 }, mrhDecreaseValue, '0.25').doHotkey()
        assert(readInteger(0x20000040) == 2175, readInteger(0x20000040))
        -- frozen to the converted value
        r.Active = true
        r.Value = '1'
        assert(readInteger(0x20000040) == 100)
        -- a preset by name
        writeBytes(0x20000044, 0, 0, 1, 0)
        local be = getAddressList().createMemoryRecord()
        be.Address = '20000044'
        be.Type = vtCustom
        be.CustomTypeName = '4 byte big endian'
        assert(be.Value == '256', be.Value)
        be.Type = vtDword
        assert(be.Type == vtDword and be.Value == '65536', be.Value)
    "#,
    );
}

#[test]
fn memscan_region_filter_pointer_scan_sort_remove_saved() {
    let (e, _, _) = engine();
    run(
        &e,
        r#"
        writeInteger(0x20000050, 42)
        local ms = createMemScan()
        local function first(vt, value)
          ms.firstScan(soExactValue, vt, rtRounded, value, '', 0, 0x7fffffffffffffff, '', fsmAligned, '4', false, false, false, false)
        end
        ms.RegionFilter = { private = false }
        first(vtDword, '42')
        assert(ms.FoundCount == 0, 'every region of the test process is private')
        ms.RegionFilter = { modules = { 'game.exe' } }
        first(vtDword, '42')
        assert(ms.FoundCount == 1)
        ms.RegionFilter = nil
        first(vtDword, '42')
        assert(ms.FoundCount == 2)
        local fl = createFoundList(ms)
        fl.initialize()
        assert(fl.Address[0] == '20000050')
        ms.sortResults(false, true) -- address, descending
        fl.initialize()
        assert(fl.Address[0] == '140003020', fl.Address[0])
        assert(ms.removeResults({ 0x140003020 }) == 1 and ms.FoundCount == 1)
        ms.saveCurrentResults('before')
        writeInteger(0x20000050, 7)
        ms.nextScan(soChanged)
        assert(ms.FoundCount == 1)
        assert(ms.getSavedResultValue('before', 0x20000050) == '42')
        assert(ms.getSavedResultValue('before', 0x20000054) == nil)
        -- pointer-type scan: game.exe+3000 -> heap, heap+8 -> heap+80
        ms.newScan()
        ms.firstScan(soUnknownValue, vtPointer, rtRounded, '', '', 0, 0x7fffffffffffffff, '', fsmAligned, '8', false, false, false, false)
        fl.initialize()
        local seen = {}
        for i = 0, fl.Count - 1 do seen[fl.Address[i]] = true end
        assert(seen['140003000'] and seen['20000008'], 'pointers found')
        ms.newScan()
        ms.RegionFilter = { pointsTo = { 'game.exe' } }
        ms.firstScan(soUnknownValue, vtPointer, rtRounded, '', '', 0, 0x7fffffffffffffff, '', fsmAligned, '8', false, false, false, false)
        fl.initialize()
        for i = 0, fl.Count - 1 do assert(fl.Address[i] ~= '140003000', 'points into the heap, not game.exe') end
        ms.destroy()
    "#,
    );
}

#[test]
fn pointer_scan_job_on_synthetic_process() {
    let (e, _, _) = engine();
    run(
        &e,
        r#"
        local ps = hhCreatePointerScan({ target = 0x20000088, maxLevel = 3, maxOffset = 0x100, threads = 1,
          threadStacks = false, maxResults = 1000 })
        assert(ps.waitTillDone(30000), 'finished')
        local pr = ps.getProgress()
        assert(pr.Finished and not pr.Cancelled)
        assert(ps.Count >= 1, 'paths found')
        local found
        for _, r in ipairs(ps.getResults(0, 100)) do
          if r.Base == 'game.exe' and r.BaseOffset == 0x3000 and #r.Offsets == 2 and r.Offsets[1] == 8 and r.Offsets[2] == 8 then
            found = r
          end
        end
        assert(found, 'game.exe+3000 -> 8 -> 8')
        assert(found.Address == 0x20000088 and found.Value == 0x1234, found.Text)
        assert(#ps.getResults(0, 0) == 0)
        ps.destroy()
        assert(not pcall(ps.getProgress), 'destroyed')
        assert(not pcall(hhCreatePointerScan, {}), 'target is required')
        -- a job still running is cancelled by clear_table_state
        running = hhCreatePointerScan({ target = 0x20000088, threads = 1 })
    "#,
    );
    e.clear_table_state().unwrap();
    let err = e.exec("running.getProgress()", "x").unwrap_err().to_string();
    assert!(err.contains("destroyed"), "{err}");
}

#[test]
fn structure_overrides_bit_fields_arrays_and_rtti() {
    let (e, p, _) = engine();
    // Itanium RTTI: object -> vtable; vtable[-1] -> type_info; type_info[1] -> "6Player".
    let mut m = vec![0u8; 0x400];
    let put = |m: &mut Vec<u8>, o: usize, v: u64| m[o..o + 8].copy_from_slice(&v.to_le_bytes());
    put(&mut m, 0, 0x3000_0108);
    put(&mut m, 0x100, 0x3000_0200);
    put(&mut m, 0x208, 0x3000_0300);
    m[0x300..0x308].copy_from_slice(b"6Player\0");
    p.map(0x3000_0000, m);
    run(
        &e,
        r#"
        assert(getRTTIClassName(0x30000000) == 'Player', tostring(getRTTIClassName(0x30000000)))
        assert(getRTTIClassName(0x20000000) == nil)
        ov = registerStructureDissectOverride(function(s, address)
          if address ~= 0x30000000 then return false end
          s.Name = 'PlayerOverride'
          local el = s.addElement()
          el.Offset = 0
          el.Name = 'vtable'
          el.Vartype = vtPointer
          return true
        end)
        nl = registerStructureNameLookup(function(address) return string.format('Obj_%X', address) end)
        local s = createStructure('guess')
        s.autoGuess(0x30000000, 0, 0x40)
        assert(s.Count == 1 and s.Element[0].Name == 'vtable', 'override filled it')
        local g = createStructure('plain')
        g.autoGuess(0x20000000, 0, 0x20)
        assert(g.Count > 1, 'not overridden: guessed')

        -- bit field: bits 4..6 of a byte
        writeBytes(0x20000060, 0xA5)
        local st = createStructure('bits')
        local f = st.addElement()
        f.Offset = 0x60
        f.Vartype = vtByte
        f.BitLength = 3
        f.BitOffset = 4
        assert(f.BitOffset == 4 and f.BitLength == 3)
        assert(f.getValue(0x20000000) == '2', f.getValue(0x20000000))
        assert(f.setValue(0x20000000, '5'))
        assert(readBytes(0x20000060) == 0xD5, readBytes(0x20000060))
        assert(not pcall(function() f.BitLength = 9 end), 'outside the byte')
        -- array of four dwords at +0x70
        for i = 0, 3 do writeInteger(0x20000070 + 4 * i, 100 + i) end
        local arr = st.addElement()
        arr.Offset = 0x70
        arr.Vartype = vtDword
        arr.ArrayCount = 4
        assert(arr.ArrayCount == 4 and arr.getValue(0x20000000, 2) == '102')
        assert(arr.setValue(0x20000000, '7', 3) and readInteger(0x2000007C) == 7)
        assert(not pcall(arr.getValue, 0x20000000, 4), 'index outside the array')
        arr.ChildStructStart = 0x10
        assert(arr.ChildStructStart == 0x10)
    "#,
    );
    // The app's guess route (hh_tools::structure::StructOverride).
    let s = e.structure_override(0x3000_0000, 0x40).expect("override");
    assert_eq!((s.name.as_str(), s.elements.len()), ("PlayerOverride", 1));
    assert!(e.structure_override(0x2000_0000, 0x40).is_none());
    let ov = |a, n| e.structure_override(a, n);
    let g = hh_tools::structure::guess_structure_with(&*p, "x", 0x3000_0000, 0x40, &hh_tools::structure::GuessOptions::plain(), Some(&ov)).unwrap();
    assert_eq!(g.name, "PlayerOverride");
    assert_eq!(e.structure_name(0x10), Some(("Obj_10".to_string(), None)));
    run(&e, "assert(unregisterStructureDissectOverride(ov) and unregisterStructureNameLookup(nl))");
    assert!(e.structure_override(0x3000_0000, 0x40).is_none() && e.structure_name(0x10).is_none());
}

#[test]
fn disassembler_helpers_and_address_names() {
    let (e, p, _) = engine();
    run(
        &e,
        r#"
        local base = getAddress('game.exe')
        local hits = hhAssemblyScan('sub [rcx+*],eax', base, base + 0x2000)
        assert(#hits == 1 and hits[1].Address == base + 0x1005, #hits)
        assert(hits[1].Text:find('sub'))
        local seq = hhAssemblyScan('sub [rcx+*],eax;mov eax,*', base, base + 0x2000)
        assert(#seq == 1)
        assert(hhFindReference(base + 0x1000, base + 0x3020, true, 0x100) == base + 0x1011)
        assert(hhFindReference(base + 0x1000, base + 0x3F00, true, 0x100) == nil)
        registerSymbol('mysym', 0x1234)
        local rows, total = hhSymbolList(nil, 'mysym')
        assert(total == 1 and rows[1].Name == 'mysym' and rows[1].User and rows[1].Address == 0x1234)

        addr = registerAddressLookupCallback(function(a) if a == base + 0x3020 then return 'hpvalue' end end)
        assert(getNameFromAddress(base + 0x3020) == 'hpvalue')
        assert(getNameFromAddress(base + 0x3024) ~= 'hpvalue')
        assert(disassemble(base + 0x1011):find('hpvalue'), disassemble(base + 0x1011))
    "#,
    );
    let name = e.address_name().expect("registered");
    assert_eq!(name(GAME + 0x3020).as_deref(), Some("hpvalue"));
    let lines = hh_asm::disassemble_with(&*p, &SymbolTable::default(), GAME + 0x1011, 1, &hh_asm::DisasmOptions { address_name: Some(name), ..Default::default() }).unwrap();
    assert!(format!("{} {}", lines[0].text, lines[0].comment).contains("hpvalue"), "{lines:?}");
    run(&e, "assert(unregisterAddressLookupCallback(addr))");
    assert!(e.address_name().is_none());
    // A budget-limited scan over a huge range stops with the budget.
    e.set_budget(Some(std::time::Duration::from_millis(300)));
    let r: Result<Vec<String>> = e.exec("hhAssemblyScan('nop;nop;nop;nop;nop;nop;nop;nop;nop;nop', 0, 0x7fffffffffffffff, 1)", "budget");
    if let Err(err) = r {
        assert!(err.to_string().contains("budget"), "{err}");
    }
}

#[test]
fn dissect_save_load_and_code_filter() {
    let (e, _, _) = engine();
    let path = std::env::temp_dir().join(format!("hh-lua-dissect-{}.hhdis", std::process::id()));
    e.lua().globals().set("PATH", path.display().to_string()).unwrap();
    run(
        &e,
        r#"
        local dc = getDissectCode()
        dc.dissect('game.exe')
        assert(dc.saveToFile(PATH))
        dc.clear()
        assert(next(dc.getReferences(0x140003020)) == nil)
        assert(dc.loadFromFile(PATH))
        assert(dc.getReferences(0x140003020)[0x140001011] == jtMemory, 'references back')
        local f = dc.codeFilter({ { 0x140001005 } }, {})
        assert(type(f) == 'table')
        assert(#dc.codeFilter({}) == 0)
        assert(not pcall(dc.loadFromFile, PATH .. '.missing'))
    "#,
    );
    std::fs::remove_file(&path).unwrap();
    let e = Engine::new(EngineOptions { allow_os: false, ..Default::default() }).unwrap();
    e.set_process(Some(game())).unwrap();
    let err = e.exec("getDissectCode().loadFromFile('x')", "x").unwrap_err().to_string();
    assert!(err.contains("file access is disabled"), "{err}");
}
