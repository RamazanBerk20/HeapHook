//! The second wave of the CE API: memory/process helpers, string and file utilities, memory
//! record members, memscan features, structures, dissect code and host-backed functions.
mod common;

use std::sync::{Arc, Mutex};

use common::*;
use hh_core::{Memory, Result};
use hh_lua::{Engine, EngineOptions, Host, MemTable, RecId, TableHost};
use hh_scan::Scanner;

#[test]
fn memory_and_process_helpers() {
    let (e, p, _) = engine();
    run(
        &e,
        r#"
        -- copyMemory target -> target, to an explicit and an allocated destination
        local base = getAddress('game.exe')
        assert(copyMemory(base + 0x3010, 6, 0x20000040) == 0x20000040)
        assert(readString(0x20000040) == 'Hello')
        local fresh = copyMemory(base + 0x3010, 6)
        assert(fresh ~= 0x20000040 and readString(fresh) == 'Hello')
        -- target -> CE and back
        local mine = copyMemory(base + 0x3010, 6, nil, 1)
        assert(readStringLocal(mine) == 'Hello')
        assert(compareMemory(base + 0x3010, 0x20000040, 6))
        writeByte(0x20000042, 0x4C)
        local same, at = compareMemory(base + 0x3010, 0x20000040, 6)
        assert(same == false and at == 2, tostring(at))
        assert(compareMemory(base + 0x3010, mine, 5, 1))

        local regions = enumMemoryRegions()
        assert(#regions == 3 and regions[1].BaseAddress == 0x20000000 and regions[1].RegionSize == 0x100)
        assert(regions[1].Protect == 0x40 and regions[1].State == 0x1000 and regions[1].Type == 0x20000)
        local prot = getMemoryProtection('game.exe+10')
        assert(prot.R and prot.W and prot.X)
        assert(getMemoryProtection(0x10) == nil)
        assert(getPointerSize() == 8)

        local tl = getThreadlist()
        assert(tl.Count == 2 and tl[0] == '1' and tl[1] == '2A')
        local into = createStringlist()
        into.add('stale')
        assert(getThreadlist(into) == into and into.Count == 2)
    "#,
    );
    // region files
    let dir = std::env::temp_dir().join(format!("hh-lua-region-{}", std::process::id()));
    let path = dir.with_extension("bin");
    e.lua().globals().set("PATH", path.display().to_string()).unwrap();
    run(
        &e,
        r#"
        assert(writeRegionToFile(PATH, 'game.exe+3010', 6) == 6)
        assert(fileExists(PATH) and not fileExists(PATH .. '.nope'))
        assert(md5file(PATH) == stringToMD5String('Hello\0'))
        assert(readRegionFromFile(PATH, 0x20000020) == 6)
        assert(readString(0x20000020) == 'Hello')
        assert(md5memory(0x20000020, 6) == stringToMD5String('Hello\0'))
    "#,
    );
    std::fs::remove_file(&path).unwrap();
    let mut b = [0u8; 5];
    p.read_exact(0x2000_0020, &mut b).unwrap();
    assert_eq!(&b, b"Hello");

    let e2 = Engine::new(EngineOptions { allow_os: false, ..Default::default() }).unwrap();
    e2.set_process(Some(p)).unwrap();
    let err = e2.exec("writeRegionToFile('/tmp/x', 0x20000000, 4)", "x").unwrap_err().to_string();
    assert!(err.contains("disabled"), "{err}");
    assert!(e2.exec("shellExecute('true')", "x").unwrap_err().to_string().contains("disabled"));
}

#[test]
fn string_and_file_utilities() {
    let (e, _, _) = engine();
    run(
        &e,
        r#"
        assert(stringToMD5String('') == 'd41d8cd98f00b204e9800998ecf8427e')
        assert(stringToMD5String('abc') == '900150983cd24fb0d6963f7d28e17f72')
        assert(ansiToUtf8('\x80\xE9') == '€é')
        assert(utf8ToAnsi('€é') == '\x80\xE9')
        assert(extractFilePath('C:\\games\\x.CT') == 'C:\\games\\' and extractFileName('/a/b/c.lua') == 'c.lua')
        assert(extractFileExt('/a/b/c.tar.gz') == '.gz' and extractFileNameWithoutExt('/a/b.ct') == 'b')
        assert(extractFilePath('plain') == '' and extractFileName('plain') == 'plain')
        local tmp = getTempFolder()
        assert(tmp:sub(-1) == package.config:sub(1, 1) and directoryExists(tmp))
        assert(translate('Hello') == 'Hello')
        assert(convertKeyComboToString(VK_CONTROL, VK_F1) == 'Ctrl+F1')
        assert(isKeyPressed(VK_F1) == false)
        processMessages()
    "#,
    );
}

#[test]
fn symbols_through_hh_asm() {
    let (e, _, _) = engine();
    run(
        &e,
        r#"
        registerSymbol('player', 'game.exe+3000')
        local i = getSymbolInfo('player')
        assert(i.address == 0x140003000 and i.modulename == 'game.exe' and i.symbolsize == 0)
        assert(getSymbolInfo('nothing.here+x') == nil)
        assert(type(enumExports('game.exe')) == 'table')
        local ok, err = pcall(enumExports, 'missing.dll')
        assert(not ok and err:find('not found'))
    "#,
    );
}

#[test]
fn memory_record_members() {
    let (e, p, cap) = engine();
    let t = Arc::new(MemTable::new());
    e.set_table(t.clone());
    run(
        &e,
        r#"
        local al = getAddressList()
        local grp = al.createGroupHeader('Cheats')
        assert(grp.IsGroupHeader and grp.Value == '' and grp.IsReadable and grp.Type ~= vtAutoAssembler)
        grp.Options = '[moActivateChildrenAsWell,moDeactivateChildrenAsWell,moRecursiveSetValue]'
        assert(grp.Options == '[moActivateChildrenAsWell,moDeactivateChildrenAsWell,moRecursiveSetValue]')
        grp.Collapsed = true
        assert(grp.Collapsed)

        local hp = al.createMemoryRecord()
        hp.Description = 'HP'
        hp.Address = 'game.exe+3020'
        hp.appendToEntry(grp)
        local ammo = al.createMemoryRecord()
        ammo.Description = 'Ammo'
        ammo.Address = 0x20000000
        ammo.appendToEntry(grp)
        assert(hp.IsReadable and hp.Index == 1)

        -- group header: activation runs nothing, children follow the options
        grp.Active = true
        assert(grp.Active and hp.Active and ammo.Active)
        grp.Active = false
        assert(not grp.Active and not hp.Active and not ammo.Active)
        -- moRecursiveSetValue
        grp.Value = 77
        assert(hp.Value == '77' and ammo.Value == '77')

        -- unreadable record
        local bad = al.createMemoryRecord()
        bad.Address = 0x10
        assert(not bad.IsReadable and bad.Value == '??')

        -- dropdown list
        hp.DropDownList.Text = '0:Off\n1:On\n'
        assert(hp.DropDownCount == 2 and hp.DropDownValue[1] == '1' and hp.DropDownDescription[1] == 'On')
        hp.DropDownList.add('2:Max')
        assert(hp.DropDownList.Count == 3 and hp.DropDownList[2] == '2:Max')
        hp.DropDownReadOnly = true
        hp.DropDownDescriptionOnly = true
        hp.DisplayAsDropDownListItem = true
        assert(hp.DropDownReadOnly and hp.DropDownDescriptionOnly and hp.DisplayAsDropDownListItem)

        -- OnValueChanged fires from tick; OnDestroy on delete
        changes = {}
        hp.OnValueChanged = function(mr, old, new) changes[#changes + 1] = old .. '>' .. new end
        destroyed = nil
        bad.OnDestroy = function(mr) destroyed = mr.Address end
        bad.destroy()
        assert(destroyed == '10')

        -- selection
        assert(al.SelectedRecord == nil and #al.getSelectedRecords() == 0)
        al.SelectedRecord = ammo
        assert(al.SelectedRecord == ammo and al.getSelectedRecords()[1] == ammo and al.SelCount == 1)
        al.setSelectedRecord(nil)
        assert(al.SelectedRecord == nil)

        -- hotkeys on records
        local hk = hp.createHotkey({VK_CONTROL, VK_F2}, mrhIncreaseValue, '5', 'more hp')
        assert(hp.HotkeyCount == 1 and hp.Hotkey[0] == hk and hk.ID == 1)
        assert(hk.HotkeyString == 'Ctrl+F2' and hk.Description == 'more hp' and hk.Owner == hp)
        local tog = hp.createHotkey({VK_F3}, mrhToggleActivation)
        posts = 0
        tog.OnPostHotkey = function(h) posts = posts + 1 end
        assert(hp.getHotkeyByID(2) == tog)
        HPID = hp.ID
    "#,
    );
    // tick sees the change made behind the script's back
    p.write(GAME + 0x3020, &80u32.to_le_bytes()).unwrap();
    e.tick().unwrap();
    assert_eq!(run(&e, "return changes[1]"), ["77>80"]);
    // record hotkeys fired by the host
    let hp: RecId = run(&e, "return HPID")[0].parse().unwrap();
    e.fire_record_hotkey(hp, 1).unwrap();
    assert_eq!(read_u32(&*p, GAME + 0x3020), 85);
    e.fire_record_hotkey(hp, 2).unwrap();
    assert!(t.get(hp).unwrap().active);
    e.fire_record_hotkey(hp, 2).unwrap();
    assert!(!t.get(hp).unwrap().active);
    assert_eq!(run(&e, "return posts"), ["2"]);
    assert!(e.fire_record_hotkey(hp, 99).is_err());
    // The data is on the record for the host.
    let r = t.get(hp).unwrap();
    assert_eq!(r.hotkeys.len(), 2);
    assert_eq!(r.hotkeys[0].keys, vec![0x11, 0x71]);
    assert_eq!(r.dropdown, vec!["0:Off", "1:On", "2:Max"]);
    let g = t.get(r.parent.unwrap()).unwrap();
    assert!(g.group_header && g.collapsed && g.options.len() == 3);
    let _ = cap;
}

#[test]
fn group_header_without_process() {
    let e = Engine::new(EngineOptions::default()).unwrap();
    let t = Arc::new(MemTable::new());
    e.set_table(t.clone());
    let id = t.create(None);
    let mut r = t.get(id).unwrap();
    r.group_header = true;
    t.set(r).unwrap();
    e.set_active(id, true).unwrap();
    assert!(t.get(id).unwrap().active);
    // What the app does today (header passed as an empty script) works without a process too.
    let s = t.create(None);
    let mut r = t.get(s).unwrap();
    r.script = Some(String::new());
    t.set(r).unwrap();
    e.set_active(s, true).unwrap();
    assert!(t.get(s).unwrap().active);
}

#[test]
fn memscan_saved_results_not_and_custom_types() {
    let (e, p, _) = engine();
    // big-endian 0x00000064 (100) somewhere the scan can find it
    p.write(0x2000_0010, &[0, 0, 0, 100]).unwrap();
    run(
        &e,
        r#"
        ms = createMemScan()
        ms.firstScan(soExactValue, vtDword, rtRounded, '42', '', 0, 0x7fffffffffffffff, '', fsmAligned, '4',
                     false, false, false, false)
        assert(ms.FoundCount == 1)
        ms.saveCurrentResults('before')
        assert(ms.getSavedResultList()[0] == 'before')
    "#,
    );
    p.write(GAME + 0x3020, &50u32.to_le_bytes()).unwrap();
    run(
        &e,
        r#"
        ms.nextScan(soIncreasedValue, rtRounded, '', '', false, false, false, false, false)
        assert(ms.FoundCount == 1)
        -- compare to the saved scan instead of the previous one
        ms.nextScan(soIncreasedValue, rtRounded, '', '', false, false, false, false, false, 'before')
        assert(ms.FoundCount == 1)
        ms.deleteSavedResult('before')
        assert(ms.getSavedResultList().Count == 0)

        -- the not flag: everything aligned that is NOT zero in the heap region
        ms.newScan()
        ms.Not = true
        ms.firstScan(soExactValue, vtDword, rtRounded, '0', '', 0x20000000, 0x20000100, '', fsmAligned, '4',
                     false, false, false, false)
        local n = ms.FoundCount
        ms.Not = false
        assert(n == 3, n) -- 0x20000008 (pointer), 0x20000010 (BE 100), 0x20000088 (0x1234)
    "#,
    );
    let _ = p;
}

#[test]
fn memscan_custom_type_and_only_one_result() {
    let (e, p, _) = engine();
    p.write(0x2000_0010, &[0, 0, 0, 100]).unwrap();
    run(
        &e,
        r#"
        ms = createMemScan()
        ms.CustomType = '4 byte big endian'
        ms.OnlyOneResult = true
        ms.firstScan(soExactValue, vtCustom, rtRounded, '100', '', 0x20000000, 0x20000100, '', fsmAligned, '4',
                     false, false, false, false)
        assert(ms.FoundCount == 1 and ms.Result == 0x20000010, ms.FoundCount)
        ms.newScan()
        ms.CustomType = { size = 2, signed = true }
        ms.firstScan(soExactValue, vtCustom, rtRounded, '4660', '', 0x20000000, 0x20000100, '', fsmAligned, '2',
                     false, false, false, false)
        assert(ms.FoundCount == 1 and ms.getOnlyResult() == 0x20000088)
        ms.CustomType = nil
        local ok, err = pcall(ms.firstScan, soExactValue, vtCustom, rtRounded, '1')
        assert(not ok and err:find('CustomType'), err)
    "#,
    );
}

#[test]
fn structures_on_hh_tools() {
    let (e, _, _) = engine();
    let t = Arc::new(MemTable::new());
    e.set_table(t.clone());
    run(
        &e,
        r#"
        assert(getStructureCount() == 0)
        local s = createStructure('Player')
        assert(s.Name == 'Player' and s.Count == 0 and getStructureCount() == 0, 'not global yet')
        local hp = s.addElement()
        hp.Name = 'health'
        hp.Offset = 8
        hp.Vartype = vtDword
        local ptr = s.addElement()
        ptr.Offset = 0
        ptr.Vartype = vtPointer
        assert(s.Count == 2, s.Count)
        assert(s.Element[0].Offset == 0, s.Element[0].Offset)
        assert(s.getElement(1).Name == 'health', tostring(s.getElement(1).Name))
        assert(s.Size == 12, s.Size)
        assert(s.getElementByOffset(9).Name == 'health')
        -- values through a base address: heap+0x80 holds 0x1234 at +8
        assert(hp.getValue(0x20000080) == '4660')
        assert(hp.setValue(0x20000080, 99) and readInteger(0x20000088) == 99)
        assert(ptr.getValue(0x20000000) == '0')
        s.addToGlobalStructureList()
        assert(getStructureCount() == 1 and getStructure(0).Name == 'Player')
        -- edits to a global structure reach the global list
        getStructure(0).Name = 'Hero'
        assert(getStructure(0).Name == 'Hero')
        local g = createStructure('Guess')
        g.autoGuess(0x20000000, 0, 0x10)
        assert(g.Count >= 1, 'auto guess fills elements')
        hp.destroy()
        assert(s.Count == 1)
        s.removeFromGlobalStructureList()
        assert(getStructureCount() == 0)
        s.destroy()
        local ok, err = pcall(function() return s.Name end)
        assert(not ok and err:find('destroyed'))
    "#,
    );
}

#[test]
fn dissect_code_accessors() {
    let (e, _, _) = engine();
    run(
        &e,
        r#"
        local dc = getDissectCode()
        dc.dissect('game.exe')
        -- `mov eax,[game.exe+3020]` at +1011 references +3020
        local refs = dc.getReferences(getAddress('game.exe+3020'))
        assert(refs[0x140001011] == jtMemory, 'memory reference found')
        assert(type(dc.getReferencedStrings()) == 'table' and type(dc.getReferencedFunctions()) == 'table')
        dc.clear()
        assert(next(dc.getReferences(0x140003020)) == nil)
        local ok, err = pcall(dc.saveToFile, 'x')
        assert(not ok and err:find('nothing dissected'), err)
    "#,
    );
}

#[derive(Default)]
struct HostCalls {
    calls: Mutex<Vec<String>>,
    scanner: Mutex<Option<Arc<Scanner>>>,
}

impl Host for HostCalls {
    fn create_process(&self, path: &str, params: &str, debug: bool, brk: bool) -> Result<u32> {
        self.calls.lock().unwrap().push(format!("create {path} {params} {debug} {brk}"));
        Ok(4242)
    }
    fn load_table(&self, path: &str, merge: bool) -> Result<()> {
        self.calls.lock().unwrap().push(format!("load {path} {merge}"));
        Ok(())
    }
    fn save_table(&self, path: &str, protect: bool) -> Result<()> {
        self.calls.lock().unwrap().push(format!("save {path} {protect}"));
        Ok(())
    }
    fn current_memscan(&self) -> Option<Arc<Scanner>> {
        self.scanner.lock().unwrap().clone()
    }
    fn is_key_pressed(&self, vk: i64) -> bool {
        vk == 0x70
    }
}

#[test]
fn host_backed_functions() {
    let (e, p, _) = engine();
    // Defaults: clear errors, not crashes.
    for (src, want) in [("createProcess('x')", "createProcess"), ("loadTable('a.CT')", "loadTable"), ("saveTable('a.CT')", "saveTable")] {
        let err = e.exec(src, "x").unwrap_err().to_string();
        assert!(err.contains(want) && err.contains("unsupported"), "{err}");
    }
    assert_eq!(run(&e, "return getCurrentMemscan()"), ["nil"]);
    let h = Arc::new(HostCalls::default());
    let s = Arc::new(Scanner::new(p.clone()));
    *h.scanner.lock().unwrap() = Some(s.clone());
    e.set_host(h.clone());
    run(
        &e,
        r#"
        opened = nil
        function onOpenProcess(pid) opened = pid end
        assert(createProcess('/bin/game', '-w', true) == 4242 and opened == 4242)
        loadTable('/t/a.CT', true)
        saveTable('/t/b.CT')
        assert(isKeyPressed(VK_F1) and not isKeyPressed(VK_F2))
        local ms = getCurrentMemscan()
        assert(ms == getCurrentMemscan(), 'same object')
        ms.firstScan(soExactValue, vtDword, rtRounded, '42', '', 0, 0x7fffffffffffffff, '', fsmAligned, '4',
                     false, false, false, false)
        assert(ms.FoundCount == 1)
        ms.destroy() -- not ours: the host keeps it
    "#,
    );
    assert_eq!(s.count(), 1, "the scan ran on the host's scanner");
    assert_eq!(*h.calls.lock().unwrap(), ["create /bin/game -w true false", "load /t/a.CT true", "save /t/b.CT false"]);
}

// ------------------------------------------------------------------ second release audit L2-L4

fn lua_err(e: &Engine, src: &str) -> String {
    e.exec(src, "test").err().map(|x| x.to_string()).unwrap_or_else(|| panic!("script succeeded: {src}"))
}

#[test]
fn file_helpers_refuse_devices_and_huge_files() {
    let (e, _, _) = engine();
    for f in ["md5file('/dev/zero')", "readRegionFromFile('/dev/zero', 0x20000000)", "md5file('/tmp')"] {
        let err = lua_err(&e, f);
        assert!(err.contains("not a regular file"), "{f}: {err}");
    }
    let dir = std::env::temp_dir().join(format!("hh-lua-l2-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    // A FIFO must be refused without blocking on open.
    let fifo = dir.join("fifo");
    if std::process::Command::new("mkfifo").arg(&fifo).status().is_ok_and(|s| s.success()) {
        let err = lua_err(&e, &format!("md5file('{}')", fifo.display()));
        assert!(err.contains("not a regular file"), "{err}");
    }
    // Over the size cap (sparse: no disk space or memory used).
    let big = dir.join("big");
    std::fs::File::create(&big).unwrap().set_len((1 << 30) + 1).unwrap();
    for f in ["md5file", "readRegionFromFile"] {
        let err = lua_err(&e, &format!("{f}('{}', 0x20000000)", big.display()));
        assert!(err.contains("larger than 1073741824 bytes"), "{f}: {err}");
    }
    // Streaming hash of a multi-chunk file matches the one-buffer hash.
    let data: Vec<u8> = (0..(3 << 20) + 17u32).map(|i| (i * 31 % 253) as u8).collect();
    let f = dir.join("data");
    std::fs::write(&f, &data).unwrap();
    e.lua().globals().set("DATA", e.lua().create_string(&data).unwrap()).unwrap();
    run(&e, &format!("assert(md5file('{}') == stringToMD5String(DATA))", f.display()));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn copy_memory_local_buffers_are_owned_and_capped() {
    let (e, _, _) = engine();
    run(
        &e,
        r#"
        local base = getAddress('game.exe')
        local mine = copyMemory(base + 0x3010, 6, nil, 1)
        assert(readStringLocal(mine) == 'Hello')
        assert(deAllocLocal(mine) == true and deAllocLocal(mine) == false)
        -- the total cap is checked before anything is allocated
        local ok, err = pcall(copyMemory, base + 0x3010, 300 * 1024 * 1024, nil, 1)
        assert(not ok and tostring(err):find('would exceed 268435456'), tostring(err))
        keep = copyMemory(base + 0x3010, 6, nil, 1)
        local ok, err = pcall(copyMemory, base + 0x3010, 256 * 1024 * 1024 - 5, nil, 1)
        assert(not ok and tostring(err):find('would exceed'), tostring(err))
        -- a failed copy frees its buffer: the same failure twice, never the cap
        for i = 1, 3 do
          local ok, err = pcall(copyMemory, 0x7000000000, 200 * 1024 * 1024, nil, 1)
          assert(not ok and not tostring(err):find('would exceed'), tostring(err))
        end
    "#,
    );
    // clear_table_state frees what is left.
    e.clear_table_state().unwrap();
    run(&e, "assert(deAllocLocal(keep) == false)");
}

#[test]
fn os_access_checks_cover_host_functions() {
    let e = Engine::new(EngineOptions { allow_os: false, ..Default::default() }).unwrap();
    for (f, what) in [
        ("createProcess('/bin/true')", "OS access is disabled"),
        ("loadTable('/tmp/x.CT')", "file access is disabled"),
        ("saveTable('/tmp/x.CT')", "file access is disabled"),
        ("getTempFolder()", "OS access is disabled"),
        ("md5file('/etc/hostname')", "file access is disabled"),
        ("readRegionFromFile('/etc/hostname', 0)", "file access is disabled"),
        ("shellExecute('true')", "OS access is disabled"),
        (&format!("openProcess({})", std::process::id()), "own memory is disabled"),
    ] {
        let err = lua_err(&e, f);
        assert!(err.contains(what), "{f}: {err}");
    }
    run(&e, "assert(fileExists('/etc/hostname') == false and directoryExists('/tmp') == false)");
}

#[test]
fn host_side_sizes_and_result_counts_are_capped() {
    let (e, _, _) = engine();
    let err = lua_err(&e, "readBytes(0x20000000, 100 * 1024 * 1024, true)");
    assert!(err.contains("more than 67108864"), "{err}");
    let err = lua_err(&e, "writeString(0x20000000, string.rep('x', 65 * 1024 * 1024))");
    assert!(err.contains("more than 67108864"), "{err}");
    let err = lua_err(&e, "local t = {} for i = 1, 70 * 1024 * 1024 // 64 do t[i] = 0 end writeBytes(0x20000000, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t, t)");
    assert!(err.contains("more than 67108864"), "{err}");
    // An AOB pattern matching every byte of this (large) process stops at the result cap.
    e.set_process(Some(hh_core::open(std::process::id()).unwrap())).unwrap();
    let err = lua_err(&e, "AOBScan('??')");
    assert!(err.contains("more than 1048576 matches"), "{err}");
    let err = lua_err(&e, "AOBScan('??', '', 1, '1')");
    assert!(err.contains("more than 1048576 matches"), "{err}");
    run(&e, "assert(AOBScanUnique('??') == nil)");
}
