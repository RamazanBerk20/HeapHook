//! Lua-script-driven tests of the Cheat Engine API against a fake process.
mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use common::*;
use hh_core::Memory;
use hh_lua::{Engine, EngineOptions, MemTable, STUBS, TableHost, UNSUPPORTED, stub_message};

#[test]
fn memory_read_write() {
    let (e, p, _) = engine();
    run(
        &e,
        r#"
        local s = 'game.exe+3020'
        assert(readInteger(s) == 0x2A)
        assert(readInteger(0x140003020) == 42)
        assert(readSmallInteger(s) == 42 and readByte(s) == 42 and readShortInteger(s) == 42)
        assert(writeInteger(s, -2))
        assert(readInteger(s) == 0xFFFFFFFE, 'unsigned by default')
        assert(readInteger(s, true) == -2)
        assert(readSmallInteger(s, true) == -2 and readSmallInteger(s) == 0xFFFE)
        assert(writeQword(s, -5) and readQword(s) == -5)
        assert(writeFloat(s, 1.5) and readFloat(s) == 1.5)
        assert(writeDouble(s, -2.25) and readDouble(s) == -2.25)
        assert(writeSmallInteger(s, 0x1234) and writeByte(s, 0x99) and readSmallInteger(s) == 0x1299)
        assert(readPointer('game.exe+3000') == 0x20000000)
        assert(readInteger(readPointer(readPointer('game.exe+3000') + 8) + 8) == 0x1234)
        assert(readInteger('[[game.exe+3000]+8]+8') == 0x1234)
        -- failures return nil / false
        assert(readInteger(0x10) == nil and readBytes(0x10, 4) == nil and readString(0x10) == nil)
        assert(readInteger('nosuchthing+5') == nil)
        assert(writeInteger(0x10, 1) == false)
        -- bytes: multi return and table forms, table and vararg writes
        assert(writeBytes(s, 1, 2, 3, 4))
        local a, b, c, d = readBytes(s, 4)
        assert(a == 1 and b == 2 and c == 3 and d == 4)
        assert(writeBytes(s, {0xAA, 0xBB}))
        local t = readBytes(s, 4, true)
        assert(#t == 4 and t[1] == 0xAA and t[2] == 0xBB and t[3] == 3)
        -- strings
        assert(readString('game.exe+3010') == 'Hello')
        assert(readString('game.exe+3010', 3) == 'Hel')
        assert(writeString(s, 'Hi', true) and readString(s, 10, true) == 'Hi')
        assert(byteTableToWideString(readBytes(s, 4, true)) == 'Hi')
    "#,
    );
    assert_eq!(read_u32(&*p, GAME + 0x3020), 0x0069_0048);
}

#[test]
fn local_memory_variants() {
    let (e, _, _) = engine();
    let cell: &'static mut u32 = Box::leak(Box::new(0xC0FFEEu32));
    let a = cell as *mut u32 as u64;
    let out = run(
        &e,
        &format!(
            "assert(readIntegerLocal({a}) == 0xC0FFEE)
             assert(writeIntegerLocal({a}, 7))
             return readBytesLocal({a}, 1)"
        ),
    );
    assert_eq!(out, ["7"]);
    assert_eq!(unsafe { std::ptr::read_volatile(a as *const u32) }, 7);
}

#[test]
fn converters_and_bit_ops() {
    let (e, _, _) = engine();
    run(
        &e,
        r#"
        local function eq(a, b) for i = 1, math.max(#a, #b) do if a[i] ~= b[i] then return false end end return true end
        assert(eq(wordToByteTable(0x1234), {0x34, 0x12}))
        assert(eq(dwordToByteTable(-1), {255, 255, 255, 255}))
        assert(eq(qwordToByteTable(0x0102030405060708), {8, 7, 6, 5, 4, 3, 2, 1}))
        assert(eq(floatToByteTable(1.0), {0, 0, 0x80, 0x3F}))
        assert(eq(stringToByteTable('AB'), {65, 66}))
        assert(eq(wideStringToByteTable('A€'), {65, 0, 0xAC, 0x20}))
        assert(byteTableToWord({0xFE, 0xFF}) == 0xFFFE and byteTableToWord({0xFE, 0xFF}, true) == -2)
        assert(byteTableToDword(dwordToByteTable(123456)) == 123456)
        assert(byteTableToQword(qwordToByteTable(-9)) == -9)
        assert(byteTableToFloat(floatToByteTable(3.5)) == 3.5)
        assert(byteTableToDouble(doubleToByteTable(-0.125)) == -0.125)
        assert(byteTableToString({72, 105}) == 'Hi')
        assert(byteTableToWideString(wideStringToByteTable('x😀y')) == 'x😀y')
        assert(bAnd(0xF0, 0x3C) == 0x30 and bOr(1, 2) == 3 and bXor(3, 1) == 2)
        assert(bShl(1, 4) == 16 and bShr(256, 4) == 16 and bNot(0) == -1)
        assert(bAnd(7.0, 3) == 3)
        assert(7 // 2 == 3 and math.type(7 // 2) == 'integer' and 7 / 2 == 3.5, 'Lua 5.3 integer semantics')
    "#,
    );
}

#[test]
fn process_and_symbols() {
    let (e, _, _) = engine();
    run(
        &e,
        r#"
        assert(getOpenedProcessID() == 1)
        assert(targetIs64Bit())
        assert(getAddress('game.exe') == 0x140000000)
        assert(getAddress('game.exe+10') == 0x140000010)
        assert(getAddress(0x1234) == 0x1234)
        assert(getAddressSafe('nope') == nil)
        local ok, err = pcall(getAddress, 'nope')
        assert(not ok and err:find('nope'), err)
        registerSymbol('player', 'game.exe+3000')
        assert(getAddress('player+8') == 0x140003008)
        assert(getNameFromAddress(0x140003000) == 'player')
        assert(getNameFromAddress(0x140003004) == 'game.exe+3004')
        assert(getNameFromAddress(0x10) == '10')
        unregisterSymbol('player')
        assert(getAddressSafe('player') == nil)
        assert(inModule(0x140000100) and not inModule(0x20000000))
        assert(getModuleSize('game.exe') == 0x4000)
        local m = enumModules()
        assert(#m == 1 and m[1].Name == 'game.exe' and m[1].Address == 0x140000000 and m[1].Is64Bit)
        assert(type(getProcessList()) == 'table')
        assert(getProcessIDFromProcessName('surely-no-such-process-xyz') == nil)
        assert(openProcess('surely-no-such-process-xyz') == false)
    "#,
    );
    // Symbols are shared with the host.
    run(&e, "registerSymbol('hostvisible', 0x99)");
    assert_eq!(e.symbols().lock().unwrap().get("hostvisible"), Some(0x99));
}

#[test]
fn allocation() {
    let (e, p, _) = engine();
    let out = run(
        &e,
        r#"
        local a = allocateMemory(0x100)
        assert(a and writeInteger(a, 5) and readInteger(a) == 5)
        local near = allocateMemory(0x100, getAddress('game.exe'))
        assert(math.abs(near - getAddress('game.exe')) < 0x80000000)
        assert(deAlloc(a))
        assert(readInteger(a) == nil)
        return near
    "#,
    );
    let near: u64 = out[0].parse().unwrap();
    assert!(p.read(near, &mut [0u8; 4]).is_ok());
}

#[test]
fn aob_scans() {
    let (e, _, _) = engine();
    run(
        &e,
        r#"
        local r = AOBScan('29 81 E0 00 00 00 8B')
        assert(r and r.Count == 1 and r[0] == '140001005' and r.getString(0) == '140001005')
        r.destroy()
        assert(AOBScan('29 81 ?? 00 00 00') .Count == 1)
        assert(AOBScan(0x29, 0x81, 0xE0).Count == 1, 'byte-argument form')
        assert(AOBScan('81 E0 00 00 00').Count == 2)
        assert(AOBScan('81 E0 00 00 00', '+W', fsmAligned, '4').Count == 1)
        assert(AOBScan('11 22 33 44 55 66 77') == nil)
        assert(AOBScanUnique('29 81 E0') == 0x140001005)
        assert(AOBScanUnique('81 E0 00 00 00') == nil, 'not unique')
        assert(AOBScanModuleUnique('game.exe', '8B 05 09 20') == 0x140001011)
        assert(AOBScanModuleUnique('other.dll', '8B 05') == nil)
        assert(AOBScan('48 65 6C 6C 6F', '-W') == nil, 'protection filter')
    "#,
    );
}

#[test]
fn memscan_and_foundlist() {
    let (e, p, _) = engine();
    run(
        &e,
        r#"
        ms = createMemScan()
        done = 0
        ms.OnScanDone = function(m) assert(m == ms); done = done + 1 end
        ms.firstScan(soExactValue, vtDword, rtRounded, '42', '', 0, 0x7fffffffffffffff, '*W*X*C',
                     fsmAligned, '4', false, false, false, false)
        ms.waitTillDone()
        assert(done == 1)
        fl = createFoundList(ms)
        fl.initialize()
        assert(fl.Count == 1, fl.Count)
        assert(fl.Address[0] == '140003020' and fl.Value[0] == '42')
        assert(fl.Address[1] == nil)
        assert(ms.getAttachedFoundlist() == fl)
    "#,
    );
    p.write(GAME + 0x3020, &50u32.to_le_bytes()).unwrap();
    run(
        &e,
        r#"
        ms:nextScan(soIncreasedValue, rtRounded, '', '', false, false, false, false, false)
        fl:initialize()
        assert(fl.Count == 1 and fl.Value[0] == '50' and ms.FoundCount == 1 and ms.getFoundCount() == 1)
        ms.nextScan(soExactValue, rtRounded, '7')
        fl.initialize()
        assert(fl.Count == 0)
        ms.newScan()
        ms.firstScan(soExactValue, vtString, rtRounded, 'hello', '', 0, 0, '', fsmNotAligned, '', false, false, false, false)
        fl.initialize()
        assert(fl.Count == 1 and fl.Address[0] == '140003010', 'case-insensitive string scan')
        ms.destroy()
        local ok, err = pcall(ms.firstScan, soExactValue, vtDword, rtRounded, '1')
        assert(not ok and err:find('destroyed'))
    "#,
    );
}

#[test]
fn assembler_functions() {
    let (e, p, _) = engine();
    run(
        &e,
        r#"
        local d = disassemble('game.exe+1005')
        assert(d == '140001005 - 29 81 E0 00 00 00 - sub [rcx+E0],eax', d)
        local extra, opcode, bytes, address = splitDisassembledString(d)
        assert(extra == '' and opcode == 'sub [rcx+E0],eax' and bytes == '29 81 E0 00 00 00' and address == '140001005')
        assert(select(2, splitDisassembledString('1 - 90 - nop : hello')) == 'nop')
        assert(getInstructionSize('game.exe+1005') == 6)
        assert(getPreviousOpcode('game.exe+100B') == 0x140001005)
        local b = assemble('mov eax,1')
        assert(#b == 5 and b[1] == 0xB8 and b[2] == 1)
        assert(assemble('bogus eax') == nil)
        local ok, err = autoAssembleCheck('[ENABLE]\nnop\n[DISABLE]\n')
        assert(not ok and err:find('line 2'), err)
        assert(autoAssembleCheck('[ENABLE]\ngame.exe+3020:\ndb 01\n[DISABLE]\n'))
    "#,
    );
    let before = p.snapshot();
    e.lua().globals().set("SCRIPT", HEALTH_SCRIPT).unwrap();
    run(
        &e,
        r#"
        local ok, info = autoAssemble(SCRIPT)
        assert(ok, info)
        assert(info.allocs.newmem.address ~= 0 and #info.registeredsymbols == 2)
        assert(readByte('godmode') == 1)
        assert(readByte('health') == 0xE9, 'jmp written')
        assert(autoAssemble(SCRIPT, info))
        assert(getAddressSafe('godmode') == nil)
        local ok2, err = autoAssemble('[ENABLE]\nbogus\n[DISABLE]\n')
        assert(ok2 == false and type(err) == 'string')
    "#,
    );
    assert_eq!(p.snapshot(), before, "disable restored memory and freed the alloc");
}

#[test]
fn lua_blocks_in_aa_scripts() {
    let (e, p, _) = engine();
    let t = Arc::new(MemTable::new());
    e.set_table(t.clone());
    let id = t.create(None);
    let mut r = t.get(id).unwrap();
    r.description = "Lua patch".into();
    t.set(r).unwrap();
    let script = "[ENABLE]\n{$lua}\nruns = (runs or 0) + 1\nif syntaxcheck then return nil end\nlastmemrec = memrec and memrec.Description\nreturn 'game.exe+3020:\\ndb ' .. string.format('%02X', 0x63)\n{$asm}\n[DISABLE]\ngame.exe+3020:\ndb 2A\n";
    let mut syms = e.symbols().lock().unwrap().clone();
    assert_eq!(hh_asm::aa_check(&*p, &syms, script, &mut e.aa_hooks(None, true)), None);
    assert_eq!(read_u32(&*p, GAME + 0x3020), 0x2A, "check does not write");
    hh_asm::aa_execute(&*p, &mut syms, script, true, None, &mut e.aa_hooks(Some(id), false)).unwrap();
    assert_eq!(read_u32(&*p, GAME + 0x3020), 0x63);
    assert_eq!(run(&e, "return lastmemrec, runs, syntaxcheck, memrec"), ["Lua patch", "2", "nil", "nil"]);
    // A failing block reports its error through the AA error.
    let bad = "[ENABLE]\n{$lua}\nerror('boom')\n{$asm}\n[DISABLE]\n";
    let err = hh_asm::aa_execute(&*p, &mut syms, bad, true, None, &mut e.aa_hooks(None, false)).unwrap_err();
    assert!(err.to_string().contains("boom"), "{err}");
}

#[test]
fn lua_block_without_return_is_nil() {
    let (e, p, _) = engine();
    let mut syms = e.symbols().lock().unwrap().clone();
    // No return value means nil: the block's side effect happens and nothing is inserted.
    let noret = "[ENABLE]\n{$lua}\nwriteInteger(0x%X, 7)\n{$asm}\n[DISABLE]\n".replace("%X", &format!("{:X}", GAME + 0x3020));
    hh_asm::aa_execute(&*p, &mut syms, &noret, true, None, &mut e.aa_hooks(None, false)).unwrap();
    assert_eq!(read_u32(&*p, GAME + 0x3020), 7);
}

#[test]
fn memory_records() {
    let (e, p, cap) = engine();
    e.lua().globals().set("SCRIPT", HEALTH_SCRIPT.replace("[ENABLE]", "[ENABLE]\n{$lua}\nif not syntaxcheck then seen = memrec.Description end\n{$asm}")).unwrap();
    run(
        &e,
        r#"
        local al = getAddressList()
        assert(al.Count == 0)
        local hp = al.createMemoryRecord()
        hp.Description = 'HP'
        hp.Address = 'game.exe+3000'
        hp.OffsetCount = 2
        hp.Offset[0] = 8
        hp.Offset[1] = 8
        assert(hp.Type == vtDword and hp.OffsetCount == 2 and hp.Offset[1] == 8)
        assert(hp.CurrentAddress == 0x20000088 and hp.getCurrentAddress() == 0x20000088)
        assert(hp.Value == '4660')
        hp.Value = 100
        assert(readInteger(0x20000088) == 100)
        hp.Value = 16
        hp.ShowAsHex = true
        assert(hp.ShowAsHex)

        local name = al.createMemoryRecord()
        name.Description = 'Name'
        name.Address = 0x140003010
        name.Type = vtString
        name.String.Size = 5
        assert(name.Address == '140003010' and name.Value == 'Hello' and name.String.Size == 5)

        local cheat = al.createMemoryRecord()
        cheat.Description = 'God mode'
        cheat.Type = vtAutoAssembler
        cheat.Script = SCRIPT
        assert(cheat.Type == vtAutoAssembler and cheat.Value == '<script>')
        local child = al.createMemoryRecord()
        child.Description = 'Flag'
        child.Address = 'godmode'
        child.Type = vtByte
        child.appendToEntry(cheat)
        assert(child.Parent == cheat and cheat.Count == 1 and cheat.Child[0] == child)
        assert(al.Count == 4 and al[3] == child and al.getMemoryRecord(0) == hp and al.MemoryRecord[1] == name)
        assert(al.getMemoryRecordByDescription('God mode') == cheat)
        assert(al.getMemoryRecordByID(cheat.ID) == cheat)
        assert(getTableEntry('HP') == hp)

        log = {}
        cheat.OnActivate = function(mr, before, cur) log[#log + 1] = tostring(before) .. ':' .. tostring(cur); return true end
        cheat.OnDeactivate = function(mr, before, cur) log[#log + 1] = 'd' .. tostring(before) .. ':' .. tostring(cur) end
        cheat.Active = true
        assert(cheat.Active and seen == 'God mode', 'script ran with memrec set')
        assert(table.concat(log, ',') == 'true:false,false:true', table.concat(log, ','))
        assert(child.Value == '1')
        cheat.Active = false
        assert(not cheat.Active and getAddressSafe('godmode') == nil)
        assert(log[4] == 'dfalse:false')

        -- abort from the before-callback
        cheat.OnActivate = function(mr, before) return not before end
        cheat.Active = true
        assert(not cheat.Active)

        -- value entries: activation = freeze at the current value
        hp.Active = true
        assert(hp.Active)
        hp.Active = false

        -- failing script: stays inactive, error reported to the host
        local bad = al.createMemoryRecord()
        bad.Description = 'Broken'
        bad.Type = vtAutoAssembler
        bad.Script = '[ENABLE]\nbogus\n[DISABLE]\n'
        bad.Active = true
        assert(not bad.Active)
        bad.destroy()
        assert(al.Count == 4)
        cheat.OnActivate = nil
    "#,
    );
    assert!(cap.out.lock().unwrap().iter().any(|l| l.contains("Broken")));
    // The host side of activation: same path as `memrec.Active = true`, including frozen value.
    let ids = run(&e, "return getAddressList().getMemoryRecordByDescription('HP').ID, getAddressList().getMemoryRecordByDescription('God mode').ID");
    let (hp, cheat): (u32, u32) = (ids[0].parse().unwrap(), ids[1].parse().unwrap());
    e.set_active(cheat, true).unwrap();
    assert_eq!(run(&e, "return getAddress('godmode') ~= 0"), ["true"]);
    e.set_active(cheat, false).unwrap();
    e.set_active(hp, true).unwrap();
    // Read the host-side record through the default table.
    let v = run(&e, "return getTableEntry('HP').Value");
    assert_eq!(v, ["10"], "hex display after ShowAsHex");
    let _ = p;
}

#[test]
fn records_on_custom_table_host() {
    let (e, _, _) = engine();
    let t = Arc::new(MemTable::new());
    let id = t.create(None);
    let mut r = t.get(id).unwrap();
    r.address = "game.exe+3020".into();
    r.description = "From host".into();
    t.set(r).unwrap();
    e.set_table(t.clone());
    assert_eq!(run(&e, "local m = getAddressList()[0]; return m.Description, m.Value"), ["From host", "42"]);
    e.set_active(id, true).unwrap();
    let r = t.get(id).unwrap();
    assert!(r.active);
    assert_eq!(r.frozen_value.as_deref(), Some("42"));
}

#[test]
fn timers_and_threads() {
    let (e, p, _) = engine();
    run(
        &e,
        r#"
        ticks = 0
        t = createTimer(nil, false)
        t.Interval = 10
        t.OnTimer = function(tm) assert(tm == t); ticks = ticks + 1; if ticks == 3 then tm.Enabled = false end end
        t.Enabled = true
        oneshot = 0
        createTimer(10, function(a, b) oneshot = oneshot + a + b end, 2, 3)
        steps = {}
        th = createThread(function(th, x)
          steps[#steps + 1] = x
          sleep(15)
          steps[#steps + 1] = 'woke'
          synchronize(function() steps[#steps + 1] = 'sync' end)
          while not th.Terminated do sleep(5) end
          steps[#steps + 1] = 'done'
        end, 'start')
        assert(#steps == 0, 'threads start on the next tick')
        assert(inMainThread())
    "#,
    );
    let start = Instant::now();
    while start.elapsed() < Duration::from_millis(400) {
        e.tick().unwrap();
        std::thread::sleep(Duration::from_millis(3));
    }
    run(
        &e,
        r#"
        assert(ticks == 3, ticks)
        assert(oneshot == 5)
        assert(table.concat(steps, ',') == 'start,woke,sync', table.concat(steps, ','))
        assert(not th.Finished)
        th.terminate()
        th.waitfor()
        assert(th.Finished and steps[4] == 'done')
        t.destroy()
        -- a freezing timer
        f = createTimer()
        f.Interval = 5
        f.OnTimer = function() writeInteger('game.exe+3020', 1000) end
    "#,
    );
    p.write(GAME + 0x3020, &1u32.to_le_bytes()).unwrap();
    std::thread::sleep(Duration::from_millis(10));
    e.tick().unwrap();
    assert_eq!(read_u32(&*p, GAME + 0x3020), 1000);
    // Callback errors surface from tick() and do not stop the timer.
    run(&e, "f.OnTimer = function() error('timer exploded') end");
    std::thread::sleep(Duration::from_millis(10));
    let err = e.tick().unwrap_err().to_string();
    assert!(err.contains("timer exploded") && err.contains("test:1"), "{err}");
    std::thread::sleep(Duration::from_millis(10));
    assert!(e.tick().is_err());
    run(&e, "f.destroy()");
    e.tick().unwrap();
}

#[test]
fn engine_is_shared_across_threads_without_concurrent_lua() {
    let (e, _, _) = engine();
    run(&e, "counter = 0 t = createTimer() t.Interval = 1 t.OnTimer = function() local c = counter; for i = 1, 1000 do end; counter = c + 1 end");
    let handles: Vec<_> = (0..4)
        .map(|_| {
            let e = e.clone();
            std::thread::spawn(move || {
                for _ in 0..50 {
                    e.tick().unwrap();
                    e.exec("counter = counter + 0", "x").unwrap();
                    std::thread::sleep(Duration::from_millis(1));
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    let n: i64 = run(&e, "return counter")[0].parse().unwrap();
    assert!(n > 0);
}

#[test]
fn host_callbacks() {
    let (e, _, cap) = engine();
    let out = run(
        &e,
        r#"
        print('hello', 1, nil, true)
        showMessage('shown')
        assert(messageDialog('Sure?', mtConfirmation, mbYes, mbNo) == mrYes)
        assert(messageDialog('Title', 'Text', mtInformation, mbCancel) == mrCancel)
        assert(messageDialog('just text') == mrOk)
        assert(inputQuery('c', 'p', 'default') == 'default')
        assert(speedhack_setSpeed(2.5) and speedhack_getSpeed() == 2.5)
        hk = createHotkey(function(h) hotkeyed = h.ID end, VK_F1, VK_CONTROL)
        playSound('x.wav') beep()
        assert(getCEVersion() >= 7.4 and cheatEngineIs64Bit())
        assert(getCheatEngineDir():sub(-1) == package.config:sub(1, 1))
        assert(math.type(getTickCount()) == 'integer' and getCPUCount() >= 1)
        return 1 + 1, 'x'
    "#,
    );
    assert_eq!(out, ["2", "x"]);
    let lines = cap.out.lock().unwrap().clone();
    assert_eq!(lines, ["hello 1 nil true", "shown"]);
    assert_eq!(*cap.hotkeys.lock().unwrap(), [(1, vec![0x70, 0x11])]);
    assert_eq!(*cap.speed.lock().unwrap(), Some(2.5));
    e.fire_hotkey(1).unwrap();
    assert_eq!(run(&e, "return hotkeyed"), ["1"]);
}

#[test]
fn errors_have_positions_and_tracebacks() {
    let (e, _, _) = engine();
    let err = e.exec("local x = 1\nlocal function f()\n  error('bad thing')\nend\nf()", "mytable").unwrap_err().to_string();
    assert!(err.contains("mytable:3: bad thing"), "{err}");
    assert!(err.contains("stack traceback") && err.contains("mytable:5"), "{err}");
    let err = e.exec("x = = 1", "syn").unwrap_err();
    assert!(matches!(err, hh_core::Error::Parse(_)) && err.to_string().contains("syn:1"), "{err}");
    let err = e.exec("\n\ngetAddress('missing')", "cb").unwrap_err().to_string();
    assert!(err.contains("missing") && err.contains("cb:3"), "{err}");
    // pcall/xpcall with debug.traceback work for scripts too.
    run(&e, "local ok, tb = xpcall(function() error('x') end, debug.traceback) assert(not ok and tb:find('stack traceback'))");
}

#[test]
fn budget_and_interrupt() {
    let (e, _, _) = engine();
    e.set_budget(Some(Duration::from_millis(200)));
    let t = Instant::now();
    let err = e.exec("while true do end", "loop").unwrap_err().to_string();
    assert!(err.contains("time budget"), "{err}");
    assert!(t.elapsed() < Duration::from_secs(3));
    // sleep counts against the budget too
    let err = e.exec("sleep(5000)", "s").unwrap_err().to_string();
    assert!(err.contains("time budget"), "{err}");
    // a runaway timer is stopped as well
    run(&e, "t = createTimer() t.Interval = 1 t.OnTimer = function() while true do end end");
    std::thread::sleep(Duration::from_millis(5));
    assert!(e.tick().unwrap_err().to_string().contains("time budget"));
    run(&e, "t.destroy()");

    e.set_budget(None);
    let h = e.interrupt_handle();
    let stopper = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        h.interrupt();
    });
    let err = e.exec("local n = 0 while true do n = n + 1 end", "spin").unwrap_err().to_string();
    stopper.join().unwrap();
    assert!(err.contains("interrupted"), "{err}");
    // and the engine keeps working afterwards
    assert_eq!(run(&e, "return 40 + 2"), ["42"]);
}

#[test]
fn stubs_raise_clear_errors() {
    let (e, _, _) = engine();
    for (cat, names) in STUBS {
        for n in *names {
            let err = e.exec(&format!("\n{n}()"), "stub").unwrap_err().to_string();
            let want = stub_message(cat, n);
            assert!(err.contains(&format!("stub:2: {want}")), "{n}: {err}");
        }
    }
    for (cat, names) in STUBS {
        let unsupported = UNSUPPORTED.iter().any(|u| u.0 == *cat);
        for n in *names {
            let m = stub_message(cat, n);
            assert!(m.starts_with(if unsupported { "not supported in HeapHook: " } else { "not implemented yet: " }), "{m}");
        }
    }
    let err = e.exec("createListView()", "s").unwrap_err().to_string();
    assert!(err.contains("not implemented yet: createListView"), "{err}");
    // hh-asm has no assembler hook: registerAssembler stays a stub.
    let err = e.exec("registerAssembler(function() end)", "s").unwrap_err().to_string();
    assert!(err.contains("not implemented yet: registerAssembler"), "{err}");
    for (f, why) in [("dbk_initialize", "kernel driver"), ("dbvm_initialize", "hypervisor"), ("injectDll", "injection"), ("mono_initialize", "mono"), ("createD3DHook", "injection")] {
        let err = e.exec(&format!("{f}()"), "s").unwrap_err().to_string();
        assert!(err.contains(&format!("not supported in HeapHook: {f}")) && err.contains(why), "{err}");
    }
    // Implemented now: no longer stubs.
    for f in [
        "createForm", "createButton", "debug_setBreakpoint", "createStructure", "loadTable", "getCurrentMemscan", "createProcess", "getMainForm",
        "registerAutoAssemblerCommand", "unregisterAutoAssemblerCommand", "registerAutoAssemblerPrologue", "unregisterAutoAssemblerPrologue",
        "registerSymbolLookupCallback", "unregisterSymbolLookupCallback", "registerAddressLookupCallback", "unregisterAddressLookupCallback",
        "registerStructureDissectOverride", "unregisterStructureDissectOverride", "registerStructureNameLookup", "unregisterStructureNameLookup",
        "getRTTIClassName", "hhCreatePointerScan", "hhAssemblyScan", "hhFindReference", "hhSymbolList",
    ] {
        assert!(!STUBS.iter().any(|(_, n)| n.contains(&f)), "{f} still listed");
        assert_eq!(run(&e, &format!("return type({f})")), ["function"]);
    }
}

#[test]
fn os_access_policy() {
    let (e, _, _) = engine();
    run(&e, "assert(io and os.execute and dofile and os.time())");
    let err = e.exec("os.exit(1)", "x").unwrap_err().to_string();
    assert!(err.contains("os.exit is disabled"));
    let e = Engine::new(EngineOptions { allow_os: false, ..Default::default() }).unwrap();
    run(&e, "assert(io == nil and os.execute == nil and os.remove == nil and dofile == nil and loadfile == nil)");
    run(&e, "assert(os.time() and os.clock() and string.format and table.concat and math.floor)");
    assert!(e.exec("require('nonexistent_mod')", "x").is_err());
}

#[test]
fn no_process_is_not_a_panic() {
    let e = Engine::new(EngineOptions::default()).unwrap();
    run(
        &e,
        r#"
        assert(getOpenedProcessID() == 0)
        assert(readInteger(0x1000) == nil and writeInteger(0x1000, 1) == false)
        assert(getAddress('10') == 0x10)
        local ok = pcall(createMemScan)
        assert(not ok)
        local ok2, err = autoAssemble('[ENABLE]\n[DISABLE]\n')
        assert(ok2 == false and err:find('no process'))
        assert(getAddressList().Count == 0)
    "#,
    );
    // Bad input of every kind returns errors instead of panicking.
    for src in ["readBytes(nil)", "writeBytes()", "getAddress({})", "AOBScan()", "createFoundList({})", "autoAssemble()"] {
        let _ = e.exec(src, "x");
    }
}
