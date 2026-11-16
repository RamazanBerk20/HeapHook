//! A cheat-table style Lua script end to end: AOB scan, an injection with registersymbol, a
//! freezing timer and memory-record callbacks.
mod common;

use std::time::Duration;

use common::*;
use hh_core::Memory;

#[test]
fn realistic_table_script() {
    let (e, p, cap) = engine();
    let before = p.snapshot();
    e.lua().globals().set("INJECT", HEALTH_SCRIPT).unwrap();
    run(
        &e,
        r#"
        -- typical table startup script
        local base = getAddress('game.exe')
        local hit = AOBScanModuleUnique('game.exe', '29 81 E0 00 00 00 8B')
        assert(hit == base + 0x1005, 'signature found')
        print(string.format('health routine at %X (%s)', hit, getNameFromAddress(hit)))

        local al = getAddressList()
        local cheat = al.createMemoryRecord()
        cheat.Description = 'God mode'
        cheat.Type = vtAutoAssembler
        cheat.Script = INJECT

        local hp = al.createMemoryRecord()
        hp.Description = 'Health'
        hp.Address = 'game.exe+3000'
        hp.OffsetCount = 2
        hp.Offset[0] = 8
        hp.Offset[1] = 8
        hp.appendToEntry(cheat)

        events = {}
        cheat.OnActivate = function(mr, before)
          if before then
            events[#events + 1] = 'activating ' .. mr.Description
          else
            events[#events + 1] = 'godmode flag ' .. readByte('godmode')
            freezer = createTimer(nil, false)
            freezer.Interval = 10
            freezer.OnTimer = function() hp.Value = 9999 end
            freezer.Enabled = true
          end
          return true
        end
        cheat.OnDeactivate = function(mr, before)
          if before and freezer then freezer.destroy(); freezer = nil end
        end
        cheat.Active = true
        assert(cheat.Active, 'injection enabled')
        assert(readByte('health') == 0xE9 and getAddress('godmode') ~= 0)
    "#,
    );
    // The game "takes damage"; the freezing timer puts it back.
    p.write(0x2000_0088, &5u32.to_le_bytes()).unwrap();
    std::thread::sleep(Duration::from_millis(15));
    e.tick().unwrap();
    assert_eq!(read_u32(&*p, 0x2000_0088), 9999);
    run(
        &e,
        r#"
        local cheat = getAddressList().getMemoryRecordByDescription('God mode')
        assert(cheat.Child[0].Value == '9999')
        cheat.Active = false
        assert(freezer == nil and getAddressSafe('godmode') == nil)
        assert(events[1] == 'activating God mode' and events[2] == 'godmode flag 1', table.concat(events, '|'))
    "#,
    );
    p.write(0x2000_0088, &0x1234u32.to_le_bytes()).unwrap();
    std::thread::sleep(Duration::from_millis(15));
    e.tick().unwrap();
    assert_eq!(p.snapshot(), before, "injection removed and no more freezing");
    assert!(cap.out.lock().unwrap()[0].starts_with("health routine at 140001005 (game.exe+1005)"));
}
