mod common;
use common::*;
use hh_asm::SymbolTable;
use hh_core::{Memory, RegionKind};
use hh_tools::codelist::*;

#[test]
fn nop_restore_verify() {
    let mut p = FakeProc::new();
    p.add(0x401000, vec![0xC3; 0x100], RX, RegionKind::Image, Some("/x/test.dll"));
    p.module("test.dll", 0x401000, 0x100);
    asm_seq(&p, 0x401010, &["mov eax,dword ptr [rbx+8]", "ret"]);
    let syms = SymbolTable::default();
    let mut cl = CodeList::default();
    assert_eq!(cl.add(&p, &syms, "test.dll+10", "health").unwrap(), 0);
    assert_eq!(cl.entries[0].original, [0x8B, 0x43, 0x08]);
    assert!(cl.add(&p, &syms, "nosuchthing", "x").is_err());
    assert_eq!(cl.status(&p, &syms)[0].state, CodeState::Original);
    cl.nop(&p, &syms, 0).unwrap();
    cl.nop(&p, &syms, 0).unwrap();
    let mut b = [0; 4];
    p.read_exact(0x401010, &mut b).unwrap();
    assert_eq!(b, [0x90, 0x90, 0x90, 0xC3]);
    assert_eq!(cl.status(&p, &syms)[0].state, CodeState::Nopped);
    cl.restore(&p, &syms, 0, false).unwrap();
    assert_eq!(cl.status(&p, &syms)[0].state, CodeState::Original);
    // Something else changed the code: refuse to patch or restore without force.
    p.put(0x401010, &[0xCC]);
    assert_eq!(cl.status(&p, &syms)[0].state, CodeState::Changed);
    assert!(cl.nop(&p, &syms, 0).is_err());
    assert!(cl.restore(&p, &syms, 0, false).is_err());
    cl.restore(&p, &syms, 0, true).unwrap();
    assert_eq!(cl.status(&p, &syms)[0].state, CodeState::Original);
    assert!(cl.nop(&p, &syms, 7).is_err());

    cl.entries.push(CodeEntry { description: "gone".into(), addr: "500000".into(), original: vec![1] });
    let st = cl.status(&p, &syms);
    assert_eq!((st[1].state, st[1].addr), (CodeState::Unreadable, None));

    let json = serde_json::to_string(&cl).unwrap();
    assert!(json.contains("\"8B 43 08\""));
    assert_eq!(serde_json::from_str::<CodeList>(&json).unwrap(), cl);
    assert_eq!(CodeList::from_ct_xml(&cl.to_ct_xml()).unwrap(), cl);
    let ct = "<CheatTable><CheatCodes><CodeEntry><Description>Change of x</Description><AddressString>game.exe+1F</AddressString><Before><Byte>00</Byte></Before><Actual><Byte>89</Byte><Byte>4E</Byte></Actual><After/></CodeEntry></CheatCodes></CheatTable>";
    let c = CodeList::from_ct_xml(ct).unwrap();
    assert_eq!(c.entries[0], CodeEntry { description: "Change of x".into(), addr: "game.exe+1F".into(), original: vec![0x89, 0x4E] });
    assert!(CodeList::from_ct_xml("<CheatCodes><CodeEntry><Actual><Byte>ZZ</Byte></Actual></CodeEntry></CheatCodes>").is_err());
    assert_eq!(cl.remove(1).unwrap().description, "gone");
}
