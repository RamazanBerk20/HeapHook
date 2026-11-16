mod common;
use common::*;
use hh_core::RegionKind;
use hh_tools::Progress;
use hh_tools::structure::*;

fn planted() -> FakeProc {
    let mut p = FakeProc::new();
    p.add(0x10000, vec![0; 0x2000], RW, RegionKind::Private, None);
    // Object A: i32, float, ptr, double, ascii, utf16, negative i32, two shorts, hex dword.
    p.put(0x10000, &100i32.to_le_bytes());
    p.put(0x10004, &1.5f32.to_le_bytes());
    p.put_u64(0x10008, 0x10800);
    p.put(0x10010, &2.25f64.to_le_bytes());
    p.put(0x10018, b"Hello World\0");
    let w: Vec<u8> = "Wide".encode_utf16().flat_map(u16::to_le_bytes).collect();
    p.put(0x10024, &w);
    p.put(0x10030, &(-5i32).to_le_bytes());
    p.put(0x10034, &0x0003_0007u32.to_le_bytes());
    p.put(0x10038, &0xDEADBEEFu32.to_le_bytes());
    // Child and grandchild.
    p.put(0x10800, &7i32.to_le_bytes());
    p.put_u64(0x10808, 0x10900);
    p.put(0x10908, &4242i32.to_le_bytes());
    p
}

#[test]
fn guess_and_expand() {
    let p = planted();
    let s = guess_structure(&p, "A", 0x10000, 64).unwrap();
    let types: Vec<(u64, ElemType)> = s.elements.iter().map(|e| (e.offset, e.vtype)).collect();
    assert_eq!(
        &types[..10],
        &[
            (0, ElemType::Bytes4),
            (4, ElemType::Float),
            (8, ElemType::Pointer),
            (16, ElemType::Double),
            (24, ElemType::String),
            (36, ElemType::String),
            (48, ElemType::Bytes4),
            (52, ElemType::Bytes2),
            (54, ElemType::Bytes2),
            (56, ElemType::Bytes4),
        ]
    );
    assert!(s.elements[5].utf16);
    let mut structs = vec![s];
    let v = evaluate(&p, &structs, "A", 0x10000).unwrap();
    let vals: Vec<_> = v.iter().map(|f| f.value.clone().unwrap()).collect();
    assert_eq!(&vals[..10], &["100", "1.5", "10800", "2.25", "Hello World", "Wide", "-5", "7", "3", "DEADBEEF"]);
    assert_eq!(v[2].target, Some(0x10800));

    // Follow the pointer chain by expanding pointer fields.
    let (c, a) = expand_pointer(&p, &mut structs, "A", 2, v[2].addr, 16).unwrap();
    assert_eq!(a, 0x10800);
    let cv = evaluate(&p, &structs, &c, a).unwrap();
    let pi = cv.iter().position(|f| f.vtype == ElemType::Pointer).unwrap();
    let (g, ga) = expand_pointer(&p, &mut structs, &c, cv[pi].index, cv[pi].addr, 16).unwrap();
    let gv = evaluate(&p, &structs, &g, ga).unwrap();
    assert_eq!(gv.iter().find(|f| f.offset == 8).unwrap().value.as_deref(), Some("4242"));
    // Expanding again reuses the linked child.
    assert_eq!(expand_pointer(&p, &mut structs, "A", 2, v[2].addr, 16).unwrap().0, c);
    assert!(guess_structure(&p, "x", 0x900000, 16).is_err());
    assert!(evaluate(&p, &structs, "missing", 0).is_err());
}

fn el(offset: u64, vtype: ElemType, desc: &str) -> Element {
    let mut e = Element::new(offset, vtype);
    e.description = desc.into();
    e
}

fn players() -> (FakeProc, Vec<Structure>, Vec<Vec<u64>>) {
    let mut p = FakeProc::new();
    p.add(0x10000, vec![0; 0x2000], RW, RegionKind::Private, None);
    let addrs = [0x11000u64, 0x11100, 0x11200, 0x11300];
    let hp = [100i32, 50, 100, 70];
    let team = [1i32, 1, 2, 2];
    let flag = [9i32, 9, 3, 3];
    for i in 0..4 {
        let a = addrs[i];
        p.put(a, &hp[i].to_le_bytes());
        p.put(a + 4, &team[i].to_le_bytes());
        let info = 0x11800 + i as u64 * 0x40;
        p.put_u64(a + 8, info);
        p.put(a + 0x14, &5f32.to_le_bytes());
        p.put(info, &flag[i].to_le_bytes());
        p.put(info + 4, &1i32.to_le_bytes());
    }
    let mut pos = el(16, ElemType::Struct, "pos");
    pos.child = Some("Pos".into());
    pos.size = 8;
    let mut ptr = el(8, ElemType::Pointer, "info");
    ptr.child = Some("Info".into());
    let structs = vec![
        Structure {
            name: "Player".into(),
            elements: vec![el(0, ElemType::Bytes4, "hp"), el(4, ElemType::Bytes4, "team"), ptr, pos],
        },
        Structure { name: "Pos".into(), elements: vec![el(0, ElemType::Float, "x"), el(4, ElemType::Float, "y")] },
        Structure { name: "Info".into(), elements: vec![el(0, ElemType::Bytes4, "flag")] },
    ];
    (p, structs, vec![vec![addrs[0], addrs[1]], vec![addrs[2], addrs[3]]])
}

#[test]
fn compare_groups() {
    let (p, structs, groups) = players();
    let rows = compare(&p, &structs, "Player", &groups).unwrap();
    let cls: Vec<_> = rows.iter().map(|r| (r.offset, r.class)).collect();
    assert_eq!(
        cls,
        [(0, Class::Mixed), (4, Class::GroupsDiffer), (8, Class::Mixed), (16, Class::AllEqual), (20, Class::AllEqual)]
    );
    assert_eq!(rows[1].values, vec![vec![Some("1".into()), Some("1".into())], vec![Some("2".into()), Some("2".into())]]);
    assert_eq!(rows[4].description, "y");

    let hits = find_fields(&p, &groups, 0x20, 4, Class::GroupsDiffer).unwrap();
    assert_eq!(hits.iter().map(|h| h.offset).collect::<Vec<_>>(), [4]);
    let same = find_fields(&p, &groups, 0x20, 4, Class::AllEqual).unwrap();
    assert!(same.iter().any(|h| h.offset == 0x14));
    assert!(find_fields(&p, &groups, 0x20, 3, Class::AllEqual).is_err());

    let prog = Progress::new();
    let opts = SpiderOptions { size: 0x40, max_depth: 1, width: 4, max_results: 100 };
    let hits = spider(&p, &groups, &opts, &prog).unwrap();
    let paths: Vec<_> = hits.iter().map(|h| h.path.clone()).collect();
    assert_eq!(paths, [vec![4], vec![8, 0]]);
    assert_eq!(hits[1].values[1], ["03 00 00 00", "03 00 00 00"]);
    assert!(prog.snapshot().done >= 2);
    let opts0 = SpiderOptions { max_depth: 0, ..opts.clone() };
    assert_eq!(spider(&p, &groups, &opts0, &Progress::new()).unwrap().len(), 1);
    let c = Progress::new();
    c.cancel();
    assert!(spider(&p, &groups, &opts, &c).is_err());
}

#[test]
fn json_ct_and_entries() {
    let (_, mut structs, _) = players();
    structs[0].elements.push(Element { size: 12, utf16: true, ..el(24, ElemType::String, "name") });
    structs[0].elements.push(Element { hex: true, ..el(36, ElemType::Bytes2, "flags & <x>") });
    assert_eq!(from_json(&to_json(&structs)).unwrap(), structs);
    let xml = to_ct_xml(&structs, 8);
    assert_eq!(from_ct_xml(&xml).unwrap(), structs);
    assert_eq!(struct_size(&structs, "Player", 8).unwrap(), 38);

    // A Cheat Engine style table.
    let ct = r#"<?xml version="1.0" encoding="utf-8"?>
<CheatTable CheatEngineTableVersion="45">
  <CheatEntries/>
  <Structures StructVersion="2">
    <Structure Name="Enemy" AutoFill="0" AutoCreate="1" DefaultHex="0" AutoDestroy="0" DoNotSaveLocal="0" RLECompression="1" AutoCreateStructsize="4096">
      <Elements>
        <Element Offset="0" Vartype="Pointer" Bytesize="8" OffsetHex="00000000" DisplayMethod="Unsigned Integer" ChildStruct="Weapon"/>
        <Element Offset="16" Vartype="Float" Bytesize="4" OffsetHex="00000010" Description="speed" DisplayMethod="Unsigned Integer"/>
        <Element Offset="8" Vartype="4 Bytes" Bytesize="4" OffsetHex="00000008" Description="hp" DisplayMethod="Signed Integer"/>
        <Element Offset="20" Vartype="Array of Bytes" Bytesize="6" OffsetHex="00000014" DisplayMethod="Unsigned Integer"/>
      </Elements>
    </Structure>
  </Structures>
</CheatTable>"#;
    let s = from_ct_xml(ct).unwrap();
    assert_eq!(s[0].name, "Enemy");
    assert_eq!(s[0].elements[0].child.as_deref(), Some("Weapon"));
    assert_eq!(s[0].elements[1].offset, 8);
    assert!(s[0].elements[1].signed);
    assert_eq!((s[0].elements[3].vtype, s[0].elements[3].size), (ElemType::Aob, 6));
    assert!(from_ct_xml("<Structures><Structure").is_err());
    assert!(from_json("{").is_err());
    // A structure that embeds itself is refused instead of recursing forever.
    let mut lp = el(0, ElemType::Struct, "self");
    lp.child = Some("Loop".into());
    let looped = vec![Structure { name: "Loop".into(), elements: vec![lp, el(u64::MAX, ElemType::Bytes8, "far")] }];
    assert!(struct_size(&looped, "Loop", 8).is_err());
    assert!(to_entries(&looped, "Loop", "a", &[], 8, None, 0).is_err());
    let far = vec![Structure { name: "Far".into(), elements: vec![el(u64::MAX, ElemType::Bytes8, "far")] }];
    let p = FakeProc::new();
    assert!(evaluate(&p, &far, "Far", 0).is_err());

    let e = to_entries(&structs, "Player", "game.exe+100", &[0x10], 8, None, 1).unwrap();
    let got: Vec<_> = e.iter().map(|e| (e.description.as_str(), e.addr.as_str(), e.offsets.clone())).collect();
    assert_eq!(got[0], ("hp", "game.exe+100", vec!["10".to_string()]));
    assert_eq!(got[3], ("x", "game.exe+100", vec!["20".to_string()]));
    assert_eq!(e[2].vtype, hh_scan::VType::Bytes8);
    assert!(e[2].hex);
    assert_eq!((e[5].vtype, e[5].len, e[5].utf16), (hh_scan::VType::String, 6, true));
    assert_eq!(e[1].id, 2);
    let e = to_entries(&structs, "Player", "base", &[], 8, Some(&[1, 3]), 0).unwrap();
    assert_eq!(e.iter().map(|e| e.addr.as_str()).collect::<Vec<_>>(), ["base+4", "base+10", "base+14"]);
    let json = serde_json::to_value(&e[0]).unwrap();
    assert_eq!(json["vtype"], "4bytes");
}
