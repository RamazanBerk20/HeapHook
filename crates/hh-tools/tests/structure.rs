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

// ---------------------------------------------------------------- hostile input (release audit)

fn nested(name: &str, child: &str, fanout: usize) -> Structure {
    let mut elements: Vec<Element> = (0..fanout)
        .map(|i| Element { child: Some(child.into()), ..Element::new(i as u64 * 8, ElemType::Struct) })
        .collect();
    elements.push(Element::new(fanout as u64 * 8, ElemType::Bytes4));
    Structure { name: name.into(), elements }
}

#[test]
fn long_nesting_chains_do_not_overflow_the_stack() {
    let p = planted();
    let mut v: Vec<Structure> = (0..30_000).map(|i| nested(&format!("s{i}"), &format!("s{}", i + 1), 1)).collect();
    v.push(Structure { name: "s30000".into(), elements: vec![Element::new(0, ElemType::Byte)] });
    let t = std::time::Instant::now();
    assert!(struct_size(&v, "s0", 8).unwrap() > 0);
    assert!(evaluate(&p, &v, "s0", 0x10000).is_ok());
    assert!(to_entries(&v, "s0", "x", &[], 8, None, 1).is_ok());
    assert!(t.elapsed().as_secs() < 10, "{:?}", t.elapsed());
    // A cycle within the evaluated depth is still refused.
    let cyc = vec![nested("a", "b", 1), nested("b", "a", 1)];
    assert!(struct_size(&cyc, "a", 8).is_err());
}

#[test]
fn exponential_nesting_is_cached_and_capped() {
    let p = planted();
    // 16 levels, each embedding the next 20 times: 20^16 fields if expanded.
    let mut v: Vec<Structure> = (0..16).map(|i| nested(&format!("l{i}"), &format!("l{}", i + 1), 20)).collect();
    v.push(Structure { name: "l16".into(), elements: vec![Element::new(0, ElemType::Byte)] });
    let t = std::time::Instant::now();
    assert!(struct_size(&v, "l0", 8).is_ok());
    let e = evaluate(&p, &v, "l0", 0x10000).unwrap_err().to_string();
    assert!(e.contains("fields"), "{e}");
    assert!(to_entries(&v, "l0", "x", &[], 8, None, 1).is_err());
    let _ = to_ct_xml(&v, 8);
    assert!(t.elapsed().as_secs() < 10, "{:?}", t.elapsed());
}

#[test]
fn deeply_nested_ct_structures_parse_in_linear_time() {
    let n = 20_000;
    let mut x = String::from("<Structures>");
    for i in 0..n {
        x += &format!("<Structure Name=\"s{i}\"><Elements><Element Offset=\"0\" Vartype=\"Byte\"/></Elements>");
    }
    x += &"</Structure>".repeat(n);
    x += "</Structures>";
    let t = std::time::Instant::now();
    if let Ok(v) = from_ct_xml(&x) {
        assert_eq!(v.len(), n);
        assert!(v.iter().all(|s| s.elements.len() == 1));
    }
    assert!(t.elapsed().as_secs() < 10, "{:?}", t.elapsed());
}

// ---------------------------------------------------------------- 1.0: caps, bits, arrays, RTTI

/// Every address reads as zeros, without backing memory (for budget tests).
struct ZeroProc;
impl hh_core::Memory for ZeroProc {
    fn read(&self, _: u64, buf: &mut [u8]) -> hh_core::Result<usize> {
        buf.fill(0);
        Ok(buf.len())
    }
    fn write(&self, _: u64, _: &[u8]) -> hh_core::Result<()> {
        Ok(())
    }
    fn pointer_size(&self) -> usize {
        8
    }
}
impl hh_core::Process for ZeroProc {
    fn pid(&self) -> u32 {
        0
    }
    fn regions(&self) -> hh_core::Result<Vec<hh_core::Region>> {
        Ok(Vec::new())
    }
}

#[test]
fn evaluation_reads_are_capped() {
    // One element over the per-element cap.
    let big = vec![Structure { name: "S".into(), elements: vec![Element { size: MAX_ELEM_BYTES + 1, ..el(0, ElemType::Aob, "blob") }] }];
    let e = evaluate(&ZeroProc, &big, "S", 0x1000).unwrap_err().to_string();
    assert!(e.contains("over"), "{e}");
    assert!(from_json(&to_json(&big)).is_err());
    assert!(from_ct_xml(&to_ct_xml(&big, 8)).is_err());
    // Within the element cap, but 20 MiB in total: refused at the evaluation budget, after
    // reading at most MAX_EVAL_BYTES.
    let many = vec![Structure { name: "S".into(), elements: vec![Element { size: MAX_ELEM_BYTES, count: 20, ..el(0, ElemType::Aob, "blob") }] }];
    let e = evaluate(&ZeroProc, &many, "S", 0x1000).unwrap_err().to_string();
    assert!(e.contains("reads more than"), "{e}");
    assert!(lock_structure(&ZeroProc, &many, "S", 0x1000).is_err());
    // Sparse definitions read only the chunks their fields touch.
    let sparse = vec![Structure { name: "S".into(), elements: vec![el(0, ElemType::Bytes4, "a"), el(1 << 40, ElemType::Bytes4, "far")] }];
    let v = evaluate(&ZeroProc, &sparse, "S", 0x1000).unwrap();
    assert_eq!(v[1].value.as_deref(), Some("0"));
    // Find-fields and the spider refuse sizes over the budget instead of allocating them.
    assert!(find_fields(&ZeroProc, &[vec![0x1000]], 1 << 30, 4, Class::AllEqual).is_err());
    let opts = SpiderOptions { size: 1 << 30, ..Default::default() };
    assert!(spider(&ZeroProc, &[vec![0x1000]], &opts, &Progress::new()).is_err());
    assert!(guess_structure(&ZeroProc, "g", 0x1000, 1 << 30).is_err());
}

fn bitfields() -> (FakeProc, Vec<Structure>) {
    let mut p = FakeProc::new();
    p.add(0x10000, vec![0; 0x1000], RW, RegionKind::Private, None);
    // flags = a:3 = 5, b:5 (signed) = -3, c:8 at bit 16 = 0xAB
    let flags: u32 = 5 | ((-3i32 as u32 & 0x1f) << 3) | (0xAB << 16);
    p.put(0x10000, &flags.to_le_bytes());
    p.put(0x10010, &[1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0]);
    let a = Element { bit_offset: 0, bit_len: 3, ..el(0, ElemType::Bytes4, "a") };
    let b = Element { bit_offset: 3, bit_len: 5, signed: true, ..el(0, ElemType::Bytes4, "b") };
    let c = Element { bit_offset: 16, bit_len: 8, hex: true, ..el(0, ElemType::Bytes4, "c") };
    let arr = Element { count: 3, ..el(0x10, ElemType::Bytes4, "arr") };
    (p, vec![Structure { name: "Bits".into(), elements: vec![a, b, c, arr] }])
}

#[test]
fn bit_fields_and_arrays() {
    let (p, s) = bitfields();
    let v = evaluate(&p, &s, "Bits", 0x10000).unwrap();
    let vals: Vec<_> = v.iter().map(|f| f.value.clone()).collect();
    assert_eq!(vals[..3], [Some("5".into()), Some("-3".into()), Some("AB".into())]);
    assert_eq!(struct_size(&s, "Bits", 8).unwrap(), 0x1C);
    // The array is one field with an item per element.
    assert_eq!((v[3].size, v[3].value.clone()), (12, None));
    let items: Vec<_> = v[3].children.iter().map(|f| (f.offset, f.description.clone(), f.value.clone().unwrap())).collect();
    assert_eq!(items, [(0x10, "arr[0]".into(), "1".into()), (0x14, "arr[1]".into(), "2".into()), (0x18, "arr[2]".into(), "3".into())]);
    assert_eq!(leaves(&v).len(), 6);

    // Writing a bit field keeps the other bits.
    write_field(&p, &s, &v[1], "7").unwrap();
    write_field(&p, &s, &v[3].children[1], "42").unwrap();
    assert!(write_field(&p, &s, &v[3], "1").is_err());
    assert!(write_field(&p, &s, &v[0], "9").is_err(), "9 does not fit 3 bits");
    let w = evaluate(&p, &s, "Bits", 0x10000).unwrap();
    let vals: Vec<_> = leaves(&w).iter().map(|f| f.value.clone().unwrap()).collect();
    assert_eq!(vals, ["5", "7", "AB", "1", "42", "3"]);
    // Highlight: leaves 1 (b) and 4 (arr[1]) changed.
    assert_eq!(changed_fields(&v, &w), [1, 4]);

    // Table entries: bit fields carry a custom type, arrays give one entry per item.
    let e = to_entries(&s, "Bits", "base", &[], 8, None, 1).unwrap();
    assert_eq!(e.len(), 6);
    let ct = e[1].custom.unwrap();
    assert_eq!((ct.size, ct.bit_start, ct.bit_len, ct.signed), (4, 3, 5, true));
    assert_eq!((e[4].description.as_str(), e[4].addr.as_str()), ("arr[1]", "base+14"));
    assert_eq!(serde_json::to_value(&e[1]).unwrap()["custom"]["bit_len"], 5);
    assert!(serde_json::to_value(&e[3]).unwrap().get("custom").is_none());

    // Formats keep the new attributes.
    assert_eq!(from_json(&to_json(&s)).unwrap(), s);
    assert_eq!(from_ct_xml(&to_ct_xml(&s, 8)).unwrap(), s);
    // Old JSON without them still loads, and they stay out of the JSON when unset.
    assert!(!to_json(&players().1).contains("bit_len"));

    // Bad bit fields are rejected, not evaluated as garbage.
    for bad in [
        Element { bit_offset: 30, bit_len: 5, ..el(0, ElemType::Bytes4, "x") },
        Element { bit_len: 3, ..el(0, ElemType::Float, "x") },
        Element { bit_offset: 2, ..el(0, ElemType::Byte, "x") },
    ] {
        let s = vec![Structure { name: "B".into(), elements: vec![bad] }];
        assert!(evaluate(&p, &s, "B", 0x10000).is_err());
        assert!(from_json(&to_json(&s)).is_err());
    }
}

#[test]
fn lock_snapshot_compares_with_live() {
    let (p, s) = bitfields();
    let snap = lock_structure(&p, &s, "Bits", 0x10000).unwrap();
    assert!(snap.bytes() <= 0x2000);
    let locked = evaluate_locked(&snap, &s, "Bits", 0x10000, 8).unwrap();
    assert_eq!(locked, evaluate(&p, &s, "Bits", 0x10000).unwrap());
    p.put(0x10018, &9u32.to_le_bytes());
    let live = evaluate(&p, &s, "Bits", 0x10000).unwrap();
    assert_eq!(changed_fields(&locked, &live), [5]);
    // The locked copy does not follow live memory.
    assert_eq!(evaluate_locked(&snap, &s, "Bits", 0x10000, 8).unwrap(), locked);
}

#[test]
fn hostile_names_survive_xml() {
    let names = ["a\u{1}b", "tab\there", "cr\rlf\n", "q\"<&>'", "\u{fffe}x", "\u{0}"];
    let structs: Vec<Structure> = names
        .iter()
        .map(|n| Structure { name: n.to_string(), elements: vec![Element { child: Some(n.to_string()), ..el(0, ElemType::Pointer, n) }] })
        .collect();
    let xml = to_ct_xml(&structs, 8);
    let back = from_ct_xml(&xml).expect("export must always parse back");
    let clean = |s: &str| s.chars().map(|c| if (c < ' ' && !"\t\r\n".contains(c)) || c == '\u{fffe}' { '\u{fffd}' } else { c }).collect::<String>();
    for (b, n) in back.iter().zip(names) {
        assert_eq!(b.name, clean(n));
        assert_eq!(b.elements[0].description, clean(n));
        assert_eq!(b.elements[0].child.as_deref(), Some(clean(n).as_str()));
    }
    // C and C# output only uses identifiers.
    let c = to_c(&structs, 8);
    assert!(c.chars().all(|ch| ch == '\n' || !ch.is_control()), "{c}");
}

/// Plants an Itanium-ABI object of class `mangled` at `obj` (vtable, type_info and name
/// placed after it at `meta`).
fn itanium_object(p: &FakeProc, obj: u64, meta: u64, mangled: &str) {
    let vt = meta + 0x10;
    p.put_u64(obj, vt);
    p.put_u64(vt - 8, meta + 0x80); // type_info
    p.put_u64(meta + 0x88, meta + 0x100); // type_info.name
    p.put(meta + 0x100, format!("{mangled}\0").as_bytes());
}

#[test]
fn rtti_names_guessed_structures() {
    let mut p = FakeProc::new();
    p.add(0x20000, vec![0; 0x4000], RW, RegionKind::Private, None);
    itanium_object(&p, 0x20000, 0x21000, "6Player");
    itanium_object(&p, 0x20100, 0x21400, "N4game5EnemyE");
    p.put_u64(0x20008, 0x20100);
    p.put(0x20010, &77i32.to_le_bytes());
    assert_eq!(rtti_class_name(&p, 0x20000).as_deref(), Some("Player"));
    assert_eq!(rtti_class_name(&p, 0x20100).as_deref(), Some("game::Enemy"));
    assert_eq!(rtti_class_name(&p, 0x20010), None);
    assert_eq!(rtti_class_name(&p, 0x900000), None);

    let s = guess_structure_with(&p, "", 0x20000, 24, &GuessOptions::default(), None).unwrap();
    assert_eq!(s.name, "Player");
    assert_eq!(s.elements[0].description, "vtable");
    assert_eq!(s.elements[1].description, "game::Enemy*");
    // The plain guess is unchanged.
    let plain = guess_structure(&p, "x", 0x20000, 24).unwrap();
    assert!(plain.elements.iter().all(|e| e.description.is_empty()));

    let mut structs = vec![s];
    let (c, a) = expand_pointer_with(&p, &mut structs, "Player", 1, 0x20008, 16, &GuessOptions::default(), None).unwrap();
    assert_eq!((c.as_str(), a), ("game::Enemy", 0x20100));
    assert_eq!(structs[0].elements[1].child.as_deref(), Some("game::Enemy"));

    // Child structure start: the pointer points 8 bytes into the child.
    structs[0].elements[1].child = None;
    structs[0].elements[1].child_start = 8;
    p.put_u64(0x20008, 0x20108);
    let (_, a) = expand_pointer(&p, &mut structs, "Player", 1, 0x20008, 16).unwrap();
    assert_eq!(a, 0x20100);
    let e = field_entry(&structs, "Player", "base", &[], &[1, 0], 8, 7).unwrap();
    assert_eq!((e.addr.as_str(), e.offsets.clone()), ("base+8", vec!["-8".to_string()]));

    // Override hook: supplies the structure before auto-guess.
    structs[0].elements[1].child = None;
    let ov = |addr: u64, _size: usize| (addr == 0x20100).then(|| Structure { name: "FromLua".into(), elements: vec![el(0x10, ElemType::Bytes4, "hp")] });
    let (c, _) = expand_pointer_with(&p, &mut structs, "Player", 1, 0x20008, 16, &GuessOptions::default(), Some(&ov)).unwrap();
    assert_eq!(c, "FromLua");
    assert_eq!(lookup_names(&structs), ["Player", "game::Enemy", "Player_8", "FromLua"]);
    let hostile = |_: u64, _: usize| Some(Structure { name: "H".into(), elements: vec![Element { size: usize::MAX, ..el(0, ElemType::Aob, "") }] });
    assert!(guess_structure_with(&p, "", 0x20000, 16, &GuessOptions::default(), Some(&hostile)).is_err());
}

fn lookup_names(s: &[Structure]) -> Vec<&str> {
    s.iter().map(|s| s.name.as_str()).collect()
}

#[test]
fn rtti_msvc_layouts() {
    // x64: the locator holds image-relative offsets, its own included.
    let mut p = FakeProc::new();
    p.add(0x30000, vec![0; 0x4000], RW, RegionKind::Image, None);
    p.put_u64(0x30100, 0x31010); // object -> vftable
    p.put_u64(0x31008, 0x32000); // vftable[-1] -> complete object locator
    p.put(0x32000, &1u32.to_le_bytes());
    p.put(0x3200C, &0x3000u32.to_le_bytes()); // type descriptor RVA
    p.put(0x32014, &0x2000u32.to_le_bytes()); // pSelf RVA -> image base 0x30000
    p.put(0x33010, b".?AVEnemy@game@@\0");
    assert_eq!(rtti_class_name(&p, 0x30100).as_deref(), Some("game::Enemy"));
    p.put(0x33010, b".?AV?$vector@H@std@@\0");
    assert_eq!(rtti_class_name(&p, 0x30100).as_deref(), Some("?$vector@H@std"));
    p.put(0x32000, &7u32.to_le_bytes());
    assert_eq!(rtti_class_name(&p, 0x30100), None);

    // x86: absolute pointers.
    let mut q = FakeProc::new();
    q.ptr = 4;
    q.add(0x30000, vec![0; 0x4000], RW, RegionKind::Image, None);
    q.put(0x30100, &0x31010u32.to_le_bytes());
    q.put(0x3100C, &0x32000u32.to_le_bytes());
    q.put(0x3200C, &0x33000u32.to_le_bytes());
    q.put(0x33008, b".?AUPoint@@\0");
    assert_eq!(rtti_class_name(&q, 0x30100).as_deref(), Some("Point"));
}

/// A mapped PE "sym.dll" at 0x500000 exporting `alpha` (+0x1000) and `beta` (+0x1100).
fn pe_with_exports() -> FakeProc {
    let mut p = FakeProc::new();
    p.add(0x500000, vec![0; 0x3000], R, RegionKind::Image, Some("/x/sym.dll"));
    p.add(0x600000, vec![0; 0x100], RW, RegionKind::Private, None);
    p.module("sym.dll", 0x500000, 0x3000);
    let u16b = |a: u64, v: u16| p.put(a, &v.to_le_bytes());
    let u32b = |a: u64, v: u32| p.put(a, &v.to_le_bytes());
    p.put(0x500000, b"MZ");
    u32b(0x50003C, 0x80);
    p.put(0x500080, b"PE\0\0");
    u16b(0x500084, 0x8664);
    u16b(0x500086, 1);
    u16b(0x500094, 0xF0);
    u16b(0x500098, 0x20b);
    u32b(0x500098 + 108, 16);
    u32b(0x500098 + 112, 0x2000);
    u32b(0x500098 + 116, 0x100);
    u32b(0x502014, 2);
    u32b(0x502018, 2);
    u32b(0x50201C, 0x2040);
    u32b(0x502020, 0x2050);
    u32b(0x502024, 0x2060);
    u32b(0x502040, 0x1000);
    u32b(0x502044, 0x1100);
    u32b(0x502050, 0x2080);
    u32b(0x502054, 0x2090);
    u16b(0x502062, 1);
    p.put(0x502080, b"alpha\0");
    p.put(0x502090, b"beta\0");
    p
}

#[test]
fn symbol_named_pointers() {
    let p = pe_with_exports();
    p.put_u64(0x600000, 0x501100);
    p.put_u64(0x600008, 0x501000);
    let s = guess_structure_with(&p, "G", 0x600000, 16, &GuessOptions::default(), None).unwrap();
    let d: Vec<_> = s.elements.iter().map(|e| e.description.as_str()).collect();
    assert_eq!(d, ["beta", "alpha"]);
    // Remote targets: no module files, so no symbol names (and no local file is opened).
    let remote = GuessOptions { local_files: false, ..Default::default() };
    let s = guess_structure_with(&p, "G", 0x600000, 16, &remote, None).unwrap();
    assert!(s.elements.iter().all(|e| e.description.is_empty()));
}

#[test]
fn field_entry_fills_pointer_paths() {
    let (_, structs, _) = players();
    // Player.weapon (pointer at 8 to Weapon) -> Weapon field at 0.
    let w = structs[0].elements.iter().position(|e| e.vtype == ElemType::Pointer).unwrap();
    let e = field_entry(&structs, "Player", "game.exe+100", &[], &[w, 0], 8, 3).unwrap();
    assert_eq!((e.addr.as_str(), e.offsets.clone(), e.id), ("game.exe+100+8", vec!["0".to_string()], 3));
    assert!(e.description.starts_with("Player."), "{}", e.description);
    // From a structure that is itself behind a pointer path.
    let e = field_entry(&structs, "Player", "base", &[0x10], &[w, 0], 8, 3).unwrap();
    assert_eq!((e.addr.as_str(), e.offsets.clone()), ("base", vec!["18".to_string(), "0".to_string()]));
    let e = field_entry(&structs, "Player", "base", &[], &[0], 8, 1).unwrap();
    assert_eq!((e.addr.as_str(), e.vtype), ("base+0", hh_scan::VType::Bytes4));
    assert!(field_entry(&structs, "Player", "b", &[], &[w], 8, 1).unwrap().hex);
    assert!(field_entry(&structs, "Player", "b", &[], &[99], 8, 1).is_err());
    assert!(field_entry(&structs, "Player", "b", &[], &[0, 0], 8, 1).is_err());
    assert!(field_entry(&structs, "Player", "b", &[], &[], 8, 1).is_err());
    // Arrays need the item index.
    let (_, bits) = bitfields();
    let e = field_entry(&bits, "Bits", "b", &[], &[3, 2], 8, 1).unwrap();
    assert_eq!((e.addr.as_str(), e.description.as_str()), ("b+18", "Bits.arr[2]"));
    assert!(field_entry(&bits, "Bits", "b", &[], &[3, 3], 8, 1).is_err());
    assert!(field_entry(&bits, "Bits", "b", &[], &[3], 8, 1).is_err());
}

#[test]
fn c_and_csharp_definitions() {
    let (_, mut s) = bitfields();
    s[0].elements.push(Element { size: 8, ..el(0x20, ElemType::String, "name") });
    s[0].elements.push(Element { child: Some("Inner".into()), ..el(0x28, ElemType::Struct, "inner") });
    s[0].elements.push(Element { child: Some("Inner".into()), ..el(0x30, ElemType::Pointer, "next") });
    s[0].elements.push(el(0x30, ElemType::Bytes4, "overlap"));
    s.push(Structure { name: "Inner".into(), elements: vec![el(0, ElemType::Float, "x"), el(4, ElemType::Float, "y")] });
    let c = to_c(&s, 8);
    for want in [
        "struct Inner {",
        "uint32_t a : 3;",
        "int32_t b : 5;",
        "uint32_t c : 8;",
        "uint32_t : 8;",
        "uint8_t _pad_4[0xC];",
        "uint32_t arr[3];",
        "char name[8];",
        "struct Inner inner;",
        "struct Inner* next;",
        "overlap overlaps",
    ] {
        assert!(c.contains(want), "{want:?} missing in\n{c}");
    }
    // Inner is defined before Bits embeds it.
    assert!(c.find("struct Inner {").unwrap() < c.find("struct Bits {").unwrap());
    assert!(to_c(&s, 4).contains("uint32_t next; /* Inner* */"));
    let cs = to_csharp(&s, 8);
    for want in [
        "[StructLayout(LayoutKind.Explicit, Size = 0x38)]",
        "public unsafe struct Bits",
        "[FieldOffset(0x0)] public uint a; // a: bits 0..2, b: bits 3..7, c: bits 16..23",
        "[FieldOffset(0x10)] public fixed uint arr[3];",
        "[FieldOffset(0x20)] public fixed byte name[8];",
        "[FieldOffset(0x28)] public Inner inner;",
        "[FieldOffset(0x30)] public IntPtr next; // Inner*",
    ] {
        assert!(cs.contains(want), "{want:?} missing in\n{cs}");
    }
}
