//! Synthetic address spaces with planted pointer chains.
use std::collections::BTreeSet;
use std::path::PathBuf;

use hh_core::{Addr, Error, Memory, Module, Pid, Process, Prot, Region, RegionKind, Result};

use crate::*;

/// Test double: several regions with their own bytes, plus a module list.
struct Fake {
    ps: usize,
    regions: Vec<(Region, Vec<u8>)>,
    modules: Vec<Module>,
}

impl Fake {
    fn new(ps: usize) -> Self {
        Fake {
            ps,
            regions: Vec::new(),
            modules: Vec::new(),
        }
    }
    fn region(&mut self, start: Addr, size: u64, w: bool, kind: RegionKind, path: Option<&str>) {
        self.regions.push((
            Region {
                start,
                size,
                prot: Prot {
                    r: true,
                    w,
                    x: false,
                },
                kind,
                shared: false,
                cow: false,
                path: path.map(Into::into),
            },
            vec![0; size as usize],
        ));
        self.regions.sort_by_key(|r| r.0.start);
    }
    fn module(&mut self, name: &str, base: Addr, size: u64, w: bool) {
        self.region(base, size, w, RegionKind::Image, Some(name));
        self.modules.push(Module {
            name: name.into(),
            path: format!("/fake/{name}"),
            base,
            size,
        });
    }
    fn find(&self, addr: Addr) -> Option<&(Region, Vec<u8>)> {
        self.regions
            .iter()
            .find(|(r, _)| r.start <= addr && addr < r.start + r.size)
    }
    fn put_bytes(&mut self, addr: Addr, b: &[u8]) {
        let (r, mem) = self
            .regions
            .iter_mut()
            .find(|(r, _)| r.start <= addr && addr < r.start + r.size)
            .expect("planted address is mapped");
        let o = (addr - r.start) as usize;
        mem[o..o + b.len()].copy_from_slice(b);
    }
    fn put(&mut self, addr: Addr, v: Addr) {
        let b = v.to_le_bytes();
        self.put_bytes(addr, &b[..self.ps]);
    }
}

impl Memory for Fake {
    fn read(&self, addr: Addr, buf: &mut [u8]) -> Result<usize> {
        let (r, mem) = self.find(addr).ok_or(Error::NoAccess { addr })?;
        let o = (addr - r.start) as usize;
        let n = buf.len().min(mem.len() - o);
        buf[..n].copy_from_slice(&mem[o..o + n]);
        Ok(n)
    }
    fn write(&self, _: Addr, _: &[u8]) -> Result<()> {
        Err(Error::Unsupported("write"))
    }
    fn pointer_size(&self) -> usize {
        self.ps
    }
}

impl Process for Fake {
    fn pid(&self) -> Pid {
        1
    }
    fn regions(&self) -> Result<Vec<Region>> {
        Ok(self.regions.iter().map(|r| r.0.clone()).collect())
    }
    fn modules(&self) -> Result<Vec<Module>> {
        Ok(self.modules.clone())
    }
}

fn tmp(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("hh-ptr-{}-{name}", std::process::id()))
}

fn p(module: Option<&str>, base_offset: i64, offsets: &[i64]) -> PointerPath {
    PointerPath {
        module: module.map(Into::into),
        base_offset,
        offsets: offsets.to_vec(),
    }
}
fn g(off: i64, offs: &[i64]) -> PointerPath {
    p(Some("game.exe"), off, offs)
}

/// Builds a 64-bit image. Chains are planted at fixed module/stack slots; heap nodes are
/// 0x10000 apart so no two nodes are within max offset of each other. `chains` selects
/// which of the "relocatable" chains (c2, c3, c5) are planted, so a second image can
/// differ from the first.
struct Image {
    fake: Fake,
    target: Addr,
    game: Addr,
    nodes: Vec<Addr>,
}

impl Image {
    fn new(game: Addr, heap: Addr, stack: Addr, all: bool) -> Self {
        let mut fake = Fake::new(8);
        fake.module("game.exe", game, 0x10000, true);
        fake.module("lib.so", game + 0x100000, 0x1000, false);
        fake.region(heap, 0x200000, true, RegionKind::Private, Some("[heap]"));
        fake.region(stack, 0x10000, true, RegionKind::Private, Some("[stack]"));
        let mut img = Image {
            fake,
            target: heap + 0x1100,
            game,
            nodes: (1..30).map(|i| heap + i * 0x10000).rev().collect(),
        };
        let t = img.target;
        img.chain(game + 0x100, &[0x24]);
        let n1 = img.chain(game + 0x208, &[0x10, 0x40])[0];
        img.fake.put(n1 + 0x18, n1); // node pointing at itself: loop
        img.chain(game + 0x400, &[0, 0x100, 8, 0x20]);
        img.chain(stack + 0x10000 - 0x40, &[0x18, 0x48]);
        img.fake.put(game + 0x100000, t - 0x44); // lib.so is read-only
        // Through a static intermediate node.
        img.fake.put(game + 0x900, game + 0xA00);
        img.fake.put(game + 0xA08, t - 0x2C);
        // Negative first offset.
        let n = img.nodes.pop().unwrap();
        img.fake.put(game + 0x600, n);
        img.fake.put(n - 0x20, t - 0x38);
        // Decoys: above target (negative only), far below, misaligned.
        img.fake.put(game + 0x700, t + 0x10);
        img.fake.put(game + 0x800, t - 0x5000);
        img.fake.put(game + 0xB04, t - 0x34);
        if all {
            img.chain(game + 0x310, &[8, 0x18, 0x30]);
            img.chain(game + 0x500, &[0x10, 0x10, 0x10, 0x10, 0x28]);
        }
        img
    }

    /// Plants `[[[base]+o1]+o2]...` ending at the target; returns the nodes used.
    fn chain(&mut self, base: Addr, offs: &[i64]) -> Vec<Addr> {
        let k = offs.len();
        let mut nodes: Vec<Addr> = (0..k - 1).map(|_| self.nodes.pop().unwrap()).collect();
        nodes.push(self.target.wrapping_add_signed(-offs[k - 1]));
        self.fake.put(base, nodes[0]);
        for i in 0..k - 1 {
            self.fake
                .put(nodes[i].wrapping_add_signed(offs[i]), nodes[i + 1]);
        }
        nodes
    }
}

/// Every path the default scan must find in a full image.
fn expected() -> BTreeSet<PointerPath> {
    [
        g(0x100, &[0x24]),
        g(0x208, &[0x10, 0x40]),
        g(0x208, &[0x18, 0x10, 0x40]),
        g(0x310, &[8, 0x18, 0x30]),
        g(0x400, &[0, 0x100, 8, 0x20]),
        g(0x500, &[0x10, 0x10, 0x10, 0x10, 0x28]),
        g(0x900, &[8, 0x2C]),
        g(0xA08, &[0x2C]),
        p(Some("THREADSTACK0"), -0x40, &[0x18, 0x48]),
        p(Some("lib.so"), 0, &[0x44]),
    ]
    .into_iter()
    .collect()
}

fn image() -> Image {
    Image::new(0x400000, 0x1000_0000, 0x7ff0_0000, true)
}

fn scan_set(map: &PointerMap, target: Addr, o: &ScanOptions, name: &str) -> BTreeSet<PointerPath> {
    scan_cmp(map, target, o, &[], name)
}

fn scan_cmp(
    map: &PointerMap,
    target: Addr,
    o: &ScanOptions,
    cmp: &[(&PointerMap, Addr)],
    name: &str,
) -> BTreeSet<PointerPath> {
    let out = tmp(name);
    let r = map.scan(target, o, cmp, &out, &Progress::new()).unwrap();
    let v = r.read(0, usize::MAX).unwrap();
    let set: BTreeSet<_> = v.iter().cloned().collect();
    assert_eq!(set.len(), v.len(), "duplicate paths");
    std::fs::remove_file(out).unwrap();
    set
}

fn collect(f: &Fake, o: &CollectOptions) -> PointerMap {
    PointerMap::collect(f, o, &Progress::new()).unwrap()
}

#[test]
fn finds_exact_planted_paths() {
    let img = image();
    let map = collect(&img.fake, &CollectOptions::default());
    let found = scan_set(&map, img.target, &ScanOptions::default(), "exact");
    assert_eq!(found, expected());
    for path in &found {
        assert_eq!(resolve(&img.fake, path).unwrap(), img.target, "{path}");
        assert_eq!(map.resolve(path), Some(img.target));
    }
}

#[test]
fn options_prune() {
    let img = image();
    let t = img.target;
    let map = collect(&img.fake, &CollectOptions::default());
    let base = ScanOptions::default();
    let all = expected();
    let check = |o: ScanOptions, keep: &dyn Fn(&PointerPath) -> bool, name: &str| {
        let want: BTreeSet<_> = all.iter().filter(|p| keep(p)).cloned().collect();
        assert_eq!(scan_set(&map, t, &o, name), want, "{name}");
    };
    check(
        ScanOptions {
            max_level: 3,
            ..base.clone()
        },
        &|p| p.offsets.len() <= 3,
        "level",
    );
    check(
        ScanOptions {
            max_offset: 0x20,
            ..base.clone()
        },
        &|p| p.offsets.iter().all(|&o| o <= 0x20),
        "offset",
    );
    check(
        ScanOptions {
            base_modules: vec!["GAME.EXE".into()],
            ..base.clone()
        },
        &|p| p.module.as_deref() != Some("lib.so"),
        "modules",
    );
    check(
        ScanOptions {
            thread_stacks: false,
            ..base.clone()
        },
        &|p| p.module.as_deref() != Some("THREADSTACK0"),
        "stacks",
    );
    check(
        ScanOptions {
            stack_max: 0x20,
            ..base.clone()
        },
        &|p| p.module.as_deref() != Some("THREADSTACK0"),
        "stack_max",
    );
    check(
        ScanOptions {
            base_range: Some((img.game, img.game + 0x300)),
            ..base.clone()
        },
        &|p| p.module.as_deref() == Some("game.exe") && p.base_offset < 0x300,
        "range",
    );
    check(
        ScanOptions {
            last_offsets: vec![0x24, 0x40],
            ..base.clone()
        },
        &|p| [0x24, 0x40].contains(p.offsets.last().unwrap()),
        "last",
    );
    check(
        ScanOptions {
            ends_with: vec![0x10, 0x40],
            ..base.clone()
        },
        &|p| p.offsets.ends_with(&[0x10, 0x40]),
        "ends",
    );
    check(
        ScanOptions {
            heap_only: true,
            ..base.clone()
        },
        &|p| *p != g(0x900, &[8, 0x2C]),
        "heap",
    );
    check(
        ScanOptions {
            max_children: 1,
            ..base.clone()
        },
        &|p| *p == g(0x400, &[0, 0x100, 8, 0x20]),
        "children",
    );

    // Negative offsets add the planted negative chain and the decoy above the target.
    let neg = scan_set(
        &map,
        t,
        &ScanOptions {
            allow_negative: true,
            ..base.clone()
        },
        "neg",
    );
    // (Module slots pointing into the module also reach other static slots backwards.)
    assert!(neg.is_superset(&all));
    assert!(neg.contains(&g(0x600, &[-0x20, 0x38])));
    assert!(neg.contains(&g(0x700, &[-0x10])));
    assert!(neg.iter().all(|p| map.resolve(p) == Some(t)));
    assert!(all.iter().flat_map(|p| &p.offsets).all(|&o| o >= 0));
    assert_eq!(
        g(0x600, &[-0x20, 0x38]).to_string(),
        r#"[["game.exe"+00000600]-20]+38"#
    );

    // Looping allowed: the self-pointing node can be passed more than once.
    let loops = scan_set(
        &map,
        t,
        &ScanOptions {
            no_loops: false,
            ..base.clone()
        },
        "loops",
    );
    assert!(loops.is_superset(&all));
    assert!(loops.contains(&g(0x208, &[0x18, 0x18, 0x10, 0x40])));

    // Not static only: heap slots become absolute bases too.
    let any = scan_set(
        &map,
        t,
        &ScanOptions {
            static_only: false,
            max_level: 2,
            ..base.clone()
        },
        "any",
    );
    let n1 = map.read_ptr(img.game + 0x208).unwrap();
    assert!(any.contains(&p(None, (n1 + 0x10) as i64, &[0x40])));
    assert!(any.contains(&g(0x100, &[0x24])));

    let out = tmp("max");
    let r = map
        .scan(
            t,
            &ScanOptions {
                max_results: 3,
                ..base.clone()
            },
            &[],
            &out,
            &Progress::new(),
        )
        .unwrap();
    assert_eq!(r.len(), 3);
    std::fs::remove_file(out).unwrap();

    let r = map.scan(
        t,
        &ScanOptions {
            threads: 1,
            ..base.clone()
        },
        &[],
        &tmp("t1"),
        &Progress::new(),
    );
    assert_eq!(r.unwrap().len() as usize, all.len());
    std::fs::remove_file(tmp("t1")).unwrap();

    assert!(
        map.scan(
            t,
            &ScanOptions {
                max_level: 0,
                ..base.clone()
            },
            &[],
            &tmp("bad"),
            &Progress::new()
        )
        .is_err()
    );
    assert!(
        map.scan(
            t,
            &ScanOptions {
                max_level: 99,
                ..base
            },
            &[],
            &tmp("bad"),
            &Progress::new()
        )
        .is_err()
    );
}

#[test]
fn collect_options() {
    let img = image();
    let t = img.target;
    let o = ScanOptions::default();
    let ro = collect(
        &img.fake,
        &CollectOptions {
            writable_only: true,
            ..Default::default()
        },
    );
    let want: BTreeSet<_> = expected()
        .into_iter()
        .filter(|p| p.module.as_deref() != Some("lib.so"))
        .collect();
    assert_eq!(scan_set(&ro, t, &o, "ro"), want);

    let a4 = collect(
        &img.fake,
        &CollectOptions {
            alignment: 4,
            ..Default::default()
        },
    );
    let mut want = expected();
    want.insert(g(0xB04, &[0x34]));
    want.insert(g(0x900, &[0x104, 0x34])); // game+A00 -> game+B04
    assert_eq!(scan_set(&a4, t, &o, "a4"), want);
    assert!(a4.len() > collect(&img.fake, &CollectOptions::default()).len());
    assert!(
        PointerMap::collect(
            &img.fake,
            &CollectOptions {
                alignment: 16,
                ..Default::default()
            },
            &Progress::new()
        )
        .is_err()
    );

    // Cancelled collection errs; cancelled scan keeps a valid (empty) file.
    let pr = Progress::new();
    pr.cancel();
    assert!(PointerMap::collect(&img.fake, &CollectOptions::default(), &pr).is_err());
    let map = collect(&img.fake, &CollectOptions::default());
    let r = map.scan(t, &o, &[], &tmp("cancel"), &pr).unwrap();
    assert_eq!(r.len(), 0);
    assert!(pr.snapshot().cancelled);
    std::fs::remove_file(tmp("cancel")).unwrap();

    // Progress counts every top-level candidate.
    let pr = Progress::new();
    map.scan(t, &o, &[], &tmp("prog"), &pr).unwrap();
    let s = pr.snapshot();
    assert_eq!((s.done, s.found), (s.total, expected().len() as u64));
    std::fs::remove_file(tmp("prog")).unwrap();
}

#[test]
fn unreadable_memory_is_skipped() {
    // A region the process lists but cannot read must not fail the collection.
    struct Holey(Fake);
    impl Memory for Holey {
        fn read(&self, addr: Addr, buf: &mut [u8]) -> Result<usize> {
            if (0x1000_8000..0x1000_9000).contains(&addr) {
                return Err(Error::NoAccess { addr });
            }
            // Reads that would cross the hole stop at it.
            let max = if addr < 0x1000_8000 {
                (0x1000_8000 - addr) as usize
            } else {
                buf.len()
            };
            let n = buf.len().min(max);
            self.0.read(addr, &mut buf[..n])
        }
        fn write(&self, a: Addr, d: &[u8]) -> Result<()> {
            self.0.write(a, d)
        }
    }
    impl Process for Holey {
        fn pid(&self) -> Pid {
            1
        }
        fn regions(&self) -> Result<Vec<Region>> {
            let mut r = self.0.regions()?;
            r.push(Region {
                start: 0x5000_0000,
                size: 0x1000,
                prot: Prot {
                    r: true,
                    w: true,
                    x: false,
                },
                kind: RegionKind::Private,
                shared: false,
                cow: false,
                path: None,
            });
            Ok(r)
        }
        fn modules(&self) -> Result<Vec<Module>> {
            self.0.modules()
        }
    }
    let img = image();
    let t = img.target;
    let h = Holey(img.fake);
    let map = PointerMap::collect(&h, &CollectOptions::default(), &Progress::new()).unwrap();
    assert_eq!(
        scan_set(&map, t, &ScanOptions::default(), "holey"),
        expected()
    );
}

#[test]
fn pointer_map_save_load_compare() {
    let a = image();
    let b = Image::new(0x800000, 0x3000_0000, 0x7fe0_0000, false);
    let ma = collect(&a.fake, &CollectOptions::default());
    let mb = collect(&b.fake, &CollectOptions::default());
    let f = tmp("a.pmap");
    ma.save(&f).unwrap();
    let la = PointerMap::load(&f).unwrap();
    assert_eq!(la.len(), ma.len());
    assert_eq!(la.pointer_size, 8);
    let o = ScanOptions::default();
    assert_eq!(scan_set(&la, a.target, &o, "loaded"), expected());

    // Only paths valid in both maps (each with its own target) survive.
    let both = scan_cmp(&la, a.target, &o, &[(&mb, b.target)], "cmp");
    let want: BTreeSet<_> = expected()
        .into_iter()
        .filter(|p| ![0x310, 0x500].contains(&p.base_offset))
        .collect();
    assert_eq!(both, want);
    // A map without the process's live data: wrong target leaves nothing.
    assert!(scan_cmp(&la, a.target, &o, &[(&mb, b.target + 8)], "cmp2").is_empty());

    // Corrupt files are errors, not panics.
    let mut bytes = std::fs::read(&f).unwrap();
    bytes.truncate(bytes.len() - 3);
    std::fs::write(&f, &bytes).unwrap();
    assert!(PointerMap::load(&f).is_err());
    std::fs::write(&f, b"garbage").unwrap();
    assert!(PointerMap::load(&f).is_err());
    std::fs::remove_file(f).unwrap();
}

#[test]
fn rescan_after_relocation() {
    let a = image();
    let mut b = Image::new(0x800000, 0x3000_0000, 0x7fe0_0000, false);
    b.fake.put_bytes(b.target, &0x1234u32.to_le_bytes());
    let ma = collect(&a.fake, &CollectOptions::default());
    let first = ma
        .scan(
            a.target,
            &ScanOptions::default(),
            &[],
            &tmp("r0"),
            &Progress::new(),
        )
        .unwrap();
    let survivors: BTreeSet<_> = expected()
        .into_iter()
        .filter(|p| ![0x310, 0x500].contains(&p.base_offset))
        .collect();
    let rescan = |src: Source, o: RescanOptions, name: &str| {
        let r = first.rescan(src, &o, &tmp(name), &Progress::new()).unwrap();
        let s: BTreeSet<_> = r.read(0, usize::MAX).unwrap().into_iter().collect();
        std::fs::remove_file(tmp(name)).unwrap();
        s
    };
    let tb = RescanOptions {
        target: Some(b.target),
        ..Default::default()
    };
    assert_eq!(
        rescan(Source::Process(&b.fake), tb.clone(), "r1"),
        survivors
    );
    let mb = collect(&b.fake, &CollectOptions::default());
    assert_eq!(rescan(Source::Map(&mb), tb.clone(), "r2"), survivors);
    // Old target in the new process: nothing.
    let old = RescanOptions {
        target: Some(a.target),
        ..Default::default()
    };
    assert!(rescan(Source::Process(&b.fake), old, "r3").is_empty());
    // Value at the end of the path.
    let v = |x: u32| RescanOptions {
        value: Some(x.to_le_bytes().to_vec()),
        ..Default::default()
    };
    assert_eq!(rescan(Source::Process(&b.fake), v(0x1234), "r4"), survivors);
    assert!(rescan(Source::Process(&b.fake), v(0x1235), "r5").is_empty());
    assert!(
        first
            .rescan(Source::Map(&mb), &v(1), &tmp("r6"), &Progress::new())
            .is_err()
    );
    // Base range / offset filters.
    let br = RescanOptions {
        base_range: Some((b.game, b.game + 0x300)),
        ..tb.clone()
    };
    assert_eq!(
        rescan(Source::Process(&b.fake), br, "r7"),
        survivors
            .iter()
            .filter(|p| p.module.as_deref() == Some("game.exe") && p.base_offset < 0x300)
            .cloned()
            .collect()
    );
    let sw = RescanOptions {
        starts_with: vec![0x18],
        max_level: 3,
        ..tb.clone()
    };
    assert_eq!(
        rescan(Source::Process(&b.fake), sw, "r8"),
        [
            g(0x208, &[0x18, 0x10, 0x40]),
            p(Some("THREADSTACK0"), -0x40, &[0x18, 0x48])
        ]
        .into_iter()
        .collect()
    );

    // Several rescans in a row, then paging with live resolution.
    let r1 = first
        .rescan(Source::Process(&b.fake), &tb, &tmp("c1"), &Progress::new())
        .unwrap();
    let ew = RescanOptions {
        ends_with: vec![0x40],
        ..tb
    };
    let r2 = r1
        .rescan(Source::Process(&b.fake), &ew, &tmp("c2"), &Progress::new())
        .unwrap();
    assert_eq!(r2.len(), 2);
    assert_eq!(r2.header.target, b.target);
    let rows = r2.results(0, 10, Some(&b.fake)).unwrap();
    assert_eq!(rows.len(), 2);
    for row in &rows {
        assert_eq!(row.address, Some(b.target));
        assert_eq!(row.value, Some(0x1234));
        assert_eq!(row.text.parse::<PointerPath>().unwrap(), row.path);
    }
    assert_eq!(r2.results(1, 10, None).unwrap().len(), 1);
    assert!(r2.results(5, 10, None).unwrap().is_empty());
    assert!(r2.read(u64::MAX, 10).unwrap().is_empty());

    // Sort / merge: union without duplicates, sorted by level.
    let m = merge(&[&first, &r1, &r2], &tmp("m")).unwrap();
    assert_eq!(m.len() as usize, expected().len());
    let paths = m.read(0, usize::MAX).unwrap();
    assert!(
        paths
            .windows(2)
            .all(|w| w[0].offsets.len() <= w[1].offsets.len())
    );
    let s = r1.sorted(&tmp("s")).unwrap();
    assert_eq!(s.len(), r1.len());

    // Truncated result file is an error.
    let bytes = std::fs::read(tmp("m")).unwrap();
    std::fs::write(tmp("m"), &bytes[..bytes.len() - 1]).unwrap();
    assert!(ResultFile::open(&tmp("m")).is_err());
    for n in ["r0", "c1", "c2", "m", "s"] {
        std::fs::remove_file(tmp(n)).unwrap();
    }
}

#[test]
fn pointer_size_4() {
    let mut f = Fake::new(4);
    f.module("game.exe", 0x400000, 0x1000, true);
    f.region(0x0100_0000, 0x40000, true, RegionKind::Private, None);
    let t = 0x0100_0100;
    f.put(0x400010, 0x0102_0000);
    f.put(0x0102_0000 + 0xC, 0x0103_0000);
    f.put(0x0103_0000 + 0x4, t - 0x8);
    f.put(0x400014, 0xFFFF_FFF0); // not valid memory
    let map = collect(&f, &CollectOptions::default());
    assert_eq!(map.len(), 3);
    let found = scan_set(&map, t, &ScanOptions::default(), "p4");
    assert_eq!(found, [g(0x10, &[0xC, 0x4, 0x8])].into_iter().collect());
    assert_eq!(resolve(&f, &g(0x10, &[0xC, 0x4, 0x8])).unwrap(), t);
}

#[test]
fn text_and_table_entry() {
    let cases = [
        (
            g(0x1A2B3C, &[0x10, 0x18, 0x8]),
            r#"[[["game.exe"+001A2B3C]+10]+18]+8"#,
        ),
        (
            p(Some("THREADSTACK0"), -0x128, &[0x10]),
            "[THREADSTACK0-00000128]+10",
        ),
        (p(None, 0x7FF6_1234_0000, &[-0x8]), "[7FF612340000]-8"),
        (g(0x10, &[]), r#""game.exe"+00000010"#),
    ];
    for (path, text) in cases {
        assert_eq!(path.to_string(), text);
        assert_eq!(text.parse::<PointerPath>().unwrap(), path);
    }
    assert_eq!(
        "[[game.exe+1A]+0x10]+8".parse::<PointerPath>().unwrap(),
        g(0x1A, &[0x10, 8])
    );
    assert_eq!(
        "[my-game.exe]+8".parse::<PointerPath>().unwrap(),
        p(Some("my-game.exe"), 0, &[8])
    );
    for bad in ["", "[[x]+1", "[x]+zz", "[x]8", "[\"a\"+1]]+2", "]"] {
        assert!(bad.parse::<PointerPath>().is_err(), "{bad}");
    }
    let e = to_table_entry(&g(0x1A2B3C, &[0x10, -0x8]), 7, "health", "4bytes");
    assert_eq!(e["addr"], r#""game.exe"+001A2B3C"#);
    assert_eq!(e["offsets"], serde_json::json!(["10", "-8"]));
    assert_eq!(e["vtype"], "4bytes");
    assert_eq!(e["id"], 7);
    assert_eq!(e["children"], serde_json::json!([]));
}

fn xorshift(s: &mut u64) -> u64 {
    *s ^= *s << 13;
    *s ^= *s >> 7;
    *s ^= *s << 17;
    *s
}

#[test]
#[ignore = "benchmark: cargo test -p hh-ptr --release -- --ignored --nocapture bench"]
fn bench_1gib() {
    const HEAP: Addr = 0x1_0000_0000;
    const SIZE: u64 = 1 << 30;
    let mut f = Fake::new(8);
    f.module("game.exe", 0x40_0000, 1 << 20, true);
    f.region(HEAP, SIZE, true, RegionKind::Private, None);
    let mut s = 0x9E37_79B9_7F4A_7C15u64;
    for (_, mem) in f.regions.iter_mut() {
        // One pointer per 128 bytes into the heap, small integers elsewhere.
        for (i, slot) in mem.chunks_exact_mut(8).enumerate() {
            let r = xorshift(&mut s);
            let v = if i % 16 == 0 {
                HEAP + ((r % SIZE) & !7)
            } else {
                r & 0xFFFF
            };
            slot.copy_from_slice(&v.to_le_bytes());
        }
    }
    let t0 = std::time::Instant::now();
    let map = collect(&f, &CollectOptions::default());
    let dt = t0.elapsed().as_secs_f64();
    println!(
        "collect: {} pointers in {:.2}s = {:.1} M pointers/s ({:.0} MiB/s)",
        map.len(),
        dt,
        map.len() as f64 / dt / 1e6,
        1025.0 / dt
    );
    for level in [5, 6, 7] {
        let o = ScanOptions {
            max_level: level,
            max_offset: 0x800,
            ..Default::default()
        };
        let t0 = std::time::Instant::now();
        let r = map
            .scan(HEAP + 0x1234_5678, &o, &[], &tmp("bench"), &Progress::new())
            .unwrap();
        let dt = t0.elapsed().as_secs_f64();
        println!(
            "scan level {level}: {} paths in {:.2}s = {:.0} paths/s",
            r.len(),
            dt,
            r.len() as f64 / dt
        );
    }
    std::fs::remove_file(tmp("bench")).unwrap();
}
