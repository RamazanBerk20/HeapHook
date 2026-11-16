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
            .find(|(r, _)| r.start <= addr && addr - r.start < r.size)
    }
    fn put_bytes(&mut self, addr: Addr, b: &[u8]) {
        let (r, mem) = self
            .regions
            .iter_mut()
            .find(|(r, _)| r.start <= addr && addr - r.start < r.size)
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

// ---------------------------------------------------------------- 1.0 feature gaps

#[test]
fn old_format_files_still_load() {
    // Written by the fixed-size (v1) code before the compact format existed.
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/v1-results.ptr");
    let f = ResultFile::open(&fixture).unwrap();
    assert!(!f.is_compact());
    assert_eq!(f.len(), 10);
    let all: BTreeSet<_> = f.read(0, usize::MAX).unwrap().into_iter().collect();
    assert_eq!(all, expected());
    assert_eq!(f.read(9, 5).unwrap().len(), 1);
    // Rescans and sorts of an old file write the new format.
    let img = image();
    let map = collect(&img.fake, &CollectOptions::default());
    let r = f.rescan(Source::Map(&map), &RescanOptions { target: Some(img.target), ..Default::default() }, &tmp("v1-rescan"), &Progress::new()).unwrap();
    assert!(r.is_compact() && r.len() == 10);
    let s = f.sorted(&tmp("v1-sorted")).unwrap();
    assert!(s.is_compact());
    assert_eq!(s.read(0, usize::MAX).unwrap().into_iter().collect::<BTreeSet<_>>(), expected());
    for n in ["v1-rescan", "v1-sorted"] {
        std::fs::remove_file(tmp(n)).unwrap();
    }
}

fn header(bases: &[&str], max_level: usize) -> ResultHeader {
    ResultHeader { pointer_size: 8, max_level, target: 0x1234, bases: bases.iter().map(|s| s.to_string()).collect() }
}

/// Writes `paths` (base index or `ABS`, base offset, offsets) as a v2 file.
fn write_v2(path: &std::path::Path, h: &ResultHeader, paths: &[(u32, i64, Vec<i64>)]) -> ResultFile {
    let mut w = results::Writer::create(path, h).unwrap();
    let mut buf = Vec::new();
    for (b, o, offs) in paths {
        results::encode(&mut buf, *b, *o, offs.iter().copied());
    }
    w.write_encoded(&buf).unwrap();
    w.finish().unwrap();
    ResultFile::open(path).unwrap()
}

#[test]
fn compact_format_pages_and_rejects_corruption() {
    let h = header(&["a.exe", "b.dll"], 4);
    let paths: Vec<(u32, i64, Vec<i64>)> = (0..10_000i64)
        .map(|i| (if i % 3 == 0 { results::ABS } else { (i % 2) as u32 }, i * 8 - 4000, (0..(i % 4 + 1)).map(|k| k * 0x10 - (i % 5)).collect()))
        .collect();
    let out = tmp("v2-paging");
    let f = write_v2(&out, &h, &paths);
    assert!(f.is_compact() && f.len() == 10_000);
    let want = |i: usize| {
        let (b, o, offs) = &paths[i];
        PointerPath { module: (*b != results::ABS).then(|| h.bases[*b as usize].clone()), base_offset: *o, offsets: offs.clone() }
    };
    for (off, n) in [(0, 3), (4095, 3), (4096, 1), (8190, 5), (9998, 10)] {
        let got = f.read(off, n).unwrap();
        let exp: Vec<_> = (off as usize..(off as usize + n).min(10_000)).map(want).collect();
        assert_eq!(got, exp, "page at {off}");
    }
    assert!(f.read(10_000, 5).unwrap().is_empty() && f.read(u64::MAX, 5).unwrap().is_empty());
    // Much smaller than fixed-size records: 12 + header + 10000 * (13 + 4 * 4) for v1.
    let size = std::fs::metadata(&out).unwrap().len();
    assert!(size < 10_000 * 29 / 3, "{size} bytes");

    // Hostile files are errors, never panics or huge allocations.
    let good = std::fs::read(&out).unwrap();
    let try_bytes = |b: &[u8]| {
        std::fs::write(&out, b).unwrap();
        ResultFile::open(&out).and_then(|f| f.read(0, usize::MAX))
    };
    assert!(try_bytes(&good[..good.len() - 1]).is_err());
    let mut b = good.clone();
    let n = b.len();
    b[n - 16..n - 8].copy_from_slice(&u64::MAX.to_le_bytes()); // absurd count
    assert!(try_bytes(&b).is_err());
    let mut b = good.clone();
    b[n - 8..].copy_from_slice(&3u64.to_le_bytes()); // index offset inside the records
    assert!(try_bytes(&b).is_err());
    let mut b = good.clone();
    let hlen = u32::from_le_bytes(b[8..12].try_into().unwrap()) as usize;
    b[12 + hlen..12 + hlen + 40].fill(0xff); // unterminated varints
    assert!(try_bytes(&b).is_err());
    let mut b = good.clone();
    b[12 + hlen] = 9; // base index out of range
    assert!(try_bytes(&b).is_err());
    std::fs::remove_file(out).unwrap();
}

#[test]
fn external_merge_sort_matches_in_memory_sort() {
    // Two inputs with different base name lists, duplicates within and across files.
    let a: Vec<(u32, i64, Vec<i64>)> = (0..300i64).map(|i| ((i % 2) as u32, (i * 7919) % 101, vec![i % 3, -(i % 7)])).collect();
    let b: Vec<(u32, i64, Vec<i64>)> = (0..200i64).map(|i| (if i % 4 == 0 { results::ABS } else { 0 }, (i * 31) % 50, vec![i % 3])).collect();
    let fa = write_v2(&tmp("merge-a"), &header(&["z.so", "a.exe"], 2), &a);
    let fb = write_v2(&tmp("merge-b"), &header(&["m.dll"], 3), &b);
    let paths = |f: &ResultFile| f.read(0, usize::MAX).unwrap();
    let mut want: Vec<PointerPath> = paths(&fa).into_iter().chain(paths(&fb)).collect();
    let key = |p: &PointerPath| {
        let names = ["a.exe", "m.dll", "z.so"];
        let base = p.module.as_deref().map_or(u32::MAX, |m| names.iter().position(|n| *n == m).unwrap() as u32);
        let mut offs = [0i64; MAX_LEVEL];
        offs[..p.offsets.len()].copy_from_slice(&p.offsets);
        (p.offsets.len(), base, p.base_offset, offs)
    };
    want.sort_by_key(key);
    want.dedup();
    let in_memory = results::merge_runs(&[&fa, &fb], &tmp("merge-mem"), usize::MAX, &Progress::new()).unwrap();
    assert_eq!(paths(&in_memory), want);
    // Runs of 1 record: 500 run files, merged 64 at a time.
    for run in [1, 3, 64] {
        let ext = results::merge_runs(&[&fa, &fb], &tmp("merge-ext"), run, &Progress::new()).unwrap();
        assert_eq!(paths(&ext), want, "run {run}");
        assert_eq!(ext.header.bases, ["a.exe", "m.dll", "z.so"]);
        assert_eq!(ext.header.max_level, 3);
    }
    let left = std::fs::read_dir(std::env::temp_dir()).unwrap().flatten().filter(|e| e.file_name().to_string_lossy().contains("merge-ext.run")).count();
    assert_eq!(left, 0, "run files left behind");
    // Sorting a file onto itself works: inputs are read before the output is written.
    let fa2 = fa.sorted(fa.path()).unwrap();
    assert_eq!(fa2.len(), paths(&fa2).len() as u64);
    for n in ["merge-a", "merge-b", "merge-mem", "merge-ext"] {
        std::fs::remove_file(tmp(n)).unwrap();
    }
}

#[test]
fn scan_offset_filters() {
    let img = image();
    let map = collect(&img.fake, &CollectOptions::default());
    let all = expected();
    let filtered = |keep: &dyn Fn(&PointerPath) -> bool| all.iter().filter(|p| keep(p)).cloned().collect::<BTreeSet<_>>();
    let o = |f: &dyn Fn(&mut ScanOptions)| {
        let mut o = ScanOptions::default();
        f(&mut o);
        o
    };
    let sw = o(&|o| o.starts_with = vec![0x10]);
    assert_eq!(scan_set(&map, img.target, &sw, "starts"), filtered(&|p| p.offsets.starts_with(&[0x10])));
    let sw2 = o(&|o| o.starts_with = vec![0x10, 0x10, 0x10]);
    assert_eq!(scan_set(&map, img.target, &sw2, "starts3"), filtered(&|p| p.offsets.starts_with(&[0x10, 0x10, 0x10])));
    let allowed = [0x10, 0x40, 0x28, 0x24];
    let ao = o(&|o| o.allowed_offsets = allowed.to_vec());
    assert_eq!(scan_set(&map, img.target, &ao, "allowed"), filtered(&|p| p.offsets.iter().all(|x| allowed.contains(x))));
    // game+0xA08 is a static node: nothing is searched behind it.
    let st = o(&|o| o.stop_at_static = true);
    assert_eq!(scan_set(&map, img.target, &st, "static"), filtered(&|p| *p != g(0x900, &[8, 0x2C])));
    let bad = o(&|o| o.starts_with = vec![1 << 40]);
    assert!(map.scan(img.target, &bad, &[], &tmp("bad"), &Progress::new()).is_err());
}

#[test]
fn pause_resume_and_time_limit() {
    let img = image();
    let map = collect(&img.fake, &CollectOptions::default());
    let prog = Progress::new();
    prog.pause();
    let o = ScanOptions { time_limit_secs: 1, ..ScanOptions::default() };
    std::thread::scope(|s| {
        let h = s.spawn(|| map.scan(img.target, &o, &[], &tmp("paused"), &prog));
        std::thread::sleep(std::time::Duration::from_millis(1300));
        assert!(!h.is_finished() && prog.snapshot().paused);
        assert_eq!(prog.snapshot().found, 0);
        prog.resume();
        // Paused time does not count against the 1 s limit: everything is found.
        let r = h.join().unwrap().unwrap();
        assert_eq!(r.read(0, usize::MAX).unwrap().into_iter().collect::<BTreeSet<_>>(), expected());
    });
    assert!(!prog.snapshot().paused && prog.paused_for() >= std::time::Duration::from_millis(1300));
    // Cancel ends a paused collect too.
    let p2 = Progress::new();
    p2.pause();
    p2.cancel();
    assert!(PointerMap::collect(&img.fake, &CollectOptions::default(), &p2).is_err());
    std::fs::remove_file(tmp("paused")).unwrap();
}

#[test]
fn per_thread_stacks_in_maps() {
    let mut img = image();
    // A second thread's stack: an untagged private mapping the caller identified.
    let stack1: Addr = 0x7fa0_0000;
    img.fake.region(stack1, 0x10000, true, RegionKind::Private, None);
    img.chain(stack1 + 0x10000 - 0x80, &[0x30]);
    // Remote / unknown processes degrade to the tagged stack regions.
    assert_eq!(thread_stacks(&img.fake, true).unwrap(), [(0x7ff0_0000, 0x7ff1_0000)]);
    let mut map = PointerMap::collect_ex(&img.fake, &CollectOptions::default(), true, &Progress::new()).unwrap();
    assert_eq!(map.stack_ranges(), [(0x7ff0_0000, 0x7ff1_0000)]);
    map.stacks = vec![(0x7ff0_0000, 0x7ff1_0000), (stack1, stack1 + 0x10000)];
    let o = ScanOptions { stack_max: 0x100, ..ScanOptions::default() };
    let found = scan_set(&map, img.target, &o, "stacks");
    let want = p(Some("THREADSTACK1"), -0x80, &[0x30]);
    assert!(found.contains(&want), "{found:?}");
    assert_eq!(map.resolve(&want), Some(img.target));
    // Saved maps keep the stacks.
    let f = tmp("stacks.pmap");
    map.save(&f).unwrap();
    let loaded = PointerMap::load(&f).unwrap();
    assert_eq!(loaded.stacks, map.stacks);
    assert_eq!(loaded.resolve(&want), Some(img.target));
    std::fs::remove_file(f).unwrap();
}

#[test]
fn script_job_runs_in_the_background() {
    let img = image();
    let target = img.target;
    let p: std::sync::Arc<dyn Process> = std::sync::Arc::new(img.fake);
    let job = PointerScanJob::start(p.clone(), target, ScanOptions::default(), CollectOptions::default(), false, tmp("job")).unwrap();
    let f = job.wait().unwrap();
    assert!(job.is_done() && job.progress().found == 10);
    assert_eq!(f.read(0, usize::MAX).unwrap().into_iter().collect::<BTreeSet<_>>(), expected());
    assert_eq!(job.wait().unwrap().len(), 10, "wait again gives the same file");
    let rows = f.results(0, 3, Some(&*p)).unwrap();
    assert!(rows.iter().all(|r| r.address == Some(target)));
    let f2 = scan_process(&*p, target, &ScanOptions::default(), &CollectOptions::default(), false, &tmp("job2"), &Progress::new()).unwrap();
    assert_eq!(f2.len(), 10);
    for n in ["job", "job2"] {
        std::fs::remove_file(tmp(n)).unwrap();
    }
}

#[test]
fn sparse_pointer_map_is_refused_without_reserving() {
    // A header claiming more pointers than the cap, backed by a sparse file of the matching
    // length: refused up front instead of reserving count × 16 bytes.
    let img = image();
    let f = tmp("sparse.pmap");
    collect(&img.fake, &CollectOptions::default()).save(&f).unwrap();
    let mut b = std::fs::read(&f).unwrap();
    let hlen = u32::from_le_bytes(b[8..12].try_into().unwrap()) as u64;
    let count = map::MAX_ENTRIES + 1;
    b.truncate(20 + hlen as usize);
    b[12 + hlen as usize..].copy_from_slice(&count.to_le_bytes());
    std::fs::write(&f, &b).unwrap();
    std::fs::OpenOptions::new().write(true).open(&f).unwrap().set_len(20 + hlen + count * 16).unwrap();
    let e = PointerMap::load(&f).unwrap_err();
    assert!(e.to_string().contains("limit"), "{e}");
    // A huge JSON header length is refused too. (The file is ~4 GiB sparse now: keep `b`.)
    b[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
    std::fs::write(&f, &b).unwrap();
    std::fs::OpenOptions::new().write(true).open(&f).unwrap().set_len(u32::MAX as u64 + 64).unwrap();
    assert!(PointerMap::load(&f).is_err());
    std::fs::remove_file(f).unwrap();
}

#[test]
fn hostile_regions_do_not_break_collection() {
    // Overlapping, unsorted and wrapping regions (a hostile remote peer).
    let mut f = Fake::new(8);
    f.module("game.exe", 0x400000, 0x1000, true);
    f.region(0x1000_0000, 0x2000, true, RegionKind::Private, None);
    f.region(0x1000_1000, 0x2000, true, RegionKind::Private, None);
    f.region(u64::MAX - 0xfff, 0x2000, true, RegionKind::Private, None);
    // Ends exactly at the top of the address space.
    f.region(u64::MAX - 0x2fff, 0x2fff, true, RegionKind::Private, None);
    f.put(0x400010, 0x1000_1800);
    let map = collect(&f, &CollectOptions::default());
    assert_eq!(map.read_ptr(0x400010), Some(0x1000_1800));
    let n = map.entries.iter().filter(|e| e.addr == 0x400010).count();
    assert_eq!(n, 1, "overlap duplicated an entry");
}

#[test]
fn huge_result_index_and_header_are_refused() {
    let out = tmp("huge-index");
    let h = serde_json::to_vec(&header(&["a.exe"], 2)).unwrap();
    let data_start = 12 + h.len() as u64;
    // count = 2^35 paths -> 2^23 index entries (64 MiB), all in a sparse file.
    let count: u64 = 1 << 35;
    let entries = count / 4096;
    let index_off = count * 3;
    let len = data_start + index_off + entries * 8 + 16;
    let mut b = b"HHPTRS02".to_vec();
    b.extend_from_slice(&(h.len() as u32).to_le_bytes());
    b.extend_from_slice(&h);
    std::fs::write(&out, &b).unwrap();
    let file = std::fs::OpenOptions::new().write(true).open(&out).unwrap();
    file.set_len(len).unwrap();
    use std::io::{Seek, Write};
    let mut file = file;
    file.seek(std::io::SeekFrom::Start(len - 16)).unwrap();
    file.write_all(&count.to_le_bytes()).unwrap();
    file.write_all(&index_off.to_le_bytes()).unwrap();
    drop(file);
    let e = ResultFile::open(&out).unwrap_err();
    assert!(e.to_string().contains("too many"), "{e}");
    // A header length beyond the cap.
    let mut b = b"HHPTRS02".to_vec();
    b.extend_from_slice(&u32::MAX.to_le_bytes());
    std::fs::write(&out, &b).unwrap();
    std::fs::OpenOptions::new().write(true).open(&out).unwrap().set_len(u32::MAX as u64 + 64).unwrap();
    assert!(ResultFile::open(&out).is_err());
    std::fs::remove_file(out).unwrap();
}

#[test]
fn cancelled_sort_errors_and_leaves_nothing() {
    let paths: Vec<(u32, i64, Vec<i64>)> = (0..500i64).map(|i| (0, (i * 7919) % 101, vec![i % 3])).collect();
    let fa = write_v2(&tmp("cancel-in"), &header(&["a.exe"], 2), &paths);
    let p = Progress::new();
    p.cancel();
    for run in [usize::MAX, 7] {
        let out = tmp("cancel-out");
        assert!(results::merge_runs(&[&fa], &out, run, &p).is_err());
        assert!(!out.exists(), "output left behind");
    }
    assert!(fa.sorted_ex(&tmp("cancel-out"), &p).is_err());
    let left = std::fs::read_dir(std::env::temp_dir()).unwrap().flatten().filter(|e| e.file_name().to_string_lossy().contains("cancel-out.run")).count();
    assert_eq!(left, 0, "run files left behind");
    // The same progress object, not cancelled, reports the work done.
    let p = Progress::new();
    let s = fa.sorted_ex(&tmp("cancel-out"), &p).unwrap();
    assert_eq!(p.snapshot().total, 500);
    assert!(!s.is_empty());
    std::fs::remove_file(tmp("cancel-in")).unwrap();
    std::fs::remove_file(tmp("cancel-out")).unwrap();
}
