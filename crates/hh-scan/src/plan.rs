//! Scan requests and their compilation into per-position predicates.
use hh_core::{Addr, Error, Result};
use serde::{Deserialize, Serialize};

use crate::hexaddr;
use crate::value::{
    CustomType, Enc, MAX_VALUE_LEN, NumVal, Num, Pattern, Prim, Rounding, VType, Val, binary_bits, float_interval, parse_aob,
    parse_num,
    parse_string, shifted, with_num,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanType {
    Exact,
    Bigger,
    Smaller,
    Between,
    Unknown,
    Increased,
    IncreasedBy,
    Decreased,
    DecreasedBy,
    Changed,
    Unchanged,
    SameAsFirst,
}

impl ScanType {
    fn needs_previous(self) -> bool {
        use ScanType::*;
        matches!(self, Increased | IncreasedBy | Decreased | DecreasedBy | Changed | Unchanged | SameAsFirst)
    }
}

/// Region filter: `yes` = must have, `no` = must not have, `any` = don't care.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tri {
    Yes,
    No,
    #[default]
    Any,
}

impl Tri {
    pub(crate) fn ok(self, v: bool) -> bool {
        match self {
            Tri::Yes => v,
            Tri::No => !v,
            Tri::Any => true,
        }
    }
}

/// How hard a scan competes with the target for CPU: `low` yields the thread after every
/// block (~256 KiB), `idle` also sleeps 1 ms there.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Priority {
    #[default]
    Normal,
    Low,
    Idle,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ScanOptions {
    #[serde(with = "hexaddr::opt")]
    pub start: Option<Addr>,
    /// Exclusive end of the scanned address range.
    #[serde(with = "hexaddr::opt")]
    pub stop: Option<Addr>,
    pub writable: Tri,
    pub executable: Tri,
    /// shortcut: `Region` has no copy-on-write flag, so COW = writable file-backed mapping
    /// (Image/Mapped); upgrade when hh-core reports private/shared mappings.
    pub copy_on_write: Tri,
    /// "Fast scan" alignment; `None` = natural (min(size, 4) for numbers, 1 otherwise).
    pub alignment: Option<u64>,
    /// "Last digits" fast scan: hex digits the address must end with (overrides alignment).
    pub last_digits: Option<String>,
    pub hex: bool,
    pub case_sensitive: bool,
    pub utf16: bool,
    pub rounding: Rounding,
    pub percent: bool,
    pub pause_while_scanning: bool,
    /// Integers compare as signed for bigger/smaller/increased... (exact accepts both).
    pub signed: bool,
    /// Worker threads for this scan and its next scans; `None` = rayon's global pool.
    pub threads: Option<usize>,
    pub priority: Priority,
    /// Types an "all" scan tries (empty = byte, 2/4/8 bytes, float, double). Adding `string`
    /// also matches the value as text (exact first scans; next scans exact with the same
    /// length, changed, unchanged, same as first/saved). The row shows the first matching
    /// type in the order 4 bytes, float, 8 bytes, double, 2 bytes, byte, string.
    pub all_types: Vec<VType>,
    /// Scan a data-defined type instead of `vtype` (any numeric scan type, unknown included).
    pub custom: Option<CustomType>,
    /// Binary: the value is a decimal number, not a bit string.
    pub binary_decimal: bool,
    /// Binary: field length in bits (the value is zero-extended to it).
    pub bit_len: Option<u32>,
    /// Binary: only match fields starting at this bit (0..7) of a byte; `None` = any bit.
    /// Results report the bit offset (`ResultRow::bit`).
    pub bit_start: Option<u8>,
    /// String code page: `None`/65001 UTF-8, 1252, 28591 (ignored with `utf16`).
    pub codepage: Option<u32>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        ScanOptions {
            start: None,
            stop: None,
            writable: Tri::Any,
            executable: Tri::Any,
            copy_on_write: Tri::Any,
            alignment: None,
            last_digits: None,
            hex: false,
            case_sensitive: false,
            utf16: false,
            rounding: Rounding::Rounded,
            percent: false,
            pause_while_scanning: false,
            signed: true,
            threads: None,
            priority: Priority::Normal,
            all_types: Vec::new(),
            custom: None,
            binary_decimal: false,
            bit_len: None,
            bit_start: None,
            codepage: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirstScan {
    pub vtype: VType,
    pub scan_type: ScanType,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub value2: Option<String>,
    #[serde(default)]
    pub not: bool,
    #[serde(default)]
    pub opts: ScanOptions,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NextScan {
    pub scan_type: ScanType,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub value2: Option<String>,
    #[serde(default)]
    pub not: bool,
    /// Overrides the first scan's `opts.percent`.
    #[serde(default)]
    pub percent: Option<bool>,
}

/// A next scan that may compare against a saved scan (same JSON as [`NextScan`] plus
/// `compare_to`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NextScanEx {
    #[serde(flatten)]
    pub scan: NextScan,
    /// Name of a saved scan (`Scanner::save_scan`) or `"first"`: increased, decreased,
    /// changed, unchanged, increased/decreased by and percent scans compare against that
    /// scan's value at the same address instead of the previous scan's; entries the saved
    /// scan does not hold drop out. `same_as_first` always compares with the first scan.
    #[serde(default)]
    pub compare_to: Option<String>,
}

impl From<NextScan> for NextScanEx {
    fn from(scan: NextScan) -> Self {
        NextScanEx { scan, compare_to: None }
    }
}

// ---------------------------------------------------------------- compiled form

#[derive(Debug, Clone, Copy)]
pub(crate) enum NumCmp {
    Bits(u64),
    I(i128, i128),
    F(f64, f64),
    Inc,
    Dec,
    Changed,
    Unchanged,
    SameFirst,
    ByI(i128),
    ByF { d: f64, dec: u32, mode: Rounding },
    /// Percent of the previous value `p`: the target is `p + |p| * k` (`rel`, increased /
    /// decreased by) or `p * k` (between), `k` in `[lo, hi]`; `widen` accepts integers that
    /// round the target (single-value integer percent scans).
    Pct { lo: f64, hi: f64, rel: bool, widen: bool },
}

/// `x` = current, `p` = previous scan, `f0` = first scan value.
#[inline(always)]
pub(crate) fn eval<T: Val>(c: &NumCmp, x: T, p: T, f0: T) -> bool {
    let within = |lo: f64, hi: f64| {
        let v = x.f();
        lo <= v && v <= hi
    };
    match *c {
        NumCmp::Bits(v) => x.bits() == v,
        NumCmp::I(lo, hi) => {
            let i = x.i();
            lo <= i && i <= hi
        }
        NumCmp::F(lo, hi) => within(lo, hi),
        NumCmp::Inc if x.float() => x.f() > p.f(),
        NumCmp::Inc => x.i() > p.i(),
        NumCmp::Dec if x.float() => x.f() < p.f(),
        NumCmp::Dec => x.i() < p.i(),
        NumCmp::Changed => x.bits() != p.bits(),
        NumCmp::Unchanged => x.bits() == p.bits(),
        NumCmp::SameFirst => x.bits() == f0.bits(),
        // Integer arithmetic wraps like the target's would.
        NumCmp::ByI(d) => (p.i().wrapping_add(d) as u64) & x.mask() == x.bits(),
        NumCmp::ByF { d, dec, mode } => {
            let (lo, hi) = float_interval(p.f() + d, dec, mode);
            within(lo, hi)
        }
        NumCmp::Pct { lo, hi, rel, widen } => {
            let pv = p.f();
            let (a, b) = if rel { (pv + pv.abs() * lo, pv + pv.abs() * hi) } else { (pv * lo, pv * hi) };
            let (a, b) = (a.min(b), a.max(b));
            let e = if widen && !x.float() { 0.5 } else { 0.0 };
            within(a - e, b + e)
        }
    }
}

pub(crate) struct NumOpts {
    pub hex: bool,
    pub rounding: Rounding,
    pub percent: bool,
}

/// What a numeric comparison runs on.
#[derive(Clone, Copy)]
pub(crate) enum Ty {
    Prim(Prim),
    Custom(CustomType),
}

impl Ty {
    fn float(self) -> bool {
        match self {
            Ty::Prim(p) => p.is_float(),
            Ty::Custom(c) => c.float || c.scale != 1.0 || c.offset != 0.0,
        }
    }
}

/// Compiles a numeric scan. Semantics (Cheat Engine's, where its documentation states them):
/// - exact float: the value rounded/truncated to the typed decimals equals the typed value
///   (see [`Rounding`]); exact integer: the bit pattern, so `-1` and `255` both find 0xFF;
/// - bigger/smaller are strict, between is inclusive in either argument order;
/// - increased/decreased by N: integers wrap like the target's arithmetic; floats match
///   `previous ± N` under the rounding mode with N's decimals;
/// - percent increased/decreased by X: the change relative to `|previous|`, so a negative
///   value that increased by 10% got 10% closer to (or past) zero. Integers accept the
///   target rounded either way (100 → 110; 15 → 16 or 17); floats accept a percentage that
///   rounds to X under the rounding mode ("25" = [24.5%, 25.5%) when rounded). With a second
///   value the change must be between X% and Y% inclusive;
/// - percent between X and Y: the value is between X% and Y% of the previous value.
pub(crate) fn num_cmp(ty: Ty, st: ScanType, v1: Option<&str>, v2: Option<&str>, o: &NumOpts) -> Result<NumCmp> {
    let fl = ty.float();
    let hex = o.hex && !fl;
    let need = |v: Option<&str>| -> Result<NumVal> {
        parse_num(v.ok_or_else(|| Error::Parse("this scan type needs a value".into()))?, hex)
    };
    Ok(match st {
        ScanType::Exact => {
            let v = need(v1)?;
            match ty {
                _ if fl => {
                    let (lo, hi) = float_interval(v.f, v.dec, o.rounding);
                    NumCmp::F(lo, hi)
                }
                Ty::Prim(p) => NumCmp::Bits(p.int_bits(v.int()?)?),
                Ty::Custom(_) => NumCmp::I(v.int()?, v.int()?),
            }
        }
        ScanType::Bigger | ScanType::Smaller => {
            let v = need(v1)?;
            match (fl, st == ScanType::Bigger) {
                (true, true) => NumCmp::F(v.f.next_up(), f64::INFINITY),
                (true, false) => NumCmp::F(f64::NEG_INFINITY, v.f.next_down()),
                // Nothing is bigger than i128::MAX (or smaller than MIN): an empty range.
                (false, true) => v.int()?.checked_add(1).map_or(NumCmp::I(1, 0), |lo| NumCmp::I(lo, i128::MAX)),
                (false, false) => v.int()?.checked_sub(1).map_or(NumCmp::I(1, 0), |hi| NumCmp::I(i128::MIN, hi)),
            }
        }
        ScanType::Between => {
            let (a, b) = (need(v1)?, need(v2)?);
            if o.percent {
                NumCmp::Pct { lo: a.f / 100.0, hi: b.f / 100.0, rel: false, widen: false }
            } else if fl {
                NumCmp::F(a.f.min(b.f), a.f.max(b.f))
            } else {
                let (a, b) = (a.int()?, b.int()?);
                NumCmp::I(a.min(b), a.max(b))
            }
        }
        ScanType::Increased => NumCmp::Inc,
        ScanType::Decreased => NumCmp::Dec,
        ScanType::Changed => NumCmp::Changed,
        ScanType::Unchanged => NumCmp::Unchanged,
        ScanType::SameAsFirst => NumCmp::SameFirst,
        ScanType::IncreasedBy | ScanType::DecreasedBy => {
            let sign = if st == ScanType::IncreasedBy { 1.0 } else { -1.0 };
            let a = need(v1)?;
            if o.percent {
                let (lo, hi, widen) = match v2.map(|v| need(Some(v))).transpose()? {
                    Some(b) => (a.f, b.f, false),
                    None if fl => {
                        let (lo, hi) = float_interval(a.f, a.dec, o.rounding);
                        (lo, hi, false)
                    }
                    None => (a.f, a.f, true),
                };
                NumCmp::Pct { lo: sign * lo / 100.0, hi: sign * hi / 100.0, rel: true, widen }
            } else if fl {
                NumCmp::ByF { d: sign * a.f, dec: a.dec, mode: o.rounding }
            } else {
                NumCmp::ByI(sign as i128 * a.int()?)
            }
        }
        ScanType::Unknown => return Err(Error::Parse("unknown initial value is a first-scan type".into())),
    })
}

/// (current bytes, previous-scan bytes, first-scan bytes) -> match.
pub(crate) type BytePred = Box<dyn Fn(&[u8], &[u8], &[u8]) -> bool + Send + Sync>;

pub(crate) struct Test {
    /// Bit in the per-entry mask ("all" type, binary bit offset); 1 otherwise.
    pub bit: u8,
    /// Current bytes needed at the address.
    pub need: usize,
    /// Previous/first bytes the predicate reads.
    pub need_prev: usize,
    pub pred: BytePred,
    /// The same test as data for specialized loops: (type, signed, comparison, not).
    pub num: Option<(Prim, bool, NumCmp, bool)>,
}

fn num_test(prim: Prim, signed: bool, cmp: NumCmp, not: bool, bit: u8) -> Test {
    let pred: BytePred = with_num!(prim, signed, T => Box::new(move |c: &[u8], p: &[u8], f: &[u8]| {
        eval::<T>(&cmp, T::rd(c), T::rd(p), T::rd(f)) != not
    }));
    Test { bit, need: prim.width(), need_prev: prim.width(), pred, num: Some((prim, signed, cmp, not)) }
}

fn custom_test(ct: CustomType, cmp: NumCmp, not: bool) -> Test {
    let pred: BytePred = Box::new(move |c, p, f| eval(&cmp, ct.decode(c), ct.decode(p), ct.decode(f)) != not);
    Test { bit: 1, need: ct.size(), need_prev: ct.size(), pred, num: None }
}

/// Byte comparison of the first `w` bytes under `mask` (binary fields) for
/// changed/unchanged/same-as-first.
fn bytes_test(st: ScanType, w: usize, mask: Option<Vec<u8>>, not: bool, bit: u8) -> Option<Test> {
    if !matches!(st, ScanType::Changed | ScanType::Unchanged | ScanType::SameAsFirst) {
        return None;
    }
    let eq = move |a: &[u8], b: &[u8]| match &mask {
        None => a.get(..w) == b.get(..w),
        Some(m) => a.iter().zip(b).zip(m).all(|((x, y), m)| (x ^ y) & m == 0),
    };
    let pred: BytePred = Box::new(move |c, p, f| {
        (match st {
            ScanType::Changed => !eq(c, p),
            ScanType::Unchanged => eq(c, p),
            _ => eq(c, f),
        }) != not
    });
    Some(Test { bit, need: w, need_prev: w, pred, num: None })
}

/// Type order of the "all" mask bits; the lowest set bit is the type shown in results.
/// Bit 6 is the optional string match.
pub(crate) const ALL_ORDER: [Prim; 6] = [Prim::B4, Prim::F4, Prim::B8, Prim::F8, Prim::B2, Prim::B1];
pub(crate) const ALL_STRING: u8 = 1 << 6;

pub(crate) enum Fast {
    None,
    Num(Prim, bool, NumCmp, bool),
    Pat(Pattern),
    /// Several patterns, one per mask bit (binary bit offsets).
    Pats(Pats),
}

pub(crate) struct Plan {
    pub tests: Vec<Test>,
    pub fast: Fast,
    pub unknown: bool,
    /// Survivors' current bytes equal their previous ones in every byte a later scan or row
    /// reads, so a dense chunk can keep its previous copy.
    pub keeps_prev: bool,
}

/// What a scan session keeps between first and next scans.
#[derive(Clone)]
pub(crate) struct Kind {
    pub vtype: VType,
    pub opts: ScanOptions,
    /// Bytes stored per entry for previous/first values (first scan; sets carry their own).
    pub width: usize,
    pub align: u64,
    pub align_off: u64,
    /// Smallest number of bytes a position needs to be a candidate.
    pub min_need: usize,
    /// Entries carry a mask ("all" types, binary bit offsets).
    pub masked: bool,
    /// Mask of an unknown-initial-value entry.
    pub full_mask: u8,
    /// "All" with strings: the text's byte length (0 = no string matching).
    pub str_len: usize,
    /// Binary: field length in bits.
    pub bits: usize,
}

impl Kind {
    pub fn all(&self) -> bool {
        self.vtype == VType::All && self.opts.custom.is_none()
    }
    pub fn binary(&self) -> bool {
        self.vtype == VType::Binary && self.opts.custom.is_none()
    }
    pub fn enc(&self) -> Enc {
        Enc::of(self.opts.utf16, self.opts.codepage).unwrap_or(Enc::Utf8)
    }
    /// Bit offsets a binary scan tries.
    fn shifts(&self) -> Vec<usize> {
        match self.opts.bit_start {
            Some(s) => vec![s as usize % 8],
            None => (0..8).collect(),
        }
    }
}

fn nopts(o: &ScanOptions) -> NumOpts {
    NumOpts { hex: o.hex, rounding: o.rounding, percent: o.percent }
}

fn val(v: &Option<String>) -> Result<&str> {
    v.as_deref().ok_or_else(|| Error::Parse("this scan type needs a value".into()))
}

fn pattern(vtype: VType, s: &str, o: &ScanOptions) -> Result<Pattern> {
    match vtype {
        VType::String => parse_string(s, Enc::of(o.utf16, o.codepage)?, o.case_sensitive),
        _ => parse_aob(s),
    }
}

fn pat_test(p: Pattern, not: bool, bit: u8) -> Test {
    Test { bit, need: p.len(), need_prev: 0, pred: Box::new(move |c, _, _| p.matches(c) != not), num: None }
}

fn group_test(g: Group, not: bool) -> Test {
    Test { bit: 1, need: g.min_len(), need_prev: 0, pred: Box::new(move |c, _, _| g.matches(c) != not), num: None }
}

/// Numeric types an "all" scan tries, with their mask bits.
fn all_prims(o: &ScanOptions) -> impl Iterator<Item = (u8, Prim)> + '_ {
    ALL_ORDER
        .iter()
        .enumerate()
        .filter(|(_, p)| o.all_types.is_empty() || o.all_types.contains(&p.vtype()))
        .map(|(i, &p)| (1u8 << i, p))
}

/// `str_len`: the first scan's text length (`None` while compiling the first scan).
fn all_tests(st: ScanType, a: Option<&str>, b: Option<&str>, o: &ScanOptions, not: bool, str_len: Option<usize>) -> Result<Vec<Test>> {
    let mut tests: Vec<Test> = all_prims(o)
        .filter_map(|(bit, p)| {
            let c = num_cmp(Ty::Prim(p), st, a, b, &nopts(o)).ok()?;
            Some(num_test(p, o.signed, c, not, bit))
        })
        .collect();
    if o.all_types.contains(&VType::String) && str_len != Some(0) {
        if st == ScanType::Exact {
            let p = pattern(VType::String, a.unwrap_or_default(), o).ok().filter(|p| str_len.is_none_or(|n| p.len() == n));
            tests.extend(p.map(|p| pat_test(p, not, ALL_STRING)));
        } else if let Some(n) = str_len {
            tests.extend(bytes_test(st, n, None, not, ALL_STRING));
        }
    }
    if tests.is_empty() {
        // Re-run one type to surface the parse error.
        num_cmp(Ty::Prim(Prim::F8), st, a, b, &nopts(o))?;
        return Err(Error::Parse("value matches no type".into()));
    }
    Ok(tests)
}

/// Patterns per mask bit (binary bit offsets).
type Pats = Vec<(u8, Pattern)>;

/// Binary tests, one per bit offset (mask bit = 1 << offset), the exact patterns and the
/// field length in bits.
fn binary_tests(k: &Kind, st: ScanType, v: Option<&str>, not: bool) -> Result<(Vec<Test>, Pats, usize)> {
    let o = &k.opts;
    if st == ScanType::Exact {
        let bits = binary_bits(val(&v.map(str::to_owned))?, o.binary_decimal, o.bit_len)?;
        let pats: Pats = k.shifts().into_iter().map(|s| (1u8 << s, shifted(&bits, s).0)).collect();
        let tests = pats.iter().map(|(b, p)| pat_test(p.clone(), not, *b)).collect();
        return Ok((tests, pats, bits.len()));
    }
    let tests = k
        .shifts()
        .into_iter()
        .filter_map(|s| {
            let field = shifted(&vec![None; k.bits], s).1;
            bytes_test(st, field.len(), Some(field), not, 1 << s)
        })
        .collect::<Vec<_>>();
    if tests.is_empty() {
        return Err(Error::Unsupported("binary next scans support exact, changed, unchanged and same as first"));
    }
    Ok((tests, Vec::new(), k.bits))
}

pub(crate) fn compile_first(req: &FirstScan) -> Result<(Kind, Plan)> {
    let o = &req.opts;
    let st = req.scan_type;
    if st.needs_previous() {
        return Err(Error::Parse(format!("{st:?} needs a previous scan")));
    }
    if o.threads == Some(0) {
        return Err(Error::Parse("thread count must be at least 1".into()));
    }
    let unknown = st == ScanType::Unknown;
    let (a, b) = (req.value.as_deref(), req.value2.as_deref());
    let mut plan = Plan { tests: Vec::new(), fast: Fast::None, unknown, keeps_prev: false };
    let mut k = Kind {
        vtype: req.vtype,
        opts: o.clone(),
        width: 0,
        align: 1,
        align_off: 0,
        min_need: 0,
        masked: false,
        full_mask: 1,
        str_len: 0,
        bits: 0,
    };
    let mut group_align = None;
    let mut natural = 1;
    if let Some(ct) = o.custom {
        ct.validate()?;
        if !unknown {
            plan.tests = vec![custom_test(ct, num_cmp(Ty::Custom(ct), st, a, b, &nopts(o))?, req.not)];
        }
        k.width = ct.size();
        natural = if ct.size.is_power_of_two() { ct.size().min(4) } else { 1 };
    } else {
        match req.vtype {
            VType::All => {
                k.masked = true;
                k.full_mask = all_prims(o).fold(0, |m, (b, _)| m | b);
                if !unknown {
                    plan.tests = all_tests(st, a, b, o, req.not, None)?;
                    k.str_len = plan.tests.iter().find(|t| t.bit == ALL_STRING).map_or(0, |t| t.need);
                } else if k.full_mask == 0 {
                    return Err(Error::Parse("no numeric type selected".into()));
                }
                k.width = k.str_len.max(8);
                k.min_need = plan.tests.iter().map(|t| t.need).min().unwrap_or(1);
            }
            VType::String | VType::Aob | VType::Binary | VType::Grouped if st != ScanType::Exact => {
                return Err(Error::Unsupported("strings, byte arrays, binary and groups only support exact first scans"));
            }
            VType::Grouped => {
                let g = parse_group(val(&req.value)?, o)?;
                group_align = g.align;
                k.width = g.width();
                plan.tests = vec![group_test(g, req.not)];
            }
            VType::Binary => {
                if o.bit_start.is_some_and(|s| s > 7) {
                    return Err(Error::Parse("start bit must be 0..7".into()));
                }
                k.masked = true;
                k.bits = 1; // placeholder for shifts()
                let (tests, pats, n) = binary_tests(&k, st, a, req.not)?;
                k.bits = n;
                k.width = (n + k.shifts().last().copied().unwrap_or(0)).div_ceil(8);
                k.min_need = n.div_ceil(8);
                if !req.not {
                    plan.fast = Fast::Pats(pats);
                }
                plan.tests = tests;
            }
            VType::String | VType::Aob => {
                let p = pattern(req.vtype, val(&req.value)?, o)?;
                if !req.not {
                    plan.fast = Fast::Pat(p.clone());
                }
                k.width = p.len();
                plan.tests = vec![pat_test(p, req.not, 1)];
            }
            v => {
                let p = Prim::of(v).ok_or(Error::Unsupported("value type"))?;
                if !unknown {
                    let c = num_cmp(Ty::Prim(p), st, a, b, &nopts(o))?;
                    plan.fast = match c {
                        // Exact integers are a byte search: memchr-accelerated, any alignment.
                        NumCmp::Bits(v) if !req.not => Fast::Pat(Pattern::exact(v.to_le_bytes()[..p.width()].to_vec())),
                        _ => Fast::Num(p, o.signed, c, req.not),
                    };
                    plan.tests = vec![num_test(p, o.signed, c, req.not, 1)];
                }
                k.width = p.width();
                natural = p.width().min(4);
            }
        }
    }
    if k.min_need == 0 {
        k.min_need = k.width;
    }
    (k.align, k.align_off) = match &o.last_digits {
        Some(d) if !d.trim().is_empty() => {
            let d = d.trim();
            let off = u64::from_str_radix(d, 16).map_err(|_| Error::Parse(format!("bad last digits {d:?}")))?;
            let step = 16u64.checked_pow(d.len() as u32).ok_or_else(|| Error::Parse("too many last digits".into()))?;
            (step, off)
        }
        _ => (group_align.or(o.alignment).unwrap_or(natural as u64), 0),
    };
    if !(1..=MAX_ALIGN).contains(&k.align) {
        return Err(Error::Parse(format!("alignment must be 1..={MAX_ALIGN:#x}, got {:#x}", k.align)));
    }
    Ok((k, plan))
}

/// `w` = the current set's entry width. Returns the plan and the new set's width (an exact
/// string / byte array / group scan may change the value's length).
pub(crate) fn compile_next(k: &Kind, req: &NextScan, w: usize) -> Result<(Plan, usize)> {
    let mut o = k.opts.clone();
    if let Some(p) = req.percent {
        o.percent = p;
    }
    let st = req.scan_type;
    let (a, b) = (req.value.as_deref(), req.value2.as_deref());
    let not = req.not;
    let mut width = w;
    let unsupported = || Error::Unsupported("this scan type needs a numeric value type");
    let tests = match k.vtype {
        _ if st == ScanType::Unknown => return Err(Error::Parse("unknown initial value is a first-scan type".into())),
        _ if o.custom.is_some() => {
            let ct = o.custom.unwrap_or(CustomType::int(1, false));
            vec![custom_test(ct, num_cmp(Ty::Custom(ct), st, a, b, &nopts(&o))?, not)]
        }
        VType::All => all_tests(st, a, b, &o, not, Some(k.str_len))?,
        VType::Binary => binary_tests(k, st, a, not)?.0,
        VType::String | VType::Aob | VType::Grouped => match st {
            ScanType::Exact if k.vtype == VType::Grouped => {
                let g = parse_group(val(&req.value)?, &o)?;
                width = g.width();
                vec![group_test(g, not)]
            }
            ScanType::Exact => {
                let p = pattern(k.vtype, val(&req.value)?, &o)?;
                width = p.len();
                vec![pat_test(p, not, 1)]
            }
            _ => vec![bytes_test(st, w, None, not, 1).ok_or_else(unsupported)?],
        },
        v => {
            let p = Prim::of(v).ok_or(Error::Unsupported("value type"))?;
            vec![num_test(p, o.signed, num_cmp(Ty::Prim(p), st, a, b, &nopts(&o))?, not, 1)]
        }
    };
    let keeps_prev = st == ScanType::Unchanged && !not && !k.binary() && width == w;
    Ok((Plan { tests, fast: Fast::None, unknown: false, keeps_prev }, width))
}

// ---------------------------------------------------------------- grouped scans

#[derive(Debug, Clone)]
enum Elem {
    Num(Prim, NumCmp),
    Pat(Pattern),
    Any(usize),
}

impl Elem {
    fn width(&self) -> usize {
        match self {
            Elem::Num(p, _) => p.width(),
            Elem::Pat(p) => p.len(),
            Elem::Any(n) => *n,
        }
    }
    fn matches(&self, b: &[u8]) -> bool {
        match self {
            Elem::Num(p, c) => b.len() >= p.width() && with_num!(*p, false, T => {
                let x = T::rd(b);
                eval::<T>(c, x, x, x)
            }),
            Elem::Pat(p) => p.matches(b),
            Elem::Any(n) => b.len() >= *n,
        }
    }
}

/// Cheat Engine group scan: `4:100 f:2.5 w:8 s:'text' su:"wide" 2:*`, plus `BA:n` (block
/// alignment), `BS:n` (block size) and `OOO` (out of order). In order, elements are laid out
/// back to back; out of order, the first element sits at the block start and every other
/// element anywhere in the block at its natural alignment.
/// shortcut: out-of-order does not stop two elements claiming the same bytes.
#[derive(Debug, Clone)]
pub(crate) struct Group {
    elems: Vec<(usize, Elem)>,
    span: usize,
    ooo: Option<usize>,
    pub align: Option<u64>,
}

const DEFAULT_BLOCK: usize = 256;

impl Group {
    pub fn width(&self) -> usize {
        self.ooo.unwrap_or(self.span)
    }
    pub(crate) fn min_len(&self) -> usize {
        if self.ooo.is_some() { self.elems[0].1.width() } else { self.span }
    }
    pub fn matches(&self, b: &[u8]) -> bool {
        let Some(bs) = self.ooo else {
            return self.elems.iter().all(|(off, e)| b.get(*off..).is_some_and(|s| e.matches(s)));
        };
        let blk = &b[..b.len().min(bs)];
        let (first, rest) = (&self.elems[0].1, &self.elems[1..]);
        first.matches(blk)
            && rest.iter().all(|(_, e)| {
                let (w, step) = (e.width(), if let Elem::Num(p, _) = e { p.width() } else { 1 });
                w <= blk.len() && (0..=blk.len() - w).step_by(step).any(|k| e.matches(&blk[k..]))
            })
    }
}

fn group_tokens(s: &str) -> Result<Vec<(String, String)>> {
    let cs: Vec<char> = s.chars().collect();
    let (mut i, mut out) = (0, Vec::new());
    loop {
        while i < cs.len() && cs[i].is_whitespace() {
            i += 1;
        }
        if i >= cs.len() {
            return Ok(out);
        }
        let start = i;
        while i < cs.len() && cs[i] != ':' && !cs[i].is_whitespace() {
            i += 1;
        }
        let key: String = cs[start..i].iter().collect::<String>().to_ascii_lowercase();
        let mut value = String::new();
        if i < cs.len() && cs[i] == ':' {
            i += 1;
            if i < cs.len() && (cs[i] == '\'' || cs[i] == '"') {
                let q = cs[i];
                let end = cs[i + 1..].iter().position(|&c| c == q).ok_or_else(|| Error::Parse("unclosed quote".into()))?;
                value = cs[i + 1..i + 1 + end].iter().collect();
                i += end + 2;
            } else {
                while i < cs.len() && !cs[i].is_whitespace() {
                    value.push(cs[i]);
                    i += 1;
                }
            }
        }
        out.push((key, value));
    }
}

/// Largest scan alignment (or last-digits step); bigger ones only overflow address math.
const MAX_ALIGN: u64 = 1 << 32;

pub(crate) fn parse_group(s: &str, o: &ScanOptions) -> Result<Group> {
    let mut g = Group { elems: Vec::new(), span: 0, ooo: None, align: None };
    let (mut ooo, mut bs) = (false, DEFAULT_BLOCK);
    let num = |v: &str| parse_num(v, true).and_then(|n| n.int()).and_then(|n| {
        usize::try_from(n).map_err(|_| Error::Parse(format!("bad size {v:?}")))
    });
    let dec = |v: &str| parse_num(v, false).and_then(|n| n.int()).and_then(|n| {
        usize::try_from(n).map_err(|_| Error::Parse(format!("bad size {v:?}")))
    });
    let no = NumOpts { hex: o.hex, rounding: o.rounding, percent: false };
    let too_wide = || Error::Parse(format!("group wider than {MAX_VALUE_LEN} bytes"));
    for (k, v) in group_tokens(s)? {
        let e = match k.as_str() {
            "ooo" => {
                ooo = true;
                continue;
            }
            "ba" => {
                g.align = Some(dec(&v)? as u64);
                continue;
            }
            "bs" => {
                bs = dec(&v)?.max(1);
                continue;
            }
            "1" | "2" | "4" | "8" | "f" | "d" => {
                let p = match k.as_str() {
                    "1" => Prim::B1,
                    "2" => Prim::B2,
                    "4" => Prim::B4,
                    "8" => Prim::B8,
                    "f" => Prim::F4,
                    _ => Prim::F8,
                };
                if v == "*" { Elem::Any(p.width()) } else { Elem::Num(p, num_cmp(Ty::Prim(p), ScanType::Exact, Some(&v), None, &no)?) }
            }
            "s" | "su" => Elem::Pat(parse_string(&v, Enc::of(k == "su", o.codepage)?, o.case_sensitive)?),
            "w" => Elem::Any(dec(&v).or_else(|_| num(&v))?),
            _ => return Err(Error::Parse(format!("unknown group element {k:?}"))),
        };
        let w = e.width();
        g.elems.push((g.span, e));
        g.span = g.span.checked_add(w).filter(|&n| n <= MAX_VALUE_LEN).ok_or_else(too_wide)?;
    }
    if bs > MAX_VALUE_LEN {
        return Err(too_wide());
    }
    if g.elems.is_empty() || g.span == 0 {
        return Err(Error::Parse("empty group".into()));
    }
    if ooo {
        g.elems.retain(|(_, e)| !matches!(e, Elem::Any(_)));
        if g.elems.is_empty() {
            return Err(Error::Parse("out-of-order group needs a value element".into()));
        }
        g.ooo = Some(bs.max(g.span));
    }
    Ok(g)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_parse_and_match() {
        let o = ScanOptions::default();
        let g = parse_group("4:100 f:2.5 w:2 s:'a b' 2:*", &o).unwrap();
        assert_eq!(g.width(), 4 + 4 + 2 + 3 + 2);
        let mut b = Vec::new();
        b.extend(100u32.to_le_bytes());
        b.extend(2.5f32.to_le_bytes());
        b.extend([9, 9]);
        b.extend(b"A B");
        b.extend([7, 7]);
        assert!(g.matches(&b));
        b[0] = 101;
        assert!(!g.matches(&b));
        assert!(parse_group("x:1", &o).is_err());
        assert!(parse_group("s:'open", &o).is_err());
        assert!(parse_group("", &o).is_err());

        let g = parse_group("OOO BS:16 4:7 2:9", &o).unwrap();
        assert_eq!(g.width(), 16);
        let mut b = [0u8; 16];
        b[..4].copy_from_slice(&7u32.to_le_bytes());
        b[10..12].copy_from_slice(&9u16.to_le_bytes());
        assert!(g.matches(&b));
        b[10] = 0;
        assert!(!g.matches(&b));
        assert_eq!(parse_group("BA:4 1:1", &o).unwrap().align, Some(4));
    }
}
