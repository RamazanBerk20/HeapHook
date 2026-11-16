//! Value types and string <-> bytes conversion (the UI passes every value as a string).
use hh_core::{Addr, Error, Memory, Result};
use serde::{Deserialize, Serialize};

use crate::hexaddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VType {
    Binary,
    Byte,
    #[serde(rename = "2bytes")]
    Bytes2,
    #[serde(rename = "4bytes")]
    Bytes4,
    #[serde(rename = "8bytes")]
    Bytes8,
    Float,
    Double,
    String,
    Aob,
    All,
    Grouped,
}

/// How a typed float like `1.5` is matched (Cheat Engine semantics, `d` = typed decimals).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Rounding {
    /// Value rounded to `d` decimals equals the typed value: 1.5 matches [1.45, 1.55).
    #[default]
    Rounded,
    /// Anything strictly within one last-digit unit: 1.5 matches (1.4, 1.6).
    Extreme,
    /// Value truncated to `d` decimals equals the typed value: 1.5 matches [1.5, 1.6).
    Truncated,
}

/// Display/encoding flags of a value (`len` = characters for strings, bytes for aob/binary).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Fmt {
    pub len: Option<usize>,
    pub signed: bool,
    pub hex: bool,
    pub utf16: bool,
}

/// One `read_values` request item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValueRef {
    #[serde(with = "hexaddr")]
    pub addr: Addr,
    pub vtype: VType,
    #[serde(flatten)]
    pub fmt: Fmt,
}

const DEFAULT_STR_LEN: usize = 16;
/// Largest string / byte-array / binary value read in one piece; lengths come from cheat
/// tables, so a hostile one must not size a multi-GB buffer.
pub const MAX_VALUE_LEN: usize = 1 << 20;

/// Bytes a value of this type occupies (at most [`MAX_VALUE_LEN`]).
pub fn value_size(vtype: VType, fmt: &Fmt) -> Result<usize> {
    let n = match vtype {
        VType::Byte => 1,
        VType::Bytes2 => 2,
        VType::Bytes4 | VType::Float => 4,
        VType::Bytes8 | VType::Double => 8,
        VType::String => fmt.len.unwrap_or(DEFAULT_STR_LEN).saturating_mul(if fmt.utf16 { 2 } else { 1 }),
        VType::Aob => fmt.len.unwrap_or(DEFAULT_STR_LEN),
        VType::Binary => fmt.len.unwrap_or(1),
        VType::All | VType::Grouped => return Err(Error::Unsupported("no fixed size for all/grouped")),
    };
    if n > MAX_VALUE_LEN {
        return Err(Error::Parse(format!("value length {n} exceeds the {MAX_VALUE_LEN}-byte limit")));
    }
    Ok(n)
}

/// Formats raw little-endian bytes as the UI shows them.
pub fn format_value(vtype: VType, b: &[u8], fmt: &Fmt) -> String {
    if let Some(p) = Prim::of(vtype) {
        if b.len() < p.width() {
            return "??".into();
        }
        return p.format(b, fmt.signed, fmt.hex);
    }
    match vtype {
        VType::String if fmt.utf16 => {
            let u: Vec<u16> = b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).take_while(|&c| c != 0).collect();
            String::from_utf16_lossy(&u)
        }
        VType::String => {
            let end = memchr::memchr(0, b).unwrap_or(b.len());
            String::from_utf8_lossy(&b[..end]).into_owned()
        }
        VType::Binary => b.iter().rev().map(|x| format!("{x:08b}")).collect::<Vec<_>>().join(" "),
        _ => hex_bytes(b),
    }
}

pub(crate) fn hex_bytes(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect::<Vec<_>>().join(" ")
}

/// Parses a typed value into the bytes to write. Wildcards are rejected.
pub fn parse_value(vtype: VType, s: &str, fmt: &Fmt) -> Result<Vec<u8>> {
    if let Some(p) = Prim::of(vtype) {
        return p.encode(&parse_num(s, fmt.hex && !p.is_float())?);
    }
    let pat = match vtype {
        VType::String => return Ok(encode_str(s, fmt.utf16)),
        VType::Aob => parse_aob(s)?,
        VType::Binary => parse_binary(s)?,
        _ => return Err(Error::Unsupported("cannot write all/grouped values")),
    };
    if pat.mask.iter().any(|&m| m != 0xff) {
        return Err(Error::Parse("wildcards cannot be written".into()));
    }
    Ok(pat.val)
}

/// Reads and formats each value; `None` where memory is unreadable.
pub fn read_values(mem: &dyn Memory, refs: &[ValueRef]) -> Vec<Option<String>> {
    refs.iter()
        .map(|r| {
            let n = value_size(r.vtype, &r.fmt).ok()?;
            let mut buf = vec![0u8; n];
            let got = mem.read(r.addr, &mut buf).ok()?;
            // Strings may be cut short by a region end; numbers must be complete.
            if got < n && r.vtype != VType::String {
                return None;
            }
            Some(format_value(r.vtype, &buf[..got], &r.fmt))
        })
        .collect()
}

pub fn write_value(mem: &dyn Memory, addr: Addr, vtype: VType, value: &str, fmt: &Fmt) -> Result<()> {
    mem.write(addr, &parse_value(vtype, value, fmt)?)
}

// ---------------------------------------------------------------- numbers

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Prim {
    B1,
    B2,
    B4,
    B8,
    F4,
    F8,
}

impl Prim {
    pub fn of(v: VType) -> Option<Prim> {
        Some(match v {
            VType::Byte => Prim::B1,
            VType::Bytes2 => Prim::B2,
            VType::Bytes4 => Prim::B4,
            VType::Bytes8 => Prim::B8,
            VType::Float => Prim::F4,
            VType::Double => Prim::F8,
            _ => return None,
        })
    }
    pub fn vtype(self) -> VType {
        match self {
            Prim::B1 => VType::Byte,
            Prim::B2 => VType::Bytes2,
            Prim::B4 => VType::Bytes4,
            Prim::B8 => VType::Bytes8,
            Prim::F4 => VType::Float,
            Prim::F8 => VType::Double,
        }
    }
    pub fn width(self) -> usize {
        match self {
            Prim::B1 => 1,
            Prim::B2 => 2,
            Prim::B4 | Prim::F4 => 4,
            Prim::B8 | Prim::F8 => 8,
        }
    }
    pub fn is_float(self) -> bool {
        matches!(self, Prim::F4 | Prim::F8)
    }
    fn format(self, b: &[u8], signed: bool, hex: bool) -> String {
        let mut x = [0u8; 8];
        x[..self.width()].copy_from_slice(&b[..self.width()]);
        let raw = u64::from_le_bytes(x);
        if hex {
            return format!("{raw:X}");
        }
        match self {
            Prim::F4 => f32::from_bits(raw as u32).to_string(),
            Prim::F8 => f64::from_bits(raw).to_string(),
            _ if signed => {
                let sh = 64 - 8 * self.width() as u32;
                (((raw << sh) as i64) >> sh).to_string()
            }
            _ => raw.to_string(),
        }
    }
    /// Integer value in the signed-or-unsigned range of this width, as little-endian bytes.
    pub fn int_bits(self, v: i128) -> Result<u64> {
        let bits = 8 * self.width() as u32;
        let (lo, hi) = (-(1i128 << (bits - 1)), (1i128 << bits) - 1);
        if v < lo || v > hi {
            return Err(Error::Parse(format!("{v} does not fit in {} bytes", self.width())));
        }
        Ok((v as u128 & (u128::MAX >> (128 - bits))) as u64)
    }
    fn encode(self, n: &NumVal) -> Result<Vec<u8>> {
        let w = self.width();
        Ok(match self {
            Prim::F4 => (n.f as f32).to_le_bytes().to_vec(),
            Prim::F8 => n.f.to_le_bytes().to_vec(),
            _ => self.int_bits(n.int()?)?.to_le_bytes()[..w].to_vec(),
        })
    }
}

/// A parsed number: `int` when it was typed as an integer, `dec` = typed decimals.
#[derive(Debug, Clone, Copy)]
pub(crate) struct NumVal {
    pub int: Option<i128>,
    pub f: f64,
    pub dec: u32,
}

impl NumVal {
    pub fn int(&self) -> Result<i128> {
        self.int.ok_or_else(|| Error::Parse(format!("{} is not an integer", self.f)))
    }
}

/// Parses decimal, `0x`/`$`-prefixed hex, or (with `hex`) bare hex; floats as decimal.
pub(crate) fn parse_num(s: &str, hex: bool) -> Result<NumVal> {
    let t = s.trim();
    let bad = || Error::Parse(format!("not a number: {s:?}"));
    let (neg, body) = match t.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, t.strip_prefix('+').unwrap_or(t)),
    };
    let hexbody = body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")).or_else(|| body.strip_prefix('$'));
    let as_int = |v: i128| {
        let v = if neg { -v } else { v };
        NumVal { int: Some(v), f: v as f64, dec: 0 }
    };
    if let Some(h) = hexbody.or(if hex { Some(body) } else { None }) {
        return i128::from_str_radix(h, 16).map(as_int).map_err(|_| bad());
    }
    if !body.is_empty() && body.bytes().all(|c| c.is_ascii_digit()) {
        return body.parse::<i128>().map(as_int).map_err(|_| bad());
    }
    let f: f64 = t.replace(',', ".").parse().map_err(|_| bad())?;
    let mant = body.split(['e', 'E']).next().unwrap_or("");
    let dec = mant.split_once(['.', ',']).map_or(0, |(_, d)| d.len() as u32);
    Ok(NumVal { int: None, f, dec })
}

/// Closed interval of floats that a typed value matches under a rounding mode.
pub(crate) fn float_interval(v: f64, dec: u32, mode: Rounding) -> (f64, f64) {
    let u = 10f64.powi(-(dec.min(30) as i32));
    match mode {
        Rounding::Rounded => (v - u / 2.0, (v + u / 2.0).next_down()),
        Rounding::Extreme => ((v - u).next_up(), (v + u).next_down()),
        Rounding::Truncated if v == 0.0 => ((-u).next_up(), u.next_down()),
        Rounding::Truncated if v > 0.0 => (v, (v + u).next_down()),
        Rounding::Truncated => ((v - u).next_up(), v),
    }
}

/// A decoded number as the comparisons see it.
pub(crate) trait Val: Copy {
    fn i(self) -> i128;
    fn f(self) -> f64;
    /// Raw value bits (two's complement / IEEE), masked to the value's width.
    fn bits(self) -> u64;
    /// Compares as a float (float types, scaled custom types).
    fn float(self) -> bool;
    /// Mask of the value's bits in `bits()`.
    fn mask(self) -> u64;
}

/// Fixed-width little-endian number read from memory bytes.
pub(crate) trait Num: Val + Send + Sync + 'static {
    const W: usize;
    const FLOAT: bool;
    fn rd(b: &[u8]) -> Self;
}

macro_rules! num_impl {
    ($($t:ty, $float:expr);*) => {$(
        impl Num for $t {
            const W: usize = std::mem::size_of::<$t>();
            const FLOAT: bool = $float;
            #[inline(always)]
            fn rd(b: &[u8]) -> Self {
                let mut a = [0u8; std::mem::size_of::<$t>()];
                a.copy_from_slice(&b[..Self::W]);
                <$t>::from_le_bytes(a)
            }
        }
        impl Val for $t {
            #[inline(always)]
            fn i(self) -> i128 { self as i128 }
            #[inline(always)]
            fn f(self) -> f64 { self as f64 }
            #[inline(always)]
            fn bits(self) -> u64 {
                let mut a = [0u8; 8];
                a[..Self::W].copy_from_slice(&self.to_le_bytes());
                u64::from_le_bytes(a)
            }
            #[inline(always)]
            fn float(self) -> bool { $float }
            #[inline(always)]
            fn mask(self) -> u64 { u64::MAX >> (64 - 8 * Self::W) }
        }
    )*};
}
num_impl!(i8, false; u8, false; i16, false; u16, false; i32, false; u32, false; i64, false; u64, false; f32, true; f64, true);

/// Runs `$body` with `$T` bound to the Rust type for a primitive and signedness.
macro_rules! with_num {
    ($prim:expr, $signed:expr, $T:ident => $body:expr) => {
        match ($prim, $signed) {
            ($crate::value::Prim::B1, true) => { type $T = i8; $body }
            ($crate::value::Prim::B1, false) => { type $T = u8; $body }
            ($crate::value::Prim::B2, true) => { type $T = i16; $body }
            ($crate::value::Prim::B2, false) => { type $T = u16; $body }
            ($crate::value::Prim::B4, true) => { type $T = i32; $body }
            ($crate::value::Prim::B4, false) => { type $T = u32; $body }
            ($crate::value::Prim::B8, true) => { type $T = i64; $body }
            ($crate::value::Prim::B8, false) => { type $T = u64; $body }
            ($crate::value::Prim::F4, _) => { type $T = f32; $body }
            ($crate::value::Prim::F8, _) => { type $T = f64; $body }
        }
    };
}
pub(crate) use with_num;

// ---------------------------------------------------------------- byte patterns

/// Byte pattern: byte `b` matches position `i` if `b & mask[i]` is `val[i]` or `alt[i]`
/// (`alt` carries the other letter case for case-insensitive strings).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Pattern {
    pub val: Vec<u8>,
    pub mask: Vec<u8>,
    pub alt: Vec<u8>,
    /// Multi-byte characters whose case variants the per-byte check over-approximates:
    /// (offset, the variants' exact bytes).
    pub verify: Vec<(usize, Vec<Vec<u8>>)>,
}

impl Pattern {
    pub fn exact(val: Vec<u8>) -> Self {
        Pattern { mask: vec![0xff; val.len()], alt: val.clone(), val, verify: Vec::new() }
    }
    pub fn len(&self) -> usize {
        self.val.len()
    }
    #[inline]
    pub fn matches(&self, b: &[u8]) -> bool {
        b.len() >= self.len()
            && b.iter().zip(&self.mask).zip(self.val.iter().zip(&self.alt)).all(|((&b, &m), (&v, &a))| {
                let x = b & m;
                x == v || x == a
            })
            && self.verify.iter().all(|(o, vs)| vs.iter().any(|v| b[*o..].starts_with(v)))
    }
    /// Calls `f` with every start offset in `hay` where the pattern matches.
    pub fn find_all(&self, hay: &[u8], mut f: impl FnMut(usize)) {
        let n = self.len();
        if n == 0 || hay.len() < n {
            return;
        }
        if self.mask.iter().all(|&m| m == 0xff) && self.val == self.alt {
            // Not memmem::find_iter: it skips overlapping matches ("AA AA" in "AA AA AA").
            let fd = memchr::memmem::Finder::new(&self.val);
            let mut pos = 0;
            while let Some(i) = fd.find(&hay[pos..]) {
                f(pos + i);
                pos += i + 1;
            }
            return;
        }
        let Some(k) = self.mask.iter().position(|&m| m == 0xff) else {
            (0..=hay.len() - n).filter(|&i| self.matches(&hay[i..])).for_each(f);
            return;
        };
        let last = hay.len() - n;
        let mut test = |at: usize| {
            if let Some(s) = at.checked_sub(k).filter(|&s| s <= last)
                && self.matches(&hay[s..])
            {
                f(s)
            }
        };
        let region = &hay[k..=last + k];
        if self.val[k] == self.alt[k] {
            memchr::memchr_iter(self.val[k], region).for_each(|i| test(i + k));
        } else {
            memchr::memchr2_iter(self.val[k], self.alt[k], region).for_each(|i| test(i + k));
        }
    }
}

/// `"8B 45 ?? 4?"`, `"8B45??"`; `?`/`*` wildcard a nibble or (alone) a byte.
pub(crate) fn parse_aob(s: &str) -> Result<Pattern> {
    let bad = |t: &str| Error::Parse(format!("bad byte {t:?} in array of bytes"));
    let mut toks: Vec<String> = s.split_whitespace().map(str::to_owned).collect();
    if toks.len() == 1 && toks[0].len() > 2 {
        let t: Vec<char> = toks[0].chars().collect();
        toks = t.chunks(2).map(|c| c.iter().collect()).collect();
    }
    let (mut val, mut mask) = (Vec::new(), Vec::new());
    for t in &toks {
        let cs: Vec<char> = t.chars().collect();
        let (hi, lo) = match cs.as_slice() {
            ['?' | '*'] => ('?', '?'),
            [a] => ('0', *a),
            [a, b] => (*a, *b),
            _ => return Err(bad(t)),
        };
        let nib = |c: char| -> Result<(u8, u8)> {
            match c {
                '?' | '*' => Ok((0, 0)),
                _ => c.to_digit(16).map(|d| (d as u8, 0xf)).ok_or_else(|| bad(t)),
            }
        };
        let ((hv, hm), (lv, lm)) = (nib(hi)?, nib(lo)?);
        val.push(hv << 4 | lv);
        mask.push(hm << 4 | lm);
    }
    if val.is_empty() {
        return Err(Error::Parse("empty array of bytes".into()));
    }
    Ok(Pattern { alt: val.clone(), val, mask, verify: Vec::new() })
}

/// Bit string, most significant bit first: `"1010 ??01"`; `?`/`*` wildcard a bit.
/// Unspecified high bits of the last byte must be zero (the value is exact).
pub(crate) fn parse_binary(s: &str) -> Result<Pattern> {
    let t = s.trim();
    let t = t.strip_prefix("0b").unwrap_or(t);
    let bits: Vec<char> = t.chars().filter(|c| !c.is_whitespace() && *c != '_').collect();
    if bits.is_empty() {
        return Err(Error::Parse("empty binary value".into()));
    }
    let n = bits.len().div_ceil(8);
    let (mut val, mut mask) = (vec![0u8; n], vec![0xffu8; n]);
    for (k, c) in bits.iter().rev().enumerate() {
        let (byte, bit) = (k / 8, 1u8 << (k % 8));
        match c {
            '0' => {}
            '1' => val[byte] |= bit,
            '?' | '*' => mask[byte] &= !bit,
            _ => return Err(Error::Parse(format!("bad binary digit {c:?}"))),
        }
    }
    Ok(Pattern { alt: val.clone(), val, mask, verify: Vec::new() })
}

pub(crate) fn encode_str(s: &str, utf16: bool) -> Vec<u8> {
    if utf16 {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    } else {
        s.as_bytes().to_vec()
    }
}

/// Text encoding of string scans: UTF-16LE (`utf16`), else the code page (`codepage`:
/// `None`/65001 = UTF-8, 1252 = Windows Western, 28591 = ISO-8859-1). Other code pages are
/// rejected; this is the seam where more single-byte tables would go.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Enc {
    Utf8,
    Utf16,
    Cp1252,
    Latin1,
}

/// Characters 0x80..=0x9F of code page 1252 (`\0` = undefined there).
const CP1252_HI: [char; 32] = [
    '€', '\0', '‚', 'ƒ', '„', '…', '†', '‡', 'ˆ', '‰', 'Š', '‹', 'Œ', '\0', 'Ž', '\0', '\0', '‘', '’', '“', '”', '•', '–',
    '—', '˜', '™', 'š', '›', 'œ', '\0', 'ž', 'Ÿ',
];

impl Enc {
    pub fn of(utf16: bool, codepage: Option<u32>) -> Result<Enc> {
        Ok(match (utf16, codepage) {
            (true, _) => Enc::Utf16,
            (false, None | Some(65001)) => Enc::Utf8,
            (false, Some(1252)) => Enc::Cp1252,
            (false, Some(28591)) => Enc::Latin1,
            _ => return Err(Error::Unsupported("code page (supported: 65001, 1252, 28591)")),
        })
    }
    fn char(self, c: char) -> Option<Vec<u8>> {
        match self {
            Enc::Utf8 => Some(c.encode_utf8(&mut [0; 4]).as_bytes().to_vec()),
            Enc::Utf16 => Some(c.encode_utf16(&mut [0; 2]).iter().flat_map(|u| u.to_le_bytes()).collect()),
            Enc::Latin1 => u8::try_from(c as u32).ok().map(|b| vec![b]),
            Enc::Cp1252 => match u8::try_from(c as u32) {
                Ok(b) if !(0x80..0xa0).contains(&b) => Some(vec![b]),
                _ => CP1252_HI.iter().position(|&x| x == c && x != '\0').map(|i| vec![0x80 + i as u8]),
            },
        }
    }
    pub fn encode(self, s: &str) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        for c in s.chars() {
            out.extend(self.char(c).ok_or_else(|| Error::Parse(format!("{c:?} is not in the code page")))?);
        }
        Ok(out)
    }
    /// Decodes up to the first NUL.
    pub fn decode(self, b: &[u8]) -> String {
        match self {
            Enc::Utf8 | Enc::Utf16 => format_value(VType::String, b, &Fmt { utf16: self == Enc::Utf16, ..Fmt::default() }),
            Enc::Latin1 | Enc::Cp1252 => b
                .iter()
                .take_while(|&&x| x != 0)
                .map(|&x| match x {
                    0x80..=0x9f if self == Enc::Cp1252 => CP1252_HI[x as usize - 0x80],
                    _ => x as char,
                })
                .filter(|&c| c != '\0')
                .collect(),
        }
    }
}

/// Simple case folds that lower/upper case round trips miss (CaseFolding.txt "C" entries
/// mapping a third character into a pair): (character, what it folds to).
const FOLD_EXTRA: [(char, char); 13] = [
    ('ς', 'σ'),
    ('ϐ', 'β'),
    ('ϑ', 'θ'),
    ('ϕ', 'φ'),
    ('ϖ', 'π'),
    ('ϰ', 'κ'),
    ('ϱ', 'ρ'),
    ('ϵ', 'ε'),
    ('ẛ', 'ṡ'),
    ('µ', 'μ'),
    ('\u{1fbe}', 'ι'),
    ('\u{345}', 'ι'),
    ('ſ', 's'),
];

/// `c` and the characters it is equal to under simple case folding.
fn case_variants(c: char) -> Vec<char> {
    fn one(mut it: impl Iterator<Item = char>) -> Option<char> {
        let x = it.next()?;
        it.next().is_none().then_some(x)
    }
    let mut v = vec![c];
    let mut i = 0;
    while i < v.len() {
        let x = v[i];
        let extra = FOLD_EXTRA.iter().filter_map(|&(a, b)| if a == x { Some(b) } else if b == x { Some(a) } else { None });
        for y in [one(x.to_lowercase()), one(x.to_uppercase())].into_iter().flatten().chain(extra) {
            if !v.contains(&y) {
                v.push(y);
            }
        }
        i += 1;
    }
    v
}

/// String pattern. Case-insensitive matching uses Unicode simple case folding per character
/// (lower/upper case closure plus [`FOLD_EXTRA`], e.g. ς/σ/Σ), limited to variants with
/// the same encoded length so the match keeps the pattern's byte length (this drops e.g. the
/// Kelvin sign and dotless i in UTF-8, whose case partners are shorter).
pub(crate) fn parse_string(s: &str, enc: Enc, case_sensitive: bool) -> Result<Pattern> {
    if s.is_empty() {
        return Err(Error::Parse("empty string".into()));
    }
    let mut val = enc.encode(s)?;
    if case_sensitive {
        return Ok(Pattern::exact(val));
    }
    let (mut alt, mut mask, mut verify) = (val.clone(), vec![0xffu8; val.len()], Vec::new());
    let mut at = 0;
    for c in s.chars() {
        let me = enc.char(c).unwrap_or_default();
        let vars: Vec<Vec<u8>> =
            case_variants(c).into_iter().filter_map(|x| enc.char(x)).filter(|b| b.len() == me.len()).collect();
        let mut differ = 0;
        for j in 0..me.len() {
            let mut seen: Vec<u8> = vars.iter().map(|v| v[j]).collect();
            seen.sort_unstable();
            seen.dedup();
            match seen.as_slice() {
                [_] => {}
                [a, b] => {
                    alt[at + j] = if *a == me[j] { *b } else { *a };
                    differ += 1;
                }
                _ => {
                    (mask[at + j], val[at + j], alt[at + j]) = (0, 0, 0);
                    differ += 2;
                }
            }
        }
        // Per-byte alternatives describe the variants exactly only if they differ in one byte.
        if differ > 1 {
            verify.push((at, vars));
        }
        at += me.len();
    }
    Ok(Pattern { val, mask, alt, verify })
}

// ---------------------------------------------------------------- binary

/// Bits of a binary scan value, least significant first; `None` = wildcard. `decimal` reads
/// the value as a decimal (or `0x` hex) number instead of a bit string (Cheat Engine's
/// "binary as decimal"); `bit_len` zero-extends to that many bits and rejects longer values.
pub(crate) fn binary_bits(s: &str, decimal: bool, bit_len: Option<u32>) -> Result<Vec<Option<bool>>> {
    let mut bits: Vec<Option<bool>> = if decimal {
        let v = parse_num(s, false)?.int()?;
        let v = u128::try_from(v).map_err(|_| Error::Parse("binary value must not be negative".into()))?;
        let n = (128 - v.leading_zeros()).max(1) as usize;
        (0..n).map(|k| Some(v >> k & 1 == 1)).collect()
    } else {
        let t = s.trim();
        let t = t.strip_prefix("0b").unwrap_or(t);
        t.chars()
            .filter(|c| !c.is_whitespace() && *c != '_')
            .rev()
            .map(|c| match c {
                '0' => Ok(Some(false)),
                '1' => Ok(Some(true)),
                '?' | '*' => Ok(None),
                _ => Err(Error::Parse(format!("bad binary digit {c:?}"))),
            })
            .collect::<Result<_>>()?
    };
    if bits.is_empty() {
        return Err(Error::Parse("empty binary value".into()));
    }
    if let Some(n) = bit_len.filter(|&n| n > 0) {
        if n > 1 << 16 {
            return Err(Error::Parse("bit length too large".into()));
        }
        let n = n as usize;
        if bits[n.min(bits.len())..].contains(&Some(true)) {
            return Err(Error::Parse(format!("value does not fit in {n} bits")));
        }
        bits.resize(n, Some(false));
    }
    Ok(bits)
}

/// The bits placed at bit offset `shift` of the first byte, as a byte pattern; bits outside
/// the field are wildcards. `field` = the pattern's mask with wildcards counted as set.
pub(crate) fn shifted(bits: &[Option<bool>], shift: usize) -> (Pattern, Vec<u8>) {
    let n = (bits.len() + shift).div_ceil(8);
    let (mut val, mut mask, mut field) = (vec![0u8; n], vec![0u8; n], vec![0u8; n]);
    for (k, b) in bits.iter().enumerate() {
        let (byte, bit) = ((k + shift) / 8, 1u8 << ((k + shift) % 8));
        field[byte] |= bit;
        if let Some(one) = b {
            mask[byte] |= bit;
            if *one {
                val[byte] |= bit;
            }
        }
    }
    (Pattern { alt: val.clone(), val, mask, verify: Vec::new() }, field)
}

/// `n` bits of `b` starting at bit `shift`, most significant first.
pub(crate) fn bit_string(b: &[u8], shift: usize, n: usize) -> String {
    (0..n)
        .rev()
        .map(|k| match b.get((k + shift) / 8) {
            Some(x) if x >> ((k + shift) % 8) & 1 == 1 => '1',
            Some(_) => '0',
            None => '?',
        })
        .collect()
}

// ---------------------------------------------------------------- custom types

/// A value type defined as data (no code): `size` bytes in memory order (`big_endian`),
/// optionally a bit field (`bit_start`, `bit_len`; 0 = whole), read as an integer
/// (`signed`) or an IEEE float (`float`, size 4 or 8), then `value = raw * scale + offset`.
/// Covers Cheat Engine's common custom types: big-endian 2/4/8-byte and float/double,
/// 3-byte integers, fixed point (`scale: 0.01`), offset encodings and bit fields. With
/// `scale` 1 and `offset` 0 an integer type compares exactly like a built-in integer;
/// otherwise values compare as floats (so the float rounding modes apply).
///
/// JSON (`custom` key of a table entry, `ScanOptions::custom`, `ValueRefEx`/`FrozenEntryEx`):
/// `{"size":4,"big_endian":true,"float":false,"signed":true,"scale":0.01,"offset":0,
///   "bit_start":0,"bit_len":0,"binary":false}`; every key but `size` is optional.
///
/// Proposed `.CT` mapping (not implemented here): an entry's
/// `<VariableType>Custom</VariableType><CustomType>NAME</CustomType>` resolves `NAME`
/// through [`CustomType::preset`] (the big-endian types Cheat Engine ships); a HeapHook
/// export of any other custom type writes the same element plus
/// `<HeapHookCustomType size="4" big_endian="1" scale="0.01" .../>` with the JSON keys as
/// attributes, so Cheat Engine still sees the name. A Binary entry's
/// `<BitStart>`/`<BitLength>`/`<ShowAsBinary>` map to `bit_start`/`bit_len`/`binary` on a
/// `size` = ceil((start + len) / 8) custom type.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct CustomType {
    pub size: u8,
    #[serde(default)]
    pub big_endian: bool,
    #[serde(default)]
    pub float: bool,
    #[serde(default)]
    pub signed: bool,
    #[serde(default = "one")]
    pub scale: f64,
    #[serde(default)]
    pub offset: f64,
    #[serde(default)]
    pub bit_start: u8,
    #[serde(default)]
    pub bit_len: u8,
    /// Shown and entered as a bit string.
    #[serde(default)]
    pub binary: bool,
}

fn one() -> f64 {
    1.0
}

/// A decoded custom value.
#[derive(Debug, Clone, Copy)]
pub(crate) struct CVal {
    i: i128,
    f: f64,
    bits: u64,
    float: bool,
    mask: u64,
}

impl Val for CVal {
    fn i(self) -> i128 {
        self.i
    }
    fn f(self) -> f64 {
        self.f
    }
    fn bits(self) -> u64 {
        self.bits
    }
    fn float(self) -> bool {
        self.float
    }
    fn mask(self) -> u64 {
        self.mask
    }
}

impl CustomType {
    /// A plain little-endian integer of `size` bytes.
    pub fn int(size: u8, signed: bool) -> Self {
        CustomType { size, big_endian: false, float: false, signed, scale: 1.0, offset: 0.0, bit_start: 0, bit_len: 0, binary: false }
    }

    /// Cheat Engine's stock custom type names (and a few obvious extras).
    pub fn preset(name: &str) -> Option<Self> {
        let be = |size, float| CustomType { big_endian: true, float, ..CustomType::int(size, false) };
        Some(match name.trim().to_ascii_lowercase().as_str() {
            "2 byte big endian" => be(2, false),
            "4 byte big endian" => be(4, false),
            "8 byte big endian" => be(8, false),
            "float big endian" => be(4, true),
            "double big endian" => be(8, true),
            "3 byte" | "3 bytes" => CustomType::int(3, false),
            "3 byte big endian" => be(3, false),
            _ => return None,
        })
    }

    pub fn validate(&self) -> Result<()> {
        let bad = |m: &str| Err(Error::Parse(format!("custom type: {m}")));
        let nbits = 8 * self.size as u32;
        if !(1..=8).contains(&self.size) {
            return bad("size must be 1..8 bytes");
        }
        if self.float && (!matches!(self.size, 4 | 8) || self.bit_len > 0) {
            return bad("float types are 4 or 8 bytes without bit fields");
        }
        if self.bit_start as u32 + self.bit_len as u32 > nbits || (self.bit_len == 0 && self.bit_start > 0) {
            return bad("bit field outside the value");
        }
        if !self.scale.is_finite() || self.scale == 0.0 || !self.offset.is_finite() {
            return bad("scale must be finite and non-zero, offset finite");
        }
        Ok(())
    }

    pub fn size(&self) -> usize {
        self.size as usize
    }
    fn nbits(&self) -> u32 {
        if self.bit_len > 0 { self.bit_len as u32 } else { 8 * self.size as u32 }
    }
    fn vmask(&self) -> u64 {
        u64::MAX >> (64 - self.nbits())
    }
    fn scaled(&self) -> bool {
        self.scale != 1.0 || self.offset != 0.0
    }
    fn mem_bytes(&self, raw: u64) -> Vec<u8> {
        let mut b = raw.to_le_bytes()[..self.size()].to_vec();
        if self.big_endian {
            b.reverse();
        }
        b
    }
    fn raw_of(&self, b: &[u8]) -> u64 {
        let mut a = [0u8; 8];
        a[..self.size()].copy_from_slice(&b[..self.size()]);
        if self.big_endian {
            a[..self.size()].reverse();
        }
        u64::from_le_bytes(a)
    }

    /// `b` must hold at least `size` bytes.
    pub(crate) fn decode(&self, b: &[u8]) -> CVal {
        let mask = self.vmask();
        let raw = (self.raw_of(b) >> if self.bit_len > 0 { self.bit_start } else { 0 }) & mask;
        let (i, mut f) = if self.float {
            let f = if self.size == 4 { f32::from_bits(raw as u32) as f64 } else { f64::from_bits(raw) };
            (f as i128, f)
        } else {
            let sh = 128 - self.nbits();
            let i = if self.signed { ((raw as i128) << sh) >> sh } else { raw as i128 };
            (i, i as f64)
        };
        if self.scaled() {
            // Divide by an integral divisor so 1234 * 0.01 prints as 12.34.
            let inv = 1.0 / self.scale;
            f = if (inv - inv.round()).abs() < 1e-9 * inv.abs() { f / inv.round() } else { f * self.scale };
            f += self.offset;
        }
        CVal { i, f, bits: raw, float: self.float || self.scaled(), mask }
    }

    pub fn format(&self, b: &[u8], fmt: &Fmt) -> String {
        if b.len() < self.size() || self.validate().is_err() {
            return "??".into();
        }
        let v = self.decode(b);
        if self.binary {
            return bit_string(&v.bits.to_le_bytes(), 0, self.nbits() as usize);
        }
        match (fmt.hex, v.float) {
            (true, _) => format!("{:X}", v.bits),
            (false, true) if self.float && !self.scaled() && self.size == 4 => (v.f as f32).to_string(),
            (false, true) => v.f.to_string(),
            (false, false) => v.i.to_string(),
        }
    }

    /// Memory bytes of `s` (only the field bits set for bit fields; see [`Self::write_mask`]).
    pub fn encode(&self, s: &str, fmt: &Fmt) -> Result<Vec<u8>> {
        self.validate()?;
        let nb = self.nbits();
        let raw = if self.binary {
            let bits = binary_bits(s, false, None)?;
            if bits.len() > nb as usize || bits.iter().any(Option::is_none) {
                return Err(Error::Parse(format!("need at most {nb} bits without wildcards")));
            }
            bits.iter().enumerate().fold(0u64, |r, (k, b)| r | (u64::from(*b == Some(true)) << k))
        } else {
            let n = parse_num(s, fmt.hex && !self.float && !self.scaled())?;
            let x = if self.scaled() { (n.f - self.offset) / self.scale } else { n.f };
            if self.float {
                if self.size == 4 { (x as f32).to_bits() as u64 } else { x.to_bits() }
            } else {
                let v = if self.scaled() { x.round() as i128 } else { n.int()? };
                let (lo, hi) = (-(1i128 << (nb - 1)), (1i128 << nb) - 1);
                if v < lo || v > hi || (!self.signed && v < 0 && self.scaled()) {
                    return Err(Error::Parse(format!("{s} does not fit in {nb} bits")));
                }
                v as u64 & self.vmask()
            }
        };
        Ok(self.mem_bytes(if self.bit_len > 0 { raw << self.bit_start } else { raw }))
    }

    /// Bytes of the value that a write may change (`None` = all of them).
    pub fn write_mask(&self) -> Option<Vec<u8>> {
        (self.bit_len > 0).then(|| self.mem_bytes(self.vmask() << self.bit_start))
    }

    /// The value of memory bytes in converted units (`raw * scale + offset`); `None` if `b`
    /// is shorter than `size` or the type is invalid. Integer types without scale/offset
    /// give [`CustomNumber::Int`], everything else [`CustomNumber::Float`].
    pub fn number(&self, b: &[u8]) -> Option<CustomNumber> {
        if b.len() < self.size() || self.validate().is_err() {
            return None;
        }
        let v = self.decode(b);
        Some(if v.float { CustomNumber::Float(v.f) } else { CustomNumber::Int(v.i) })
    }

    /// Memory bytes of a number in converted units (what [`Self::encode`] makes of its text).
    pub fn encode_number(&self, n: CustomNumber) -> Result<Vec<u8>> {
        let exact_int = self.binary || (!self.float && !self.scaled());
        let n = match n {
            CustomNumber::Float(f) if exact_int => {
                if !f.is_finite() || f.fract() != 0.0 || f.abs() > 2f64.powi(64) {
                    return Err(Error::Parse(format!("{f} is not an integer")));
                }
                CustomNumber::Int(f as i128)
            }
            n => n,
        };
        match n {
            CustomNumber::Int(i) if self.binary => {
                let u = u64::try_from(i).map_err(|_| Error::Parse(format!("{i} does not fit the bit field")))?;
                self.encode(&format!("{u:b}"), &Fmt::default())
            }
            CustomNumber::Int(i) => self.encode(&i.to_string(), &Fmt::default()),
            // Debug keeps exponents ("1e300"), which the parser reads back exactly.
            CustomNumber::Float(f) => self.encode(&format!("{f:?}"), &Fmt::default()),
        }
    }
}

/// A custom-typed value in converted units (see [`CustomType::number`]).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CustomNumber {
    Int(i128),
    Float(f64),
}

impl CustomNumber {
    pub fn as_f64(self) -> f64 {
        match self {
            CustomNumber::Int(i) => i as f64,
            CustomNumber::Float(f) => f,
        }
    }
}

impl std::fmt::Display for CustomNumber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CustomNumber::Int(i) => write!(f, "{i}"),
            CustomNumber::Float(x) => write!(f, "{x}"),
        }
    }
}

/// Reads a custom-typed value as a number in converted units (for Lua and hotkeys).
pub fn read_custom(mem: &dyn Memory, addr: Addr, ct: &CustomType) -> Result<CustomNumber> {
    ct.validate()?;
    let mut buf = vec![0u8; ct.size()];
    mem.read_exact(addr, &mut buf)?;
    ct.number(&buf).ok_or(Error::NoAccess { addr })
}

/// Writes a number in converted units; bit fields keep the other bits.
pub fn write_custom_number(mem: &dyn Memory, addr: Addr, ct: &CustomType, n: CustomNumber) -> Result<()> {
    write_masked(mem, addr, ct, &ct.encode_number(n)?)
}

/// Hotkey "increase / decrease value by": adds `delta` (converted units, negative to
/// decrease) to the value at `addr` and returns what was written. Integers stay exact when
/// `delta` is whole; a result outside the type's range is an error, nothing is written.
pub fn add_custom(mem: &dyn Memory, addr: Addr, ct: &CustomType, delta: f64) -> Result<CustomNumber> {
    let new = match read_custom(mem, addr, ct)? {
        CustomNumber::Int(i) if delta.fract() == 0.0 && delta.abs() < 2f64.powi(100) => {
            CustomNumber::Int(i.checked_add(delta as i128).ok_or_else(|| Error::Parse("value out of range".into()))?)
        }
        n => CustomNumber::Float(n.as_f64() + delta),
    };
    let bytes = ct.encode_number(new)?;
    write_masked(mem, addr, ct, &bytes)?;
    ct.number(&bytes).ok_or(Error::NoAccess { addr })
}

fn write_masked(mem: &dyn Memory, addr: Addr, ct: &CustomType, new: &[u8]) -> Result<()> {
    match ct.write_mask() {
        None => mem.write(addr, new),
        Some(m) => {
            let mut old = vec![0u8; new.len()];
            mem.read_exact(addr, &mut old)?;
            mem.write(addr, &merge(&old, new, &m))
        }
    }
}

/// Merges `new` into `old` under `mask` (bit-field writes).
pub(crate) fn merge(old: &[u8], new: &[u8], mask: &[u8]) -> Vec<u8> {
    old.iter().zip(new).zip(mask).map(|((&o, &n), &m)| (o & !m) | (n & m)).collect()
}

/// A `read_values` item that may use a custom type (same JSON as [`ValueRef`] plus `custom`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValueRefEx {
    #[serde(flatten)]
    pub r: ValueRef,
    #[serde(default)]
    pub custom: Option<CustomType>,
}

/// [`read_values`] with custom types (`custom` overrides `vtype`).
pub fn read_values_ex(mem: &dyn Memory, refs: &[ValueRefEx]) -> Vec<Option<String>> {
    refs.iter()
        .map(|x| match &x.custom {
            None => read_values(mem, std::slice::from_ref(&x.r)).pop().flatten(),
            Some(c) => {
                c.validate().ok()?;
                let mut buf = vec![0u8; c.size()];
                mem.read_exact(x.r.addr, &mut buf).ok()?;
                Some(c.format(&buf, &x.r.fmt))
            }
        })
        .collect()
}

/// Writes a custom-typed value; bit fields keep the other bits (read-modify-write).
pub fn write_custom(mem: &dyn Memory, addr: Addr, ct: &CustomType, value: &str, fmt: &Fmt) -> Result<()> {
    write_masked(mem, addr, ct, &ct.encode(value, fmt)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers() {
        assert_eq!(parse_num("100", false).unwrap().int, Some(100));
        assert_eq!(parse_num("100", true).unwrap().int, Some(0x100));
        assert_eq!(parse_num("-0x10", false).unwrap().int, Some(-16));
        assert_eq!(parse_num("$ff", false).unwrap().int, Some(255));
        let v = parse_num("1.25", false).unwrap();
        assert_eq!((v.int, v.f, v.dec), (None, 1.25, 2));
        assert_eq!(parse_num("1e3", false).unwrap().dec, 0);
        assert!(parse_num("abc", false).is_err());
        assert!(parse_num("", false).is_err());
    }

    #[test]
    fn rounding() {
        let r = float_interval(1.5, 1, Rounding::Rounded);
        assert!(r.0 <= 1.45 && 1.549 <= r.1 && r.1 < 1.55);
        let e = float_interval(1.5, 1, Rounding::Extreme);
        assert!(e.0 > 1.4 && e.0 < 1.41 && e.1 < 1.6 && e.1 > 1.59);
        let t = float_interval(1.5, 1, Rounding::Truncated);
        assert!(t.0 == 1.5 && t.1 < 1.6 && t.1 > 1.59);
        let t = float_interval(-1.5, 1, Rounding::Truncated);
        assert!(t.1 == -1.5 && t.0 > -1.6);
        let z = float_interval(100.0, 0, Rounding::Rounded);
        assert_eq!(z.0, 99.5);
    }

    #[test]
    fn format_parse_roundtrip() {
        let f = Fmt::default();
        let s = Fmt { signed: true, ..f };
        assert_eq!(parse_value(VType::Byte, "-1", &f).unwrap(), [0xff]);
        assert_eq!(parse_value(VType::Byte, "255", &f).unwrap(), [0xff]);
        assert!(parse_value(VType::Byte, "256", &f).is_err());
        assert!(parse_value(VType::Bytes4, "1.5", &f).is_err());
        assert_eq!(format_value(VType::Byte, &[0xff], &f), "255");
        assert_eq!(format_value(VType::Byte, &[0xff], &s), "-1");
        assert_eq!(format_value(VType::Bytes2, &[0x34, 0x12], &Fmt { hex: true, ..f }), "1234");
        assert_eq!(format_value(VType::Bytes8, &(-5i64).to_le_bytes(), &s), "-5");
        assert_eq!(format_value(VType::Float, &1.5f32.to_le_bytes(), &f), "1.5");
        assert_eq!(format_value(VType::Double, &parse_value(VType::Double, "-2.25", &f).unwrap(), &f), "-2.25");
        assert_eq!(format_value(VType::String, b"hi\0xx", &f), "hi");
        let u = Fmt { utf16: true, ..f };
        assert_eq!(parse_value(VType::String, "hi", &u).unwrap(), [b'h', 0, b'i', 0]);
        assert_eq!(format_value(VType::String, &[b'h', 0, b'i', 0], &u), "hi");
        assert_eq!(parse_value(VType::Aob, "de ad", &f).unwrap(), [0xde, 0xad]);
        assert!(parse_value(VType::Aob, "de ??", &f).is_err());
        assert_eq!(format_value(VType::Aob, &[0xde, 0xad], &f), "DE AD");
        assert_eq!(parse_value(VType::Binary, "1010", &f).unwrap(), [10]);
        assert_eq!(format_value(VType::Binary, &[10], &f), "00001010");
        assert!(parse_value(VType::All, "1", &f).is_err());
    }

    #[test]
    fn custom_and_binary_helpers() {
        let bad = CustomType { size: 0, ..CustomType::int(1, false) };
        assert_eq!(bad.format(&[1, 2], &Fmt::default()), "??");
        assert!(bad.encode("1", &Fmt::default()).is_err());
        let s3 = CustomType::int(3, true);
        assert_eq!(s3.format(&[0xff, 0xff, 0xff], &Fmt::default()), "-1");
        assert_eq!(s3.encode("-2", &Fmt::default()).unwrap(), [0xfe, 0xff, 0xff]);
        let be = CustomType::preset("2 Byte Big Endian").unwrap();
        assert_eq!((be.encode("258", &Fmt::default()).unwrap(), be.format(&[1, 2], &Fmt::default())), (vec![1, 2], "258".into()));
        let off = CustomType { offset: -40.0, ..CustomType::int(1, false) };
        assert_eq!((off.format(&[50], &Fmt::default()), off.encode("10", &Fmt::default()).unwrap()), ("10".into(), vec![50]));
        let d = CustomType::preset("Double Big Endian").unwrap();
        assert_eq!(d.format(&2.5f64.to_be_bytes(), &Fmt::default()), "2.5");
        assert_eq!(binary_bits("5", true, Some(4)).unwrap(), [Some(true), Some(false), Some(true), Some(false)]);
        assert!(binary_bits("1", false, Some(1 << 20)).is_err());
        assert_eq!(bit_string(&[0b1011_0000, 1], 4, 5), "11011");
        let (p, field) = shifted(&[Some(true), None], 7);
        assert_eq!((p.val, p.mask, field), (vec![0x80, 0], vec![0x80, 0], vec![0x80, 1]));
        assert_eq!(Enc::Cp1252.encode("€é").unwrap(), [0x80, 0xe9]);
        assert_eq!(Enc::Cp1252.decode(&[0x80, 0xe9, 0, 1]), "€é");
        let k = parse_string("K", Enc::Utf8, false).unwrap();
        assert!(k.matches(b"k") && k.matches(b"K"));
        let sigma = parse_string("σ", Enc::Utf8, false).unwrap();
        assert!(!sigma.verify.is_empty() && sigma.matches("ς".as_bytes()) && sigma.matches("Σ".as_bytes()) && !sigma.matches("ρ".as_bytes()));
    }

    #[test]
    fn patterns() {
        let p = parse_aob("8B ?5 ?? 4*").unwrap();
        assert_eq!(p.mask, [0xff, 0x0f, 0, 0xf0]);
        assert!(p.matches(&[0x8b, 0x75, 0x00, 0x4c]));
        assert!(!p.matches(&[0x8b, 0x76, 0x00, 0x4c]));
        assert_eq!(parse_aob("8B45??").unwrap().mask, [0xff, 0xff, 0]);
        assert!(parse_aob("8G").is_err());
        let b = parse_binary("1?01").unwrap();
        assert!(b.matches(&[0b1101]) && b.matches(&[0b1001]) && !b.matches(&[0b1_1001]));
        assert_eq!(parse_binary("1 0000 0000").unwrap().len(), 2);
        assert!(parse_binary("102").is_err());
        let s = parse_string("Ab", Enc::Utf8, false).unwrap();
        let mut hits = vec![];
        s.find_all(b"xxaBxAbab", |i| hits.push(i));
        assert_eq!(hits, [2, 5, 7]);
        let w = parse_string("Ab", Enc::Utf16, false).unwrap();
        assert!(w.matches(&[b'a', 0, b'B', 0]) && !w.matches(&[b'a', 0x20, b'B', 0]));
        let mut hits = vec![];
        parse_aob("AA AA").unwrap().find_all(&[0xaa; 3], |i| hits.push(i));
        assert_eq!(hits, [0, 1]);
        let mut hits = vec![];
        parse_aob("?? 01").unwrap().find_all(&[1, 1, 1], |i| hits.push(i));
        assert_eq!(hits, [0, 1]);
    }
}
