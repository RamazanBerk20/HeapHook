//! Address expressions: `game.exe+1A2B`, `[[base+10]+8]`, user symbols, hex by default.
use std::collections::HashMap;

use hh_core::{Addr, Error, Memory, Module, Process, Result};
use serde::{Deserialize, Serialize};

/// User-registered symbols (case-insensitive). Exported / debug symbols of the target's modules
/// are looked up separately (see `crate::symbols`) after these and module names.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SymbolTable {
    syms: HashMap<String, Addr>,
}

impl SymbolTable {
    pub fn register(&mut self, name: &str, addr: Addr) {
        self.syms.insert(name.to_ascii_lowercase(), addr);
    }
    pub fn unregister(&mut self, name: &str) -> Option<Addr> {
        self.syms.remove(&name.to_ascii_lowercase())
    }
    pub fn get(&self, name: &str) -> Option<Addr> {
        self.syms.get(&name.to_ascii_lowercase()).copied()
    }
    pub fn iter(&self) -> impl Iterator<Item = (&str, Addr)> {
        self.syms.iter().map(|(k, v)| (k.as_str(), *v))
    }
}

/// A host-provided symbol lookup (Cheat Engine's `registerSymbolLookupCallback`), asked after
/// every built-in lookup failed.
pub type SymbolLookup = std::sync::Arc<dyn Fn(&str) -> Option<Addr>>;

/// By name, case-insensitive; `$process` is the main module (the first one listed).
pub(crate) fn find_module<'m>(mods: &'m [Module], name: &str) -> Option<&'m Module> {
    if name.eq_ignore_ascii_case("$process") {
        return mods.first();
    }
    mods.iter().find(|m| m.name.eq_ignore_ascii_case(name))
}

/// Whether `name` is the name (or the file name) of one of `mods`: such a name may not be
/// registered as a symbol or label.
pub fn names_module(mods: &[Module], name: &str) -> bool {
    let n = name.trim();
    !n.is_empty()
        && (n.eq_ignore_ascii_case("$process")
            || mods.iter().any(|m| {
                m.name.eq_ignore_ascii_case(n) || m.path.rsplit(['/', '\\']).next().is_some_and(|f| f.eq_ignore_ascii_case(n))
            }))
}

/// `game.exe+1A2B` for an address inside a module, else `None`.
pub fn module_offset(mods: &[Module], addr: Addr) -> Option<String> {
    mods.iter()
        .find(|m| addr >= m.base && addr - m.base < m.size)
        .map(|m| format!("{}+{:X}", quote_name(&m.name), addr - m.base))
}

/// The name as an expression can read it back: quoted if it has characters the tokenizer
/// does not accept in a bare name.
pub(crate) fn quote_name(name: &str) -> String {
    if !name.is_empty()
        && name
            .chars()
            .all(|c| is_ident_char(c) || c == '-' || c == '+')
    {
        name.to_string()
    } else {
        format!("\"{name}\"")
    }
}

/// Parses a number token: hex by default, `#123` decimal, `0x`/`$` hex prefixes.
pub fn parse_num(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(d) = s.strip_prefix('#') {
        return d
            .parse::<u64>()
            .ok()
            .or_else(|| d.parse::<i64>().ok().map(|v| v as u64));
    }
    let h = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .or_else(|| s.strip_prefix('$'))
        .unwrap_or(s);
    if h.is_empty() {
        return None;
    }
    u64::from_str_radix(h, 16).ok()
}

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Ident(String, bool), // (text, quoted)
    Op(char),
}

pub(crate) fn is_ident_char(c: char) -> bool {
    c.is_alphanumeric() || "_.@$!#?".contains(c)
}

/// Byte length of the identifier at the start of `s`. Module and symbol names may contain `-`
/// and `+` (`hh-target`, `libstdc++.so.6`), so the identifier is extended across those as
/// long as the longer name resolves; otherwise they stay operators (`base-10`).
pub(crate) fn ident_len(s: &str, lookup: &dyn Fn(&str) -> Option<u64>) -> usize {
    let run = |from: usize| {
        s[from..]
            .find(|c: char| !is_ident_char(c))
            .map_or(s.len(), |n| from + n)
    };
    let mut best = run(0);
    let mut end = best;
    // shortcut: at most 8 `-`/`+` joins per name, more never occurs in real module names.
    for _ in 0..8 {
        let ops = s[end..]
            .find(|c: char| c != '-' && c != '+')
            .map_or(s.len(), |n| end + n);
        if ops == end || !s[ops..].starts_with(is_ident_char) {
            break;
        }
        end = run(ops);
        if lookup(&s[..end]).is_some() {
            best = end;
        }
    }
    best
}

fn tokenize(s: &str, lookup: &dyn Fn(&str) -> Option<u64>) -> Result<Vec<Tok>> {
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(c) = s[i..].chars().next() {
        if c.is_whitespace() {
            i += c.len_utf8();
        } else if "+-*/()[]".contains(c) {
            out.push(Tok::Op(c));
            i += 1;
        } else if c == '"' || c == '\'' {
            let end = s[i + 1..]
                .find(c)
                .ok_or_else(|| Error::Parse(format!("unterminated quote in {s:?}")))?;
            out.push(Tok::Ident(s[i + 1..i + 1 + end].to_string(), true));
            i += end + 2;
        } else if is_ident_char(c) {
            let n = ident_len(&s[i..], lookup);
            out.push(Tok::Ident(s[i..i + n].to_string(), false));
            i += n;
        } else {
            return Err(Error::Parse(format!("unexpected '{c}' in {s:?}")));
        }
    }
    Ok(out)
}

/// What an expression can see: a symbol lookup and (optionally) memory for `[ptr]`.
pub struct Ctx<'a> {
    pub lookup: &'a dyn Fn(&str) -> Option<u64>,
    pub mem: Option<&'a dyn Memory>,
}

/// Deepest nesting of parentheses, brackets and unary signs an expression may use; real
/// pointer paths stay far below it, and it keeps the recursive parser off the stack limit.
pub const MAX_EXPR_DEPTH: usize = 256;

struct Parser<'a, 'c> {
    toks: Vec<Tok>,
    pos: usize,
    ctx: &'c Ctx<'a>,
    depth: usize,
}

impl Parser<'_, '_> {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }
    fn eat(&mut self, c: char) -> bool {
        if self.peek() == Some(&Tok::Op(c)) {
            self.pos += 1;
            true
        } else {
            false
        }
    }
    fn expr(&mut self) -> Result<u64> {
        let mut v = self.term()?;
        loop {
            if self.eat('+') {
                v = v.wrapping_add(self.term()?);
            } else if self.eat('-') {
                v = v.wrapping_sub(self.term()?);
            } else {
                return Ok(v);
            }
        }
    }
    fn term(&mut self) -> Result<u64> {
        let mut v = self.factor()?;
        loop {
            if self.eat('*') {
                v = v.wrapping_mul(self.factor()?);
            } else if self.eat('/') {
                let d = self.factor()?;
                v = v
                    .checked_div(d)
                    .ok_or_else(|| Error::Parse("division by zero".into()))?;
            } else {
                return Ok(v);
            }
        }
    }
    /// Every recursive path (unary signs, `(...)`, `[...]`) goes through here.
    fn factor(&mut self) -> Result<u64> {
        if self.depth >= MAX_EXPR_DEPTH {
            return Err(Error::Parse(format!(
                "expression nested deeper than {MAX_EXPR_DEPTH} levels"
            )));
        }
        self.depth += 1;
        let v = self.factor_inner();
        self.depth -= 1;
        v
    }
    fn factor_inner(&mut self) -> Result<u64> {
        if self.eat('-') {
            return Ok(self.factor()?.wrapping_neg());
        }
        if self.eat('+') {
            return self.factor();
        }
        if self.eat('(') {
            let v = self.expr()?;
            return if self.eat(')') {
                Ok(v)
            } else {
                Err(Error::Parse("missing ')'".into()))
            };
        }
        if self.eat('[') {
            let v = self.expr()?;
            if !self.eat(']') {
                return Err(Error::Parse("missing ']'".into()));
            }
            let mem = self
                .ctx
                .mem
                .ok_or_else(|| Error::Parse("pointer dereference not available here".into()))?;
            return mem.read_ptr(v);
        }
        match self.toks.get(self.pos).cloned() {
            Some(Tok::Ident(t, quoted)) => {
                self.pos += 1;
                if let Some(v) = (self.ctx.lookup)(&t) {
                    return Ok(v);
                }
                if !quoted && let Some(v) = parse_num(&t) {
                    return Ok(v);
                }
                Err(Error::Parse(format!("unknown symbol '{t}'")))
            }
            Some(Tok::Op(c)) => Err(Error::Parse(format!("unexpected '{c}'"))),
            None => Err(Error::Parse("unexpected end of expression".into())),
        }
    }
}

/// Evaluates an address expression with wrapping 64-bit arithmetic (`+ - * /`, parens,
/// `[x]` reads a pointer).
pub fn eval(expr: &str, ctx: &Ctx) -> Result<u64> {
    let mut p = Parser {
        toks: tokenize(expr, ctx.lookup)?,
        pos: 0,
        ctx,
        depth: 0,
    };
    if p.toks.is_empty() {
        return Err(Error::Parse("empty expression".into()));
    }
    let v = p.expr()?;
    if p.pos != p.toks.len() {
        return Err(Error::Parse(format!("trailing input in {expr:?}")));
    }
    Ok(v)
}

/// Standard lookup: user symbols, then module names, then the modules' exported symbols.
pub(crate) fn std_lookup(
    p: &dyn Process,
    syms: &SymbolTable,
    mods: &[Module],
    name: &str,
) -> Option<u64> {
    // Module names win: a registered symbol or label can never redirect `module+offset`.
    find_module(mods, name)
        .map(|m| m.base)
        .or_else(|| syms.get(name))
        .or_else(|| crate::symbols::lookup(p, mods, name))
}

/// Backs the `resolve_address` IPC command.
pub fn resolve_address(p: &dyn Process, syms: &SymbolTable, expr: &str) -> Result<Addr> {
    resolve_address_with(p, syms, expr, &|_| None)
}

/// [`resolve_address`] that asks `extra` for names nothing else knows.
pub fn resolve_address_with(
    p: &dyn Process,
    syms: &SymbolTable,
    expr: &str,
    extra: &dyn Fn(&str) -> Option<Addr>,
) -> Result<Addr> {
    let mods = p.modules().unwrap_or_default();
    let lookup = |n: &str| std_lookup(p, syms, &mods, n).or_else(|| extra(n));
    eval(
        expr,
        &Ctx {
            lookup: &lookup,
            mem: Some(p),
        },
    )
}
