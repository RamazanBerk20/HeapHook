//! Auto Assembler: runs Cheat Engine style scripts (`[ENABLE]`/`[DISABLE]`, alloc, labels,
//! aobscan, db, ...) against a `Process`.
use std::collections::{HashMap, HashSet};

use hh_core::{Addr, Error, Module, Process, Prot, Result};
use serde::{Deserialize, Serialize};

use crate::asm::{assemble_line, bitness, split_top};
use crate::disasm::{decode_at, formatter};
use crate::expr::{Ctx, SymbolTable, eval, find_module, module_offset, parse_num};
use iced_x86::Formatter;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AaAlloc {
    pub name: String,
    pub addr: Addr,
    pub size: u64,
}

/// What an enabled script did; pass it back to disable.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AaState {
    pub allocs: Vec<AaAlloc>,
    /// Symbols registered by the script, with their addresses.
    pub registered: Vec<(String, Addr)>,
    /// Bytes overwritten by the script, in write order.
    pub originals: Vec<(Addr, Vec<u8>)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AaError {
    /// 1-based line in the script.
    pub line: usize,
    pub message: String,
}

type Hook<A, O> = Option<Box<dyn FnMut(A) -> Result<O>>>;

/// Seams for things the assembler cannot do itself. An unset hook makes the command that
/// needs it an error (also in `aa_check`); `aa_check` never calls hooks with side effects.
///
/// | Script feature | Hook | When it runs |
/// |---|---|---|
/// | `{$lua}` ... `{$asm}` | `lua` | while preprocessing; returns AA text inserted in place |
/// | `include(file)` | `include` | while preprocessing; returns the file's script text |
/// | `loadlibrary(path)` | `load_library` | in script order, before assembling (so the new module's symbols resolve); not undone on a later error |
/// | `createthread(addr)` | `create_thread` | after all writes succeeded; an error rolls the enable back |
/// | `{$try}` ... `{$except}` | `try_except` | after all writes; gets (start of guarded code, handler address) and must install a handler in the target that resumes at the handler on an exception |
/// | `sharedallocate(name,size)` | `shared_alloc` | in script order; returns the address of named memory shared between processes; registered like `globalalloc` |
///
/// Not supported at all: `kalloc` (kernel mode), `aobscanex`.
#[derive(Default)]
pub struct AaHooks {
    /// `{$lua}` block source -> Auto Assembler text to insert in its place.
    pub lua: Hook<String, String>,
    /// `include(file)` -> script text.
    pub include: Hook<String, String>,
    /// `createthread(addr)`, run after all writes.
    pub create_thread: Hook<Addr, ()>,
    /// `loadlibrary(path)`.
    pub load_library: Hook<String, ()>,
    /// `{$try}`/`{$except}`: (guarded code start, handler address), run after all writes.
    pub try_except: Hook<(Addr, Addr), ()>,
    /// `sharedallocate(name, size)` -> address.
    pub shared_alloc: Hook<(String, u64), Addr>,
}

type R<T> = std::result::Result<T, AaError>;

fn err<T>(line: usize, message: impl Into<String>) -> R<T> {
    Err(AaError {
        line,
        message: message.into(),
    })
}
fn at(line: usize) -> impl Fn(Error) -> AaError {
    move |e| AaError {
        line,
        message: e.to_string(),
    }
}

/// Removes `//`, `/* */` and `{ }` comments (keeping `{$...}` directives and line count).
fn strip_comments(s: &str) -> String {
    let c: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    let mut quote: Option<char> = None;
    while i < c.len() {
        let ch = c[i];
        if let Some(q) = quote {
            if ch == q || ch == '\n' {
                quote = None;
            }
            out.push(ch);
            i += 1;
            continue;
        }
        let close = match (ch, c.get(i + 1)) {
            ('/', Some('/')) => Some("\n"),
            ('/', Some('*')) => Some("*/"),
            ('{', next) if next != Some(&'$') => Some("}"),
            _ => None,
        };
        if ch == '\'' || ch == '"' {
            quote = Some(ch);
        }
        let Some(close) = close else {
            out.push(ch);
            i += 1;
            continue;
        };
        // Skip to the terminator, keeping newlines so line numbers stay right.
        let close: Vec<char> = close.chars().collect();
        i += if ch == '{' { 1 } else { 2 };
        while i < c.len() && !c[i..].starts_with(&close) {
            if c[i] == '\n' {
                out.push('\n');
            }
            i += 1;
        }
        if close != ['\n'] {
            i += close.len();
        }
    }
    out
}

fn replace_word(line: &str, name: &str, value: &str) -> String {
    let is_id = |c: char| c.is_alphanumeric() || c == '_';
    let mut out = String::new();
    let mut rest = line;
    while let Some(pos) = rest.to_ascii_lowercase().find(&name.to_ascii_lowercase()) {
        let before_ok = rest[..pos].chars().next_back().is_none_or(|c| !is_id(c));
        let after = &rest[pos + name.len()..];
        let after_ok = after.chars().next().is_none_or(|c| !is_id(c));
        out.push_str(&rest[..pos]);
        out.push_str(if before_ok && after_ok {
            value
        } else {
            &rest[pos..pos + name.len()]
        });
        rest = after;
    }
    out.push_str(rest);
    out
}

/// `name(args)` -> (lowercase name, args).
fn directive(line: &str) -> Option<(String, Vec<String>)> {
    let open = line.find('(')?;
    let name = line[..open].trim();
    if name.is_empty()
        || !name.chars().all(|c| c.is_ascii_alphanumeric())
        || !line.trim_end().ends_with(')')
    {
        return None;
    }
    let inner = &line[open + 1..line.trim_end().len() - 1];
    Some((
        name.to_ascii_lowercase(),
        split_top(inner, ',')
            .into_iter()
            .map(|s| s.trim().to_string())
            .collect(),
    ))
}

const DIRECTIVES: &[&str] = &[
    "alloc",
    "globalalloc",
    "dealloc",
    "label",
    "registersymbol",
    "unregistersymbol",
    "aobscan",
    "aobscanmodule",
    "aobscanregion",
    "assert",
    "fullaccess",
    "createthread",
    "loadlibrary",
    "kalloc",
    "sharedallocate",
    "include",
    "define",
    "readmem",
    "reassemble",
];

/// Pulls `{$lua}` ... `{$asm}` blocks out verbatim, before comment stripping could mangle Lua
/// (`{1, 2}`, `7 // 2`, `/* */`). Each block leaves a `{$lua:N}` marker (N indexes `blocks`)
/// and blank lines, so line numbers stay right.
fn extract_lua(text: &str, blocks: &mut Vec<String>) -> String {
    let mut out = String::with_capacity(text.len());
    let mut cur: Option<String> = None;
    for l in text.lines() {
        let t = l.trim();
        if let Some(src) = cur.as_mut() {
            if t.eq_ignore_ascii_case("{$asm}") {
                blocks.extend(cur.take());
                out.push_str("{$asm}\n");
            } else {
                src.push_str(l);
                src.push('\n');
                out.push('\n');
            }
        } else if t.eq_ignore_ascii_case("{$lua}") {
            out.push_str(&format!("{{$lua:{}}}\n", blocks.len()));
            cur = Some(String::new());
        } else {
            out.push_str(l);
            out.push('\n');
        }
    }
    blocks.extend(cur);
    out
}

/// Splits the script into the lines for one section, with 1-based line numbers. Lines before
/// the first section header belong to both sections.
fn section_lines(
    script: &str,
    enable: bool,
    lua: &mut Vec<String>,
) -> (Vec<(usize, String)>, bool) {
    let stripped = strip_comments(&extract_lua(script, lua));
    let mut cur: Option<bool> = None;
    let mut has_disable = false;
    let mut out = Vec::new();
    for (i, l) in stripped.lines().enumerate() {
        let t = l.trim();
        match t.to_ascii_uppercase().as_str() {
            "[ENABLE]" => cur = Some(true),
            "[DISABLE]" => {
                cur = Some(false);
                has_disable = true;
            }
            _ if !t.is_empty() && cur.is_none_or(|c| c == enable) => {
                out.push((i + 1, t.to_string()))
            }
            _ => {}
        }
    }
    (out, has_disable)
}

/// Expands `{$lua}` blocks, `include`, and `define` into plain lines.
fn preprocess(
    mut lines: Vec<(usize, String)>,
    hooks: &mut AaHooks,
    lua_blocks: &mut Vec<String>,
    depth: usize,
) -> R<Vec<(usize, String)>> {
    let mut out: Vec<(usize, String)> = Vec::new();
    let mut defines: Vec<(String, String)> = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let (ln, raw) = lines[i].clone();
        let mut line = raw.clone();
        for (n, v) in &defines {
            line = replace_word(&line, n, v);
        }
        let lower = line.to_ascii_lowercase();
        i += 1;
        if lower.starts_with("{$") {
            match lower.as_str() {
                _ if lower.starts_with("{$lua:") => {
                    let src = lower
                        .get(6..lower.len().saturating_sub(1))
                        .and_then(|n| n.parse::<usize>().ok())
                        .and_then(|i| lua_blocks.get(i))
                        .cloned()
                        .unwrap_or_default();
                    let Some(lua) = hooks.lua.as_mut() else {
                        return err(ln, "{$lua} blocks need a Lua engine");
                    };
                    let text = lua(src).map_err(at(ln))?;
                    let new: Vec<(usize, String)> = strip_comments(&text)
                        .lines()
                        .map(|l| (ln, l.trim().to_string()))
                        .filter(|(_, l)| !l.is_empty())
                        .collect();
                    lines.splice(i..i, new);
                }
                "{$asm}" | "{$strict}" => {}
                "{$try}" | "{$except}" => {
                    if hooks.try_except.is_none() {
                        return err(
                            ln,
                            "{$try}/{$except} is unsupported without an exception-handler hook",
                        );
                    }
                    out.push((ln, lower));
                }
                _ => return err(ln, format!("unsupported directive {line}")),
            }
            continue;
        }
        match directive(&line) {
            Some((name, args)) if name == "define" => {
                if args.len() < 2 || args[0].is_empty() {
                    return err(ln, "define(name,value) expected");
                }
                // Value may itself contain commas.
                let open = line.find('(').unwrap_or(0);
                let comma = line[open..]
                    .find(',')
                    .map(|c| open + c + 1)
                    .unwrap_or(line.len());
                let value = line[comma..line.trim_end().len() - 1].trim().to_string();
                defines.push((args[0].clone(), value));
            }
            Some((name, args)) if name == "include" => {
                if depth > 8 {
                    return err(ln, "include nesting too deep");
                }
                let Some(inc) = hooks.include.as_mut() else {
                    return err(ln, "include needs a file loader");
                };
                let text = inc(args.join(",")).map_err(at(ln))?;
                let new = strip_comments(&extract_lua(&text, lua_blocks))
                    .lines()
                    .map(|l| (ln, l.trim().to_string()))
                    .filter(|(_, l)| !l.is_empty())
                    .collect();
                out.extend(preprocess(new, hooks, lua_blocks, depth + 1)?);
            }
            _ => out.push((ln, line)),
        }
    }
    Ok(out)
}

#[derive(Debug)]
enum Item {
    Origin(String),
    Label(String),
    Asm(String),
    Bytes(Vec<u8>),
    Reassemble(String),
}

/// Parses `11 22 ?? 3? *` (spaces optional, `*`/`?` alone = any byte) into (byte, mask).
fn parse_pattern(s: &str) -> Result<Vec<(u8, u8)>> {
    let bad = || Error::Parse(format!("bad pattern '{s}'"));
    let nib = |c: char| match c {
        '?' | '*' | 'x' | 'X' => Some((0, 0)),
        _ => c.to_digit(16).map(|d| (d as u8, 0xF)),
    };
    let mut out = Vec::new();
    for tok in s.split_whitespace() {
        if tok == "?" {
            out.push((0, 0));
            continue;
        }
        let c: Vec<char> = tok.chars().collect();
        let mut i = 0;
        while i < c.len() {
            if c[i] == '*' {
                out.push((0, 0));
                i += 1;
                continue;
            }
            let (h, hm) = nib(c[i]).ok_or_else(bad)?;
            let (l, lm) = nib(*c.get(i + 1).ok_or_else(bad)?).ok_or_else(bad)?;
            out.push(((h << 4) | l, (hm << 4) | lm));
            i += 2;
        }
    }
    if out.is_empty() {
        return Err(bad());
    }
    Ok(out)
}

fn matches_at(hay: &[u8], pat: &[(u8, u8)]) -> bool {
    hay.len() >= pat.len() && pat.iter().zip(hay).all(|((b, m), h)| h & m == *b)
}

/// Scans readable memory in `[start, stop)` for `pat`; returns up to `max` hits.
pub fn aob_scan(
    p: &dyn Process,
    start: Addr,
    stop: Addr,
    pattern: &str,
    max: usize,
) -> Result<Vec<Addr>> {
    let pat = parse_pattern(pattern)?;
    const CHUNK: u64 = 1 << 20;
    let mut hits = Vec::new();
    for r in p.regions()? {
        if !r.prot.r {
            continue;
        }
        let (lo, hi) = (r.start.max(start), r.start.saturating_add(r.size).min(stop));
        let mut a = lo;
        while a < hi {
            let len = (hi - a).min(CHUNK) + pat.len() as u64 - 1;
            let mut buf = vec![0u8; len as usize];
            let n = p.read(a, &mut buf).unwrap_or(0);
            for off in 0..n.saturating_sub(pat.len() - 1) {
                if a + off as u64 >= hi {
                    break;
                }
                if matches_at(&buf[off..n], &pat) {
                    hits.push(a + off as u64);
                    if hits.len() >= max {
                        return Ok(hits);
                    }
                }
            }
            a = a.saturating_add(CHUNK);
        }
    }
    Ok(hits)
}

/// Writes code bytes, temporarily making the page writable if a plain write fails.
pub fn write_code(p: &dyn Process, addr: Addr, data: &[u8]) -> Result<()> {
    match p.write(addr, data) {
        Ok(()) => Ok(()),
        Err(e) => {
            let Ok(old) = p.protect(
                addr,
                data.len() as u64,
                Prot {
                    r: true,
                    w: true,
                    x: true,
                },
            ) else {
                return Err(e);
            };
            let r = p.write(addr, data);
            let _ = p.protect(addr, data.len() as u64, old);
            r
        }
    }
}

struct Run<'a> {
    p: &'a dyn Process,
    syms: SymbolTable,
    mods: Vec<Module>,
    dry: bool,
    /// alloc / aobscan / previous-state names (lowercase).
    locals: HashMap<String, Addr>,
    fake_next: Addr,
    new_allocs: Vec<AaAlloc>,
}

impl Run<'_> {
    fn lookup(&self, name: &str) -> Option<Addr> {
        let l = name.to_ascii_lowercase();
        self.locals
            .get(&l)
            .copied()
            .or_else(|| crate::expr::std_lookup(self.p, &self.syms, &self.mods, name))
    }
    fn eval(&self, expr: &str, line: usize) -> R<Addr> {
        let f = |n: &str| self.lookup(n);
        eval(
            expr,
            &Ctx {
                lookup: &f,
                mem: Some(self.p),
            },
        )
        .map_err(at(line))
    }
    fn alloc(&mut self, size: u64, near: Option<Addr>) -> Result<Addr> {
        if self.dry {
            let a = near.unwrap_or(0x1000_0000).wrapping_add(self.fake_next);
            self.fake_next = self
                .fake_next
                .saturating_add(size.saturating_add(0x1FFF) & !0xFFF);
            return Ok(a);
        }
        self.p.alloc(
            size,
            Prot {
                r: true,
                w: true,
                x: true,
            },
            near,
        )
    }
    fn free_new(&self) {
        if !self.dry {
            for a in &self.new_allocs {
                let _ = self.p.free(a.addr, a.size);
            }
        }
    }
}

fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.starts_with('$') || s.starts_with("0x") || s.starts_with('#') {
        parse_num(s)
    } else {
        s.parse().ok().or_else(|| parse_num(s))
    }
}

fn is_ident(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_alphanumeric() || "_@.".contains(c))
}

/// Runs one section. `prev` is the enable state when disabling.
fn run(
    p: &dyn Process,
    syms: &mut SymbolTable,
    script: &str,
    enable: bool,
    prev: Option<&AaState>,
    hooks: &mut AaHooks,
    dry: bool,
) -> R<AaState> {
    let mut lua_blocks = Vec::new();
    let (lines, has_disable) = section_lines(script, enable, &mut lua_blocks);
    if !enable && !has_disable {
        // No [DISABLE] section: undo what enable recorded.
        if let Some(st) = prev.filter(|_| !dry) {
            for (a, b) in st.originals.iter().rev() {
                write_code(p, *a, b).map_err(at(0))?;
            }
            for a in &st.allocs {
                let _ = p.free(a.addr, a.size);
            }
            for (n, _) in &st.registered {
                syms.unregister(n);
            }
        }
        return Ok(AaState::default());
    }
    let lines = preprocess(lines, hooks, &mut lua_blocks, 0)?;
    let bits = bitness(p);
    let mut r = Run {
        p,
        syms: syms.clone(),
        mods: p.modules().unwrap_or_default(),
        dry,
        locals: HashMap::new(),
        fake_next: 0x10000,
        new_allocs: Vec::new(),
    };
    if let Some(st) = prev {
        for a in &st.allocs {
            r.locals.insert(a.name.to_ascii_lowercase(), a.addr);
        }
        for (n, a) in &st.registered {
            r.locals.entry(n.to_ascii_lowercase()).or_insert(*a);
        }
    }
    let mut labels: HashSet<String> = HashSet::new();
    let mut items: Vec<(usize, Item)> = Vec::new();
    let mut to_register: Vec<(usize, String)> = Vec::new();
    let mut to_unregister: Vec<String> = Vec::new();
    let mut to_dealloc: Vec<AaAlloc> = Vec::new();
    let mut threads: Vec<(usize, String)> = Vec::new();
    let mut global: Vec<(String, Addr)> = Vec::new();
    // {$try} label stack and finished (line, try label, except label) pairs.
    let mut try_open: Vec<(usize, String)> = Vec::new();
    let mut tries: Vec<(usize, String, String)> = Vec::new();

    let result = (|| -> R<()> {
        let mut in_struct: Option<(usize, String, u64)> = None;
        for (ln, line) in &lines {
            let ln = *ln;
            let lower = line.to_ascii_lowercase();
            if let Some((_, sname, off)) = in_struct.as_mut() {
                if lower == "ends" || lower == "endstruct" {
                    in_struct = None;
                    continue;
                }
                let (member, data) = match line.split_once(':') {
                    Some((m, d)) if is_ident(m.trim()) => (Some(m.trim()), d.trim()),
                    _ => (None, line.as_str()),
                };
                if let Some(m) = member {
                    r.locals.insert(m.to_ascii_lowercase(), *off);
                    r.locals
                        .insert(format!("{sname}.{m}").to_ascii_lowercase(), *off);
                }
                if !data.is_empty() {
                    *off += struct_size(data, bits).map_err(at(ln))?;
                }
                continue;
            }
            if let Some(sname) = lower.strip_prefix("struct ").map(str::trim) {
                if !is_ident(sname) {
                    return err(ln, format!("bad struct name '{sname}'"));
                }
                in_struct = Some((ln, line[7..].trim().to_string(), 0));
                continue;
            }
            if lower == "{$try}" {
                let l = format!("__try{}", tries.len() + try_open.len());
                items.push((ln, Item::Label(l.clone())));
                try_open.push((ln, l));
                continue;
            }
            if lower == "{$except}" {
                let Some((_, t)) = try_open.pop() else {
                    return err(ln, "{$except} without {$try}");
                };
                let e = t.replace("__try", "__except");
                items.push((ln, Item::Label(e.clone())));
                tries.push((ln, t, e));
                continue;
            }
            let Some((name, args)) =
                directive(line).filter(|(n, _)| DIRECTIVES.contains(&n.as_str()))
            else {
                // `label:` / `address:` optionally followed by an instruction on the same line.
                if let Some(c) = line.find(':') {
                    let head = line[..c].trim();
                    let tail = line[c + 1..].trim();
                    let seg = crate::asm::parse_reg(head).is_some_and(|r| r.is_segment_register());
                    if !seg && !head.contains('[') && !head.contains(' ') && !tail.starts_with('[')
                    {
                        items.push((ln, Item::Origin(head.to_string())));
                        if !tail.is_empty() {
                            items.push((ln, Item::Asm(tail.to_string())));
                        }
                        continue;
                    }
                }
                items.push((ln, Item::Asm(line.clone())));
                continue;
            };
            let need = |n: usize| {
                if args.len() < n || args[..n].iter().any(|a| a.is_empty()) {
                    err(ln, format!("{name}: expected {n} arguments"))
                } else {
                    Ok(())
                }
            };
            match name.as_str() {
                "alloc" | "globalalloc" => {
                    need(2)?;
                    let key = args[0].to_ascii_lowercase();
                    if name == "globalalloc"
                        && let Some(a) = r.syms.get(&args[0])
                    {
                        r.locals.insert(key, a);
                        continue;
                    }
                    let size = parse_size(&args[1]).ok_or_else(|| AaError {
                        line: ln,
                        message: format!("bad size '{}'", args[1]),
                    })?;
                    let near = match args.get(2) {
                        Some(n) if !n.is_empty() => Some(r.eval(n, ln)?),
                        _ => None,
                    };
                    let a = r.alloc(size.max(1), near).map_err(at(ln))?;
                    r.locals.insert(key, a);
                    if name == "globalalloc" {
                        global.push((args[0].clone(), a));
                    } else {
                        r.new_allocs.push(AaAlloc {
                            name: args[0].clone(),
                            addr: a,
                            size: size.max(1),
                        });
                    }
                }
                "dealloc" if args.first().is_some_and(|a| a == "*") => {
                    to_dealloc.extend(prev.iter().flat_map(|s| s.allocs.iter().cloned()));
                }
                "dealloc" => {
                    need(1)?;
                    if let Some(a) = prev.and_then(|s| {
                        s.allocs
                            .iter()
                            .find(|a| a.name.eq_ignore_ascii_case(&args[0]))
                    }) {
                        to_dealloc.push(a.clone());
                    }
                }
                "label" => {
                    need(1)?;
                    labels.extend(args.iter().map(|a| a.to_ascii_lowercase()));
                }
                "registersymbol" => to_register.extend(
                    args.iter()
                        .filter(|a| !a.is_empty())
                        .map(|a| (ln, a.clone())),
                ),
                "unregistersymbol" => {
                    to_unregister.extend(args.iter().filter(|a| !a.is_empty()).cloned())
                }
                "kalloc" => return err(ln, "kalloc: unsupported: kernel mode"),
                "sharedallocate" => {
                    need(2)?;
                    let size = parse_size(&args[1]).ok_or_else(|| AaError {
                        line: ln,
                        message: format!("bad size '{}'", args[1]),
                    })?;
                    let a = match r.syms.get(&args[0]) {
                        Some(a) => a,
                        None => {
                            let Some(h) = hooks.shared_alloc.as_mut() else {
                                return err(ln, "sharedallocate is unsupported without a hook");
                            };
                            if dry {
                                r.alloc(size.max(1), None).map_err(at(ln))?
                            } else {
                                h((args[0].clone(), size)).map_err(at(ln))?
                            }
                        }
                    };
                    r.locals.insert(args[0].to_ascii_lowercase(), a);
                    global.push((args[0].clone(), a));
                }
                "aobscan" | "aobscanmodule" | "aobscanregion" => {
                    let (lo, hi, pat, place) = match name.as_str() {
                        "aobscan" => {
                            need(2)?;
                            (0, u64::MAX, args[1..].join(" "), "the process".to_string())
                        }
                        "aobscanmodule" => {
                            need(3)?;
                            let m = find_module(&r.mods, args[1].trim_matches('"')).ok_or_else(
                                || AaError {
                                    line: ln,
                                    message: format!("module '{}' not found", args[1]),
                                },
                            )?;
                            (
                                m.base,
                                m.base.saturating_add(m.size),
                                args[2..].join(" "),
                                format!("module {}", m.name),
                            )
                        }
                        _ => {
                            need(4)?;
                            let (lo, hi) = (r.eval(&args[1], ln)?, r.eval(&args[2], ln)?);
                            (lo, hi, args[3..].join(" "), format!("{lo:X}-{hi:X}"))
                        }
                    };
                    let hits = aob_scan(p, lo, hi, &pat, 1).map_err(at(ln))?;
                    let a = *hits.first().ok_or_else(|| AaError {
                        line: ln,
                        message: format!(
                            "{name}({}): pattern '{pat}' not found in {place}",
                            args[0]
                        ),
                    })?;
                    r.locals.insert(args[0].to_ascii_lowercase(), a);
                }
                "assert" => {
                    need(2)?;
                    let a = r.eval(&args[0], ln)?;
                    let pat = parse_pattern(&args[1..].join(" ")).map_err(at(ln))?;
                    let mut buf = vec![0u8; pat.len()];
                    if p.read_exact(a, &mut buf).is_err() || !matches_at(&buf, &pat) {
                        return err(ln, format!("assert failed at {a:X}"));
                    }
                }
                "fullaccess" => {
                    need(2)?;
                    let a = r.eval(&args[0], ln)?;
                    let n = parse_size(&args[1]).unwrap_or(1);
                    if !dry {
                        match p.protect(
                            a,
                            n,
                            Prot {
                                r: true,
                                w: true,
                                x: true,
                            },
                        ) {
                            Ok(_) | Err(Error::Unsupported(_)) => {}
                            Err(e) => return Err(at(ln)(e)),
                        }
                    }
                }
                "createthread" => {
                    need(1)?;
                    threads.push((ln, args[0].clone()));
                }
                "loadlibrary" => {
                    need(1)?;
                    if !dry {
                        let Some(h) = hooks.load_library.as_mut() else {
                            return err(ln, "loadlibrary is not supported");
                        };
                        h(args[0].trim_matches('"').to_string()).map_err(at(ln))?;
                        r.mods = p.modules().unwrap_or_default();
                    }
                }
                "readmem" => {
                    need(2)?;
                    let a = r.eval(&args[0], ln)?;
                    let n = parse_size(&args[1]).ok_or_else(|| AaError {
                        line: ln,
                        message: "bad size".into(),
                    })?;
                    let mut buf = vec![0u8; n.min(1 << 20) as usize];
                    p.read_exact(a, &mut buf).map_err(at(ln))?;
                    items.push((ln, Item::Bytes(buf)));
                }
                "reassemble" => {
                    need(1)?;
                    items.push((ln, Item::Reassemble(args[0].clone())));
                }
                _ => return err(ln, format!("{name} is not supported here")),
            }
        }
        if let Some((ln, n, _)) = in_struct {
            return err(ln, format!("struct {n} without ends"));
        }
        if let Some((ln, _)) = try_open.first() {
            return err(*ln, "{$try} without {$except}");
        }
        Ok(())
    })();
    if let Err(e) = result {
        r.free_new();
        return Err(e);
    }

    // Anonymous labels: @@ defines, @f/@b refer to the next/previous one.
    let mut anon = 0;
    for (_, it) in items.iter_mut() {
        match it {
            Item::Origin(s) if s == "@@" => {
                *it = Item::Label(format!("__anon{anon}"));
                anon += 1;
            }
            Item::Asm(s) => {
                let f = format!("__anon{anon}");
                let b = if anon == 0 {
                    "__anon_none".to_string()
                } else {
                    format!("__anon{}", anon - 1)
                };
                *s = replace_word(&replace_word(s, "@f", &f), "@b", &b);
            }
            _ => {}
        }
    }
    for (_, it) in &items {
        if let Item::Label(l) = it {
            labels.insert(l.clone());
        }
    }
    // `x:` is a declared label, else an address expression (which may use labels, as in
    // `exit+2:`). An undeclared bare name is an error, as in Cheat Engine.
    for (ln, it) in items.iter_mut() {
        let Item::Origin(s) = it else { continue };
        let l = s.to_ascii_lowercase();
        if labels.contains(&l) {
            *it = Item::Label(l);
            continue;
        }
        let with_labels = |n: &str| {
            if labels.contains(&n.to_ascii_lowercase()) {
                Some(0)
            } else {
                r.lookup(n)
            }
        };
        let ok = eval(
            s,
            &Ctx {
                lookup: &with_labels,
                mem: None,
            },
        )
        .is_ok()
            || r.eval(s, *ln).is_ok();
        if !ok {
            r.free_new();
            return Err(if is_ident(s) {
                AaError {
                    line: *ln,
                    message: format!("'{s}' is not declared: add label({s}) or alloc it"),
                }
            } else {
                r.eval(s, *ln).unwrap_err()
            });
        }
    }

    let placed = match place(&r, &items, &labels, bits) {
        Ok(v) => v,
        Err(e) => {
            r.free_new();
            return Err(e);
        }
    };
    let (writes, label_addrs) = placed;

    // Write everything, rolling back on failure.
    let mut originals: Vec<(Addr, Vec<u8>)> = Vec::new();
    if !dry {
        for (ln, a, bytes) in &writes {
            let mut old = vec![0u8; bytes.len()];
            let res = p
                .read_exact(*a, &mut old)
                .and_then(|_| write_code(p, *a, bytes));
            if let Err(e) = res {
                for (oa, ob) in originals.iter().rev() {
                    let _ = write_code(p, *oa, ob);
                }
                r.free_new();
                return Err(at(*ln)(e));
            }
            originals.push((*a, old));
        }
    }

    let value_of = |n: &str| {
        label_addrs
            .get(&n.to_ascii_lowercase())
            .copied()
            .or_else(|| r.lookup(n))
    };
    // Everything after the writes can still fail; keep the enable all-or-nothing.
    let finish = |hooks: &mut AaHooks| -> R<Vec<(String, Addr)>> {
        let mut registered = Vec::new();
        for (ln, n) in &to_register {
            let Some(a) = value_of(n) else {
                return err(*ln, format!("registersymbol: unknown '{n}'"));
            };
            registered.push((n.clone(), a));
        }
        let mut thread_addrs = Vec::new();
        for (ln, t) in &threads {
            let f = |n: &str| value_of(n);
            let a = eval(
                t,
                &Ctx {
                    lookup: &f,
                    mem: Some(p),
                },
            )
            .map_err(at(*ln))?;
            thread_addrs.push((*ln, a));
        }
        if dry {
            return Ok(registered);
        }
        if let Some((ln, _)) = thread_addrs.first()
            && hooks.create_thread.is_none()
        {
            return err(*ln, "createthread is not supported");
        }
        for (ln, t, e) in &tries {
            let (Some(t), Some(e)) = (label_addrs.get(t), label_addrs.get(e)) else {
                return err(*ln, "{$try}/{$except} without an address");
            };
            let h = hooks.try_except.as_mut().ok_or_else(|| AaError {
                line: *ln,
                message: "{$try}/{$except} is unsupported without an exception-handler hook".into(),
            })?;
            h((*t, *e)).map_err(at(*ln))?;
        }
        for (ln, a) in thread_addrs {
            if let Some(h) = hooks.create_thread.as_mut() {
                h(a).map_err(at(ln))?;
            }
        }
        Ok(registered)
    };
    let registered = match finish(hooks) {
        Ok(v) => v,
        Err(e) => {
            for (oa, ob) in originals.iter().rev() {
                let _ = write_code(p, *oa, ob);
            }
            r.free_new();
            return Err(e);
        }
    };
    let allocs = r.new_allocs;
    if !dry {
        for (n, a) in registered.iter().chain(&global) {
            syms.register(n, *a);
        }
        for n in &to_unregister {
            syms.unregister(n);
        }
        for a in &to_dealloc {
            let _ = p.free(a.addr, a.size);
        }
    }
    Ok(AaState {
        allocs,
        registered,
        originals,
    })
}

/// Bytes a struct member takes: `resb/resw/resd/resq n` or `db/dw/dd/dq` items (`?` = 0).
fn struct_size(data: &str, bits: u32) -> Result<u64> {
    let (m, rest) = data.split_once(char::is_whitespace).unwrap_or((data, ""));
    let w = match m.to_ascii_lowercase().as_str() {
        "resb" => 1,
        "resw" => 2,
        "resd" => 4,
        "resq" => 8,
        _ => {
            let b = assemble_line(&data.replace('?', "0"), 0, bits, &|_| Some(0))?;
            return Ok(b.len() as u64);
        }
    };
    parse_size(rest)
        .map(|n| n.saturating_mul(w))
        .ok_or_else(|| Error::Parse(format!("bad count in '{data}'")))
}

type Placed = (Vec<(usize, Addr, Vec<u8>)>, HashMap<String, Addr>);

/// Multi-pass placement: label addresses start unknown (assumed to be the current address),
/// instruction sizes only grow, shorter re-encodings are padded with NOPs; repeat until stable.
fn place(r: &Run, items: &[(usize, Item)], labels: &HashSet<String>, bits: u32) -> R<Placed> {
    let mut sizes = vec![0usize; items.len()];
    let mut prev: HashMap<String, Addr> = HashMap::new();
    let mut reasm: HashMap<usize, String> = HashMap::new();
    for _pass in 0..64 {
        let mut now: HashMap<String, Addr> = HashMap::new();
        let mut cur: Option<Addr> = None;
        let mut changed = false;
        let mut unresolved: Option<(usize, String)> = None;
        let mut out = Vec::new();
        for (i, (ln, it)) in items.iter().enumerate() {
            let ln = *ln;
            if let Item::Label(l) = it {
                let Some(c) = cur else {
                    return err(ln, format!("label '{l}' has no address before it"));
                };
                now.insert(l.clone(), c);
                continue;
            }
            let here = cur.unwrap_or(0);
            let unres = std::cell::RefCell::new(None::<String>);
            let lookup = |n: &str| -> Option<Addr> {
                let l = n.to_ascii_lowercase();
                if labels.contains(&l) {
                    return now.get(&l).or_else(|| prev.get(&l)).copied().or_else(|| {
                        *unres.borrow_mut() = Some(n.to_string());
                        Some(here)
                    });
                }
                r.lookup(n)
            };
            let bytes = match it {
                Item::Origin(e) => {
                    cur = Some(
                        eval(
                            e,
                            &Ctx {
                                lookup: &lookup,
                                mem: Some(r.p),
                            },
                        )
                        .map_err(at(ln))?,
                    );
                    None
                }
                Item::Label(_) => None,
                Item::Asm(t) => {
                    let Some(c) = cur else {
                        return err(ln, "code without an address (missing 'name:' line)");
                    };
                    Some(assemble_line(t, c, bits, &lookup).map_err(at(ln))?)
                }
                Item::Bytes(b) => Some(b.clone()),
                Item::Reassemble(e) => {
                    let Some(c) = cur else {
                        return err(ln, "code without an address");
                    };
                    if let std::collections::hash_map::Entry::Vacant(v) = reasm.entry(i) {
                        let a = eval(
                            e,
                            &Ctx {
                                lookup: &lookup,
                                mem: Some(r.p),
                            },
                        )
                        .map_err(at(ln))?;
                        let (ins, _) = decode_at(r.p, a).map_err(at(ln))?;
                        let mut text = String::new();
                        formatter().format(&ins, &mut text);
                        v.insert(text);
                    }
                    Some(assemble_line(&reasm[&i], c, bits, &lookup).map_err(at(ln))?)
                }
            };
            if let Some(n) = unres.into_inner() {
                unresolved.get_or_insert((ln, n));
            }
            if let Some(mut b) = bytes {
                if b.len() > sizes[i] {
                    sizes[i] = b.len();
                    changed = true;
                }
                b.resize(sizes[i], 0x90);
                let c = cur.unwrap_or(0);
                cur = Some(c.wrapping_add(b.len() as u64));
                out.push((ln, c, b));
            }
        }
        if !changed && now == prev {
            if let Some((ln, n)) = unresolved {
                return err(ln, format!("label '{n}' is used but never defined"));
            }
            return Ok((out, now));
        }
        prev = now;
    }
    err(0, "label placement did not converge")
}

/// Runs the `[ENABLE]` (enable = true) or `[DISABLE]` section. Disabling takes the state the
/// enable returned. A script without `[DISABLE]` is disabled by restoring the recorded bytes.
pub fn aa_execute(
    p: &dyn Process,
    syms: &mut SymbolTable,
    script: &str,
    enable: bool,
    state: Option<&AaState>,
    hooks: &mut AaHooks,
) -> Result<AaState> {
    run(p, syms, script, enable, state, hooks, false)
        .map_err(|e| Error::Parse(format!("line {}: {}", e.line, e.message)))
}

/// Syntax check: runs both sections without allocating or writing. `None` if fine.
pub fn aa_check(
    p: &dyn Process,
    syms: &SymbolTable,
    script: &str,
    hooks: &mut AaHooks,
) -> Option<AaError> {
    let mut syms = syms.clone();
    let st = match run(p, &mut syms, script, true, None, hooks, true) {
        Ok(s) => s,
        Err(e) => return Some(e),
    };
    run(p, &mut syms, script, false, Some(&st), hooks, true).err()
}

/// Template generators like CE's "Code injection", "AOB injection" and "Full injection".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Template {
    CodeInjection,
    AobInjection,
    FullInjection,
}

/// Produces a script that hooks the instruction(s) at `addr` (at least 5 bytes are moved).
pub fn injection_template(p: &dyn Process, addr: Addr, kind: Template) -> Result<String> {
    let mods = p.modules().unwrap_or_default();
    let mut f = formatter();
    let (mut code, mut orig) = (String::new(), Vec::new());
    while orig.len() < 5 {
        let (ins, bytes) = decode_at(p, addr + orig.len() as u64)?;
        if ins.is_invalid() {
            return Err(Error::Parse(format!(
                "cannot decode instruction at {:X}",
                addr + orig.len() as u64
            )));
        }
        let mut t = String::new();
        f.format(&ins, &mut t);
        code.push_str(&format!("  {t}\n"));
        orig.extend(bytes);
    }
    let name = module_offset(&mods, addr).unwrap_or_else(|| format!("{addr:X}"));
    let nops = if orig.len() > 5 {
        format!("  nop {:X}\n", orig.len() - 5)
    } else {
        String::new()
    };
    let hex = |b: &[u8]| {
        b.iter()
            .map(|x| format!("{x:02X}"))
            .collect::<Vec<_>>()
            .join(" ")
    };
    let origb = hex(&orig);
    Ok(match kind {
        Template::CodeInjection => format!(
            "[ENABLE]\nalloc(newmem,2048,{name})\nlabel(returnhere)\nlabel(originalcode)\nlabel(exit)\n\nnewmem:\n\noriginalcode:\n{code}\nexit:\n  jmp returnhere\n\n{name}:\n  jmp newmem\n{nops}returnhere:\n\n[DISABLE]\ndealloc(newmem)\n{name}:\n  db {origb}\n"
        ),
        Template::AobInjection => {
            // Grow the pattern until it is unique in its module (or the whole process).
            let m = mods
                .iter()
                .find(|m| addr >= m.base && addr - m.base < m.size);
            let (lo, hi) = m.map_or((0, u64::MAX), |m| (m.base, m.base.saturating_add(m.size)));
            let mut cands = aob_scan(p, lo, hi, &origb, 10_000)?;
            let mut pat = orig.clone();
            while cands.len() > 1 && pat.len() < 64 {
                let mut b = [0u8];
                p.read_exact(addr + pat.len() as u64, &mut b)?;
                let off = pat.len() as u64;
                cands.retain(|c| {
                    let mut x = [0u8];
                    p.read_exact(c + off, &mut x).is_ok() && x == b
                });
                pat.push(b[0]);
            }
            let scan = match m {
                Some(m) => format!("aobscanmodule(INJECT,{},{})", m.name, hex(&pat)),
                None => format!("aobscan(INJECT,{})", hex(&pat)),
            };
            format!(
                "[ENABLE]\n{scan}\nalloc(newmem,$1000,INJECT)\nlabel(code)\nlabel(return)\n\nnewmem:\n\ncode:\n{code}  jmp return\n\nINJECT:\n  jmp newmem\n{nops}return:\nregistersymbol(INJECT)\n\n[DISABLE]\nINJECT:\n  db {origb}\n\nunregistersymbol(INJECT)\ndealloc(newmem)\n"
            )
        }
        Template::FullInjection => format!(
            "define(address,{name})\ndefine(bytes,{origb})\n\n[ENABLE]\nassert(address,bytes)\nalloc(newmem,$1000,address)\nlabel(code)\nlabel(return)\n\nnewmem:\n\ncode:\n{code}  jmp return\n\naddress:\n  jmp newmem\n{nops}return:\n\n[DISABLE]\naddress:\n  db bytes\n\ndealloc(newmem)\n"
        ),
    })
}

/// A "replace with code that does nothing" patch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Patch {
    pub addr: Addr,
    pub original: Vec<u8>,
}

/// NOPs the instruction at `addr`, returning the original bytes.
pub fn nop_instruction(p: &dyn Process, addr: Addr) -> Result<Patch> {
    let (ins, bytes) = decode_at(p, addr)?;
    if ins.is_invalid() {
        return Err(Error::Parse(format!("no valid instruction at {addr:X}")));
    }
    write_code(p, addr, &vec![0x90; bytes.len()])?;
    Ok(Patch {
        addr,
        original: bytes,
    })
}

pub fn restore_patch(p: &dyn Process, patch: &Patch) -> Result<()> {
    write_code(p, patch.addr, &patch.original)
}
