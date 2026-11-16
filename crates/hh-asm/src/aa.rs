//! Auto Assembler: runs Cheat Engine style scripts (`[ENABLE]`/`[DISABLE]`, alloc, labels,
//! aobscan, db, ...) against a `Process`.
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};

use hh_core::{Addr, Error, Module, Process, Prot, Result};
use serde::{Deserialize, Serialize};

use crate::asm::{assemble_line, bitness, split_top};
use crate::disasm::{decode_at, formatter};
use crate::expr::{Ctx, SymbolLookup, SymbolTable, eval, find_module, module_offset, parse_num};
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
    /// Every `aobscan*` the section ran, in script order.
    #[serde(default)]
    pub scans: Vec<AaScan>,
}

/// One `aobscan` / `aobscanmodule` / `aobscanregion` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AaScan {
    pub name: String,
    /// First match (the address the name gets).
    pub addr: Addr,
    /// Matches in the scanned range, counted up to [`MAX_AOB_COUNT`]; `None` when not
    /// counted ([`AobUnique::Off`] stops at the first match, like Cheat Engine).
    pub matches: Option<usize>,
}

/// What `aobscan*` does when its pattern matches more than once.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum AobUnique {
    /// Take the first match, do not count (Cheat Engine's behaviour).
    #[default]
    Off,
    /// Count the matches into [`AaState::scans`], take the first.
    Warn,
    /// Count, and fail the script when a pattern matches more than once.
    Fail,
}

/// Most matches an `aobscan` counts when uniqueness is checked.
pub const MAX_AOB_COUNT: usize = 1000;
/// Deepest `{$ifdef}` nesting.
pub const MAX_IF_DEPTH: usize = 64;
/// Most custom (`registerAutoAssemblerCommand`) command expansions per script.
pub const MAX_CUSTOM_COMMANDS: usize = 1024;
/// Largest `align` boundary.
pub const MAX_ALIGN: u64 = 0x10000;
/// Part of every error for a directive whose hook is missing (`{$lua}`, `luacall`,
/// `loadbinary`, `include`): the host did not hand this script that capability. Hosts that
/// withhold capabilities from untrusted scripts look for it to ask the user instead.
pub const NOT_AVAILABLE: &str = "is not available to this script";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AaError {
    /// 1-based line in the script.
    pub line: usize,
    pub message: String,
}

type Hook<A, O> = Option<Box<dyn FnMut(A) -> Result<O>>>;

/// Seams for things the assembler cannot do itself. An unset hook makes the command that
/// needs it an error (also in `aa_check`; for `{$lua}`, `luacall`, `loadbinary` and
/// `include` one containing [`NOT_AVAILABLE`]); `aa_check` never calls hooks with side
/// effects. The hooks are the script's capabilities: a host that does not trust a script
/// leaves out everything that runs Lua or reads local files.
///
/// | Script feature | Hook | When it runs |
/// |---|---|---|
/// | `{$lua}` ... `{$asm}` | `lua` | while preprocessing; returns AA text inserted in place |
/// | `include(file)` | `include` | while preprocessing; returns the file's script text |
/// | `loadlibrary(path)` | `load_library` | in script order, before assembling (so the new module's symbols resolve); not undone on a later error |
/// | `createthread(addr)` | `create_thread` | after all writes succeeded; an error rolls the enable back |
/// | `{$try}` ... `{$except}` | `try_except` | after all writes; gets (start of guarded code, handler address) and must install a handler in the target that resumes at the handler on an exception |
/// | `sharedallocate(name,size)` | `shared_alloc` | in script order; returns the address of named memory shared between processes; registered like `globalalloc` |
/// | `luacall(code)` | `lua_call`, else `lua` (output ignored) | while preprocessing, in script order; never while checking, but required |
/// | `loadbinary(addr,file)` | `read_file` | while assembling; returns the file's bytes (the host applies its consent / file-access rules); not called while checking, but required |
/// | `name(args)` not built in | `command` | while preprocessing (also while checking, with `true`); `Some(text)` replaces the line, `None` = not a custom command |
/// | whole script | `prologue` | first, on every section run; returns the script to use |
/// | after a section | `epilogue` | after all writes succeeded; an error rolls the section back |
/// | unknown symbol | `symbol_lookup` | after every built-in lookup failed |
///
/// Not supported at all: `kalloc` (kernel mode), `aobscanex`.
#[derive(Default)]
pub struct AaHooks {
    /// `luacall(code)`; without it the `lua` hook runs the code and its output is ignored.
    pub lua_call: Hook<String, ()>,
    /// `loadbinary(address, file)`: file name -> contents (at most [`MAX_ASSEMBLED_BYTES`]).
    pub read_file: Hook<String, Vec<u8>>,
    /// Custom commands (Cheat Engine's `registerAutoAssemblerCommand`): (lowercase name,
    /// argument text, syntax check only) -> replacement script text, or `None` if `name` is
    /// not one.
    pub command: Hook<(String, String, bool), Option<String>>,
    /// `registerAutoAssemblerPrologue`: (script, syntax check only) -> script.
    pub prologue: Hook<(String, bool), String>,
    /// Runs after a section succeeded: (enable, syntax check only).
    pub epilogue: Hook<(bool, bool), ()>,
    /// `registerSymbolLookupCallback` (failure stage): name -> address.
    pub symbol_lookup: Option<SymbolLookup>,
    /// What `aobscan*` does with a pattern that matches more than once.
    pub aob_unique: AobUnique,
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

/// Most bytes a script may expand to (defines, includes, `{$lua}` output), counted over every
/// preprocessed line; real scripts are a few KB.
pub const MAX_SCRIPT_BYTES: usize = 8 << 20;
/// Most `define`s per script; each one is applied to every later line.
pub const MAX_DEFINES: usize = 1024;
/// Most `{$lua}` block runs per script (also stops a block that emits itself).
pub const MAX_LUA_BLOCKS: usize = 256;
/// Most `include`s per script, over all nesting levels.
pub const MAX_INCLUDES: usize = 256;
/// Most bytes one `readmem` may copy, and all of a script's `readmem`s together.
pub const MAX_READMEM_BYTES: u64 = 16 << 20;
/// Most bytes a script may assemble in total (`nop N` and `readmem` multiply quickly).
pub const MAX_ASSEMBLED_BYTES: usize = 64 << 20;
/// Longest AOB pattern, in bytes; real signatures are well under 100.
pub const MAX_PATTERN_LEN: usize = 1024;

/// Whole-word, case-insensitive replace of `name` by `value`. `None` once the result would
/// exceed `limit` bytes.
fn replace_word(line: &str, name: &str, value: &str, limit: usize) -> Option<String> {
    let is_id = |c: char| c.is_alphanumeric() || c == '_';
    if name.is_empty() {
        return Some(line.to_string());
    }
    // ASCII lowercasing keeps byte offsets, so positions in `lower` index `line` too.
    let (lower, lname) = (line.to_ascii_lowercase(), name.to_ascii_lowercase());
    let mut out = String::with_capacity(line.len());
    let (mut last, mut from) = (0, 0);
    while let Some(p) = lower[from..].find(&lname) {
        let (pos, end) = (from + p, from + p + name.len());
        let before_ok = line[..pos].chars().next_back().is_none_or(|c| !is_id(c));
        let after_ok = line[end..].chars().next().is_none_or(|c| !is_id(c));
        if before_ok && after_ok {
            out.push_str(&line[last..pos]);
            out.push_str(value);
            last = end;
            if out.len() > limit {
                return None;
            }
        }
        from = end;
    }
    out.push_str(&line[last..]);
    (out.len() <= limit).then_some(out)
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
    "allocnx",
    "allocxo",
    "align",
    "loadbinary",
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
    "undefine",
    "luacall",
    "readmem",
    "reassemble",
];

/// Text between the outer parentheses of `name(...)`.
fn raw_args(line: &str) -> &str {
    let t = line.trim_end();
    line.find('(')
        .and_then(|o| t.get(o + 1..t.len().saturating_sub(1)))
        .unwrap_or("")
}

fn is_section(t: &str) -> bool {
    t.eq_ignore_ascii_case("[enable]") || t.eq_ignore_ascii_case("[disable]")
}

/// Pulls `{$lua}` ... `{$asm}` blocks out verbatim, before comment stripping could mangle Lua
/// (`{1, 2}`, `7 // 2`, `/* */`). Each block leaves a `{$lua:N}` marker (N indexes `blocks`)
/// and blank lines, so line numbers stay right. `[ENABLE]` / `[DISABLE]` inside a block split
/// it (Cheat Engine splits sections before running Lua), the marker of the part after the
/// header going on that part's first line.
fn extract_lua(text: &str, blocks: &mut Vec<String>) -> String {
    let mut out = String::with_capacity(text.len());
    // (source, marker already written)
    let mut cur: Option<(String, bool)> = None;
    let finish = |cur: &mut Option<(String, bool)>, blocks: &mut Vec<String>| {
        if let Some((src, true)) = cur.take() {
            blocks.push(src);
        }
    };
    for l in text.lines() {
        let t = l.trim();
        if cur.is_some() && t.eq_ignore_ascii_case("{$asm}") {
            finish(&mut cur, blocks);
            out.push_str("{$asm}\n");
        } else if cur.is_some() && is_section(t) {
            finish(&mut cur, blocks);
            out.push_str(t);
            out.push('\n');
            cur = Some((String::new(), false));
        } else if let Some((src, marked)) = cur.as_mut() {
            src.push_str(l);
            src.push('\n');
            if *marked {
                out.push('\n');
            } else {
                out.push_str(&format!("{{$lua:{}}}\n", blocks.len()));
                *marked = true;
            }
        } else if t.eq_ignore_ascii_case("{$lua}") {
            out.push_str(&format!("{{$lua:{}}}\n", blocks.len()));
            cur = Some((String::new(), true));
        } else {
            out.push_str(l);
            out.push('\n');
        }
    }
    finish(&mut cur, blocks);
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

/// Shared by every nesting level of one script's preprocessing.
struct Pre<'a> {
    hooks: &'a mut AaHooks,
    lua_blocks: Vec<String>,
    syms: &'a SymbolTable,
    bits: u32,
    dry: bool,
    bytes: usize,
    lua_runs: usize,
    includes: usize,
    commands: usize,
}

impl Pre<'_> {
    /// Hook output -> lines at `ln`, counted against the script size.
    fn lines_of(&mut self, text: &str, ln: usize) -> R<Vec<(usize, String)>> {
        self.bytes = self.bytes.saturating_add(text.len());
        if self.bytes > MAX_SCRIPT_BYTES {
            return err(
                ln,
                format!("script expands to more than {MAX_SCRIPT_BYTES} bytes"),
            );
        }
        Ok(strip_comments(&extract_lua(text, &mut self.lua_blocks))
            .lines()
            .map(|l| (ln, l.trim().to_string()))
            .filter(|(_, l)| !l.is_empty())
            .collect())
    }
    /// `{$ifdef name}`: a define, a registered symbol, or a predefined name.
    fn defined(&self, name: &str, defines: &[(String, String)]) -> bool {
        let n = name.to_ascii_lowercase();
        let predefined: &[&str] = if self.bits == 64 {
            &["heaphook", "cpu64", "x64", "x86_64", "amd64"]
        } else {
            &["heaphook", "cpu32", "x86", "i386"]
        };
        predefined.contains(&n.as_str())
            || defines.iter().any(|(d, _)| d.eq_ignore_ascii_case(name))
            || self.syms.get(name).is_some()
    }
}

/// Expands `{$lua}` blocks, `include`, `define`, `{$ifdef}` and custom commands into plain
/// lines.
fn preprocess(
    mut lines: Vec<(usize, String)>,
    cx: &mut Pre,
    depth: usize,
) -> R<Vec<(usize, String)>> {
    let mut out: Vec<(usize, String)> = Vec::new();
    let mut defines: Vec<(String, String)> = Vec::new();
    // Open `{$ifdef}`s: (line, this branch is taken, an enclosing one is skipped, seen else).
    let mut conds: Vec<(usize, bool, bool, bool)> = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let ln = lines[i].0;
        let mut line = std::mem::take(&mut lines[i].1);
        i += 1;
        let lower = line.to_ascii_lowercase();
        // Conditionals first: their names must not go through define replacement.
        let cond = |kw: &str| {
            lower
                .strip_prefix(kw)
                .and_then(|r| r.strip_suffix('}'))
                .filter(|r| r.starts_with(char::is_whitespace))
                .map(|r| line[kw.len()..kw.len() + r.len()].trim().to_string())
        };
        let skipping = conds.last().is_some_and(|c| !c.1 || c.2);
        if let Some((name, neg)) = cond("{$ifdef").map(|n| (n, false)).or_else(|| cond("{$ifndef").map(|n| (n, true))) {
            if name.is_empty() {
                return err(ln, "{$ifdef} needs a name");
            }
            if conds.len() >= MAX_IF_DEPTH {
                return err(ln, format!("{{$ifdef}} nested deeper than {MAX_IF_DEPTH}"));
            }
            let taken = cx.defined(&name, &defines) != neg;
            conds.push((ln, taken, skipping, false));
            continue;
        }
        match lower.as_str() {
            "{$else}" => {
                let Some(c) = conds.last_mut().filter(|c| !c.3) else {
                    return err(ln, "{$else} without {$ifdef}");
                };
                c.1 = !c.1;
                c.3 = true;
                continue;
            }
            "{$endif}" => {
                if conds.pop().is_none() {
                    return err(ln, "{$endif} without {$ifdef}");
                }
                continue;
            }
            _ if skipping => continue,
            _ => {}
        }
        let too_big = || AaError {
            line: ln,
            message: format!("script expands to more than {MAX_SCRIPT_BYTES} bytes"),
        };
        // `define(name,...)` / `undefine(name)` keep their name: redefining works.
        let keep = match lower.trim_start() {
            l if l.starts_with("undefine(") => line.len(),
            l if l.starts_with("define(") => line.find(',').unwrap_or(line.len()),
            _ => 0,
        };
        let (head, mut rest) = (line[..keep].to_string(), line[keep..].to_string());
        for (n, v) in &defines {
            rest = replace_word(&rest, n, v, MAX_SCRIPT_BYTES).ok_or_else(too_big)?;
        }
        line = head + &rest;
        cx.bytes = cx.bytes.saturating_add(line.len());
        if cx.bytes > MAX_SCRIPT_BYTES {
            return Err(too_big());
        }
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("{$") {
            match lower.as_str() {
                _ if lower.starts_with("{$lua:") => {
                    cx.lua_runs += 1;
                    if cx.lua_runs > MAX_LUA_BLOCKS {
                        return err(ln, format!("more than {MAX_LUA_BLOCKS} {{$lua}} blocks"));
                    }
                    let src = lower
                        .get(6..lower.len().saturating_sub(1))
                        .and_then(|n| n.parse::<usize>().ok())
                        .and_then(|i| cx.lua_blocks.get(i))
                        .cloned()
                        .unwrap_or_default();
                    let Some(lua) = cx.hooks.lua.as_mut() else {
                        return err(ln, format!("{{$lua}}: Lua {NOT_AVAILABLE}"));
                    };
                    let text = lua(src).map_err(at(ln))?;
                    let new = cx.lines_of(&text, ln)?;
                    lines.splice(i..i, new);
                }
                "{$asm}" => {}
                "{$strict}" | "{$nostrict}" => out.push((ln, lower)),
                "{$try}" | "{$except}" => {
                    if cx.hooks.try_except.is_none() {
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
                let value = raw_args(&line)
                    .split_once(',')
                    .map_or("", |(_, v)| v)
                    .trim()
                    .to_string();
                if let Some(d) = defines.iter_mut().find(|d| d.0.eq_ignore_ascii_case(&args[0])) {
                    d.1 = value;
                } else if defines.len() >= MAX_DEFINES {
                    return err(ln, format!("more than {MAX_DEFINES} defines"));
                } else {
                    defines.push((args[0].clone(), value));
                }
            }
            Some((name, args)) if name == "undefine" => {
                if args.iter().all(|a| a.is_empty()) {
                    return err(ln, "undefine(name) expected");
                }
                defines.retain(|(d, _)| !args.iter().any(|a| a.eq_ignore_ascii_case(d)));
            }
            Some((name, _)) if name == "luacall" => {
                let code = raw_args(&line).to_string();
                let h = &mut cx.hooks;
                if h.lua_call.is_none() && h.lua.is_none() {
                    return err(ln, format!("luacall: Lua {NOT_AVAILABLE}"));
                }
                if cx.dry {
                    continue;
                }
                match (h.lua_call.as_mut(), h.lua.as_mut()) {
                    (Some(f), _) => f(code).map_err(at(ln))?,
                    (None, Some(f)) => {
                        f(code).map_err(at(ln))?;
                    }
                    (None, None) => unreachable!("checked above"),
                }
            }
            Some((name, args)) if name == "include" => {
                if depth > 8 {
                    return err(ln, "include nesting too deep");
                }
                cx.includes += 1;
                if cx.includes > MAX_INCLUDES {
                    return err(ln, format!("more than {MAX_INCLUDES} includes"));
                }
                let Some(inc) = cx.hooks.include.as_mut() else {
                    return err(ln, format!("include: file access {NOT_AVAILABLE}"));
                };
                let text = inc(args.join(",")).map_err(at(ln))?;
                let new = cx.lines_of(&text, ln)?;
                out.extend(preprocess(new, cx, depth + 1)?);
            }
            Some((name, _))
                if !DIRECTIVES.contains(&name.as_str()) && cx.hooks.command.is_some() =>
            {
                let args = raw_args(&line).to_string();
                let dry = cx.dry;
                let f = cx.hooks.command.as_mut().ok_or_else(|| AaError {
                    line: ln,
                    message: "internal: command hook".into(),
                })?;
                match f((name, args, dry)).map_err(at(ln))? {
                    Some(text) => {
                        cx.commands += 1;
                        if cx.commands > MAX_CUSTOM_COMMANDS {
                            return err(
                                ln,
                                format!("more than {MAX_CUSTOM_COMMANDS} custom command runs"),
                            );
                        }
                        let new = cx.lines_of(&text, ln)?;
                        lines.splice(i..i, new);
                    }
                    None => out.push((ln, line)),
                }
            }
            _ => out.push((ln, line)),
        }
    }
    if let Some((ln, ..)) = conds.first() {
        return err(*ln, "{$ifdef} without {$endif}");
    }
    Ok(out)
}

#[derive(Debug)]
enum Item {
    Origin(String),
    /// `org address`: like `address:`, never an implicit label.
    Org(String),
    Label(String),
    Asm(String),
    Bytes(Vec<u8>),
    Reassemble(String),
    /// `align n,fill`.
    Align(u64, u8),
    /// `loadbinary(address,file)`: bytes written at an address, not at the current one.
    Load(String, Vec<u8>),
}

/// Parses `11 22 ?? 3? *` (spaces optional, `*`/`?` alone = any byte) into (byte, mask).
fn parse_pattern(s: &str) -> Result<Vec<(u8, u8)>> {
    let bad = || Error::Parse(format!("bad pattern '{s}'"));
    // A quoted pattern: "11 22 ?? 33".
    let s = s.trim();
    let s = ['"', '\'']
        .iter()
        .find_map(|q| s.strip_prefix(*q).and_then(|x| x.strip_suffix(*q)))
        .unwrap_or(s);
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
    if out.len() > MAX_PATTERN_LEN {
        return Err(Error::Parse(format!(
            "pattern longer than {MAX_PATTERN_LEN} bytes"
        )));
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
    aob_scan_cancellable(p, start, stop, pattern, max, &AtomicBool::new(false))
}

/// [`aob_scan`] that stops with `Err(Other("cancelled"))` once `cancel` is set (checked
/// every MiB).
pub fn aob_scan_cancellable(
    p: &dyn Process,
    start: Addr,
    stop: Addr,
    pattern: &str,
    max: usize,
    cancel: &AtomicBool,
) -> Result<Vec<Addr>> {
    let pat = parse_pattern(pattern)?;
    // Anchor on a fixed byte (preferring one that is not common filler) and let memchr skip
    // to its occurrences instead of comparing the whole pattern at every byte.
    let fixed = || pat.iter().enumerate().filter(|(_, (_, m))| *m == 0xFF);
    let anchor = fixed()
        .find(|(_, (b, _))| !matches!(b, 0x00 | 0xFF | 0x90 | 0xCC))
        .or_else(|| fixed().next())
        .map(|(k, (b, _))| (k, *b));
    const CHUNK: u64 = 1 << 20;
    let mut hits = Vec::new();
    let mut buf = Vec::new();
    for r in p.regions()? {
        if !r.prot.r {
            continue;
        }
        let (lo, hi) = (r.start.max(start), r.start.saturating_add(r.size).min(stop));
        let mut a = lo;
        while a < hi {
            if cancel.load(Ordering::Relaxed) {
                return Err(Error::Other("cancelled".into()));
            }
            let span = (hi - a).min(CHUNK) as usize;
            buf.resize(span + pat.len() - 1, 0);
            let n = p.read(a, &mut buf).unwrap_or(0);
            let hay = &buf[..n];
            let mut test = |off: usize| {
                let hit = off < span && matches_at(&hay[off..], &pat);
                if hit {
                    hits.push(a + off as u64);
                }
                hit && hits.len() >= max
            };
            let done = match anchor {
                Some((k, b)) => hay
                    .get(k..)
                    .is_some_and(|h| memchr::memchr_iter(b, h).any(&mut test)),
                None => (0..n.min(span)).any(test),
            };
            if done {
                return Ok(hits);
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
    /// The host's symbol lookup, asked last.
    extra: Option<SymbolLookup>,
}

impl Run<'_> {
    fn lookup(&self, name: &str) -> Option<Addr> {
        let l = name.to_ascii_lowercase();
        self.locals
            .get(&l)
            .copied()
            .or_else(|| crate::expr::std_lookup(self.p, &self.syms, &self.mods, name))
            .or_else(|| self.extra.as_ref().and_then(|f| f(name)))
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
    fn alloc(&mut self, size: u64, near: Option<Addr>, prot: Prot) -> Result<Addr> {
        if self.dry {
            let a = near.unwrap_or(0x1000_0000).wrapping_add(self.fake_next);
            self.fake_next = self
                .fake_next
                .saturating_add(size.saturating_add(0x1FFF) & !0xFFF);
            return Ok(a);
        }
        self.p.alloc(size, prot, near)
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

/// `label:` / `address:`, optionally followed by an instruction: (head, tail).
fn origin_of(line: &str) -> Option<(&str, &str)> {
    let c = line.find(':')?;
    let (head, tail) = (line[..c].trim(), line[c + 1..].trim());
    let seg = crate::asm::parse_reg(head).is_some_and(|r| r.is_segment_register());
    (!seg && !head.contains('[') && !head.contains(' ') && !tail.starts_with('['))
        .then_some((head, tail))
}

/// The first `address:` of the section that already resolves to something the script did not
/// allocate (a module address, an `aobscan` result): where the code will be patched.
fn patch_site(r: &Run, lines: &[(usize, String)]) -> Option<Addr> {
    lines.iter().find_map(|(_, l)| {
        let (head, _) = origin_of(l)?;
        if r.new_allocs.iter().any(|a| a.name.eq_ignore_ascii_case(head)) {
            return None;
        }
        r.eval(head, 0).ok().filter(|a| *a != 0)
    })
}

/// `rwx` letters or a Windows `PAGE_*` name.
fn parse_prot(s: &str) -> Option<Prot> {
    let s = s.trim().to_ascii_lowercase();
    let (r, w, x) = match s.strip_prefix("page_") {
        Some("noaccess") => (false, false, false),
        Some("readonly") => (true, false, false),
        Some("readwrite") | Some("writecopy") => (true, true, false),
        Some("execute") | Some("execute_read") => (true, false, true),
        Some("execute_readwrite") | Some("execute_writecopy") => (true, true, true),
        Some(_) => return None,
        None if !s.is_empty() && s.chars().all(|c| "rwx-".contains(c)) => {
            (s.contains('r'), s.contains('w'), s.contains('x'))
        }
        None => return None,
    };
    Some(Prot { r, w, x })
}

const RWX: Prot = Prot {
    r: true,
    w: true,
    x: true,
};

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
    let prologued;
    let script = match hooks.prologue.as_mut() {
        Some(f) => {
            prologued = f((script.to_string(), dry)).map_err(at(0))?;
            if prologued.len() > MAX_SCRIPT_BYTES {
                return err(0, format!("prologue: script longer than {MAX_SCRIPT_BYTES} bytes"));
            }
            prologued.as_str()
        }
        None => script,
    };
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
    let bits = bitness(p);
    let mut pre = Pre {
        hooks: &mut *hooks,
        lua_blocks,
        syms,
        bits,
        dry,
        bytes: 0,
        lua_runs: 0,
        includes: 0,
        commands: 0,
    };
    let lines = preprocess(lines, &mut pre, 0)?;
    let mut r = Run {
        p,
        syms: syms.clone(),
        mods: p.modules().unwrap_or_default(),
        dry,
        locals: HashMap::new(),
        fake_next: 0x10000,
        new_allocs: Vec::new(),
        extra: hooks.symbol_lookup.clone(),
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
    let mut scans: Vec<AaScan> = Vec::new();
    // Cheat Engine's default: an undeclared `name:` is a label; `{$strict}` makes it an error.
    let mut strict = false;
    let mut site: Option<Option<Addr>> = None;

    let result = (|| -> R<()> {
        let mut in_struct: Option<(usize, String, u64)> = None;
        let mut readmem_total = 0u64;
        let mut loaded_total = 0usize;
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
                    let n = struct_size(data, bits).map_err(at(ln))?;
                    *off = off.checked_add(n).ok_or_else(|| AaError {
                        line: ln,
                        message: format!("struct {sname} is larger than 2^64 bytes"),
                    })?;
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
            if lower == "{$strict}" || lower == "{$nostrict}" {
                strict = lower == "{$strict}";
                continue;
            }
            if let Some(a) = lower.strip_prefix("org ") {
                items.push((ln, Item::Org(line[line.len() - a.len()..].trim().to_string())));
                continue;
            }
            // `align n[,fill]`, `align n fill` or `align(n[,fill])`.
            if let Some(a) = lower.strip_prefix("align").filter(|a| a.starts_with([' ', '('])) {
                let a = a.trim().trim_start_matches('(').trim_end_matches(')');
                let mut it = a.split([',', ' ']).filter(|s| !s.is_empty());
                let (n, fill) = (it.next().and_then(parse_num), it.next().map(parse_num));
                let n = n.filter(|n| (1..=MAX_ALIGN).contains(n));
                let fill = match fill {
                    None => Some(0x90),
                    Some(f) => f.filter(|f| *f <= 0xFF).map(|f| f as u8),
                };
                let (Some(n), Some(fill), None) = (n, fill, it.next()) else {
                    return err(ln, format!("align n[,fill byte] expected (n at most {MAX_ALIGN:X})"));
                };
                items.push((ln, Item::Align(n, fill)));
                continue;
            }
            let Some((name, args)) =
                directive(line).filter(|(n, _)| DIRECTIVES.contains(&n.as_str()))
            else {
                // `label:` / `address:` optionally followed by an instruction on the same line.
                if let Some((head, tail)) = origin_of(line) {
                    items.push((ln, Item::Origin(head.to_string())));
                    if !tail.is_empty() {
                        items.push((ln, Item::Asm(tail.to_string())));
                    }
                    continue;
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
                "alloc" | "allocnx" | "allocxo" | "globalalloc" => {
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
                    let mut prot = match name.as_str() {
                        "allocnx" => parse_prot("rw"),
                        // Execute-only is not portable: read + execute.
                        "allocxo" => parse_prot("rx"),
                        _ => Some(RWX),
                    };
                    if let Some(s) = args.get(3).filter(|s| !s.is_empty()) {
                        prot = parse_prot(s);
                    }
                    let mut near_arg = args.get(2).filter(|n| !n.is_empty());
                    // `alloc(x,size,PAGE_READWRITE)`: a protection in the address slot.
                    if let Some(pr) = near_arg.filter(|n| n.to_ascii_lowercase().starts_with("page_")) {
                        prot = parse_prot(pr);
                        near_arg = None;
                    }
                    let prot = prot.ok_or_else(|| AaError {
                        line: ln,
                        message: format!("{name}: bad protection (rwx letters or PAGE_*)"),
                    })?;
                    let near = match near_arg {
                        Some(n) => Some(r.eval(n, ln)?),
                        None => None,
                    };
                    // 64-bit without an address: near the first patched address, so `jmp`
                    // between the hook and the allocation stays 5 bytes.
                    // Looked up once per section: rescanning per alloc would be quadratic.
                    let hint = if near.is_none() && bits == 64 {
                        *site.get_or_insert_with(|| patch_site(&r, &lines))
                    } else {
                        None
                    };
                    let a = match hint {
                        Some(h) => r
                            .alloc(size.max(1), Some(h), prot)
                            .or_else(|_| r.alloc(size.max(1), None, prot)),
                        None => r.alloc(size.max(1), near, prot),
                    }
                    .map_err(at(ln))?;
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
                "registersymbol" => {
                    // A symbol may not shadow a module (it would redirect other scripts'
                    // `module+offset` writes).
                    if let Some(a) = args.iter().find(|a| crate::expr::names_module(&r.mods, a)) {
                        return err(ln, format!("registersymbol: {a} is the name of a loaded module"));
                    }
                    to_register.extend(args.iter().filter(|a| !a.is_empty()).map(|a| (ln, a.clone())))
                }
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
                                r.alloc(size.max(1), None, RWX).map_err(at(ln))?
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
                    let unique = hooks.aob_unique;
                    let max = if unique == AobUnique::Off { 1 } else { MAX_AOB_COUNT };
                    let hits = aob_scan(p, lo, hi, &pat, max).map_err(at(ln))?;
                    let a = *hits.first().ok_or_else(|| AaError {
                        line: ln,
                        message: format!(
                            "{name}({}): pattern '{pat}' not found in {place}",
                            args[0]
                        ),
                    })?;
                    if unique == AobUnique::Fail && hits.len() > 1 {
                        let more = if hits.len() >= MAX_AOB_COUNT { "or more " } else { "" };
                        return err(
                            ln,
                            format!(
                                "{name}({}): pattern '{pat}' is not unique: {} {more}matches in {place}",
                                args[0],
                                hits.len()
                            ),
                        );
                    }
                    scans.push(AaScan {
                        name: args[0].clone(),
                        addr: a,
                        matches: (unique != AobUnique::Off).then_some(hits.len()),
                    });
                    r.locals.insert(args[0].to_ascii_lowercase(), a);
                }
                "loadbinary" => {
                    need(2)?;
                    let file = args[1..].join(",").trim().trim_matches('"').to_string();
                    let Some(h) = hooks.read_file.as_mut() else {
                        return err(ln, format!("loadbinary: file access {NOT_AVAILABLE}"));
                    };
                    let data = if dry { Vec::new() } else { h(file).map_err(at(ln))? };
                    // Running total: stop at the file that crosses the limit, not after all
                    // of them are in memory.
                    loaded_total = loaded_total.saturating_add(data.len());
                    if loaded_total > MAX_ASSEMBLED_BYTES {
                        return err(
                            ln,
                            format!("loadbinary: files larger than {MAX_ASSEMBLED_BYTES} bytes in all"),
                        );
                    }
                    items.push((ln, Item::Load(args[0].clone(), data)));
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
                    let n = parse_size(&args[1]).ok_or_else(|| AaError {
                        line: ln,
                        message: format!("fullaccess: bad size '{}'", args[1]),
                    })?;
                    // shortcut: a third "preferred size" argument is accepted and ignored;
                    // the whole pages holding the range are changed anyway.
                    if !dry {
                        match p.protect(a, n.max(1), RWX) {
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
                    readmem_total = readmem_total.saturating_add(n);
                    if readmem_total > MAX_READMEM_BYTES {
                        return err(
                            ln,
                            format!("readmem: more than {MAX_READMEM_BYTES} bytes per script"),
                        );
                    }
                    let mut buf = vec![0u8; n as usize];
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
                // Cannot fail: the labels are shorter than any line the limit would reject.
                *s = replace_word(s, "@f", &f, usize::MAX)
                    .and_then(|t| replace_word(&t, "@b", &b, usize::MAX))
                    .unwrap_or_default();
            }
            _ => {}
        }
    }
    for (_, it) in &items {
        match it {
            Item::Label(l) => {
                labels.insert(l.clone());
            }
            // Implicit label: a bare name that is nothing else (not a number, not a symbol).
            Item::Origin(s)
                if !strict && is_ident(s) && parse_num(s).is_none() && r.lookup(s).is_none() =>
            {
                labels.insert(s.to_ascii_lowercase());
            }
            _ => {}
        }
    }
    // `x:` is a label, else an address expression (which may use labels, as in `exit+2:`).
    // Under `{$strict}` an undeclared bare name is an error.
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
        for (ln, a, bytes) in writes.iter().filter(|w| !w.2.is_empty()) {
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
            if let Some(f) = hooks.epilogue.as_mut() {
                f((enable, true)).map_err(at(0))?;
            }
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
        if let Some(f) = hooks.epilogue.as_mut() {
            f((enable, false)).map_err(at(0))?;
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
        scans,
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
        // (index in `out`, item) of raw data, copied once after placement converged.
        let mut raw: Vec<(usize, usize)> = Vec::new();
        let mut total = 0usize;
        for (i, (ln, it)) in items.iter().enumerate() {
            let too_big = |total: usize| {
                if total > MAX_ASSEMBLED_BYTES {
                    err(
                        *ln,
                        format!("script assembles to more than {MAX_ASSEMBLED_BYTES} bytes"),
                    )
                } else {
                    Ok(())
                }
            };
            if let Item::Bytes(b) = it {
                let c = cur.unwrap_or(0);
                cur = Some(c.wrapping_add(b.len() as u64));
                total = total.saturating_add(b.len());
                too_big(total)?;
                raw.push((out.len(), i));
                out.push((*ln, c, Vec::new()));
                continue;
            }
            if let Item::Align(n, fill) = it {
                let Some(c) = cur else {
                    return err(*ln, "align without an address");
                };
                let pad = ((n - c % n) % n) as usize;
                cur = Some(c.wrapping_add(pad as u64));
                total = total.saturating_add(pad);
                too_big(total)?;
                out.push((*ln, c, vec![*fill; pad]));
                continue;
            }
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
            let ev = |e: &str| {
                eval(
                    e,
                    &Ctx {
                        lookup: &lookup,
                        mem: Some(r.p),
                    },
                )
                .map_err(at(ln))
            };
            let bytes = match it {
                Item::Origin(e) | Item::Org(e) => {
                    cur = Some(ev(e)?);
                    None
                }
                Item::Load(e, b) => {
                    let a = ev(e)?;
                    total = total.saturating_add(b.len());
                    too_big(total)?;
                    raw.push((out.len(), i));
                    out.push((ln, a, Vec::new()));
                    None
                }
                Item::Label(_) | Item::Align(..) => None,
                Item::Asm(t) => {
                    let Some(c) = cur else {
                        return err(ln, "code without an address (missing 'name:' line)");
                    };
                    Some(assemble_line(t, c, bits, &lookup).map_err(at(ln))?)
                }
                Item::Bytes(_) => None,
                Item::Reassemble(e) => {
                    let Some(c) = cur else {
                        return err(ln, "code without an address");
                    };
                    if let std::collections::hash_map::Entry::Vacant(v) = reasm.entry(i) {
                        let a = ev(e)?;
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
                total = total.saturating_add(b.len());
                too_big(total)?;
                let c = cur.unwrap_or(0);
                cur = Some(c.wrapping_add(b.len() as u64));
                out.push((ln, c, b));
            }
        }
        if !changed && now == prev {
            if let Some((ln, n)) = unresolved {
                return err(ln, format!("label '{n}' is used but never defined"));
            }
            for (o, i) in raw {
                if let (Some(slot), Some((_, Item::Bytes(b) | Item::Load(_, b)))) =
                    (out.get_mut(o), items.get(i))
                {
                    slot.2 = b.clone();
                }
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
    /// Hooks a function entry: the entry jumps to `newfunction`; `originalcall` (registered)
    /// runs the moved entry bytes and continues in the original function.
    ApiHook,
}

/// Produces a script that hooks the instruction(s) at `addr` (at least 5 bytes are moved).
pub fn injection_template(p: &dyn Process, addr: Addr, kind: Template) -> Result<String> {
    let mods = p.modules().unwrap_or_default();
    let mut f = formatter();
    let (mut code, mut orig) = (String::new(), Vec::new());
    while orig.len() < 5 {
        let (ins, bytes) = decode_at(p, addr.wrapping_add(orig.len() as u64))?;
        if ins.is_invalid() {
            return Err(Error::Parse(format!(
                "cannot decode instruction at {:X}",
                addr.wrapping_add(orig.len() as u64)
            )));
        }
        let mut t = String::new();
        f.format(&ins, &mut t);
        code.push_str(&format!("  {t}\n"));
        orig.extend(bytes);
    }
    // Module names come from the target (or a remote server): only a plain one goes into the
    // script text, never one that could close a quote, open a comment or start a line.
    let name = module_offset(&mods, addr)
        .filter(|_| {
            mods.iter()
                .find(|m| addr >= m.base && addr - m.base < m.size)
                .is_some_and(|m| plain_name(&m.name))
        })
        .unwrap_or_else(|| format!("{addr:X}"));
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
                p.read_exact(addr.wrapping_add(pat.len() as u64), &mut b)?;
                let off = pat.len() as u64;
                cands.retain(|c| {
                    let mut x = [0u8];
                    p.read_exact(c.wrapping_add(off), &mut x).is_ok() && x == b
                });
                pat.push(b[0]);
            }
            let scan = match m.filter(|m| plain_name(&m.name)) {
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
        Template::ApiHook => format!(
            "define(address,{name})\ndefine(bytes,{origb})\n\n[ENABLE]\nassert(address,bytes)\nalloc(newfunction,$1000,address)\nlabel(originalcall)\nlabel(returnhere)\nregistersymbol(originalcall)\n\nnewfunction:\n  // Replacement for the function. Call or jump to originalcall to run the original.\n  jmp originalcall\n\noriginalcall:\n{code}  jmp returnhere\n\naddress:\n  jmp newfunction\n{nops}returnhere:\n\n[DISABLE]\naddress:\n  db bytes\n\nunregistersymbol(originalcall)\ndealloc(newfunction)\n"
        ),
    })
}

/// A name safe to place into generated script text: letters, digits and `_ . - + @` only (no
/// quotes, braces, slashes, commas, parentheses, spaces or control characters).
fn plain_name(n: &str) -> bool {
    !n.is_empty() && n.len() <= 255 && n.chars().all(|c| c.is_ascii_alphanumeric() || "_.-+@".contains(c))
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
