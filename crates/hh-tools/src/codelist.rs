//! Cheat Engine's code list ("advanced options"): instructions the user found, with their
//! original bytes, that can be replaced with NOPs and restored. Patching first checks that
//! the bytes in memory are still the recorded original (the module may have been reloaded
//! or patched by something else). Serializes as JSON and as the `.CT` `<CheatCodes>` section.
use hh_asm::{SymbolTable, analyze_instruction, resolve_address, write_code};
use hh_core::{Addr, Error, Process, Result};
use serde::{Deserialize, Serialize};

use crate::{hexaddr, hexbytes};

/// Most entries and most bytes per entry a `<CheatCodes>` import accepts (an instruction is
/// at most 15 bytes; the slack covers hand-made multi-instruction entries).
pub const MAX_CODE_ENTRIES: usize = 100_000;
pub const MAX_CODE_BYTES: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeEntry {
    pub description: String,
    /// Address expression (`game.exe+1234`, a symbol, a hex address).
    pub addr: String,
    #[serde(with = "hexbytes")]
    pub original: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeState {
    /// Memory holds the original bytes.
    Original,
    /// Memory holds NOPs.
    Nopped,
    /// Something else: patched by someone else or a different module version.
    Changed,
    /// Address does not resolve or cannot be read.
    Unreadable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeStatus {
    #[serde(with = "hexaddr::opt")]
    pub addr: Option<Addr>,
    pub state: CodeState,
    #[serde(with = "hexbytes")]
    pub current: Vec<u8>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeList {
    #[serde(default)]
    pub entries: Vec<CodeEntry>,
}

impl CodeList {
    fn entry(&self, i: usize) -> Result<&CodeEntry> {
        self.entries.get(i).ok_or_else(|| Error::Other(format!("no code entry {i}")))
    }

    /// Adds the instruction at `addr` (an address expression); returns its index.
    pub fn add(&mut self, p: &dyn Process, syms: &SymbolTable, addr: &str, description: &str) -> Result<usize> {
        let a = resolve_address(p, syms, addr)?;
        let len = analyze_instruction(p, a, None)?.len;
        let mut original = vec![0u8; len];
        p.read_exact(a, &mut original)?;
        self.entries.push(CodeEntry { description: description.into(), addr: addr.into(), original });
        Ok(self.entries.len() - 1)
    }

    pub fn remove(&mut self, i: usize) -> Result<CodeEntry> {
        self.entry(i)?;
        Ok(self.entries.remove(i))
    }

    fn current(&self, p: &dyn Process, syms: &SymbolTable, i: usize) -> Result<(Addr, Vec<u8>, CodeState)> {
        let e = self.entry(i)?;
        let a = resolve_address(p, syms, &e.addr)?;
        let mut cur = vec![0u8; e.original.len()];
        p.read_exact(a, &mut cur)?;
        let state = if cur == e.original {
            CodeState::Original
        } else if cur.iter().all(|&b| b == 0x90) {
            CodeState::Nopped
        } else {
            CodeState::Changed
        };
        Ok((a, cur, state))
    }

    /// State of every entry.
    pub fn status(&self, p: &dyn Process, syms: &SymbolTable) -> Vec<CodeStatus> {
        (0..self.entries.len())
            .map(|i| match self.current(p, syms, i) {
                Ok((a, current, state)) => CodeStatus { addr: Some(a), state, current },
                Err(_) => CodeStatus { addr: None, state: CodeState::Unreadable, current: Vec::new() },
            })
            .collect()
    }

    /// Replaces entry `i` with NOPs after checking memory still holds the original bytes.
    pub fn nop(&self, p: &dyn Process, syms: &SymbolTable, i: usize) -> Result<()> {
        match self.current(p, syms, i)? {
            (_, _, CodeState::Nopped) => Ok(()),
            (a, _, CodeState::Original) => write_code(p, a, &vec![0x90; self.entries[i].original.len()]),
            (a, cur, _) => Err(Error::Other(format!(
                "bytes at {a:#x} ({}) differ from the recorded original; not patching",
                hexbytes::to_string(&cur)
            ))),
        }
    }

    /// Restores entry `i`. Refuses when memory holds neither NOPs nor the original unless
    /// `force` is set.
    pub fn restore(&self, p: &dyn Process, syms: &SymbolTable, i: usize, force: bool) -> Result<()> {
        match self.current(p, syms, i)? {
            (_, _, CodeState::Original) => Ok(()),
            (a, _, CodeState::Nopped) => write_code(p, a, &self.entries[i].original),
            (a, _, _) if force => write_code(p, a, &self.entries[i].original),
            (a, cur, _) => Err(Error::Other(format!(
                "bytes at {a:#x} ({}) are not the NOPs written; use force to restore anyway",
                hexbytes::to_string(&cur)
            ))),
        }
    }

    /// Cheat Engine `<CheatCodes>` section (`Before` / `After` context is left empty).
    pub fn to_ct_xml(&self) -> String {
        let esc = crate::xml_escape;
        let mut x = String::from("<CheatCodes>\n");
        for e in &self.entries {
            x += "  <CodeEntry>\n";
            x += &format!("    <Description>{}</Description>\n", esc(&e.description));
            x += &format!("    <AddressString>{}</AddressString>\n", esc(&e.addr));
            x += "    <Before/>\n    <Actual>\n";
            for b in &e.original {
                x += &format!("      <Byte>{b:02X}</Byte>\n");
            }
            x += "    </Actual>\n    <After/>\n  </CodeEntry>\n";
        }
        x + "</CheatCodes>\n"
    }

    /// Reads the `<CheatCodes>` section of a `.CT` file (whole file or just the section).
    pub fn from_ct_xml(xml: &str) -> Result<CodeList> {
        let doc = roxmltree::Document::parse(xml.trim_start_matches('\u{feff}'))
            .map_err(|e| Error::Parse(format!("bad .CT XML: {e}")))?;
        let text = |n: roxmltree::Node, tag: &str| {
            n.children().find(|c| c.has_tag_name(tag)).and_then(|c| c.text()).unwrap_or("").trim().to_string()
        };
        let mut entries = Vec::new();
        for e in doc.descendants().filter(|n| n.has_tag_name("CodeEntry")) {
            if entries.len() >= MAX_CODE_ENTRIES {
                return Err(Error::Parse(format!("more than {MAX_CODE_ENTRIES} <CodeEntry> elements")));
            }
            let actual = e.children().find(|c| c.has_tag_name("Actual"));
            if actual.is_some_and(|a| a.children().filter(|b| b.has_tag_name("Byte")).count() > MAX_CODE_BYTES) {
                return Err(Error::Parse(format!("<CodeEntry> with more than {MAX_CODE_BYTES} bytes")));
            }
            let original = actual
                .map(|a| {
                    a.children()
                        .filter(|b| b.has_tag_name("Byte"))
                        .map(|b| u8::from_str_radix(b.text().unwrap_or("").trim(), 16))
                        .collect::<std::result::Result<Vec<u8>, _>>()
                })
                .transpose()
                .map_err(|_| Error::Parse("bad <Byte> in <CheatCodes>".into()))?
                .unwrap_or_default();
            let mut addr = text(e, "AddressString");
            if addr.is_empty() {
                // Old tables store a plain number in <Address>.
                addr = text(e, "Address");
            }
            entries.push(CodeEntry { description: text(e, "Description"), addr, original });
        }
        Ok(CodeList { entries })
    }
}
