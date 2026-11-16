//! Cheat tables: HeapHook JSON and Cheat Engine `.CT` XML (import and export).
//! No Tauri types here; `load`/`save` pick the format by file extension.
use std::path::Path;

use hh_scan::{FreezeMode, VType};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Table {
    pub entries: Vec<Entry>,
    /// The table's own Lua script (CE `<LuaScript>`). Never run without asking the user.
    pub lua_script: String,
    /// Table comments (CE `<Comments>`).
    pub comments: String,
    /// The debugger's code list (CE `<CheatCodes>`).
    pub codes: Vec<CodeEntry>,
    /// Structure dissector definitions (CE `<Structures>`).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub structures: Vec<hh_tools::structure::Structure>,
    /// `<CheatTable>` children HeapHook does not understand, as raw XML, re-emitted on export.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ct_extra: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct CodeEntry {
    pub description: String,
    /// Address expression (CE `AddressString`).
    pub address: String,
    /// Hex bytes, space separated: the original instruction (`Actual`) and its neighbours.
    pub bytes: String,
    pub before: String,
    pub after: String,
}

/// What `table_save` accepts: `{entries}` or a bare entry array.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum TableIn {
    Table(Table),
    Entries(Vec<Entry>),
}

impl From<TableIn> for Table {
    fn from(t: TableIn) -> Table {
        match t {
            TableIn::Table(t) => t,
            TableIn::Entries(entries) => Table { entries, ..Table::default() },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Entry {
    pub id: i64,
    pub description: String,
    /// Address expression; empty for a group header.
    pub addr: String,
    /// Hex offsets, first applied first: `[[addr]+o0]+o1`.
    pub offsets: Vec<String>,
    pub vtype: VType,
    /// Characters for strings, bytes for aob; 0 = default.
    pub len: usize,
    pub utf16: bool,
    pub signed: bool,
    pub hex: bool,
    pub frozen: bool,
    pub freeze_mode: FreezeMode,
    /// `#RRGGBB` or null.
    pub color: Option<String>,
    pub dropdown: Option<Dropdown>,
    pub hotkeys: Vec<Hotkey>,
    /// Auto Assembler text; makes this a script entry.
    pub script: Option<String>,
    pub children: Vec<Entry>,
    /// Cheat Engine group options (`moHideChildren`, `moActivateChildrenAsWell`, ...).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub options: Vec<String>,
    /// `<CheatEntry>` children HeapHook does not understand, as raw XML.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ct_extra: Vec<String>,
}

impl Default for Entry {
    fn default() -> Self {
        Entry {
            id: 0,
            description: String::new(),
            addr: String::new(),
            offsets: Vec::new(),
            vtype: VType::Bytes4,
            len: 0,
            utf16: false,
            signed: false,
            hex: false,
            frozen: false,
            freeze_mode: FreezeMode::Exact,
            color: None,
            dropdown: None,
            hotkeys: Vec::new(),
            script: None,
            children: Vec::new(),
            options: Vec::new(),
            ct_extra: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Dropdown {
    pub options: Vec<DropdownItem>,
    pub read_only: bool,
    pub description_only: bool,
    pub display_value_as_item: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DropdownItem {
    pub value: String,
    pub text: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Hotkey {
    /// Cheat Engine action name, e.g. "Toggle Activation", "Set Value".
    pub action: String,
    /// Virtual key codes.
    pub keys: Vec<u32>,
    pub value: Option<String>,
    pub description: Option<String>,
}

pub fn load(path: &Path) -> Result<Table, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if is_ct(path) {
        return from_ct(&text);
    }
    // A bare entry array is accepted too.
    serde_json::from_str::<TableIn>(&text).map(Table::from).map_err(|e| format!("{}: {e}", path.display()))
}

pub fn save(path: &Path, t: &Table) -> Result<(), String> {
    let text = if is_ct(path) {
        to_ct(t)
    } else {
        serde_json::to_string_pretty(t).map_err(|e| e.to_string())?
    };
    std::fs::write(path, text).map_err(|e| format!("{}: {e}", path.display()))
}

fn is_ct(path: &Path) -> bool {
    path.extension().is_some_and(|e| e.eq_ignore_ascii_case("ct"))
}

// ---------------------------------------------------------------- .CT import

type Node<'a, 'i> = roxmltree::Node<'a, 'i>;

pub fn from_ct(xml: &str) -> Result<Table, String> {
    let doc = roxmltree::Document::parse(xml.trim_start_matches('\u{feff}')).map_err(|e| format!("bad .CT XML: {e}"))?;
    let root = doc.root_element();
    if root.tag_name().name() != "CheatTable" {
        return Err("not a Cheat Engine table (no <CheatTable>)".into());
    }
    let known = ["CheatEntries", "LuaScript", "Comments", "CheatCodes", "Structures"];
    let structures = match child(root, "Structures") {
        Some(n) => hh_tools::structure::from_ct_xml(&xml.trim_start_matches('\u{feff}')[n.range()]).map_err(|e| e.to_string())?,
        None => Vec::new(),
    };
    Ok(Table {
        structures,
        entries: child(root, "CheatEntries").map(entries).unwrap_or_default(),
        lua_script: text(root, "LuaScript").unwrap_or_default(),
        comments: text(root, "Comments").unwrap_or_default(),
        codes: child(root, "CheatCodes").map(codes).unwrap_or_default(),
        ct_extra: unknown(root, &known),
    })
}

/// Raw XML of the element children not named in `known`.
fn unknown(n: Node, known: &[&str]) -> Vec<String> {
    let src = n.document().input_text();
    n.children().filter(|c| c.is_element() && !known.contains(&c.tag_name().name())).map(|c| src[c.range()].to_string()).collect()
}

fn byte_list(n: Node, name: &str) -> String {
    child(n, name)
        .map(|b| b.children().filter(|c| c.has_tag_name("Byte")).filter_map(|c| c.text()).map(|t| t.trim().to_uppercase()).collect::<Vec<_>>().join(" "))
        .unwrap_or_default()
}

fn codes(list: Node) -> Vec<CodeEntry> {
    list.children()
        .filter(|c| c.has_tag_name("CodeEntry"))
        .map(|c| CodeEntry {
            description: text(c, "Description").map(|d| unquote(&d)).unwrap_or_default(),
            address: text(c, "AddressString").or_else(|| text(c, "Address")).unwrap_or_default().trim().into(),
            bytes: byte_list(c, "Actual"),
            before: byte_list(c, "Before"),
            after: byte_list(c, "After"),
        })
        .collect()
}

const ENTRY_TAGS: &[&str] = &[
    "ID", "Description", "Options", "Color", "VariableType", "AssemblerScript", "GroupHeader", "ShowAsHex",
    "ShowAsSigned", "Length", "Unicode", "CodePage", "ZeroTerminate", "ByteLength", "AllowIncrease",
    "AllowDecrease", "Address", "Offsets", "DropDownList", "Hotkeys", "CheatEntries",
];

fn child<'a, 'i>(n: Node<'a, 'i>, name: &str) -> Option<Node<'a, 'i>> {
    n.children().find(|c| c.has_tag_name(name))
}

/// All text (incl. CDATA) of the named child.
fn text(n: Node, name: &str) -> Option<String> {
    child(n, name).map(|c| c.children().filter(|t| t.is_text()).filter_map(|t| t.text()).collect())
}

fn flag(n: Node, name: &str) -> bool {
    text(n, name).is_some_and(|t| t.trim() == "1")
}

fn entries(list: Node) -> Vec<Entry> {
    list.children().filter(|c| c.has_tag_name("CheatEntry")).map(entry).collect()
}

fn entry(n: Node) -> Entry {
    let mut e = Entry {
        id: text(n, "ID").and_then(|t| t.trim().parse().ok()).unwrap_or(0),
        description: text(n, "Description").map(|d| unquote(&d)).unwrap_or_default(),
        addr: text(n, "Address").map(|a| a.trim().to_string()).unwrap_or_default(),
        signed: flag(n, "ShowAsSigned"),
        hex: flag(n, "ShowAsHex"),
        color: text(n, "Color").and_then(|c| ce_color(&c)),
        children: child(n, "CheatEntries").map(entries).unwrap_or_default(),
        ct_extra: unknown(n, ENTRY_TAGS),
        ..Entry::default()
    };
    // CE lists offsets last-applied first.
    if let Some(o) = child(n, "Offsets") {
        e.offsets = o.children().filter(|c| c.has_tag_name("Offset")).map(|c| c.text().unwrap_or("0").trim().to_string()).collect();
        e.offsets.reverse();
    }
    if flag(n, "AllowIncrease") {
        e.freeze_mode = FreezeMode::AllowIncrease;
    } else if flag(n, "AllowDecrease") {
        e.freeze_mode = FreezeMode::AllowDecrease;
    }
    let vt = text(n, "VariableType").unwrap_or_default();
    e.vtype = match vt.trim() {
        "Binary" => VType::Binary,
        "Byte" => VType::Byte,
        "2 Bytes" => VType::Bytes2,
        "8 Bytes" => VType::Bytes8,
        "Float" => VType::Float,
        "Double" => VType::Double,
        "String" => VType::String,
        "Array of byte" => VType::Aob,
        "Grouped" => VType::Grouped,
        // shortcut: CE custom types ("Custom") become 4 bytes; upgrade when HeapHook has custom types.
        _ => VType::Bytes4,
    };
    match e.vtype {
        VType::String => {
            e.len = text(n, "Length").and_then(|t| t.trim().parse().ok()).unwrap_or(0);
            e.utf16 = flag(n, "Unicode");
        }
        VType::Aob => e.len = text(n, "ByteLength").and_then(|t| t.trim().parse().ok()).unwrap_or(0),
        _ => {}
    }
    if vt.trim() == "Auto Assembler Script" || child(n, "AssemblerScript").is_some() {
        e.script = Some(text(n, "AssemblerScript").unwrap_or_default());
        e.addr.clear();
    }
    if flag(n, "GroupHeader") {
        e.addr.clear();
    }
    if let Some(o) = child(n, "Options") {
        e.options = o.attributes().filter(|a| a.value() == "1").map(|a| a.name().to_string()).collect();
    }
    if let Some(d) = child(n, "DropDownList") {
        let attr = |k| d.attribute(k) == Some("1");
        e.dropdown = Some(Dropdown {
            options: d
                .text()
                .unwrap_or("")
                .lines()
                .filter(|l| !l.trim().is_empty())
                .map(|l| {
                    let (v, t) = l.split_once(':').unwrap_or((l, ""));
                    DropdownItem { value: v.trim().into(), text: t.trim().into() }
                })
                .collect(),
            read_only: attr("ReadOnly"),
            description_only: attr("DescriptionOnly"),
            display_value_as_item: attr("DisplayValueAsItem"),
        });
    }
    if let Some(h) = child(n, "Hotkeys") {
        e.hotkeys = h
            .children()
            .filter(|c| c.has_tag_name("Hotkey"))
            .map(|k| Hotkey {
                action: text(k, "Action").unwrap_or_default().trim().into(),
                keys: child(k, "Keys")
                    .map(|ks| ks.children().filter_map(|x| x.text()?.trim().parse().ok()).collect())
                    .unwrap_or_default(),
                value: text(k, "Value"),
                description: text(k, "Description").map(|d| unquote(&d)),
            })
            .collect();
    }
    e
}

/// CE writes descriptions as `"text"`.
fn unquote(s: &str) -> String {
    let t = s.trim();
    t.strip_prefix('"').and_then(|x| x.strip_suffix('"')).unwrap_or(t).to_string()
}

/// CE colors are Delphi TColor hex (0x00BBGGRR); high byte set = system color (default).
fn ce_color(s: &str) -> Option<String> {
    let v = u32::from_str_radix(s.trim(), 16).ok()?;
    (v >> 24 == 0).then(|| format!("#{:02X}{:02X}{:02X}", v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff))
}

fn to_ce_color(s: &str) -> Option<String> {
    let v = u32::from_str_radix(s.trim().trim_start_matches('#'), 16).ok().filter(|_| s.trim().len() == 7)?;
    Some(format!("{:06X}", ((v & 0xff) << 16) | (v & 0xff00) | (v >> 16)))
}

// ---------------------------------------------------------------- .CT export

pub fn to_ct(t: &Table) -> String {
    let mut o = String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<CheatTable CheatEngineTableVersion=\"45\">\n");
    write_entries(&mut o, &t.entries, 1);
    if !t.codes.is_empty() {
        o.push_str("  <CheatCodes>\n");
        for c in &t.codes {
            o.push_str(&format!("    <CodeEntry>\n      <Description>\"{}\"</Description>\n      <AddressString>{}</AddressString>\n", esc(&c.description), esc(&c.address)));
            for (k, v) in [("Before", &c.before), ("Actual", &c.bytes), ("After", &c.after)] {
                let bytes: String = v.split_whitespace().map(|b| format!("<Byte>{}</Byte>", esc(b))).collect();
                o.push_str(&format!("      <{k}>{bytes}</{k}>\n"));
            }
            o.push_str("    </CodeEntry>\n");
        }
        o.push_str("  </CheatCodes>\n");
    }
    if !t.structures.is_empty() {
        // Pointer element sizes are written for 64-bit targets (CE recomputes them anyway).
        for l in hh_tools::structure::to_ct_xml(&t.structures, 8).lines() {
            o.push_str(&format!("  {l}\n"));
        }
    }
    for x in &t.ct_extra {
        o.push_str(&format!("  {x}\n"));
    }
    if !t.comments.is_empty() {
        o.push_str(&format!("  <Comments>{}</Comments>\n", esc(&t.comments)));
    }
    if !t.lua_script.is_empty() {
        o.push_str(&format!("  <LuaScript>{}</LuaScript>\n", esc(&t.lua_script)));
    }
    o.push_str("</CheatTable>\n");
    o
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

fn write_entries(o: &mut String, list: &[Entry], d: usize) {
    let pad = "  ".repeat(d);
    o.push_str(&format!("{pad}<CheatEntries>\n"));
    for e in list {
        let p = "  ".repeat(d + 1);
        let tag = |o: &mut String, k: &str, v: &str| o.push_str(&format!("{p}  <{k}>{}</{k}>\n", esc(v)));
        o.push_str(&format!("{p}<CheatEntry>\n"));
        tag(o, "ID", &e.id.to_string());
        tag(o, "Description", &format!("\"{}\"", e.description));
        if !e.options.is_empty() {
            let attrs: String = e.options.iter().map(|k| format!(" {}=\"1\"", esc(k))).collect();
            o.push_str(&format!("{p}  <Options{attrs}/>\n"));
        }
        if let Some(c) = e.color.as_deref().and_then(to_ce_color) {
            tag(o, "Color", &c);
        }
        if let Some(s) = &e.script {
            tag(o, "VariableType", "Auto Assembler Script");
            tag(o, "AssemblerScript", s);
        } else if e.addr.trim().is_empty() {
            tag(o, "GroupHeader", "1");
        } else {
            if e.hex {
                tag(o, "ShowAsHex", "1");
            }
            if e.signed {
                tag(o, "ShowAsSigned", "1");
            }
            let vt = match e.vtype {
                VType::Binary => "Binary",
                VType::Byte => "Byte",
                VType::Bytes2 => "2 Bytes",
                VType::Bytes8 => "8 Bytes",
                VType::Float => "Float",
                VType::Double => "Double",
                VType::String => "String",
                VType::Aob => "Array of byte",
                VType::Grouped => "Grouped",
                VType::Bytes4 | VType::All => "4 Bytes",
            };
            tag(o, "VariableType", vt);
            match e.vtype {
                VType::String => {
                    tag(o, "Length", &(if e.len == 0 { 16 } else { e.len }).to_string());
                    tag(o, "Unicode", if e.utf16 { "1" } else { "0" });
                    tag(o, "CodePage", "0");
                    tag(o, "ZeroTerminate", "1");
                }
                VType::Aob => tag(o, "ByteLength", &(if e.len == 0 { 8 } else { e.len }).to_string()),
                _ => {}
            }
            match e.freeze_mode {
                FreezeMode::AllowIncrease => tag(o, "AllowIncrease", "1"),
                FreezeMode::AllowDecrease => tag(o, "AllowDecrease", "1"),
                FreezeMode::Exact => {}
            }
            tag(o, "Address", &e.addr);
            if !e.offsets.is_empty() {
                o.push_str(&format!("{p}  <Offsets>\n"));
                for off in e.offsets.iter().rev() {
                    o.push_str(&format!("{p}    <Offset>{}</Offset>\n", esc(off)));
                }
                o.push_str(&format!("{p}  </Offsets>\n"));
            }
        }
        if let Some(dd) = &e.dropdown {
            let b = |v: bool| if v { "1" } else { "0" };
            let items: String = dd.options.iter().map(|i| format!("{}:{}\n", i.value, i.text)).collect();
            o.push_str(&format!(
                "{p}  <DropDownList DisplayValueAsItem=\"{}\" ReadOnly=\"{}\" DescriptionOnly=\"{}\">{}</DropDownList>\n",
                b(dd.display_value_as_item),
                b(dd.read_only),
                b(dd.description_only),
                esc(&items)
            ));
        }
        if !e.hotkeys.is_empty() {
            o.push_str(&format!("{p}  <Hotkeys>\n"));
            for (i, h) in e.hotkeys.iter().enumerate() {
                o.push_str(&format!("{p}    <Hotkey>\n{p}      <Action>{}</Action>\n{p}      <Keys>\n", esc(&h.action)));
                for k in &h.keys {
                    o.push_str(&format!("{p}        <Key>{k}</Key>\n"));
                }
                o.push_str(&format!("{p}      </Keys>\n"));
                if let Some(v) = &h.value {
                    o.push_str(&format!("{p}      <Value>{}</Value>\n", esc(v)));
                }
                if let Some(d) = &h.description {
                    o.push_str(&format!("{p}      <Description>\"{}\"</Description>\n", esc(d)));
                }
                o.push_str(&format!("{p}      <ID>{i}</ID>\n{p}    </Hotkey>\n"));
            }
            o.push_str(&format!("{p}  </Hotkeys>\n"));
        }
        for x in &e.ct_extra {
            o.push_str(&format!("{p}  {x}\n"));
        }
        if !e.children.is_empty() {
            write_entries(o, &e.children, d + 2);
        }
        o.push_str(&format!("{p}</CheatEntry>\n"));
    }
    o.push_str(&format!("{pad}</CheatEntries>\n"));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-written in the shape Cheat Engine 7.x saves.
    const CT: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<CheatTable CheatEngineTableVersion="45">
  <CheatEntries>
    <CheatEntry>
      <ID>1</ID>
      <Description>"Player"</Description>
      <Options moHideChildren="1" moActivateChildrenAsWell="0"/>
      <LastState Value="" RealAddress="00000000"/>
      <GroupHeader>1</GroupHeader>
      <CheatEntries>
        <CheatEntry>
          <ID>2</ID>
          <Description>"Health"</Description>
          <ShowAsSigned>1</ShowAsSigned>
          <Color>0000FF</Color>
          <VariableType>4 Bytes</VariableType>
          <Address>game.exe+1A2B30</Address>
          <Offsets>
            <Offset>8</Offset>
            <Offset>1C</Offset>
            <Offset>10</Offset>
          </Offsets>
          <Hotkeys>
            <Hotkey>
              <Action>Set Value</Action>
              <Keys>
                <Key>17</Key>
                <Key>112</Key>
              </Keys>
              <Value>999</Value>
              <ID>0</ID>
            </Hotkey>
          </Hotkeys>
        </CheatEntry>
        <CheatEntry>
          <ID>3</ID>
          <Description>"Name &amp; title"</Description>
          <VariableType>String</VariableType>
          <Length>24</Length>
          <Unicode>1</Unicode>
          <CodePage>0</CodePage>
          <ZeroTerminate>1</ZeroTerminate>
          <Address>7FF6A0001000</Address>
        </CheatEntry>
        <CheatEntry>
          <ID>4</ID>
          <Description>"Difficulty"</Description>
          <ShowAsHex>1</ShowAsHex>
          <BitStart>0</BitStart>
          <DropDownList DisplayValueAsItem="1" ReadOnly="0" DescriptionOnly="0">0:Easy
1:Hard
</DropDownList>
          <VariableType>Byte</VariableType>
          <Address>game.exe+200</Address>
          <CheatEntries>
            <CheatEntry>
              <ID>6</ID>
              <Description>"Bytes"</Description>
              <VariableType>Array of byte</VariableType>
              <ByteLength>6</ByteLength>
              <Address>game.exe+204</Address>
            </CheatEntry>
          </CheatEntries>
        </CheatEntry>
      </CheatEntries>
    </CheatEntry>
    <CheatEntry>
      <ID>5</ID>
      <Description>"Infinite ammo"</Description>
      <VariableType>Auto Assembler Script</VariableType>
      <AssemblerScript Async="1">[ENABLE]
aobscan(ammo, 89 46 ?? 8B)
alloc(newmem, $1000, ammo)
label(code)
newmem:
  mov [rsi+10],#999
code:
  jmp ammo+5
ammo:
  jmp newmem
[DISABLE]
ammo:
  db 89 46 10 8B 45
dealloc(newmem)
</AssemblerScript>
    </CheatEntry>
  </CheatEntries>
  <CheatCodes>
    <CodeEntry>
      <Description>"Change of mov [rbx+58],eax"</Description>
      <AddressString>game.exe+3A10</AddressString>
      <Before><Byte>48</Byte><Byte>8B</Byte></Before>
      <Actual><Byte>89</Byte><Byte>43</Byte><Byte>58</Byte></Actual>
      <After><Byte>C3</Byte></After>
    </CodeEntry>
  </CheatCodes>
  <UserdefinedSymbols/>
  <Structures StructVersion="2">
    <Structure Name="player" AutoFill="0" AutoCreate="1" DefaultHex="0" AutoDestroy="0" DoNotSaveLocal="0" RLECompression="1" AutoCreateStructsize="4096">
      <Elements>
        <Element Offset="0" Vartype="Pointer" Bytesize="8" OffsetHex="00000000" Description="inventory" DisplayMethod="Unsigned Integer" ChildStruct="inv"/>
        <Element Offset="16" Vartype="4 Bytes" Bytesize="4" OffsetHex="00000010" Description="health" DisplayMethod="Signed Integer"/>
        <Element Offset="20" Vartype="String" Bytesize="12" OffsetHex="00000014" Description="name &amp; tag" DisplayMethod="Unsigned Integer"/>
      </Elements>
    </Structure>
    <Structure Name="inv"><Elements><Element Offset="8" Vartype="Float" Bytesize="4" Description="weight"/></Elements></Structure>
  </Structures>
  <Comments>Info about this table:
works on v1.2</Comments>
  <LuaScript>local hp = getAddressList().getMemoryRecordByDescription('Health')
if hp and 1 &lt; 2 then print("loaded") end
</LuaScript>
</CheatTable>
"#;

    #[test]
    fn ct_import() {
        let t = from_ct(CT).unwrap();
        assert_eq!(t.entries.len(), 2);
        let g = &t.entries[0];
        assert_eq!((g.description.as_str(), g.addr.as_str(), g.children.len()), ("Player", "", 3));
        assert_eq!(g.options, ["moHideChildren"]);
        let hp = &g.children[0];
        assert_eq!(hp.addr, "game.exe+1A2B30");
        assert_eq!(hp.offsets, ["10", "1C", "8"]);
        assert!(hp.signed && hp.vtype == VType::Bytes4);
        assert_eq!(hp.color.as_deref(), Some("#FF0000"));
        assert_eq!(hp.hotkeys, [Hotkey { action: "Set Value".into(), keys: vec![17, 112], value: Some("999".into()), description: None }]);
        let s = &g.children[1];
        assert_eq!((s.description.as_str(), s.vtype, s.len, s.utf16), ("Name & title", VType::String, 24, true));
        let dd = &g.children[2];
        assert!(dd.hex);
        assert_eq!(dd.dropdown.as_ref().unwrap().options[1], DropdownItem { value: "1".into(), text: "Hard".into() });
        assert_eq!((dd.children[0].vtype, dd.children[0].len), (VType::Aob, 6));
        let sc = &t.entries[1];
        assert!(sc.addr.is_empty());
        assert!(sc.script.as_ref().unwrap().starts_with("[ENABLE]\naobscan(ammo, 89 46 ?? 8B)"));
        assert!(sc.script.as_ref().unwrap().contains("dealloc(newmem)"));
        // Table-level parts and unknown elements.
        assert!(t.lua_script.contains("1 < 2 then print(\"loaded\")"));
        assert_eq!(t.comments, "Info about this table:\nworks on v1.2");
        assert_eq!(t.codes, [CodeEntry { description: "Change of mov [rbx+58],eax".into(), address: "game.exe+3A10".into(), bytes: "89 43 58".into(), before: "48 8B".into(), after: "C3".into() }]);
        assert_eq!(t.ct_extra, ["<UserdefinedSymbols/>"]);
        let st = &t.structures;
        assert_eq!((st.len(), st[0].name.as_str(), st[0].elements.len(), st[1].name.as_str()), (2, "player", 3, "inv"));
        let el = &st[0].elements;
        assert_eq!((el[0].child.as_deref(), el[1].offset, el[1].signed, el[2].size, el[2].description.as_str()), (Some("inv"), 16, true, 12, "name & tag"));
        assert_eq!(dd.ct_extra, ["<BitStart>0</BitStart>"]);
        assert_eq!(g.ct_extra, ["<LastState Value=\"\" RealAddress=\"00000000\"/>"]);
    }

    #[test]
    fn ct_round_trip() {
        let t = from_ct(CT).unwrap();
        let back = from_ct(&to_ct(&t)).unwrap();
        assert_eq!(t, back);
    }

    #[test]
    fn json_and_ct_files() {
        let dir = std::env::temp_dir().join(format!("hh-table-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let t = from_ct(CT).unwrap();
        for name in ["t.json", "t.CT"] {
            let p = dir.join(name);
            save(&p, &t).unwrap();
            assert_eq!(load(&p).unwrap(), t, "{name}");
        }
        assert!(std::fs::read_to_string(dir.join("t.CT")).unwrap().contains("<CheatTable"));
        // The UI's own JSON shape: sparse entries, extra keys ignored.
        std::fs::write(dir.join("ui.json"), r#"{"entries":[{"id":7,"addr":"0x10","vtype":"float","extra":1,"children":[]}]}"#).unwrap();
        let u = load(&dir.join("ui.json")).unwrap();
        assert_eq!((u.entries[0].vtype, u.entries[0].addr.as_str()), (VType::Float, "0x10"));
        assert!(from_ct("<foo/>").is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
