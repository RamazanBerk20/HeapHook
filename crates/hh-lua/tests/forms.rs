//! Forms: a trainer-style script driven through a recording `UiHost`, `fire_event` and
//! `ui_input`, toggling memory records.
mod common;

use std::sync::{Arc, Mutex};

use common::*;
use hh_core::Memory;
use hh_lua::{ControlId, ControlNode, Engine, EngineOptions, Prop, UiChange, UiHost};

#[derive(Default)]
struct Rec(Mutex<Vec<UiChange>>);
impl UiHost for Rec {
    fn changed(&self, c: &UiChange) {
        self.0.lock().unwrap().push(c.clone());
    }
    fn screen_size(&self) -> (i64, i64) {
        (1000, 800)
    }
}

fn find<'a>(n: &'a [ControlNode], f: &dyn Fn(&ControlNode) -> bool) -> Option<&'a ControlNode> {
    n.iter().find_map(|x| if f(x) { Some(x) } else { find(&x.children, f) })
}

const TRAINER: &str = r#"
local al = getAddressList()
godmode = al.createMemoryRecord()
godmode.Description = 'God mode'
godmode.Type = vtAutoAssembler
godmode.Script = INJECT
hp = al.createMemoryRecord()
hp.Description = 'Health'
hp.Address = 'game.exe+3020'

form = createForm(false)
form.Caption = 'Game Trainer +3'
form.Width, form.Height = 300, 220
form.BorderStyle = bsSingle
form.Color = clBlack
form.ShowInTaskBar = 'stAlways'           -- cosmetic, unknown to HeapHook: stored
form.Tag2 = { theme = 'dark' }            -- not a plain value: kept on the Lua side

local title = createLabel(form)
title.Caption = 'F1: god mode'
title.Font.Size = 14
title.Font.Color = clLime

status = createLabel(form)
status.Top = 80
status.Caption = 'OFF'

cb = createCheckBox(form)
cb.Caption = 'God mode'
cb.Top = 40
cb.OnChange = function(sender)
  godmode.Active = sender.Checked
  status.Caption = sender.Checked and 'ON' or 'OFF'
end

hpcb = createCheckBox(form)
hpcb.Caption = 'Freeze health'
hpcb.OnClick = function(s) hp.Active = s.Checked end

edit = createEdit(form)
edit.Text = '100'
btn = createButton(form)
btn.Caption = 'Set health'
btn.OnClick = function() hp.Value = edit.Text end

combo = createComboBox(form)
combo.Items.add('Easy')
combo.Items.add('Hard')
combo.OnChange = function(c) difficulty = c.Text end

tb = createTrackBar(form)
tb.Max = 100
tb.OnChange = function(t) speed = t.Position end
pb = createProgressBar(form)
pb.stepIt()

memo = createMemo(form)
memo.Lines.add('one')
memo.Lines.add('two')
lb = createListBox(form)
lb.Items.Text = 'x\ny\n'
lb.OnSelectionChange = function(l) picked = l.Items[l.ItemIndex] end

local mm = createMainMenu(form)
local file = createMenuItem(mm)
file.Caption = 'File'
mm.Items.add(file)
exit = createMenuItem(mm)
exit.Caption = 'Exit'
file.add(exit)
exit.OnClick = function() form.close() end
form.OnClose = function(sender) closed = true; return caFree end

hk = createHotkey(function() cb.Checked = not cb.Checked end, VK_F1)

form.centerScreen()
form.show()

assert(form.ShowInTaskBar == 'stAlways' and form.Tag2.theme == 'dark')
assert(title.Font.Size == 14 and title.Font.Name == 'default')
assert(cb.getCaption() == 'God mode' and cb.ClassName == 'TCheckBox' and cb.Parent == form and cb.Owner == form)
assert(form.ControlCount >= 10 and form.Control[0] == title)
assert(pb.Position == 10 and memo.Text == 'one\ntwo\n' and lb.Items.Count == 2)
assert(mm.Items.Count == 1 and mm.Items.Item[0] == file and file.Count == 1)
assert(form.Left == (getScreenWidth() - 300) // 2 and form.Top == (getScreenHeight() - 220) // 2, form.Left .. ',' .. form.Top)
assert(getFormCount() == 1 and getForm(0) == form)
IDS = { form = form.Handle, cb = cb.Handle, hpcb = hpcb.Handle, edit = edit.Handle, btn = btn.Handle,
        combo = combo.Handle, tb = tb.Handle, exit = exit.Handle, lb = lb.Handle }
"#;

fn id(e: &Engine, name: &str) -> ControlId {
    run(e, &format!("return IDS.{name}"))[0].parse().unwrap()
}

#[test]
fn trainer_form_drives_memory_records() {
    let (e, p, _) = engine();
    let rec = Arc::new(Rec::default());
    e.set_ui_host(rec.clone());
    e.lua().globals().set("INJECT", HEALTH_SCRIPT).unwrap();
    run(&e, TRAINER);

    // The host saw the tree being built.
    let changes = rec.0.lock().unwrap().clone();
    let form = id(&e, "form");
    assert!(matches!(&changes[0], UiChange::Create { control } if control.class == "TCEForm" && control.props["Visible"] == Prop::Bool(false)));
    assert!(changes.iter().any(|c| *c == UiChange::Update { id: form, prop: "Visible".into(), value: Prop::Bool(true) }));
    assert!(changes.iter().any(|c| matches!(c, UiChange::Event { event, set: true, .. } if event == "OnClose")));
    let snap = e.ui_snapshot();
    assert_eq!(snap.roots.len(), 1);
    assert_eq!((snap.roots[0].control.props["Left"].clone(), snap.roots[0].control.props["Top"].clone()), (Prop::Int(350), Prop::Int(290)));
    let f = &snap.roots[0];
    assert_eq!(f.control.props["Caption"], Prop::Str("Game Trainer +3".into()));
    assert_eq!(f.control.props["ShowInTaskBar"], Prop::Str("stAlways".into()));
    let title = find(&snap.roots, &|n| n.control.props.get("Caption") == Some(&Prop::Str("F1: god mode".into()))).unwrap();
    assert_eq!(title.control.props["Font.Size"], Prop::Int(14));
    let menu = find(&snap.roots, &|n| n.control.class == "TMainMenu").unwrap();
    assert_eq!(menu.children[0].children[0].control.props["Caption"], Prop::Str("File".into()));
    // Serializable for the UI.
    let json = serde_json::to_value(&snap).unwrap();
    assert_eq!(json["roots"][0]["class"], "TCEForm");
    assert!(serde_json::to_string(&changes).unwrap().contains("\"op\":\"create\""));

    // Hotkey toggles the checkbox, whose OnChange activates the injection.
    e.fire_hotkey(1).unwrap();
    assert_eq!(run(&e, "return cb.Checked, godmode.Active, status.Caption"), ["true", "true", "ON"]);
    let mut b = [0u8; 1];
    p.read_exact(GAME + 0x1005, &mut b).unwrap();
    assert_eq!(b[0], 0xE9, "injection written");

    // User clicks the checkbox in the UI: ui_input + OnChange.
    let n = rec.0.lock().unwrap().len();
    e.ui_input(id(&e, "cb"), "Checked", Prop::Bool(false)).unwrap();
    assert_eq!(run(&e, "return godmode.Active, status.Caption"), ["false", "OFF"]);
    p.read_exact(GAME + 0x1005, &mut b).unwrap();
    assert_eq!(b[0], 0x29, "injection removed");
    let after = rec.0.lock().unwrap()[n..].to_vec();
    assert!(!after.iter().any(|c| matches!(c, UiChange::Update { prop, .. } if prop == "Checked")), "user input is not echoed");

    // Typing a value and pressing the button writes it.
    e.ui_input(id(&e, "edit"), "Text", Prop::Str("250".into())).unwrap();
    e.fire_event(id(&e, "btn"), "OnClick", &[]).unwrap();
    assert_eq!(read_u32(&*p, GAME + 0x3020), 250);
    // A checkbox click fires OnClick too: freeze health.
    e.ui_input(id(&e, "hpcb"), "Checked", Prop::Bool(true)).unwrap();
    assert_eq!(run(&e, "return hp.Active"), ["true"]);
    e.ui_input(id(&e, "combo"), "ItemIndex", Prop::Int(1)).unwrap();
    e.ui_input(id(&e, "tb"), "Position", Prop::Int(42)).unwrap();
    e.ui_input(id(&e, "lb"), "ItemIndex", Prop::Int(1)).unwrap();
    assert_eq!(run(&e, "return difficulty, speed, picked, combo.Text"), ["Hard", "42", "y", "Hard"]);
    // Events with no handler are fine; handler results come back.
    assert!(e.fire_event(id(&e, "edit"), "OnDblClick", &[]).unwrap().is_empty());
    run(&e, "edit.OnKeyPress = function(sender, key) return key == 'a' and 'b' or key end");
    assert_eq!(e.fire_event(id(&e, "edit"), "OnKeyPress", &[Prop::Str("a".into())]).unwrap(), [Prop::Str("b".into())]);
    // Errors in handlers surface.
    run(&e, "btn.OnClick = function() error('click failed') end");
    assert!(e.fire_event(id(&e, "btn"), "OnClick", &[]).unwrap_err().to_string().contains("click failed"));

    // Menu Exit -> form.close() -> OnClose returns caFree -> destroyed.
    e.fire_event(id(&e, "exit"), "OnClick", &[]).unwrap();
    assert_eq!(run(&e, "return closed, getFormCount()"), ["true", "0"]);
    assert!(e.ui_snapshot().roots.is_empty());
    assert!(rec.0.lock().unwrap().contains(&UiChange::Destroy { id: form }));
    // Events for destroyed controls are ignored; writes to them raise.
    assert!(e.fire_event(form, "OnClick", &[]).unwrap().is_empty());
    assert!(e.exec("form.Caption = 'x'", "x").unwrap_err().to_string().contains("destroyed"));
}

#[test]
fn headless_forms_and_late_ui_host() {
    // No UI attached: the same script runs; a host attached later gets the tree.
    let (e, _, _) = engine();
    e.lua().globals().set("INJECT", HEALTH_SCRIPT).unwrap();
    run(&e, TRAINER);
    run(
        &e,
        r#"
        local m = getMainForm()
        assert(m.ClassName == 'TMainForm' and getMainForm() == m)
        local item = createMenuItem(nil)
        item.Caption = 'My cheat'
        assert(getScreenWidth() == 1920 and getScreenHeight() == 1080)
        f2 = createForm()
        f2.OnClose = function() return caNone end
        assert(f2.close() == caNone and f2.Visible)
        f2.OnClose = nil
        f2.close()
        assert(not f2.Visible, 'default close hides')
        f2.Visible = true
        assert(f2.showModal() == mrNone)
        local t = createTimer(f2)
        t.Interval = 1
        t.OnTimer = function() owned_tick = true end
        f2.destroy()
        app = getApplication()
        app.Title = 'Trainer'
        assert(getApplication().Title == 'Trainer')
    "#,
    );
    std::thread::sleep(std::time::Duration::from_millis(5));
    e.tick().unwrap();
    assert_eq!(run(&e, "return owned_tick"), ["nil"], "timer owned by the form died with it");
    let rec = Arc::new(Rec::default());
    e.set_ui_host(rec.clone());
    let c = rec.0.lock().unwrap().clone();
    let snap = e.ui_snapshot();
    assert!(!c.is_empty() && c.iter().all(|x| matches!(x, UiChange::Create { .. })));
    assert!(snap.roots.len() >= 2, "trainer form, main form, loose menu item");
    // Parents arrive before children.
    let mut seen = std::collections::HashSet::new();
    for x in &c {
        if let UiChange::Create { control } = x {
            assert!(control.parent.is_none_or(|p| seen.contains(&p)));
            seen.insert(control.id);
        }
    }
    let _ = Engine::new(EngineOptions::default()).unwrap().ui_snapshot();
}
