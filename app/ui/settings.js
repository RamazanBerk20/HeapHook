// Settings dialog. The backend stores them (config dir) and enforces freeze interval and Lua
// budget; here they set the theme, the live-update interval and the defaults other views read.
import { api } from './backend.js';
import { $, attempt, toast, h, icon } from './util.js';
import { comboOf, comboText, MODS } from './keys.js';
import { state, emit, setTick } from './core.js';

const NUM = ['freeze_interval_ms', 'live_update_ms', 'scan_alignment', 'lua_budget_ms', 'lua_memory_mb', 'scan_threads', 'hotkey_delay_ms'];

function apply(s) {
  state.settings = s;
  const root = document.documentElement;
  if (s.theme === 'system') delete root.dataset.theme; else root.dataset.theme = s.theme;
  setTick(s.live_update_ms);
  emit('settings', s);
}

export async function initSettings() {
  const s = await attempt(() => api.settingsGet());
  if (s) apply(s);
  const d = $('#dlg-settings'), f = d.querySelector('form');
  // Debugger signals: the debugger's own table (names and defaults), what it does with each.
  const sigs = (await api.debugSignals().catch(() => [])) || [];
  const sigSel = new Map();
  if (sigs.length) {
    const grid = h('div.sig-grid');
    for (const [code, name, dflt] of sigs) {
      const sel = h('select.compact', { 'aria-label': `${name} (${code})` }, ['pass', 'ignore', 'break'].map((a) => h('option', { value: a }, a[0].toUpperCase() + a.slice(1) + (a === dflt ? ' (default)' : ''))));
      sigSel.set(code, sel);
      sel.addEventListener('change', () => sel.classList.toggle('changed', sel.value !== dflt));
      grid.append(h('label.sig-row', null, h('span.mono', null, `${name} `, h('span.muted', null, String(code))), sel));
    }
    const reset = h('button.btn.ghost', { type: 'button', title: 'Every signal back to the debugger\'s default action' }, 'Reset to defaults');
    reset.addEventListener('click', () => { for (const [code, , dflt] of sigs) { const x = sigSel.get(code); x.value = dflt; x.classList.remove('changed'); } });
    $('#st-path').before(h('fieldset.group', null, h('legend', null, 'Debugger signals'),
      h('p.hint', null, 'Pass: the process gets it. Ignore: it is dropped. Break: the debugger stops and asks. Applies to an attached debugger at once.'), grid, reset));
  }
  // HeapHook's own hotkeys: speedhack presets, pause / resume. Registered like table hotkeys.
  const hkRows = h('div.ahk-rows', { role: 'group', 'aria-label': 'HeapHook hotkeys' });
  const addHk = (hk = { action: 'speed', value: 2, keys: [] }) => {
    let keys = [...hk.keys];
    const act = h('select.compact', { 'aria-label': 'Action' }, h('option', { value: 'speed', selected: hk.action === 'speed' }, 'Set the speed to'), h('option', { value: 'pause', selected: hk.action === 'pause' }, 'Pause / resume the process'));
    const val = h('input.mono.num', { value: String(hk.value || 1), 'aria-label': 'Speed (0.001 to 1000)', spellcheck: 'false', autocomplete: 'off' });
    const keyBtn = h('button.btn.hk-keys.mono', { type: 'button', 'aria-label': 'Key combination; focus and press keys, Backspace clears' });
    const note = h('span.hint.ahk-note');
    const sync = () => {
      val.hidden = act.value !== 'speed';
      keyBtn.textContent = keys.length ? comboText(keys) : 'Press keys…';
      note.textContent = !keys.length ? '' : keys.some((k) => MODS.has(k)) ? 'system-wide on X11; under Wayland only sure while HeapHook has focus' : 'only while HeapHook has focus (no Ctrl, Shift, Alt or Win)';
    };
    act.onchange = sync;
    keyBtn.onkeydown = (ev) => {
      if (ev.key === 'Tab' && !ev.ctrlKey && !ev.altKey) return;
      ev.preventDefault(); ev.stopPropagation();
      if ((ev.key === 'Backspace' || ev.key === 'Delete') && !ev.ctrlKey && !ev.altKey && !ev.shiftKey) { keys = []; sync(); return; }
      const c = comboOf(ev);
      if (c.some((k) => !MODS.has(k))) { keys = c; sync(); } else keyBtn.textContent = comboText(c) + ' …';
    };
    keyBtn.onblur = sync;
    const row = h('div.ahk-row', null, act, val, keyBtn, note, h('button.btn.icon', { type: 'button', 'aria-label': 'Remove hotkey', html: icon('x'), onclick: () => row.remove() }));
    row.read = () => (keys.length ? { action: act.value, value: act.value === 'speed' ? +val.value || 1 : 0, keys } : null);
    hkRows.append(row);
    sync();
    return keyBtn;
  };
  $('#st-path').before(h('fieldset.group', null, h('legend', null, 'HeapHook hotkeys'),
    h('p.hint', null, 'Speedhack presets and pausing the process, from anywhere. A combination with Ctrl, Shift, Alt or Win is registered system-wide (X11). Under Wayland the desktop decides whether other windows let it through: count on it only while HeapHook has focus. A key without a modifier only ever works while HeapHook has focus.'),
    hkRows, h('button.btn.ghost', { type: 'button', onclick: () => addHk().focus(), html: icon('plus') + 'Hotkey' })));
  function open() {
    const cur = state.settings;
    hkRows.replaceChildren();
    (cur.app_hotkeys || []).forEach((x) => addHk(x));
    for (const [code, , dflt] of sigs) { const x = sigSel.get(code); x.value = cur.signals?.[code] ?? dflt; x.classList.toggle('changed', x.value !== dflt); }
    for (const el of f.elements) {
      if (!el.name || !(el.name in cur)) continue;
      if (el.type === 'checkbox') el.checked = !!cur[el.name]; else el.value = cur[el.name];
    }
    d.returnValue = '';
    $('#st-spill-hint').textContent = 'Loading the current directory…';
    api.scanProgress().then((p) => { $('#st-spill-hint').textContent = p?.spill_dir ? `Results that do not fit in memory currently go to ${p.spill_dir}` : ''; }, () => { $('#st-spill-hint').textContent = ''; });
    d.showModal();
    f.elements.theme.focus();
  }
  f.elements.theme.addEventListener('change', () => {
    // Preview the theme while the dialog is open; Cancel restores it below.
    const t = f.elements.theme.value, root = document.documentElement;
    if (t === 'system') delete root.dataset.theme; else root.dataset.theme = t;
  });
  d.addEventListener('close', async () => {
    if (d.returnValue !== 'ok') { apply(state.settings); return; }
    const next = { ...state.settings };
    for (const el of f.elements) {
      if (!el.name || !(el.name in next)) continue;
      next[el.name] = el.type === 'checkbox' ? el.checked : NUM.includes(el.name) ? Math.max(0, Math.round(+el.value || 0)) : el.name === 'scan_spill_dir' ? el.value.trim() : el.value;
    }
    next.app_hotkeys = [...hkRows.children].map((r) => r.read?.()).filter(Boolean);
    if (sigs.length) next.signals = Object.fromEntries(sigs.filter(([c, , dflt]) => sigSel.get(c).value !== dflt).map(([c]) => [String(c), sigSel.get(c).value]));
    const saved = await attempt(() => api.settingsSet(next));
    if (saved) { apply(saved); toast('Settings saved', 'info'); }
  });
  return { open };
}
