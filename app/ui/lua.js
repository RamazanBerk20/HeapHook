// Lua console view, the dialogs scripts open (showMessage / messageDialog / inputQuery), the
// backend poller (console log, table version, bound hotkeys, beeps) and in-app hotkeys.
import { api } from './backend.js';
import { $, h, store, toast, modal, splitter } from './util.js';
import { state, emit } from './core.js';
import { comboOf } from './keys.js';

const POLL_MS = 250;
const MAX_LINES = 2000;
const MB = ['Yes', 'No', 'OK', 'Cancel', 'Abort', 'Retry', 'Ignore', 'All', 'No to all', 'Yes to all', 'Help', 'Close'];
const MT = ['Warning', 'Error', 'Information', 'Confirmation', ''];

export function initLua({ openTableScript }) {
  const out = $('#lua-out'), ta = $('#lua-text'), gut = $('#lua-gutter');
  const bRun = $('#lua-run'), bStop = $('#lua-stop'), status = $('#lua-state');
  let since = 0, busy = false, running = false, shownDialog = 0, sound = null;
  let history = store.get('lua.history', []), hIdx = history.length, draft = '';
  let bound = new Set();

  // ---------- output ----------
  function append(lines) {
    if (!lines.length) return;
    out.querySelector('.empty')?.remove();
    const stick = out.scrollHeight - out.scrollTop - out.clientHeight < 24;
    for (const l of lines) out.append(h('div.lua-line.' + l.kind, null, l.kind === 'in' ? l.text.replace(/\n/g, '\n  ') : l.text));
    while (out.childElementCount > MAX_LINES) out.firstElementChild.remove();
    if (stick) out.scrollTop = out.scrollHeight;
    if (state.view !== 'lua' && lines.some((l) => l.kind === 'err')) $('[data-view=lua]').classList.add('unread');
  }

  // ---------- editor ----------
  const lines = () => {
    gut.textContent = Array.from({ length: ta.value.split('\n').length }, (_, i) => i + 1).join('\n');
    gut.scrollTop = ta.scrollTop;
  };
  ta.addEventListener('input', lines);
  ta.addEventListener('scroll', () => { gut.scrollTop = ta.scrollTop; });
  async function run() {
    const code = ta.value;
    if (!code.trim() || running) return;
    if (history[history.length - 1] !== code) history.push(code);
    history = history.slice(-100);
    store.set('lua.history', history);
    hIdx = history.length; draft = '';
    running = true; sync();
    try { await api.luaExec(code); ta.value = ''; lines(); } catch { /* the error is in the log */ }
    running = false;
    await poll();
    sync();
  }
  function recall(d) {
    if (!history.length) return;
    if (hIdx === history.length) draft = ta.value;
    hIdx = Math.max(0, Math.min(history.length, hIdx + d));
    ta.value = hIdx === history.length ? draft : history[hIdx];
    lines();
  }
  ta.addEventListener('keydown', (e) => {
    const ctrl = e.ctrlKey || e.metaKey;
    if (ctrl && e.key === 'Enter') run();
    else if (ctrl && e.key === 'ArrowUp') recall(-1);
    else if (ctrl && e.key === 'ArrowDown') recall(1);
    else if (e.key === 'Escape' && busy) api.luaInterrupt();
    else if (e.key === 'Tab' && !e.shiftKey && !ctrl) ta.setRangeText('  ', ta.selectionStart, ta.selectionEnd, 'end');
    else return;
    e.preventDefault(); e.stopPropagation();
  });
  bRun.addEventListener('click', run);
  bStop.addEventListener('click', () => api.luaInterrupt().catch(toast));
  $('#lua-clear').addEventListener('click', () => out.replaceChildren());
  $('#lua-tscript').addEventListener('click', openTableScript);
  splitter($('#div-lua'), $('#lua-ed'), { axis: 'y', key: 'split.lua', min: 80, max: () => innerHeight - 200, sign: -1, initial: 180 });
  lines();

  function sync() {
    bStop.disabled = !busy;
    bRun.disabled = running;
    status.textContent = busy ? 'running…' : '';
  }

  // ---------- dialogs from scripts ----------
  async function showDialog(d) {
    shownDialog = d.id;
    let value = null;
    if (d.kind === 'message') {
      await modal({ title: 'Message', text: d.text, buttons: [{ label: 'OK', value: 'ok', primary: true, kbd: 'Enter' }] });
    } else if (d.kind === 'dialog') {
      const buttons = (d.buttons.length ? d.buttons : [2]).map((b, i) => ({ label: MB[b] ?? `Button ${b}`, value: String(b), primary: i === 0 }));
      const r = await modal({ title: d.title || MT[d.dlg_type] || 'Question', text: d.text, buttons });
      value = r.value === 'cancel' ? null : +r.value;
    } else {
      const r = await modal({ title: d.title || 'Input', text: d.text, input: d.initial,
        buttons: [{ label: 'OK', value: 'ok', primary: true, kbd: 'Enter' }, { label: 'Cancel', value: 'cancel', kbd: 'Esc' }] });
      value = r.value === 'ok' ? r.input : null;
    }
    await api.luaDialogReply(d.id, value).catch(toast);
  }

  // ---------- beeps (hotkey sound setting, Lua beep()) ----------
  let actx = null;
  function beep() {
    try {
      actx ??= new AudioContext();
      const o = actx.createOscillator(), g = actx.createGain();
      o.frequency.value = 880; g.gain.value = 0.06;
      o.connect(g).connect(actx.destination);
      o.start(); o.stop(actx.currentTime + 0.08);
    } catch { /* no audio device: stay silent */ }
  }

  // ---------- poller ----------
  let polling = false;
  async function poll() {
    if (polling) return;
    polling = true;
    try {
      const p = await api.luaPoll(since);
      since = p.next;
      append(p.log);
      if (p.dialog && p.dialog.id !== shownDialog) showDialog(p.dialog);
      emit('table:version', p.table_version);
      bound = new Set(p.hotkeys.map((k) => k.join(',')));
      if (busy !== p.busy) { busy = p.busy; sync(); }
      if (sound != null && p.sound > sound) beep();
      sound = p.sound;
    } catch (e) {
      console.warn('lua poll failed:', e);
    } finally { polling = false; }
  }
  setInterval(() => { if (!document.hidden) poll(); }, POLL_MS);
  poll();

  // ---------- in-app hotkeys (global ones are grabbed by the OS before this sees them) ----------
  const PRINTABLE = (k) => k === 32 || (k >= 48 && k <= 90) || (k >= 96 && k <= 111) || k >= 186;
  window.addEventListener('keydown', (e) => {
    if (!bound.size || document.querySelector('dialog[open]') || e.repeat) return;
    const c = comboOf(e);
    if (!bound.has(c.join(','))) return;
    // Typing into a field is not a hotkey unless a modifier or a non-character key is involved.
    const typing = e.target.matches?.('input, textarea, select, [contenteditable]');
    if (typing && !e.ctrlKey && !e.altKey && !e.metaKey && c.every((k) => k === 16 || PRINTABLE(k))) return;
    e.preventDefault(); e.stopPropagation();
    api.hotkeyPress(c).catch(toast);
  }, true);

  return {
    focus() { $('[data-view=lua]').classList.remove('unread'); ta.focus(); },
    get busy() { return busy; },
    interrupt: () => api.luaInterrupt().catch(toast),
  };
}
