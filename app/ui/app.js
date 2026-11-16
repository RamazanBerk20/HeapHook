// Entry point: wires panels, process picker, view switching, global shortcuts, splitters.
import { api, isMock, isBridge } from './backend.js';
import { $, $$, h, icon, splitter, toast, closeMenu, attempt } from './util.js';
import { state, emit, on } from './core.js';
import { initResults } from './results.js';
import { initScan } from './scan.js';
import { initTable, VTYPES } from './table.js';
import { initMemview } from './memview.js';
import { initDebugger } from './debugger.js';
import { initPtrscan } from './ptrscan.js';
import { initLua } from './lua.js';
import { initSettings } from './settings.js';
import { initStructs } from './structs.js';
import { initDissect } from './dissect.js';
import { initForms } from './forms.js';
import { jobs } from './memtools.js';
import { askPath } from './backend.js';

// static icons
for (const el of $$('[data-icon]')) el.insertAdjacentHTML('afterbegin', icon(el.dataset.icon));
$('#ed-vtype').append(...VTYPES.map(([v, l]) => h('option', { value: v }, l)));
if (isMock) $('#mock-badge').hidden = false;
if (isBridge) Object.assign($('#mock-badge'), { hidden: false, textContent: 'dev bridge', title: 'Real backend over the development HTTP bridge: no native dialogs or global hotkeys' });

const results = initResults($('#results'));
const scan = initScan(results);
const table = initTable($('#table'));
const mem = initMemview();

// ---------- views ----------
function showView(v) {
  state.view = v;
  for (const t of $$('.tabs [role=tab]')) {
    const sel = t.dataset.view === v;
    t.setAttribute('aria-selected', String(sel));
    t.tabIndex = sel ? 0 : -1;
    $('#' + t.getAttribute('aria-controls')).hidden = !sel;
  }
  if (v === 'mem') mem.refresh();
  if (v === 'lua') lua.focus();
  if (v === 'struct') structs.refresh();
}
for (const t of $$('.tabs [role=tab]')) t.addEventListener('click', () => showView(t.dataset.view));
$('.tabs').addEventListener('keydown', (e) => {
  if (e.key !== 'ArrowLeft' && e.key !== 'ArrowRight') return;
  const tabs = $$('.tabs [role=tab]'), i = tabs.findIndex((t) => t.dataset.view === state.view);
  const n = tabs[(i + (e.key === 'ArrowRight' ? 1 : tabs.length - 1)) % tabs.length];
  n.focus(); showView(n.dataset.view);
});
on('mem:goto', (d) => { showView('mem'); mem.goto(d); });
const dbg = initDebugger({ showView, mem });
const ptr = initPtrscan({ showView });
const lua = initLua({ openTableScript: () => table.editTableScript() });
const structs = initStructs({ showView });
const code = initDissect({ showView });
const settings = await initSettings();
const forms = initForms();

// ---------- process picker ----------
const dlgProc = $('#dlg-proc'), pSearch = $('#proc-search'), pList = $('#proc-list');
let procs = [], shown = [], pIdx = 0;
function renderProcs() {
  const q = pSearch.value.trim().toLowerCase();
  shown = procs.filter((p) => !q || p.name.toLowerCase().includes(q) || String(p.pid).startsWith(q) || (p.exe || '').toLowerCase().includes(q));
  pIdx = Math.min(pIdx, Math.max(0, shown.length - 1));
  pList.replaceChildren(...shown.map((p, i) => h('div.proc', {
    role: 'option', id: 'proc-' + i, 'aria-selected': String(i === pIdx), 'data-i': i,
    class: state.proc?.pid === p.pid ? 'proc attached' : 'proc',
  }, h('span.mono.pid', null, String(p.pid)), h('span.name', null, p.name), h('span.exe', { title: p.exe || '' }, p.exe || ''),
  state.proc?.pid === p.pid ? h('span.badge.green', null, 'attached') : null)));
  pSearch.setAttribute('aria-activedescendant', shown.length ? 'proc-' + pIdx : '');
  $('#proc-empty').hidden = shown.length > 0;
  $(`#proc-${pIdx}`)?.scrollIntoView({ block: 'nearest' });
}
async function openPicker() {
  closeMenu();
  pSearch.value = '';
  pIdx = 0;
  dlgProc.showModal();
  pSearch.focus();
  $('#proc-close').hidden = !state.proc;
  try { procs = await api.listProcesses(); } catch (e) { procs = []; toast(e); }
  renderProcs();
}
function opened(info) {
  state.proc = info;
  $('#proc-label').textContent = `${info.name}`;
  $('#proc-meta').textContent = `${info.pid} · ${info.is_64bit ? '64-bit' : '32-bit'}`;
  $('#proc-btn').classList.add('attached');
  document.title = `${info.name} · HeapHook`;
  emit('process:opened', info);
  refreshSpeed();
  scan.focusValue();
}
let closing = false;
async function closeProcess(why = 'Process closed; the debugger is detached') {
  if (!state.proc || closing) return;
  dlgProc.close();
  closing = true;
  const ok = await attempt(async () => { await api.closeProcess(); return true; });
  closing = false;
  if (!ok) return;
  state.proc = null;
  $('#proc-label').textContent = 'No process';
  $('#proc-meta').textContent = '';
  $('#proc-btn').classList.remove('attached');
  document.title = 'HeapHook';
  emit('process:closed');
  refreshSpeed();
  toast(why, 'info');
}
// The Lua poll reports the backend's process: pick it up after a reload, close it when it exits.
let firstPoll = true;
on('backend:process', (p) => {
  if (firstPoll && p?.alive && !state.proc) opened(p);
  firstPoll = false;
  if (p && !p.alive && state.proc?.pid === p.pid) closeProcess(`${p.name} (pid ${p.pid}) exited; closed it`);
});
async function createProcess() {
  dlgProc.close();
  const d = $('#dlg-create'), f = d.querySelector('form');
  d.returnValue = '';
  d.onclose = async () => {
    if (d.returnValue !== 'ok') return;
    const req = { program: f.elements.program.value.trim(), args: f.elements.args.value, cwd: f.elements.cwd.value.trim(), speedhack: f.elements.speedhack.checked };
    const info = await attempt(() => api.processCreate(req));
    if (info) { opened(info); if (req.speedhack) toast('Started with the speedhack: the speed control is in the top bar', 'info'); }
  };
  d.showModal();
  f.elements.program.focus();
}
$('#cr-browse').addEventListener('click', async () => {
  const p = await askPath({ save: false, title: 'Program to start', filters: [['All files', ['*']]] });
  if (p) $('#cr-prog').value = p;
});
$('#proc-create').addEventListener('click', createProcess);
$('#proc-close').addEventListener('click', () => closeProcess());

// ---------- speedhack ----------
let speed = null;
async function refreshSpeed() {
  speed = state.proc ? await api.speedGet().catch(() => null) : null;
  $('#speed-btn').hidden = !speed;
  if (speed) $('#speed-text').textContent = `${+speed.speed.toFixed(3)}×`;
  $('#sp-status').textContent = speed ? `pid ${speed.pid} · control block ${speed.addr} · ${speed.generation} change(s)` : '';
  if (speed && !$('#dlg-speed').open) syncSpeedInputs();
}
const toRange = (v) => Math.round(Math.log10(v) * 100), fromRange = (r) => +(10 ** (r / 100)).toPrecision(3);
function syncSpeedInputs() { $('#sp-range').value = toRange(speed.speed); $('#sp-value').value = String(+speed.speed.toFixed(3)); }
async function setSpeed(v) {
  if (!speed) { toast('This process has no speedhack: start it with Create process (Ctrl P, then Ctrl N)'); return; }
  const st = await attempt(() => api.speedSet(v));
  if (st) { speed = st; refreshSpeed().then(() => { if ($('#dlg-speed').open && document.activeElement !== $('#sp-value')) syncSpeedInputs(); }); }
}
$('#speed-btn').addEventListener('click', () => { syncSpeedInputs(); $('#dlg-speed').showModal(); $('#sp-range').focus(); });
$('#sp-range').addEventListener('input', () => { $('#sp-value').value = String(fromRange(+$('#sp-range').value)); });
$('#sp-range').addEventListener('change', () => setSpeed(fromRange(+$('#sp-range').value)));
$('#sp-value').addEventListener('keydown', (e) => {
  if (e.key !== 'Enter') return;
  e.preventDefault();
  const v = parseFloat($('#sp-value').value);
  if (v > 0) setSpeed(v); else toast('Speed must be a number above 0');
});
$('#sp-reset').addEventListener('click', () => setSpeed(1));
$('#dlg-speed').addEventListener('keydown', (e) => { if (e.key.toLowerCase() === 'r' && e.target.id !== 'sp-value') { e.preventDefault(); setSpeed(1); } });

async function attach(p) {
  if (!p) return;
  dlgProc.close();
  try {
    const info = await api.openProcess(p.pid);
    opened(info);
  } catch (e) { toast(e); }
}
pSearch.addEventListener('input', () => { pIdx = 0; renderProcs(); });
pSearch.addEventListener('keydown', (e) => {
  const d = { ArrowDown: 1, ArrowUp: -1, PageDown: 10, PageUp: -10 }[e.key];
  if (d) { e.preventDefault(); pIdx = Math.max(0, Math.min(shown.length - 1, pIdx + d)); renderProcs(); }
  else if (e.key === 'Enter') { e.preventDefault(); attach(shown[pIdx]); }
  else if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'n') { e.preventDefault(); createProcess(); }
  else if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'w') { e.preventDefault(); closeProcess(); }
});
pList.addEventListener('click', (e) => { const r = e.target.closest('.proc'); if (r) attach(shown[+r.dataset.i]); });
$('#proc-refresh').addEventListener('click', async () => { procs = await api.listProcesses().catch((e) => (toast(e), procs)); renderProcs(); pSearch.focus(); });
$('#proc-btn').addEventListener('click', openPicker);

// ---------- toolbar ----------
$('#tbl-open').addEventListener('click', table.load);
$('#tbl-save').addEventListener('click', table.save);
$('#help-btn').addEventListener('click', () => $('#dlg-help').showModal());
$('#settings-btn').addEventListener('click', () => settings.open());

// ---------- global shortcuts ----------
document.addEventListener('keydown', (e) => {
  if (document.querySelector('dialog[open]')) return;
  const k = e.key.toLowerCase(), ctrl = e.ctrlKey || e.metaKey;
  const inField = !!e.target.matches?.('input, select, textarea');
  if (ctrl && k === 'p') openPicker();
  else if (ctrl && k === '1') showView('scan');
  else if (ctrl && k === '2') showView('mem');
  else if (ctrl && k === '3') { showView('dbg'); dbg.focus(); }
  else if (ctrl && k === '4') { showView('ptr'); ptr.focus(); }
  else if (ctrl && k === '5') showView('lua');
  else if (ctrl && k === '6') { showView('struct'); structs.focus(); }
  else if (ctrl && k === '7') { showView('code'); code.focus(); }
  else if (ctrl && e.shiftKey && k === 'w') closeProcess();
  else if (ctrl && e.shiftKey && e.key === 'ArrowUp') setSpeed(Math.min(1000, (speed?.speed || 1) * 2));
  else if (ctrl && e.shiftKey && e.key === 'ArrowDown') setSpeed((speed?.speed || 1) / 2);
  else if (ctrl && e.shiftKey && e.key === 'Backspace') setSpeed(1);
  else if (e.key === 'Escape' && jobs.running) jobs.cancel();
  else if (ctrl && k === ',') settings.open();
  else if (ctrl && e.shiftKey && k === 'd') dbg.toggleAttach();
  else if (ctrl && e.shiftKey && k === 'l') forms.cycle();
  else if (e.key === 'F9' && !ctrl) e.shiftKey ? dbg.pause() : dbg.cont();
  else if (e.key === 'F7' && !ctrl) dbg.step('into');
  else if (e.key === 'F8' && !ctrl) dbg.step(e.shiftKey ? 'out' : 'over');
  else if (ctrl && k === 'o') table.load();
  else if (ctrl && k === 's') table.save();
  else if (ctrl && e.shiftKey && k === 'a') { showView('scan'); table.addDialog(); }
  else if (ctrl && k === 'n') { showView('scan'); scan.newScan(); }
  else if (ctrl && k === 'enter') { showView('scan'); scan.run(); }
  else if (ctrl && k === 'z' && !inField) scan.undo();
  else if (e.key === 'Escape' && scan.running) scan.cancel();
  else if (e.key === 'Escape' && ptr.running) ptr.cancel();
  else if (e.key === 'Escape' && lua.busy) lua.interrupt();
  else if (e.key === 'F1') $('#dlg-help').showModal();
  else if (e.altKey && k === '1') { showView('scan'); scan.focusValue(); }
  else if (e.altKey && k === '2') { showView('scan'); results.focus(); }
  else if (e.altKey && k === '3') { showView('scan'); table.focus(); }
  else if (e.altKey && k === '4') { showView('mem'); $('#da-list').focus(); }
  else if (e.altKey && k === '5') { showView('mem'); $('#hx-list').focus(); }
  else return;
  e.preventDefault();
});

// ---------- splitters ----------
splitter($('#div-scan'), $('#scan-panel'), { axis: 'x', key: 'split.scanPanel', min: 260, max: () => innerWidth * 0.5, sign: -1, initial: 320 });
splitter($('#div-table'), $('#scan-top'), { axis: 'y', key: 'split.table', min: 180, max: () => innerHeight - 220, initial: Math.round(innerHeight * 0.55) });
splitter($('#div-mem'), $('#disasm-pane'), { axis: 'y', key: 'split.disasm', min: 120, max: () => innerHeight - 200, initial: Math.round(innerHeight * 0.45) });
splitter($('#div-side'), $('#mem-side'), { axis: 'x', key: 'split.side', min: 220, max: () => innerWidth * 0.45, sign: -1, initial: 340 });

showView('scan');
