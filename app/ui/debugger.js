// Debugger: attach state (top bar), watches ("find out what writes / accesses", "what addresses
// this instruction accesses", break-and-trace), breakpoints, code list, and the break state
// (registers, stack, threads) in the memory view's side panel.
import { api } from './backend.js';
import { $, $$, h, fmtAddr, isHexAddr, attempt, toast, nf, splitter, modal } from './util.js';
import { vlist } from './vlist.js';
import { state, emit, on, addTicker } from './core.js';

const VSIZE = { byte: 1, binary: 1, '2bytes': 2, '4bytes': 4, '8bytes': 8, float: 4, double: 8 };
const GPR = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'rip'];
const FLAGS = [['CF', 0], ['PF', 2], ['AF', 4], ['ZF', 6], ['SF', 7], ['TF', 8], ['IF', 9], ['DF', 10], ['OF', 11]];
const SEGS = ['cs', 'ds', 'es', 'fs', 'gs', 'ss'];
const KIND = { write: 'Writes', access: 'Accesses', ea: 'Addresses', trace: 'Trace' };
const WL_COLS = '64px 116px minmax(0, 1fr) 116px';
const COND_HINT = 'Condition, e.g. rax==5 && rcx>0x100  (rax..r15, eax..r15d, rip, rflags; + - * & | ^  == != < <= > >=  ! && ||  parentheses)';

const r64 = (v) => BigInt(v).toString(16).toUpperCase().padStart(16, '0');
/** xmm hex (little-endian bytes) -> dwords high to low, and float lanes. */
function xmmText(hex) {
  const b = Uint8Array.from(hex.match(/../g), (x) => parseInt(x, 16)), dv = new DataView(b.buffer);
  const dw = [3, 2, 1, 0].map((i) => dv.getUint32(i * 4, true).toString(16).toUpperCase().padStart(8, '0')).join(' ');
  const fl = [3, 2, 1, 0].map((i) => +dv.getFloat32(i * 4, true).toPrecision(6)).join(' · ');
  return [dw, fl];
}

export function initDebugger({ showView, mem }) {
  const dbg = (state.dbg = { attached: false, state: 'detached', tid: null, rip: null, reason: null, exit_code: null, bpAddrs: new Set(), bps: [] });
  let curTid = null, lastCtx = null, prevCtx = null;
  const watches = [];
  let active = null;
  let codes = [], codeKey = '', codeSel = 0, bpSel = 0;

  // ---------- attach state ----------
  function renderChip() {
    const b = $('#dbg-btn'), s = dbg.attached ? dbg.state : 'detached';
    b.dataset.state = s;
    $('#dbg-state').textContent = !dbg.attached ? 'Debugger off'
      : s === 'broken' ? `Broken · thread ${dbg.tid}` : s === 'exited' ? `Exited${dbg.exit_code != null ? ' · ' + dbg.exit_code : ''}`
        : s === 'suspended' ? 'Suspended' : 'Running';
    b.title = (dbg.reason && s === 'broken' ? `Stopped: ${dbg.reason}. ` : '') + (dbg.attached ? 'Detach the debugger' : 'Attach the debugger') + ' (Ctrl Shift D)';
    $('#dbg-ctl').hidden = !dbg.attached;
    for (const id of ['dc-cont', 'dc-into', 'dc-over', 'dc-out', 'dc-runto']) $('#' + id).disabled = s !== 'broken';
    $('#dc-pause').disabled = s !== 'running';
    for (const t of $$('#mem-side .dbg-only')) {
      t.hidden = !dbg.attached;
      if (t.hidden && t.getAttribute('aria-selected') === 'true') mem.side('reg-list');
    }
  }
  function apply(st) {
    const was = dbg.state, wasRip = dbg.rip;
    Object.assign(dbg, st, { rip: st.rip ? BigInt(st.rip) : null });
    renderChip();
    if (st.state === 'broken' && (was !== 'broken' || wasRip !== dbg.rip)) onBreak(was !== 'broken');
    else if (was === 'broken' && st.state !== 'broken') { emit('debug:marks'); renderBreak(); }
  }
  async function refresh() { if (dbg.attached) apply(await api.debugStatus()); }

  async function attach() {
    if (!state.proc) { toast('Open a process first'); return false; }
    if (dbg.attached) return true;
    const st = await attempt(() => api.debugAttach());
    if (!st) return false;
    apply(st);
    toast('Debugger attached; memory access now goes through it', 'info');
    return true;
  }
  function reset() {
    Object.assign(dbg, { attached: false, state: 'detached', tid: null, rip: null, reason: null, exit_code: null, bps: [] });
    dbg.bpAddrs = new Set();
    curTid = null; lastCtx = prevCtx = null;
    for (const w of watches) w.stopped = true;
    renderChip(); renderBps(); renderTabs(); renderBreak(); emit('debug:marks');
  }
  async function detach() {
    if (!dbg.attached) return;
    if (await attempt(async () => { await api.debugDetach(); return true; })) { reset(); toast('Debugger detached', 'info'); }
  }
  const toggleAttach = () => (dbg.attached ? detach() : attach());
  $('#dbg-btn').addEventListener('click', toggleAttach);
  on('debug:attach', attach);

  // ---------- run control ----------
  const run = (f) => async () => { if (dbg.attached && await attempt(async () => { await f(); return true; })) setTimeout(() => attempt(refresh), 60); };
  const tid = () => curTid ?? dbg.tid;
  const resume = (pass) => run(() => api.debugContinue(pass))();
  /** A stop caused by a signal asks first whether the process gets it. */
  async function cont() {
    if (!dbg.attached) return;
    if (dbg.state === 'broken' && /^signal/i.test(dbg.reason || '')) {
      const r = await modal({
        title: `Signal ${dbg.reason.replace(/^signal\s*/i, '')}`,
        text: 'The process stopped because it received this signal. Pass it on to let the process handle it (or crash), or discard it and continue as if it never arrived.',
        buttons: [{ label: 'Pass to the process', value: 'pass', primary: true }, { label: 'Discard signal', value: 'discard' }, { label: 'Cancel', value: 'cancel', kbd: 'Esc' }],
      });
      if (r.value === 'cancel') return;
      return resume(r.value === 'pass');
    }
    return resume(false);
  }
  const pause = run(() => api.debugPause());
  const step = (kind) => run(() => api.debugStep(tid(), kind))();
  const runTo = (addr) => run(() => api.debugRunTo(addr))();
  $('#dc-cont').addEventListener('click', cont);
  $('#dc-pause').addEventListener('click', pause);
  $('#dc-into').addEventListener('click', () => step('into'));
  $('#dc-over').addEventListener('click', () => step('over'));
  $('#dc-out').addEventListener('click', () => step('out'));
  $('#dc-runto').addEventListener('click', () => { const a = mem.cursor(); if (a) runTo(a); });
  on('debug:run-to', (a) => { if (dbg.state === 'broken') runTo(a); else toast('Run to cursor needs the process stopped at a break'); });

  function onBreak(fresh) {
    curTid = dbg.tid;
    emit('debug:marks');
    if (fresh) { showView('mem'); mem.side('cpu-list'); }
    mem.goto({ addr: '0x' + dbg.rip.toString(16), pane: 'da' });
    loadBreak();
  }

  // ---------- breakpoints ----------
  async function loadBps() {
    if (!dbg.attached) return;
    dbg.bps = await api.debugBreakpoints();
    const addrs = new Set(dbg.bps.filter((b) => b.enabled && b.kind === 'execute' && b.action === 'break').map((b) => BigInt(b.addr)));
    const changed = addrs.size !== dbg.bpAddrs.size || [...addrs].some((a) => !dbg.bpAddrs.has(a));
    dbg.bpAddrs = addrs;
    if (changed) emit('debug:marks');
    renderBps();
  }
  const bpList = $('#bp-list');
  function renderBps() {
    const bps = dbg.bps;
    bpSel = Math.max(0, Math.min(bpSel, bps.length - 1));
    $('#bp-count').textContent = bps.length || '';
    bpList.replaceChildren(...bps.map((b, i) => h('div.li.bp-row', {
      role: 'option', id: 'bp-' + b.id, 'aria-selected': String(i === bpSel), 'data-i': i, class: b.enabled ? 'li bp-row' : 'li bp-row off',
    },
    h('span.box', { 'data-act': 'toggle', role: 'checkbox', 'aria-checked': String(b.enabled), 'aria-label': 'Enabled', html: b.enabled ? '<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" aria-hidden="true"><path d="m5 12 5 5 9-10"/></svg>' : '' }),
    h('span.mono', null, fmtAddr(b.addr)),
    h('span', null, `${b.kind}${b.kind !== 'execute' ? ' ' + b.size : ''}`),
    bpInfo(b),
    h('span.mono.muted.hits', { title: 'Hits' }, nf.format(b.hits)))));
    bpList.setAttribute('aria-activedescendant', bps[bpSel] ? 'bp-' + bps[bpSel].id : '');
    if (!bps.length) bpList.append(h('p.empty', null, dbg.attached ? 'No breakpoints. F5 in the disassembler sets one.' : 'Debugger not attached.'));
  }
  function bpInfo(b) {
    const t = `${b.method === 'hardware' ? 'hw' + (b.slot != null ? ' DR' + b.slot : '') : 'int3'} · ${b.ea ? 'addresses' : b.action}${b.condition ? ' · if ' + b.condition : ''}`;
    return h('span.muted' + (b.condition ? '.mono' : ''), { title: b.condition ? t : null }, t);
  }
  bpList.title = 'Insert: add · E or F2: condition · H: software / hardware · Space: enable · Del: remove';
  /** Add dialog (no `bp`) or condition editor (`bp`: the other fields stay as they are). */
  function bpDialog({ addr = '', bp = null } = {}) {
    const sel = (name, vals, v) => h('select', { name }, vals.map((x) => h('option', { value: x, selected: String(x) === String(v) }, String(x))));
    const addrI = h('input.mono', { type: 'text', value: bp ? fmtAddr(bp.addr) : addr ? fmtAddr(addr) : '', spellcheck: 'false', autocomplete: 'off', placeholder: 'address or expression', disabled: !!bp });
    const kind = sel('kind', ['execute', 'write', 'access'], bp?.kind ?? 'execute'), size = sel('size', [1, 2, 4, 8], bp?.size ?? 4);
    const method = sel('method', ['software', 'hardware'], bp?.method ?? state.settings.bp_method);
    const cond = h('input.mono', { type: 'text', value: bp?.condition ?? '', spellcheck: 'false', autocomplete: 'off', placeholder: 'rax==5 && rcx>0x100' });
    const err = h('p.hint.mono', { role: 'alert' });
    const syncOpts = () => {
      const x = kind.value === 'execute';
      size.disabled = !!bp || x;
      if (!x) method.value = 'hardware';
      method.disabled = !!bp || !x;
      kind.disabled = !!bp;
    };
    kind.addEventListener('change', syncOpts);
    const form = h('form', { method: 'dialog' },
      h('h2', null, bp ? 'Breakpoint condition' : 'Add breakpoint'),
      h('label.field', null, h('span', null, 'Address'), addrI),
      h('div.row2.row2-even', null, h('label.field', null, h('span', null, 'Kind'), kind), h('label.field', null, h('span', null, 'Size (write / access)'), size)),
      h('label.field', null, h('span', null, 'Method (watches always use hardware)'), method),
      h('label.field', null, h('span', null, 'Condition (optional)'), cond),
      h('p.hint.mono', null, COND_HINT), err,
      h('div.dlg-actions', null,
        h('button.btn.primary', { value: 'ok', type: 'submit' }, bp ? 'Set ' : 'Add ', h('kbd', null, 'Enter')),
        h('button.btn', { value: 'cancel', type: 'submit', formnovalidate: true }, 'Cancel ', h('kbd', null, 'Esc'))));
    const d = h('dialog.dlg.dlg-sm', { 'aria-label': bp ? 'Breakpoint condition' : 'Add breakpoint' }, form);
    form.addEventListener('submit', async (e) => {
      if (e.submitter?.value === 'cancel') return;
      e.preventDefault();
      err.textContent = '';
      const c = cond.value.trim() || null;
      try {
        if (bp) await api.debugSetCondition(bp.id, c ?? '');
        else {
          const t = addrI.value.trim();
          if (!t) throw 'Enter an address';
          const a = isHexAddr(t) ? '0x' + t.replace(/^0x/i, '') : await api.resolveAddress(t), k = kind.value;
          await api.debugAddBreakpoint({ addr: a, kind: k, ...(k === 'execute' ? {} : { size: +size.value }), method: k === 'execute' ? method.value : 'hardware', action: 'break', condition: c });
        }
      } catch (ex) { err.textContent = String(ex?.message || ex); return; }
      d.close('ok');
      attempt(loadBps);
    });
    d.addEventListener('close', () => d.remove());
    document.body.append(d);
    syncOpts();
    d.showModal();
    (bp || addrI.value ? cond : addrI).focus();
  }
  /** Switches an execute breakpoint between int3 and a debug register: re-added with the same settings. */
  async function swapMethod(b) {
    if (!b || b.kind !== 'execute') return;
    const mk = (method) => ({ addr: b.addr, kind: b.kind, size: b.size, method, action: b.action, ea: b.ea, condition: b.condition || null });
    const to = b.method === 'hardware' ? 'software' : 'hardware';
    if (!(await attempt(async () => { await api.debugRemoveBreakpoint(b.id); return true; }))) return;
    let id = await attempt(() => api.debugAddBreakpoint(mk(to)));
    if (id == null) id = await attempt(() => api.debugAddBreakpoint(mk(b.method)));
    if (id != null) {
      if (!b.enabled) await attempt(() => api.debugSetEnabled(id, false));
      const w = watches.find((x) => x.id === b.id);
      if (w) w.id = id;
    }
    await attempt(loadBps);
  }
  async function removeBp(b) {
    if (!b || !(await attempt(async () => { await api.debugRemoveBreakpoint(b.id); return true; }))) return;
    const w = watches.find((x) => x.id === b.id);
    if (w) { w.stopped = true; renderTabs(); }
    await attempt(loadBps);
  }
  async function toggleBp(b) {
    if (b && await attempt(async () => { await api.debugSetEnabled(b.id, !b.enabled); return true; })) await attempt(loadBps);
  }
  bpList.addEventListener('mousedown', (e) => {
    const r = e.target.closest('.bp-row');
    if (!r) return;
    bpSel = +r.dataset.i;
    if (e.target.closest('[data-act]')) { e.preventDefault(); toggleBp(dbg.bps[bpSel]); }
    renderBps();
  });
  bpList.addEventListener('dblclick', (e) => { const r = e.target.closest('.bp-row'); if (r) emit('mem:goto', { addr: dbg.bps[+r.dataset.i].addr, pane: 'da' }); });
  bpList.addEventListener('keydown', (e) => {
    if (e.ctrlKey || e.metaKey || e.altKey) return;
    const b = dbg.bps[bpSel];
    if (e.key === 'ArrowDown') bpSel++;
    else if (e.key === 'ArrowUp') bpSel--;
    else if (e.key === ' ') toggleBp(b);
    else if (e.key === 'Delete') removeBp(b);
    else if (e.key === 'Insert') bpDialog();
    else if ((e.key === 'e' || e.key === 'E' || e.key === 'F2') && b) bpDialog({ bp: b });
    else if ((e.key === 'h' || e.key === 'H') && b) swapMethod(b);
    else if (e.key === 'Enter' && b) emit('mem:goto', { addr: b.addr, pane: 'da' });
    else return;
    e.preventDefault(); e.stopPropagation();
    renderBps();
  });
  on('debug:bp-dialog', async (addr) => { if (await attach()) { await attempt(loadBps); bpDialog({ addr }); } });
  on('debug:toggle-bp', async (addr) => {
    if (!(await attach())) return;
    const b = dbg.bps.find((x) => x.kind === 'execute' && x.action === 'break' && !x.ea && BigInt(x.addr) === BigInt(addr));
    if (b) await removeBp(b);
    else if (await attempt(() => api.debugAddBreakpoint({ addr, kind: 'execute', method: state.settings.bp_method, action: 'break' })) != null) await attempt(loadBps);
  });

  // ---------- watches ----------
  const tabs = $('#wl-tabs'), list = $('#wl-list');
  // The list is virtualized (vlist), so a trace can hold any number of rows; #wl-head keeps the labels.
  Object.assign(list.style, { display: 'flex', flexDirection: 'column', overflow: 'hidden' });
  list.removeAttribute('tabindex'); list.removeAttribute('role'); list.removeAttribute('aria-label');
  const wl = vlist(list, {
    cols: WL_COLS, label: 'Watch records', row: 22,
    empty: () => (!active ? '' : active.stopped ? 'Stopped before any hit.' : active.kind === 'trace' ? 'Waiting for the instruction to execute…' : 'Waiting for the first hit…'),
    count: () => active?.rows.length ?? 0,
    item: (i) => active?.rows[i] ?? null,
    cells(r, i) {
      const trace = active.kind === 'trace', ea = active.kind === 'ea', [m, ...rest] = r.text.split(' ');
      return [trace ? String(i + 1) : nf.format(r.count), fmtAddr(ea ? r.address : r.addr),
        h('span.c-text', { role: 'gridcell' }, h('b', null, m), rest.length ? ' ' + rest.join(' ') : ''), h('span.muted', null, ea ? fmtAddr(r.addr) : '')];
    },
    rowClass: () => 'wl-row',
    onSelect: (i, r) => { if (active) active.sel = i; renderSnap(r?.context); syncTools(); },
    onActivate: (i, r) => r && emit('mem:goto', { addr: r.addr, pane: 'da' }),
    onKey(e, i, r) {
      if (e.ctrlKey || e.metaKey || e.altKey) return false;
      const k = e.key.toLowerCase();
      if (k === 'n' && r) addToCode(r, true);
      else if (k === 'l' && r) addToCode(r, false);
      else if (k === 's') stopWatch();
      else if (e.key === 'Delete') closeWatch();
      else return false;
      return true;
    },
  });
  /** Makes `w` the shown watch, with its own selection. */
  function showWatch(w) {
    active = w;
    wl.refresh({ reset: true });
    if (w?.rows.length) wl.select(w.sel, { quiet: true });
    renderTabs(); renderWatch(); attempt(loadWatch);
  }
  async function addWatch(kind, d) {
    if (!(await attach())) return;
    const req = kind === 'ea' ? { addr: d.addr, kind: 'execute', method: state.settings.bp_method, action: 'record', ea: true }
      : kind === 'trace' ? { addr: d.addr, kind: 'execute', method: state.settings.bp_method, action: 'trace', steps: d.steps, step_over_calls: d.step_over_calls }
        : { addr: d.addr, kind, size: VSIZE[d.vtype] ?? 4, method: 'hardware', action: 'record' };
    const id = await attempt(() => api.debugAddBreakpoint(req));
    if (id == null) return;
    const w = { id, kind, addr: d.addr, label: `${KIND[kind]} · ${fmtAddr(d.addr)}`, rows: [], sel: 0, stopped: false, key: '' };
    watches.push(w);
    active = w;
    showWatch(w);
    showView('dbg');
    wl.focus();
    attempt(loadBps);
    await attempt(loadWatch);
  }
  on('debug:writes', (d) => addWatch('write', d));
  on('debug:accesses', (d) => addWatch('access', d));
  on('debug:ea', (d) => addWatch('ea', d));
  on('debug:trace', (d) => {
    const dlg = $('#dlg-trace'), f = dlg.querySelector('form');
    $('#tr-at').textContent = `${fmtAddr(d.addr)}  ${d.text || ''}`;
    dlg.onclose = () => {
      if (dlg.returnValue === 'ok') addWatch('trace', { addr: d.addr, steps: Math.max(1, +f.elements.steps.value || 1000), step_over_calls: f.elements.step_over_calls.checked });
    };
    dlg.returnValue = '';
    dlg.showModal();
    f.elements.steps.select();
  });

  async function loadWatch() {
    const w = active;
    if (!w || w.stopped || !dbg.attached) return;
    const rows = w.kind === 'trace' ? await api.debugTrace(w.id) : await api.debugRecords(w.id);
    if (w !== active || w.stopped) return;
    w.rows = rows;
    renderWatch();
    renderTabs();
  }
  function renderTabs() {
    tabs.replaceChildren(...watches.map((w) => h('button', {
      role: 'tab', type: 'button', 'aria-selected': String(w === active), tabindex: w === active ? '0' : '-1', 'data-id': w.id, class: w.stopped ? 'stopped' : null,
      title: w.stopped ? 'Stopped' : 'Live',
    }, w.label, h('span.count.mono', null, w.kind === 'trace' ? (w.rows.length ? nf.format(w.rows.length) : '') : nf.format(w.rows.reduce((s, r) => s + r.count, 0))))));
    const none = !watches.length;
    $('#wl-empty').hidden = !none;
    list.hidden = none;
    $('#wl-head').hidden = none;
    $('#wl-regs').hidden = none;
    syncTools();
  }
  tabs.addEventListener('click', (e) => {
    const t = e.target.closest('[role=tab]');
    if (!t) return;
    showWatch(watches.find((w) => w.id === +t.dataset.id));
  });
  tabs.addEventListener('keydown', (e) => {
    if (e.key !== 'ArrowLeft' && e.key !== 'ArrowRight') return;
    const i = watches.indexOf(active), n = watches[(i + (e.key === 'ArrowRight' ? 1 : watches.length - 1)) % watches.length];
    if (!n) return;
    showWatch(n);
    tabs.querySelector('[aria-selected=true]')?.focus();
  });
  const selRow = () => active?.rows[active.sel];
  function syncTools() {
    const r = selRow(), live = active && !active.stopped;
    $('#wl-show').disabled = !r;
    $('#wl-nop').disabled = !r;
    $('#wl-code').disabled = !r;
    $('#wl-clear').disabled = !live || active.kind === 'trace';
    $('#wl-stop').disabled = !live;
    $('#wl-close').disabled = !active;
  }
  function renderWatch() {
    const w = active;
    if (!w) { wl.refresh({ reset: true }); $('#wl-regs').replaceChildren(); syncTools(); return; }
    const trace = w.kind === 'trace';
    const head = $('#wl-head').children;
    head[0].textContent = trace ? 'Step' : 'Count';
    head[1].textContent = w.kind === 'ea' ? 'Accessed address' : 'Address';
    head[2].textContent = 'Instruction';
    head[3].textContent = w.kind === 'ea' ? 'Instruction address' : '';
    w.sel = Math.max(0, Math.min(w.sel, w.rows.length - 1));
    wl.refresh({ force: true });
    if (w.rows.length && wl.sel !== w.sel) wl.select(w.sel, { quiet: true });
    renderSnap(selRow()?.context);
    syncTools();
  }
  function renderSnap(c) {
    const box = $('#wl-regs');
    if (!c) { box.replaceChildren(h('p.empty', null, 'Select a record to see the registers at its last hit.')); return; }
    const flags = BigInt(c.rflags);
    box.replaceChildren(
      ...GPR.map((n) => h('span.rg', null, h('span.rn', null, n.toUpperCase()), h('span.rv', null, r64(c[n])))),
      h('span.rg.flags', null, h('span.rn', null, 'FLAGS'), h('span.rv', null, FLAGS.map(([f, b]) => ((flags >> BigInt(b)) & 1n ? f : f.toLowerCase())).join(' '))));
  }
  const showRow = () => { const r = selRow(); if (r) emit('mem:goto', { addr: r.addr, pane: 'da' }); };
  async function stopWatch(w = active) {
    if (!w || w.stopped) return;
    if (dbg.attached) await attempt(() => api.debugRemoveBreakpoint(w.id));
    w.stopped = true;
    renderTabs(); renderWatch();
    attempt(loadBps);
  }
  async function closeWatch() {
    const w = active;
    if (!w) return;
    await stopWatch(w);
    watches.splice(watches.indexOf(w), 1);
    showWatch(watches[watches.length - 1] || null);
  }
  $('#wl-show').addEventListener('click', showRow);
  $('#wl-nop').addEventListener('click', () => selRow() && addToCode(selRow(), true));
  $('#wl-code').addEventListener('click', () => selRow() && addToCode(selRow(), false));
  $('#wl-clear').addEventListener('click', async () => { if (active && await attempt(async () => { await api.debugClearRecords(active.id); return true; })) await attempt(loadWatch); });
  $('#wl-stop').addEventListener('click', () => stopWatch());
  $('#wl-close').addEventListener('click', closeWatch);

  // ---------- code list ----------
  // The backend owns it (it is saved with the cheat table); this only shows and drives it.
  const clList = $('#cl-list');
  async function loadCode() {
    if (!state.proc) { codes = []; codeKey = ''; renderCode(); return; }
    const r = await api.codeList().catch(() => null);
    const k = JSON.stringify(r);
    if (!r || k === codeKey) return;
    codes = r; codeKey = k;
    renderCode();
  }
  const reloadCode = () => attempt(loadCode);
  async function codeOp(f) {
    const ok = await attempt(async () => { await f(); return true; });
    await reloadCode();
    mem.refresh();
    return ok;
  }
  const nopAt = (i) => codeOp(() => api.codeNop(i));
  async function restoreAt(i, force = false) { if (await codeOp(() => api.codeRestore(i, force))) toast('Restored the original bytes', 'info'); }
  async function addToCode(r, nop) {
    let i = codes.findIndex((c) => c.addr && BigInt(c.addr) === BigInt(r.addr));
    if (i < 0) {
      i = await attempt(() => api.codeAdd(r.addr, r.text));
      if (i == null) return;
      await reloadCode();
    }
    codeSel = i;
    if (nop && codes[i]?.state !== 'nopped') { if (await nopAt(i)) toast(`Replaced ${r.text || ''} at ${fmtAddr(r.addr)} with NOPs`, 'info'); }
    else toast(`Added ${fmtAddr(r.addr)} to the code list`, 'info');
    renderCode();
  }
  async function toggleCode(i) {
    const c = codes[i];
    if (!c) return;
    if (c.state === 'nopped') await restoreAt(i);
    else if (c.state === 'original') await nopAt(i);
    else if (c.state === 'changed') {
      const r = await modal({
        title: 'Bytes changed', text: `The bytes at ${c.addr ? fmtAddr(c.addr) : c.address} (${c.current}) are neither the original nor NOPs. Restore the original bytes anyway?`,
        buttons: [{ label: 'Restore anyway', value: 'force', primary: true }, { label: 'Cancel', value: 'cancel', kbd: 'Esc' }],
      });
      if (r.value === 'force') await restoreAt(i, true);
    } else toast(`${c.address}: memory is not readable`);
  }
  function renderCode() {
    codeSel = Math.max(0, Math.min(codeSel, codes.length - 1));
    $('#cl-count').textContent = codes.length || '';
    const badge = (c) => (c.state === 'unreadable' ? h('span.muted', null, 'unreadable')
      : h('span', { class: c.state === 'original' ? 'badge green' : 'badge yellow' }, c.state === 'nopped' ? 'nop' : c.state));
    clList.replaceChildren(...codes.map((c, i) => h('div.li.cl-row', { role: 'option', id: 'cl-' + i, 'data-i': i, 'aria-selected': String(i === codeSel) },
      h('span.mono', null, c.addr ? fmtAddr(c.addr) : c.address), h('span.mono.c-text', null, c.description), badge(c))));
    clList.setAttribute('aria-activedescendant', codes.length ? 'cl-' + codeSel : '');
    if (!codes.length) clList.append(h('p.empty', null, 'Instructions you add or NOP from a watch list appear here.'));
  }
  clList.title = 'Space: NOP / restore · Enter: disassemble · Del: remove';
  clList.addEventListener('mousedown', (e) => { const r = e.target.closest('.cl-row'); if (r) { codeSel = +r.dataset.i; renderCode(); } });
  clList.addEventListener('dblclick', (e) => { if (e.target.closest('.cl-row') && codes[codeSel]?.addr) emit('mem:goto', { addr: codes[codeSel].addr, pane: 'da' }); });
  clList.addEventListener('keydown', (e) => {
    if (e.ctrlKey || e.metaKey || e.altKey) return;
    const c = codes[codeSel];
    if (e.key === 'ArrowDown') codeSel++;
    else if (e.key === 'ArrowUp') codeSel--;
    else if (e.key === ' ') toggleCode(codeSel);
    else if (e.key === 'Enter' && c?.addr) emit('mem:goto', { addr: c.addr, pane: 'da' });
    else if (e.key === 'Delete' && c) codeOp(() => api.codeRemove(codeSel));
    else return;
    e.preventDefault(); e.stopPropagation();
    renderCode();
  });
  on('debug:nop', (d) => addToCode(d, true));
  on('debug:codelist', (d) => addToCode(d, false));
  // Emitted on every Lua poll; the code list only changes with the table.
  let codeVer = null;
  on('table:version', (v) => { if (v !== codeVer) { codeVer = v; reloadCode(); } });

  // ---------- break state: registers, stack, threads ----------
  const cpu = $('#cpu-list'), stk = $('#stk-list'), thr = $('#thr-list');
  const broken = () => dbg.attached && dbg.state === 'broken';
  async function loadBreak() {
    if (!broken()) { renderBreak(); return; }
    const t = tid();
    const [ctx, stack, threads] = await Promise.all([api.debugContext(t).catch(() => null), api.debugStack(t, 64).catch(() => []), api.debugThreads().catch(() => [])]);
    if (lastCtx && lastCtx.rip !== ctx?.rip) prevCtx = lastCtx;
    lastCtx = ctx;
    renderBreak(ctx, stack, threads);
  }
  function renderBreak(ctx = null, stack = [], threads = []) {
    const msg = dbg.attached ? 'The process is running. Registers and stack are shown while it is stopped at a break (Shift F9).' : 'Debugger not attached.';
    if (!broken() || !ctx) {
      cpu.replaceChildren(h('p.empty', null, msg)); stk.replaceChildren(h('p.empty', null, msg));
      if (!dbg.attached) thr.replaceChildren(h('p.empty', null, msg));
      else attempt(async () => renderThreads(await api.debugThreads()));
      return;
    }
    const chg = (n) => prevCtx && prevCtx[n] !== ctx[n];
    const flags = BigInt(ctx.rflags);
    const fpu = ctx.fpu;
    cpu.replaceChildren(
      h('div.cpu-sec', null, `Thread ${tid()}`, dbg.reason && tid() === dbg.tid ?h('span.muted', null, ' · ' + dbg.reason) : null),
      ...GPR.map((n) => h('button.reg', { type: 'button', 'data-reg': n, class: chg(n) ? 'reg chg' : 'reg', title: 'Enter or double-click to edit' },
        h('span.rn', null, n.toUpperCase()), h('span.rv.mono', null, r64(ctx[n])))),
      h('div.flags', { role: 'group', 'aria-label': 'Flags' }, ...FLAGS.map(([f, b]) => {
        const on_ = !!((flags >> BigInt(b)) & 1n);
        return h('button.flag', { type: 'button', 'data-bit': b, 'aria-pressed': String(on_), title: `Toggle ${f}` }, f, h('span.mono', null, on_ ? '1' : '0'));
      })),
      h('div.cpu-sec', null, 'Segments'),
      h('div.segs.mono', null, ...SEGS.map((n) => h('span', null, h('span.rn', null, n.toUpperCase() + ' '), ctx[n]))),
      h('div.cpu-sec', null, 'FPU', h('span.muted.mono', null, ` FCW ${fpu.fcw} · FSW ${fpu.fsw} · MXCSR ${fpu.mxcsr}`)),
      ...fpu.st.map((s, i) => h('div.reg.ro', { title: s.hex }, h('span.rn', null, 'ST' + i), h('span.rv.mono', null, s.value))),
      h('div.cpu-sec', null, 'SSE'),
      ...fpu.xmm.map((x, i) => { const [dw, fl] = xmmText(x); return h('div.reg.ro.xmm', { title: fl }, h('span.rn', null, 'XMM' + i), h('span.rv.mono', null, dw)); }));
    stk.replaceChildren(...stack.map((s) => h('button.li.stk-row', { type: 'button', title: 'Show in the hex view', onclick: () => emit('mem:goto', { addr: s.value, pane: 'hex' }) },
      h('span.mono.muted', null, fmtAddr(s.addr)), h('span.mono', null, r64(s.value)), h('span.path', null, s.comment))));
    renderThreads(threads);
  }
  function renderThreads(threads) {
    thr.replaceChildren(...threads.map((t) => h('div.li.thr-row', null,
      h('span.mono', null, String(t.tid)),
      h('span', { class: t.tid === tid() && broken() ? 'badge green' : t.suspended ? 'badge yellow' : 'muted' }, t.tid === tid() && broken() ? 'current' : t.suspended ? 'suspended' : ''),
      h('button.btn.ghost', { type: 'button', disabled: !broken() || t.tid === tid(), onclick: () => { curTid = t.tid; prevCtx = null; lastCtx = null; loadBreak(); } }, 'Switch'),
      h('button.btn.ghost', { type: 'button', onclick: async () => { await attempt(() => api.debugSuspendThread(t.tid, !t.suspended)); loadBreak(); } }, t.suspended ? 'Resume' : 'Suspend'))));
    if (!threads.length) thr.replaceChildren(h('p.empty', null, 'No threads.'));
  }
  async function setReg(name, value) {
    if (await attempt(async () => { await api.debugSetRegister(tid(), name, value); return true; })) {
      if (name === 'rip') { dbg.rip = BigInt(value); emit('debug:marks'); mem.goto({ addr: value, pane: 'da' }); }
      await loadBreak();
    }
  }
  function editReg(btn) {
    const n = btn.dataset.reg, v = btn.querySelector('.rv');
    const input = h('input.cell-input.mono', { value: v.textContent, spellcheck: 'false', 'aria-label': `New value of ${n.toUpperCase()} (hex)` });
    v.replaceWith(input);
    input.focus(); input.select();
    let done = false;
    const finish = (ok) => {
      if (done) return;
      done = true;
      const t = input.value.trim().replace(/^0x/i, '');
      const back = () => cpu.querySelector(`[data-reg="${n}"]`)?.focus();
      if (ok && /^[0-9a-f]{1,16}$/i.test(t)) setReg(n, '0x' + t).then(back);
      else { if (ok) toast('Enter a hex value'); loadBreak().then(back); }
    };
    input.addEventListener('keydown', (e) => { e.stopPropagation(); if (e.key === 'Enter') { e.preventDefault(); finish(true); } else if (e.key === 'Escape') { e.preventDefault(); finish(false); } });
    input.addEventListener('blur', () => finish(false));
  }
  cpu.addEventListener('click', (e) => {
    const f = e.target.closest('.flag');
    if (f && lastCtx) setReg('rflags', '0x' + (BigInt(lastCtx.rflags) ^ (1n << BigInt(f.dataset.bit))).toString(16));
  });
  cpu.addEventListener('dblclick', (e) => { const b = e.target.closest('button.reg'); if (b) editReg(b); });
  cpu.addEventListener('keydown', (e) => {
    const b = e.target.closest('button.reg');
    if (b && (e.key === 'Enter' || e.key === 'F2')) { e.preventDefault(); e.stopPropagation(); editReg(b); }
    else if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      const all = $$('button.reg, button.flag', cpu), i = all.indexOf(document.activeElement);
      all[Math.max(0, Math.min(all.length - 1, i + (e.key === 'ArrowDown' ? 1 : -1)))]?.focus();
      e.preventDefault(); e.stopPropagation();
    }
  });
  on('mem:side', (id) => { if (['cpu-list', 'stk-list', 'thr-list'].includes(id)) attempt(loadBreak); });

  // ---------- polling ----------
  addTicker(async () => {
    if (!state.proc) return;
    if (state.view === 'dbg') await loadCode().catch(() => {});
    if (!dbg.attached) return;
    await refresh();
    if (state.view === 'dbg' || state.view === 'mem') await loadBps();
    if (state.view === 'dbg') await loadWatch();
  });
  const fresh = () => {
    watches.length = 0; active = null; codes = []; codeKey = '';
    reset();
    wl.refresh({ reset: true });
    renderCode(); reloadCode();
  };
  on('process:opened', fresh);
  on('process:closed', fresh);
  splitter($('#div-dbg'), $('#dbg-side'), { axis: 'x', key: 'split.dbgSide', min: 260, max: () => innerWidth * 0.5, sign: -1, initial: 380 });
  reset(); renderCode();

  return { cont, pause, step, toggleAttach, focus: () => (watches.length ? wl : bpList).focus() };
}
