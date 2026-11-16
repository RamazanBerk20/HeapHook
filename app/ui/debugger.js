// Debugger: attach state (top bar), watches ("find out what writes / accesses", "what addresses
// this instruction accesses", break-and-trace), breakpoints, code list, and the break state
// (registers, stack, threads) in the memory view's side panel.
import { api, askPath } from './backend.js';
import { $, $$, h, fmtAddr, isHexAddr, attempt, toast, nf, splitter, modal, contextMenu, helpAdd, icon, excerpt } from './util.js';
import { vlist } from './vlist.js';
import { state, emit, on, addTicker } from './core.js';

const VSIZE = { byte: 1, binary: 1, '2bytes': 2, '4bytes': 4, '8bytes': 8, float: 4, double: 8 };
const GPR = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'rip'];
const FLAGS = [['CF', 0], ['PF', 2], ['AF', 4], ['ZF', 6], ['SF', 7], ['TF', 8], ['IF', 9], ['DF', 10], ['OF', 11]];
const SEGS = ['cs', 'ds', 'es', 'fs', 'gs', 'ss'];
const KIND = { write: 'Writes', access: 'Accesses', ea: 'Addresses', trace: 'Trace', range: 'Range' };
const WL_COLS = '64px 116px minmax(0, 1fr) 116px';
const COND_HINT = 'Condition, e.g. rax==5 && rcx>0x100  (rax..r15, eax..r15d, rip, rflags; + - * & | ^  == != < <= > >=  ! && ||  parentheses)';
const RANGE_WARN = 'A range watch takes write access (or all access) away from every memory page the range touches. '
  + 'Every access to those pages, also outside the range, stops the process for a moment, so the target runs much slower while the watch is on. '
  + 'System calls that write into a watched page fail instead of being seen, and a program that changes the protection itself breaks the watch. '
  + 'Never use it on stack memory: HeapHook refuses ranges inside a stack. For 8 bytes or less, Find out what writes / accesses (debug registers) is faster.';

const r64 = (v) => BigInt(v).toString(16).toUpperCase().padStart(16, '0');
/** xmm hex (little-endian bytes) -> dwords high to low, and float lanes. */
function xmmText(hex) {
  const b = Uint8Array.from(hex.match(/../g), (x) => parseInt(x, 16)), dv = new DataView(b.buffer);
  const dw = [3, 2, 1, 0].map((i) => dv.getUint32(i * 4, true).toString(16).toUpperCase().padStart(8, '0')).join(' ');
  const fl = [3, 2, 1, 0].map((i) => +dv.getFloat32(i * 4, true).toPrecision(6)).join(' · ');
  return [dw, fl];
}

const TRACE_FILTERS = [['HeapHook trace', ['hhtrace']], ['JSON', ['json']]];
const HEXV = /^(0x)?[0-9a-f]{1,16}$/i;
const w0x = (s) => '0x' + String(s).replace(/^0x/i, '');
/** Register name (rax, eax, r8d, al ...) -> [64-bit name, bits] or null. */
function reg64(n) {
  let m;
  if (/^r(ax|bx|cx|dx|si|di|bp|sp)$/.test(n) || n === 'rip') return [n, 64];
  if ((m = /^e(ax|bx|cx|dx|si|di|bp|sp)$/.exec(n))) return ['r' + m[1], 32];
  if ((m = /^(ax|bx|cx|dx|si|di|bp|sp)$/.exec(n))) return ['r' + m[1], 16];
  if ((m = /^([abcd])[lh]$/.exec(n))) return ['r' + m[1] + 'x', 8];
  if ((m = /^(si|di|bp|sp)l$/.exec(n))) return ['r' + m[1], 8];
  if ((m = /^(r(?:8|9|1[0-5]))([dwb]?)$/.exec(n))) return [m[1], { '': 64, d: 32, w: 16, b: 8 }[m[2]]];
  return null;
}
/** Access size of an instruction text as a cheat-table type. */
function vtypeOf(text) {
  const t = text.toLowerCase(), k = /\b(qword|dword|word|byte)\b/.exec(t);
  if (k) return { qword: '8bytes', dword: '4bytes', word: '2bytes', byte: 'byte' }[k[1]];
  const bits = (t.replace(/\[[^\]]*\]/g, ' ').split(/[\s,]+/).slice(1).map(reg64).find(Boolean) || [])[1];
  return { 8: 'byte', 16: '2bytes', 32: '4bytes', 64: '8bytes' }[bits] || '4bytes';
}
/** Memory operand [base+index*s+disp] of a record: {reg, base, off} or {why}. Displacements are hex, as the disassembler prints them. */
function baseOf(r) {
  const m = /\[([^\]]+)\]/.exec(r.text);
  if (!m) return { why: 'no memory operand' };
  let base = null, off = 0n;
  for (const t of m[1].replace(/\s+/g, '').toLowerCase().match(/[+-]?[^+-]+/g) || []) {
    const neg = t[0] === '-', v = t.replace(/^[+-]/, '');
    if (reg64(v.split('*')[0])) { if (!v.includes('*') && !base && !neg) base = v; }
    else if (/^(0x)?[0-9a-f]+$/i.test(v)) off += (neg ? -1n : 1n) * BigInt(/^0x/i.test(v) ? v : '0x' + v);
  }
  if (!base) return { why: 'no base register' };
  const [reg, bits] = reg64(base);
  if (reg === 'rip') return { why: 'RIP-relative operand' };
  const val = r.context?.[reg];
  if (typeof val !== 'string' || !HEXV.test(val)) return { why: 'no register snapshot' };
  return { reg, off, base: '0x' + (bits === 32 ? BigInt(val) & 0xffffffffn : bits === 64 ? BigInt(val) : BigInt(val) & ((1n << BigInt(bits)) - 1n)).toString(16) };
}
const hexN = (n) => (t) => { const x = t.replace(/^0x/i, ''); return new RegExp(`^[0-9a-f]{1,${n}}$`, 'i').test(x) ? '0x' + x : null; };
const REGK = {
  gpr: { what: 'hex', parse: hexN(16) }, m16: { what: 'hex, up to 4 digits', parse: hexN(4) }, m32: { what: 'hex, up to 8 digits', parse: hexN(8) },
  st: { what: 'a decimal number, e.g. 1.5 or -2e10', parse: (t) => (/^[+-]?(\d+\.?\d*|\.\d+)(e[+-]?\d+)?$/i.test(t) ? t : null) },
};
const regKind = (n) => (/^st\d$/.test(n) ? 'st' : n === 'mxcsr' ? 'm32' : n === 'fcw' || n === 'fsw' ? 'm16' : 'gpr');
/** Validated trace file (it is untrusted input): plain strings only. */
function cleanTrace(t) {
  if (!t || typeof t !== 'object' || t.version !== 1 || !Array.isArray(t.rows)) throw 'Not a HeapHook trace file (version 1 expected)';
  if (t.rows.length > 1e6) throw 'The trace file has too many records';
  const rows = t.rows.map((r) => {
    if (!r || typeof r.addr !== 'string' || !HEXV.test(r.addr) || typeof r.text !== 'string') throw 'The trace file has a malformed record';
    const c = r.context && typeof r.context === 'object' ? r.context : {}, ctx = {};
    for (const n of [...GPR, 'rflags']) if (typeof c[n] === 'string' && HEXV.test(c[n])) ctx[n] = w0x(c[n]);
    return { addr: w0x(r.addr), text: excerpt(r.text, 200), context: GPR.every((n) => n in ctx) && 'rflags' in ctx ? ctx : null };
  });
  return { addr: rows.length && !(typeof t.addr === 'string' && HEXV.test(t.addr)) ? rows[0].addr : w0x(t.addr || '0'), steps: Number.isFinite(t.steps) ? t.steps : rows.length, rows };
}

export function initDebugger({ showView, mem }) {
  const dbg = (state.dbg = { attached: false, state: 'detached', tid: null, rip: null, reason: null, exit_code: null, bpAddrs: new Set(), bps: [] });
  let curTid = null, lastCtx = null, prevCtx = null;
  const watches = [];
  let active = null;
  let codes = [], codeKey = '', codeSel = 0, bpSel = 0, logSince = 0;

  // ---------- attach state ----------
  function renderChip() {
    const b = $('#dbg-btn'), s = dbg.attached ? dbg.state : 'detached';
    b.dataset.state = s;
    $('#dbg-state').textContent = !dbg.attached ? 'Debugger off'
      : s === 'broken' ? `Broken · thread ${dbg.tid}` : s === 'exited' ? `Exited${dbg.exit_code != null ? ' · ' + dbg.exit_code : ''}`
        : s === 'suspended' ? 'Suspended' : 'Running';
    b.title = (dbg.reason && s === 'broken' ? `Stopped: ${dbg.reason}. ` : '') + (dbg.attached ? 'Detach the debugger' : 'Attach the debugger') + ' (Ctrl Shift D)';
    $('#dbg-ctl').hidden = !dbg.attached;
    for (const id of ['dc-cont', 'dc-into', 'dc-over', 'dc-out', 'dc-runto', 'dc-runto-t']) $('#' + id).disabled = s !== 'broken';
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
    curTid = null; lastCtx = prevCtx = null; logSince = 0;
    $('#dlog-list').replaceChildren(h('p.empty', null, 'Exec, fork and breakpoints the debugger switched off are noted here.'));
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
  const runTo = (addr, thread = false) => run(() => api.debugRunTo(addr, thread ? tid() : null))();
  $('#dc-cont').addEventListener('click', cont);
  $('#dc-pause').addEventListener('click', pause);
  $('#dc-into').addEventListener('click', () => step('into'));
  $('#dc-over').addEventListener('click', () => step('over'));
  $('#dc-out').addEventListener('click', () => step('out'));
  $('#dc-runto').addEventListener('click', () => { const a = mem.cursor(); if (a) runTo(a); });
  $('#dc-runto-t').addEventListener('click', () => { const a = mem.cursor(); if (a) runTo(a, true); });
  on('debug:run-to', (a) => { if (dbg.state === 'broken') runTo(a); else toast('Run to cursor needs the process stopped at a break'); });
  on('debug:run-to-thread', (a) => { if (dbg.state === 'broken') runTo(a, true); else toast('Run to cursor needs the process stopped at a break'); });

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
    if (watches.length) renderTabs();
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
    h('span', null, `${b.kind}${b.kind !== 'execute' ? ' ' + nf.format(b.len ?? b.size) : ''}`),
    bpInfo(b),
    h('span.mono.muted.hits', { title: b.records_dropped ? `Hits; ${nf.format(b.records_dropped)} not recorded (record list full)` : 'Hits' },
      b.records_dropped ? h('span.dropped', { 'aria-label': 'record list full' }, '! ') : null, nf.format(b.hits)))));
    bpList.setAttribute('aria-activedescendant', bps[bpSel] ? 'bp-' + bps[bpSel].id : '');
    if (!bps.length) bpList.append(h('p.empty', null, ...(dbg.attached ? ['No breakpoints. ', h('kbd', null, 'F5'), ' in the disassembler sets one.']
      : state.proc?.remote ? ['The debugger works on local processes only; this target is on ', state.proc.remote, '.']
        : !state.proc ? ['Open a process (', h('kbd', null, 'Ctrl P'), '), then attach the debugger.'] : ['Debugger not attached. ', h('kbd', null, 'Ctrl Shift D'), ' attaches it.'])));
  }
  /** Method, action, hit options and condition; why it is off when the debugger switched it off. */
  function bpInfo(b) {
    const o = b.options || {};
    const parts = [b.method === 'hardware' ? 'hw' + (b.slot != null ? ' DR' + b.slot : '') : b.method === 'page' ? 'page' : 'int3', b.ea ? 'addresses' : b.action];
    if (o.skip_hits) parts.push(`after ${nf.format(o.skip_hits)}`);
    if (o.one_shot) parts.push('one-shot');
    if (o.max_hits) parts.push(`stop at ${nf.format(o.max_hits)}`);
    if (b.condition) parts.push('if ' + b.condition);
    if (b.stop_when) parts.push('stop when ' + b.stop_when);
    const t = !b.enabled && b.note ? 'off: ' + b.note : parts.join(' · ');
    return h('span.bp-info', { title: [t, b.owner === 'script' ? 'Set by a Lua script (debug_setBreakpoint)' : null].filter(Boolean).join('\n') },
      b.owner === 'script' ? h('span.badge.blue', null, 'Lua') : null,
      h('span.muted' + (b.condition || b.stop_when ? '.mono' : '') + (!b.enabled && b.note ? '.note' : ''), null, t));
  }
  bpList.title = 'Insert: add · E or F2: condition and hit options · H: software / hardware · Space: enable · Del: remove';
  /** Add dialog (no `bp`) or the editor of an existing one (`bp`: condition and hit options change in place). */
  function bpDialog({ addr = '', bp = null } = {}) {
    const sel = (name, vals, v) => h('select', { name }, vals.map((x) => h('option', { value: x, selected: String(x) === String(v) }, String(x))));
    const addrI = h('input.mono', { type: 'text', value: bp ? fmtAddr(bp.addr) : addr ? fmtAddr(addr) : '', spellcheck: 'false', autocomplete: 'off', placeholder: 'address or expression', disabled: !!bp });
    const kind = sel('kind', ['execute', 'write', 'access'], bp?.kind ?? 'execute'), size = sel('size', [1, 2, 4, 8], bp?.size ?? 4);
    const method = sel('method', ['software', 'hardware'], bp?.method ?? state.settings.bp_method);
    const cond = h('input.mono', { type: 'text', value: bp?.condition ?? '', spellcheck: 'false', autocomplete: 'off', placeholder: 'rax==5 && rcx>0x100' });
    const o = bp?.options || {};
    const num = (v, label) => h('input.mono.num', { type: 'number', min: '0', value: v || 0, 'aria-label': label });
    const skip = num(o.skip_hits, 'Break after this many hits'), maxH = num(o.max_hits, 'Stop after this many hits');
    const oneShot = h('input', { type: 'checkbox', checked: !!o.one_shot });
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
      h('h2', null, bp ? 'Edit breakpoint' : 'Add breakpoint'),
      h('label.field', null, h('span', null, 'Address'), addrI),
      h('div.row2.row2-even', null, h('label.field', null, h('span', null, 'Kind'), kind), h('label.field', null, h('span', null, 'Size (write / access)'), size)),
      h('label.field', null, h('span', null, 'Method (watches always use hardware)'), method),
      h('label.field', null, h('span', null, 'Condition (optional)'), cond),
      h('p.hint.mono', null, COND_HINT),
      h('fieldset.group', null, h('legend', null, 'Hits (counted only when the condition holds)'),
        h('div.bp-opts', null,
          h('label.field', null, h('span', null, 'Break after N hits'), skip),
          h('label.field', null, h('span', null, 'Stop after N hits (0 = never)'), maxH),
          h('label.check', null, oneShot, ' One-shot: switch off after it acted once'))),
      bp ? h('p.hint', null, `Changes apply in place: ${nf.format(bp.hits)} hit(s) so far still count.`) : null, err,
      h('div.dlg-actions', null,
        h('button.btn.primary', { value: 'ok', type: 'submit' }, bp ? 'Set ' : 'Add ', h('kbd', null, 'Enter')),
        h('button.btn', { value: 'cancel', type: 'submit', formnovalidate: true }, 'Cancel ', h('kbd', null, 'Esc'))));
    const d = h('dialog.dlg.dlg-sm', { 'aria-label': bp ? 'Edit breakpoint' : 'Add breakpoint' }, form);
    form.addEventListener('submit', async (e) => {
      if (e.submitter?.value === 'cancel') return;
      e.preventDefault();
      err.textContent = '';
      const c = cond.value.trim() || null;
      const options = { skip_hits: Math.max(0, Math.round(+skip.value || 0)), one_shot: oneShot.checked, max_hits: Math.round(+maxH.value || 0) || null };
      try {
        if (bp) {
          if ((bp.condition ?? null) !== c) await api.debugSetCondition(bp.id, c ?? '');
          await api.debugSetOptions(bp.id, options);
        } else {
          const t = addrI.value.trim();
          if (!t) throw 'Enter an address';
          const a = isHexAddr(t) ? '0x' + t.replace(/^0x/i, '') : await api.resolveAddress(t), k = kind.value;
          await api.debugAddBreakpoint({ addr: a, kind: k, ...(k === 'execute' ? {} : { size: +size.value }), method: k === 'execute' ? method.value : 'hardware', action: 'break', condition: c ?? '', ...options });
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
    if (b.hits && (await modal({ title: 'Switch the method?', text: `The breakpoint is removed and set again with the other method; its ${nf.format(b.hits)} hit(s) and records start over.`,
      buttons: [{ label: 'Switch', value: 'ok', primary: true }, { label: 'Cancel', value: 'cancel', kbd: 'Esc' }] })).value !== 'ok') return;
    const mk = (method) => ({ addr: b.addr, kind: b.kind, size: b.size, method, action: b.action, ea: b.ea, condition: b.condition || '', ...(b.options || {}) });
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
  on('debug:bps-changed', () => attempt(loadBps));
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
    empty: () => (!active ? '' : active.rows.length && q() ? 'No record matches the filter.' : active.loaded ? 'The trace file has no records.' : active.stopped ? 'Stopped before any hit.' : active.kind === 'trace' ? 'Waiting for the instruction to execute…' : 'Waiting for the first hit…'),
    count: () => shown().length,
    item: (i) => shown()[i] ?? null,
    cells(r, i) {
      const trace = active.kind === 'trace', ea = active.kind === 'ea' || active.kind === 'range', [m, ...rest] = r.text.split(' ');
      return [trace ? String(r.n ?? i + 1) : nf.format(r.count), fmtAddr(ea ? r.address : r.addr),
        h('span.c-text', { role: 'gridcell' }, h('b', null, m), rest.length ? ' ' + rest.join(' ') : ''), h('span.muted', null, ea ? fmtAddr(r.addr) : '')];
    },
    rowClass: (r) => 'wl-row' + (q() && !hideOthers && matcher()(r) ? ' wl-hit' : ''),
    onSelect: (i, r) => { if (active) active.sel = i; renderSnap(r?.context); syncTools(); },
    onActivate: (i, r) => r && emit('mem:goto', { addr: r.addr, pane: 'da' }),
    onMenu: (x, y, i, r) => wlMenu(x, y, r),
    onKey(e, i, r) {
      const k = e.key.toLowerCase();
      if (e.ctrlKey || e.metaKey) { if (k === 'f' && !e.altKey && !e.shiftKey) { fIn.focus(); fIn.select(); return true; } return false; }
      if (e.altKey) return false;
      if (e.key === 'F3') jump(e.shiftKey ? -1 : 1);
      else if (e.key === 'Escape' && q()) setFilter('');
      else if (k === 'i' && r) moreInfo(r);
      else if (k === 'a' && r) copyAddrs(e.shiftKey ? shown() : [r]);
      else if (k === 'd' && r) openStruct(r);
      else if (k === 'n' && r && !active.loaded) addToCode(r, true);
      else if (k === 'l' && r) addToCode(r, false);
      else if (k === 's') stopWatch();
      else if (k === 'r') rangeDialog();
      else if (e.key === 'Delete') closeWatch();
      else return false;
      return true;
    },
  });
  // ---------- filter / find ----------
  let hideOthers = true, vc = null;
  const q = () => (active?.q || '').trim().toLowerCase().replace(/^0x/, '');
  const matcher = () => { const t = q(); return (r) => `${fmtAddr(r.addr)} ${r.address != null ? fmtAddr(r.address) : ''} ${r.text}`.toLowerCase().includes(t); };
  /** Matching rows of the active watch (null without a filter), cached per rows array and text. */
  function matches() {
    if (!q()) return null;
    if (!vc || vc.rows !== active.rows || vc.q !== q()) {
      const m = matcher(), idx = [];
      active.rows.forEach((r, i) => m(r) && idx.push(i));
      vc = { rows: active.rows, q: q(), idx, list: idx.map((i) => active.rows[i]) };
    }
    return vc;
  }
  const shown = () => (active ? (hideOthers && matches()?.list) || active.rows : []);
  const fIn = h('input#wl-q.mono', { type: 'text', spellcheck: 'false', autocomplete: 'off', placeholder: 'Filter by address or instruction', 'aria-label': 'Filter records by address or instruction' });
  const fCount = h('span.wl-fcount.mono.muted', { role: 'status', 'aria-live': 'polite' });
  const fHide = h('button.btn.ghost.wl-fhide', { type: 'button', 'aria-pressed': 'true', title: 'On: list only the matches. Off: list everything and mark the matches (F3 jumps between them).' }, 'Only matches');
  const fBar = h('div.wl-filter', { role: 'search' }, fIn, fCount, fHide,
    h('span.wl-fkeys.muted', null, h('kbd', null, 'F3'), ' next · ', h('kbd', null, 'Esc'), ' clear'));
  $('#wl-head').before(fBar);
  function syncFilter() {
    fIn.value = active?.q || '';
    fHide.setAttribute('aria-pressed', String(hideOthers));
    const m = matches();
    fCount.textContent = m ? `${nf.format(m.idx.length)} of ${nf.format(active.rows.length)}` : '';
  }
  function setFilter(t) {
    if (!active) return;
    active.q = t; active.sel = 0;
    wl.refresh({ reset: true, force: true });
    if (shown().length) wl.select(0, { quiet: true });
    renderSnap(selRow()?.context); syncTools(); syncFilter();
  }
  fIn.addEventListener('input', () => setFilter(fIn.value));
  fIn.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); if (fIn.value) setFilter(''); else wl.focus(); }
    else if (e.key === 'F3' || e.key === 'Enter') { e.preventDefault(); e.stopPropagation(); jump(e.shiftKey ? -1 : 1); }
    else if (e.key === 'ArrowDown') { e.preventDefault(); e.stopPropagation(); wl.focus(); }
  });
  fHide.addEventListener('click', () => { hideOthers = !hideOthers; setFilter(active?.q || ''); });
  /** Next / previous match after the selected record, wrapping; the list keeps all rows when "Only matches" is off. */
  function jump(dir) {
    const m = matches();
    if (!m) { toast('Type in the filter first (Ctrl F)', 'info'); return; }
    if (!m.idx.length) { toast('No match', 'info'); return; }
    const cur = hideOthers ? m.idx[wl.sel] ?? -1 : wl.sel;
    const next = dir > 0 ? m.idx.find((i) => i > cur) ?? m.idx[0] : m.idx.findLast((i) => i < cur) ?? m.idx.at(-1);
    wl.select(hideOthers ? m.idx.indexOf(next) : next);
  }

  /** Makes `w` the shown watch, with its own selection. */
  function showWatch(w) {
    active = w;
    wl.refresh({ reset: true, force: true });
    if (shown().length) wl.select(w.sel, { quiet: true });
    renderTabs(); renderWatch(); attempt(loadWatch);
  }
  async function addWatch(kind, d) {
    if (!(await attach())) return;
    const req = kind === 'ea' ? { addr: d.addr, kind: 'execute', method: state.settings.bp_method, action: 'record', ea: true }
      : kind === 'trace' ? { addr: d.addr, kind: 'execute', method: state.settings.bp_method, action: 'trace', steps: d.steps, step_over_calls: d.step_over_calls, ...(d.stop_when ? { stop_when: d.stop_when } : {}) }
        : { addr: d.addr, kind, size: VSIZE[d.vtype] ?? 4, method: 'hardware', action: 'record' };
    const id = await attempt(() => (kind === 'range' ? api.debugWatchRange(d.req) : api.debugAddBreakpoint(req)));
    if (id == null) return;
    const label = kind === 'range' ? `${d.req.kind === 'access' ? 'Accesses' : 'Writes'} · ${fmtAddr(d.addr)} +${nf.format(d.req.len)}` : `${KIND[kind]} · ${fmtAddr(d.addr)}`;
    const w = { id, kind, addr: d.addr, steps: d.steps, label, rows: [], sel: 0, stopped: false, key: '' };
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
  /** Range watch dialog: address, length, writes or accesses, with the plain warning about its cost. */
  function rangeDialog({ addr = '', len = 16, kind = 'write' } = {}) {
    const addrI = h('input.mono', { type: 'text', value: addr ? fmtAddr(addr) : '', spellcheck: 'false', autocomplete: 'off', placeholder: 'address or expression' });
    const lenI = h('input.mono', { type: 'text', value: String(len), spellcheck: 'false', autocomplete: 'off', 'aria-describedby': 'rw-lenhint' });
    const kindS = h('select', { name: 'kind' }, h('option', { value: 'write', selected: kind === 'write' }, 'Writes'), h('option', { value: 'access', selected: kind === 'access' }, 'Reads and writes'));
    const maxH = h('input.mono.num', { type: 'number', min: '0', value: '0', 'aria-label': 'Stop after this many hits' });
    const err = h('p.hint.mono', { role: 'alert' });
    const form = h('form', { method: 'dialog' },
      h('h2', null, 'Watch a memory range'),
      h('div.row2', null, h('label.field', null, h('span', null, 'Start address'), addrI), h('label.field', null, h('span', null, 'Length (bytes)'), lenI)),
      h('p#rw-lenhint.hint', null, 'Decimal, or hex with 0x. Any length; debug registers only cover 8 bytes.'),
      h('div.row2.row2-even', null, h('label.field', null, h('span', null, 'Find out what'), kindS), h('label.field', null, h('span', null, 'Stop after N hits (0 = never)'), maxH)),
      h('p.warn', { role: 'note' }, h('b', null, 'Slows the target. '), RANGE_WARN), err,
      h('div.dlg-actions', null,
        h('button.btn.primary', { value: 'ok', type: 'submit' }, 'Watch ', h('kbd', null, 'Enter')),
        h('button.btn', { value: 'cancel', type: 'submit', formnovalidate: true }, 'Cancel ', h('kbd', null, 'Esc'))));
    const d = h('dialog.dlg.dlg-sm', { 'aria-label': 'Watch a memory range' }, form);
    form.addEventListener('submit', async (e) => {
      if (e.submitter?.value === 'cancel') return;
      e.preventDefault();
      err.textContent = '';
      try {
        const t = addrI.value.trim();
        if (!t) throw 'Enter an address';
        const a = isHexAddr(t) ? '0x' + t.replace(/^0x/i, '') : await api.resolveAddress(t);
        const n = Number(lenI.value.trim());
        if (!Number.isInteger(n) || n < 1) throw 'Enter a length of at least 1 byte';
        if (!(await attach())) return;
        d.close('ok');
        addWatch('range', { addr: a, req: { addr: a, len: n, kind: kindS.value, max_hits: Math.round(+maxH.value || 0) || null } });
      } catch (ex) { err.textContent = String(ex?.message || ex); }
    });
    d.addEventListener('close', () => d.remove());
    document.body.append(d);
    d.showModal();
    (addrI.value ? lenI : addrI).select();
  }
  on('debug:watch-range', (d) => rangeDialog(d));
  on('debug:trace', (d) => {
    const dlg = $('#dlg-trace'), f = dlg.querySelector('form');
    $('#tr-at').textContent = `${fmtAddr(d.addr)}  ${d.text || ''}`;
    dlg.onclose = () => {
      if (dlg.returnValue === 'ok') addWatch('trace', { addr: d.addr, steps: Math.max(1, +f.elements.steps.value || 1000), step_over_calls: f.elements.step_over_calls.checked, stop_when: f.elements.stop_when?.value.trim() || '' });
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
    if (w.kind === 'trace') rows.forEach((r, i) => { r.n = i + 1; });
    w.rows = rows;
    renderWatch();
    renderTabs();
  }
  function renderTabs() {
    tabs.replaceChildren(...watches.map((w) => {
      const b = dbg.bps.find((x) => x.id === w.id), off = !w.stopped && b && !b.enabled;
      return h('button', {
        role: 'tab', type: 'button', 'aria-selected': String(w === active), tabindex: w === active ? '0' : '-1', 'data-id': w.id, class: w.loaded ? 'loaded' : w.stopped ? 'stopped' : off ? 'paused' : null,
        title: w.loaded ? `Loaded from ${w.file} (read only)` : w.stopped ? 'Stopped' : off ? 'Switched off' + (b.note ? ': ' + b.note : '') : 'Live',
      }, w.label, h('span.count.mono', null, w.kind === 'trace' ? (w.rows.length ? nf.format(w.rows.length) : '') : nf.format(w.rows.reduce((s, r) => s + r.count, 0))));
    }));
    const ab = active && !active.stopped && dbg.bps.find((x) => x.id === active.id);
    const dropped = $('#wl-dropped');
    dropped.hidden = !ab?.records_dropped;
    dropped.textContent = ab?.records_dropped ? `List full · ${nf.format(ab.records_dropped)} not recorded` : '';
    dropped.title = 'The watch keeps at most 65,536 distinct instruction and address pairs; hits on new pairs are counted but not listed. Clear the counts to make room.';
    const none = !watches.length;
    $('#wl-empty').hidden = !none;
    list.hidden = none;
    $('#wl-head').hidden = none;
    $('#wl-regs').hidden = none;
    fBar.hidden = none;
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
  const selRow = () => shown()[active?.sel];
  function syncTools() {
    const r = selRow(), live = active && !active.stopped;
    $('#wl-show').disabled = !r;
    $('#wl-nop').disabled = !r || active.loaded;
    $('#wl-info').disabled = !r;
    $('#wl-save').disabled = active?.kind !== 'trace' || !active.rows.length;
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
    head[1].textContent = w.kind === 'ea' || w.kind === 'range' ? 'Accessed address' : 'Address';
    head[2].textContent = 'Instruction';
    head[3].textContent = w.kind === 'ea' || w.kind === 'range' ? 'Instruction address' : '';
    w.sel = Math.max(0, Math.min(w.sel, shown().length - 1));
    wl.refresh({ force: true });
    if (shown().length && wl.sel !== w.sel) wl.select(w.sel, { quiet: true });
    renderSnap(selRow()?.context);
    syncTools(); syncFilter();
  }
  function renderSnap(c) {
    const box = $('#wl-regs');
    if (!c) { box.replaceChildren(h('p.empty', null, 'Select a record to see the registers at its last hit.')); return; }
    box.replaceChildren(...snapNodes(c));
  }
  function snapNodes(c) {
    const flags = BigInt(c.rflags);
    return [...GPR.map((n) => h('span.rg', null, h('span.rn', null, n.toUpperCase()), h('span.rv', null, r64(c[n])))),
      h('span.rg.flags', null, h('span.rn', null, 'FLAGS'), h('span.rv', null, FLAGS.map(([f, b]) => ((flags >> BigInt(b)) & 1n ? f : f.toLowerCase())).join(' ')))];
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
  $('#wl-range').addEventListener('click', () => rangeDialog());

  // ---------- record actions: menu, more information, address list, dissector, trace files ----------
  const tb = $('#wl-clear').parentElement;
  const tbtn = (id, ic, label, f) => { const b = h('button.btn.ghost.icon', { id, type: 'button', 'aria-label': label, title: label, html: icon(ic) }); b.addEventListener('click', f); return b; };
  tb.insertBefore(tbtn('wl-info', 'info', 'More information on the record (I)', () => moreInfo(selRow())), $('#wl-clear'));
  tb.insertBefore(tbtn('wl-save', 'save', 'Save this trace to a file', () => saveTrace()), $('#wl-clear'));
  tb.insertBefore(tbtn('wl-load', 'folder', 'Open a saved trace', () => loadTrace()), $('#wl-clear'));
  function wlMenu(x, y, r) {
    if (!r) return;
    const why = (t, w) => (w ? `${t} (${w})` : t), noAddr = r.address == null ? 'no accessed address' : '', sd = baseOf(r).why;
    contextMenu(x, y, [
      { label: 'Disassemble', kbd: 'Enter', run: showRow },
      { label: 'More information…', kbd: 'I', run: () => moreInfo(r) },
      { label: why('Copy to address list', noAddr), kbd: 'A', disabled: !!noAddr, run: () => copyAddrs([r]) },
      { label: 'Copy all listed addresses to address list', kbd: 'Shift A', disabled: !shown().some((x) => x.address != null), run: () => copyAddrs(shown()) },
      { label: why('Open in structure dissector', sd), kbd: 'D', disabled: !!sd, run: () => openStruct(r) },
      '-',
      { label: 'Replace with NOPs', kbd: 'N', disabled: !!active.loaded, run: () => addToCode(r, true) },
      { label: 'Add to code list', kbd: 'L', run: () => addToCode(r, false) },
      '-',
      { label: 'Filter…', kbd: 'Ctrl F', run: () => { fIn.focus(); fIn.select(); } },
      { label: 'Save this trace…', disabled: active.kind !== 'trace', run: saveTrace },
      { label: 'Open a saved trace…', run: loadTrace },
    ], wl.el);
  }
  /** Accessed addresses of `rs` (ea / range records) added to the cheat table. */
  function copyAddrs(rs) {
    const seen = new Set(), items = [];
    for (const r of rs) {
      if (r.address == null) continue;
      const a = BigInt(r.address).toString(16);
      if (!seen.has(a)) { seen.add(a); items.push({ description: `Accessed by ${fmtAddr(r.addr)}`, addr: a, vtype: vtypeOf(r.text) }); }
    }
    if (!items.length) { toast('No accessed address: only "what addresses this instruction accesses" and range watches record one', 'info'); return; }
    emit('table:add', items);
    toast(`Added ${nf.format(items.length)} address${items.length > 1 ? 'es' : ''} to the address list`, 'info');
  }
  function openStruct(r) {
    const b = baseOf(r);
    if (b.why) { toast(`Cannot open the dissector: ${b.why}`, 'info'); return; }
    emit('struct:open', { addr: b.base });
    toast(`Structure at ${b.reg.toUpperCase()}; the instruction reaches ${b.off < 0n ? '-' : '+'}0x${(b.off < 0n ? -b.off : b.off).toString(16)} into it`, 'info');
  }
  async function saveTrace() {
    const w = active;
    if (w?.kind !== 'trace' || !w.rows.length) { toast('Select a trace with records first', 'info'); return; }
    const path = await askPath({ save: true, title: 'Save trace', filters: TRACE_FILTERS, dflt: `trace-${fmtAddr(w.addr)}.hhtrace` });
    if (!path) return;
    const rows = w.rows.map(({ addr, text, context }) => ({ addr, text, context }));
    if (await attempt(async () => { await api.traceSave(path, { version: 1, addr: w.addr, steps: w.steps ?? rows.length, rows }); return true; })) toast(`Saved ${nf.format(rows.length)} records`, 'info');
  }
  async function loadTrace() {
    const path = await askPath({ save: false, title: 'Open trace', filters: TRACE_FILTERS });
    if (!path) return;
    const t = await attempt(async () => cleanTrace(await api.traceLoad(path)));
    if (!t) return;
    const file = excerpt(String(path).split(/[\\/]/).pop(), 40);
    t.rows.forEach((r, i) => { r.n = i + 1; });
    const w = { id: -(++fileSeq), kind: 'trace', addr: t.addr, steps: t.steps, label: `File · ${file}`, file, rows: t.rows, sel: 0, stopped: true, loaded: true, key: '' };
    watches.push(w);
    showWatch(w);
    showView('dbg');
    wl.focus();
  }
  let fileSeq = 0;
  /** Dialog: instructions around the record, its register snapshot and the stack at its RSP. */
  async function moreInfo(r) {
    if (!r) return;
    const loaded = !!active?.loaded, a = BigInt(r.addr), body = h('div.mi-body', null, h('p.hint', null, 'Loading…'));
    const d = h('dialog.dlg.dlg-wide.mi-dlg', { 'aria-label': `Record at ${fmtAddr(r.addr)}` }, h('form', { method: 'dialog' },
      h('h2', null, `Record at ${fmtAddr(r.addr)}`), body,
      h('div.dlg-actions', null, h('button.btn.primary', { value: 'ok', type: 'submit' }, 'Close ', h('kbd', null, 'Esc')))));
    d.addEventListener('close', () => { d.remove(); wl.focus(); });
    document.body.append(d);
    d.showModal();
    const sec = (title, note, ...kids) => h('section.mi-sec', null, h('h3', null, title), note ? h('p.hint', null, note) : null, ...kids);
    const [code, stack] = await Promise.all([miCode(r, a), miStack(r)]);
    body.replaceChildren(
      sec('Instructions', code.note + (loaded ? ' Read from the open process, which may differ from the traced one.' : ''), h('div.mi-list.mono', { role: 'list' }, ...code.rows)),
      sec('Registers', r.context ? 'At the hit of this record.' : '', r.context ? h('div.regs-snap.mi-regs.mono', null, ...snapNodes(r.context)) : h('p.empty', null, 'No register snapshot for this record.')),
      sec('Stack', stack.note, h('div.mi-list.mono', { role: 'list' }, ...stack.rows)));
  }
  async function miCode(r, a) {
    const starts = [], fn = await api.codeFunction(r.addr).catch(() => null);
    if (fn?.start) starts.push([BigInt(fn.start), 'the start of its function']);
    for (const x of active?.rows || []) { const b = BigInt(x.addr); if (b < a) starts.push([b, 'an earlier record']); }
    const near = starts.filter(([b]) => a - b <= 64n).sort((x, y) => (x[0] > y[0] ? -1 : 1)).slice(0, 3);
    for (const [b, why] of [...near, [a, null]]) {
      const ins = await api.disassemble('0x' + b.toString(16), 48).catch(() => null);
      const at = ins?.findIndex((x) => BigInt(x.addr) === a) ?? -1;
      if (at < 0) continue;
      const from = Math.max(0, at - 12);
      return {
        note: why ? `Shown from ${fmtAddr(b)}, ${why}, ${a - b} byte(s) before the record (there is no backward disassembly).` : 'Shown from the instruction itself: no known instruction start within 64 bytes before it.',
        rows: ins.slice(from, at + 9).map((x, i) => h('div.mi-ins', { role: 'listitem', class: from + i === at ? 'mi-ins cur' : 'mi-ins', ...(from + i === at ? { 'aria-current': 'true' } : {}) },
          h('span.muted', null, fmtAddr(x.addr)), h('span.muted', null, x.bytes), h('span', null, x.text))),
      };
    }
    return { note: 'The memory at this address cannot be disassembled.', rows: [] };
  }
  async function miStack(r) {
    const rsp = r.context?.rsp;
    if (!rsp) return { note: 'No RSP in the snapshot.', rows: [] };
    const hex = await api.readMemory(rsp, 128).catch(() => null);
    if (typeof hex !== 'string') return { note: 'The stack cannot be read.', rows: [] };
    const bytes = hex.replace(/\s+/g, '').match(/../g) || [], base = BigInt(rsp);
    return {
      note: `16 qwords at RSP ${fmtAddr(rsp)}; memory as it is now, not as it was at the hit.`,
      rows: Array.from({ length: 16 }, (_, i) => {
        const q = bytes.slice(i * 8, i * 8 + 8);
        return h('div.mi-stk', { role: 'listitem' }, h('span.muted', null, fmtAddr(base + BigInt(i * 8))), h('span', null, q.length < 8 || q.includes('??') ? '?'.repeat(16) : q.reverse().join('').toUpperCase()));
      }),
    };
  }
  helpAdd('Debugger', [['Ctrl F', 'Filter the watch list (while it has focus)'], ['F3 / Shift F3', 'Next / previous filter match'], ['Esc', 'Clear the filter'],
    ['I', 'More information on a watch record'], ['A / Shift A', 'Copy the accessed address (all listed) to the address list'], ['D', 'Open a record\'s base register in the structure dissector'],
    ['F2', 'Edit the selected register, also ST, XMM, MXCSR, FCW, FSW']]);

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
  const cpu = $('#cpu-list'), stk = $('#stk-list'), thr = $('#thr-list'), bt = $('#bt-list');
  const broken = () => dbg.attached && dbg.state === 'broken';
  async function loadBreak() {
    if (!broken()) { renderBreak(); return; }
    const t = tid();
    const [ctx, stack, threads, frames] = await Promise.all([api.debugContext(t).catch(() => null), api.debugStack(t, 64).catch(() => []),
      api.debugThreads().catch(() => []), api.debugBacktrace(t, 64).catch(() => [])]);
    if (lastCtx && lastCtx.rip !== ctx?.rip) prevCtx = lastCtx;
    lastCtx = ctx;
    renderBreak(ctx, stack, threads, frames);
  }
  const regRow = (n, label, text, changed = false, tip = '', cls = '') => h('button.reg' + (cls ? '.' + cls : ''), {
    type: 'button', 'data-reg': n, class: `reg ${cls} ${changed ? 'chg' : ''}`, title: (tip ? tip + '. ' : '') + 'Enter, F2 or double-click to edit' }, h('span.rn', null, label), h('span.rv.mono', null, text));
  function renderBreak(ctx = null, stack = [], threads = [], frames = []) {
    const msg = dbg.attached ? 'The process is running. Registers and stack are shown while it is stopped at a break (Shift F9).' : 'Debugger not attached.';
    if (!broken() || !ctx) {
      cpu.replaceChildren(h('p.empty', null, msg)); stk.replaceChildren(h('p.empty', null, msg)); bt.replaceChildren(h('p.empty', null, msg));
      if (!dbg.attached) thr.replaceChildren(h('p.empty', null, msg));
      else attempt(async () => renderThreads(await api.debugThreads()));
      return;
    }
    const chg = (n) => prevCtx && prevCtx[n] !== ctx[n];
    const flags = BigInt(ctx.rflags);
    const fpu = ctx.fpu;
    cpu.replaceChildren(
      h('div.cpu-sec', null, `Thread ${tid()}`, dbg.reason && tid() === dbg.tid ?h('span.muted', null, ' · ' + dbg.reason) : null),
      ...GPR.map((n) => regRow(n, n.toUpperCase(), r64(ctx[n]), chg(n))),
      h('div.flags', { role: 'group', 'aria-label': 'Flags' }, ...FLAGS.map(([f, b]) => {
        const on_ = !!((flags >> BigInt(b)) & 1n);
        return h('button.flag', { type: 'button', 'data-bit': b, 'aria-pressed': String(on_), title: `Toggle ${f}` }, f, h('span.mono', null, on_ ? '1' : '0'));
      })),
      h('div.cpu-sec', null, 'Segments'),
      h('div.segs.mono', null, ...SEGS.map((n) => h('span', null, h('span.rn', null, n.toUpperCase() + ' '), ctx[n]))),
      h('div.cpu-sec', null, 'FPU'),
      regRow('fcw', 'FCW', fpu.fcw), regRow('fsw', 'FSW', fpu.fsw), regRow('mxcsr', 'MXCSR', fpu.mxcsr),
      ...fpu.st.map((s, i) => regRow('st' + i, 'ST' + i, s.value, false, s.hex)),
      h('div.cpu-sec', null, 'SSE'),
      ...fpu.xmm.map((x, i) => { const [dw, fl] = xmmText(x); return regRow('xmm' + i, 'XMM' + i, dw, false, fl, 'xmm'); }));
    stk.replaceChildren(...stack.map((s) => h('button.li.stk-row', { type: 'button', title: 'Show in the hex view', onclick: () => emit('mem:goto', { addr: s.value, pane: 'hex' }) },
      h('span.mono.muted', null, fmtAddr(s.addr)), h('span.mono', null, r64(s.value)), h('span.path', null, s.comment))));
    bt.replaceChildren(h('div.cpu-sec', null, `Thread ${tid()} · call chain`),
      ...frames.map((f, i) => h('button.li.bt-row', { type: 'button', title: 'Disassemble here', onclick: () => emit('mem:goto', { addr: f.addr, pane: 'da' }) },
        h('span.mono.muted', null, '#' + i), h('span.mono', null, fmtAddr(f.addr)), h('span.mono.bt-sym', { title: f.symbol || f.module || '' }, f.symbol || f.module || ''))),
      h('p.hint.bt-hint', null, 'Walked through frame pointers: code built without them shows a shorter chain.'));
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
    if (n.startsWith('xmm')) { xmmDialog(+n.slice(3)); return; }
    const k = REGK[regKind(n)];
    const input = h('input.cell-input.mono', { value: v.textContent, spellcheck: 'false', 'aria-label': `New value of ${n.toUpperCase()} (${k.what})` });
    v.replaceWith(input);
    input.focus(); input.select();
    let done = false;
    const finish = (ok) => {
      if (done) return;
      done = true;
      const val = k.parse(input.value.trim()), back = () => cpu.querySelector(`[data-reg="${n}"]`)?.focus();
      if (ok && val) setReg(n, val).then(back);
      else { if (ok) toast(`Enter ${k.what}`); loadBreak().then(back); }
    };
    input.addEventListener('keydown', (e) => { e.stopPropagation(); if (e.key === 'Enter') { e.preventDefault(); finish(true); } else if (e.key === 'Escape') { e.preventDefault(); finish(false); } });
    input.addEventListener('blur', () => finish(false));
  }
  /** XMM edit: 32 hex digits (bytes in memory order, as the context reports them) or four floats, kept in step. */
  function xmmDialog(i) {
    const cur = lastCtx?.fpu?.xmm?.[i];
    if (!cur) return;
    const hexI = h('input.mono', { type: 'text', value: cur, spellcheck: 'false', autocomplete: 'off', 'aria-label': `XMM${i} as 32 hex digits` });
    const flI = h('input.mono', { type: 'text', spellcheck: 'false', autocomplete: 'off', 'aria-label': `XMM${i} as 4 floats, lowest first` });
    const err = h('p.hint.mono', { role: 'alert' });
    const hexOf = () => { const t = hexI.value.replace(/\s+/g, ''); return /^[0-9a-f]{32}$/i.test(t) ? t.toLowerCase() : null; };
    const floatsOf = () => {
      const t = flI.value.trim().split(/[\s,]+/);
      return t.length === 4 && t.every((x) => x !== '' && (!isNaN(Number(x)) || /^[+-]?nan$/i.test(x))) ? t.map((x) => (/nan/i.test(x) ? NaN : Number(x))) : null;
    };
    const toFloats = (hx) => { const dv = new DataView(Uint8Array.from(hx.match(/../g), (x) => parseInt(x, 16)).buffer); return [0, 1, 2, 3].map((k) => +dv.getFloat32(k * 4, true).toPrecision(9)).join(' '); };
    const toHex = (f) => { const dv = new DataView(new ArrayBuffer(16)); f.forEach((x, k) => dv.setFloat32(k * 4, x, true)); return [...new Uint8Array(dv.buffer)].map((b) => b.toString(16).padStart(2, '0')).join(''); };
    flI.value = toFloats(cur);
    hexI.addEventListener('input', () => { const x = hexOf(); if (x) flI.value = toFloats(x); });
    flI.addEventListener('input', () => { const f = floatsOf(); if (f) hexI.value = toHex(f); });
    const form = h('form', { method: 'dialog' }, h('h2', null, `Edit XMM${i}`),
      h('label.field', null, h('span', null, '32 hex digits (byte 0 first)'), hexI),
      h('label.field', null, h('span', null, '4 floats (lowest first, single precision)'), flI), err,
      h('div.dlg-actions', null,
        h('button.btn.primary', { value: 'ok', type: 'submit' }, 'Set ', h('kbd', null, 'Enter')),
        h('button.btn', { value: 'cancel', type: 'submit', formnovalidate: true }, 'Cancel ', h('kbd', null, 'Esc'))));
    const d = h('dialog.dlg.dlg-sm', { 'aria-label': `Edit XMM${i}` }, form);
    form.addEventListener('submit', async (e) => {
      if (e.submitter?.value === 'cancel') return;
      e.preventDefault();
      const f = floatsOf(), x = hexOf() || (f && toHex(f));
      if (!x) { err.textContent = 'Enter 32 hex digits or four numbers'; return; }
      d.close('ok');
      await setReg('xmm' + i, x);
      cpu.querySelector(`[data-reg="xmm${i}"]`)?.focus();
    });
    d.addEventListener('close', () => d.remove());
    document.body.append(d);
    d.showModal();
    hexI.select();
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
  on('mem:side', (id) => { if (['cpu-list', 'stk-list', 'thr-list', 'bt-list'].includes(id)) attempt(loadBreak); });

  // ---------- debugger log: exec, fork, breakpoints the debugger switched off ----------
  async function loadLog() {
    const r = await api.debugLog(logSince);
    if (!r.lines.length) return;
    logSince = r.next;
    const box = $('#dlog-list');
    box.querySelector('.empty')?.remove();
    for (const l of r.lines) {
      box.append(h('div.dlog-line', null, h('span.muted', null, '#' + l.seq), ' ', l.text));
      if (state.view !== 'dbg') toast('Debugger: ' + l.text, 'info');
    }
    while (box.childElementCount > 300) box.firstElementChild.remove();
    box.scrollTop = box.scrollHeight;
  }

  // ---------- polling ----------
  addTicker(async () => {
    if (!state.proc) return;
    if (state.view === 'dbg') await loadCode().catch(() => {});
    if (!dbg.attached) return;
    await refresh();
    await loadLog().catch(() => {});
    if (state.view === 'dbg' || state.view === 'mem') await loadBps();
    if (state.view === 'dbg') await loadWatch();
  });
  const fresh = () => {
    watches.length = 0; active = null; codes = []; codeKey = '';
    reset();
    wl.refresh({ reset: true });
    renderCode(); reloadCode();
  };
  // After a page reload the backend may still be attached: pick its state up.
  on('process:opened', () => { fresh(); api.debugStatus().then((st) => { if (st.attached) { apply(st); loadBps().catch(() => {}); } }).catch(() => {}); });
  on('process:closed', fresh);
  splitter($('#div-dbg'), $('#dbg-side'), { axis: 'x', key: 'split.dbgSide', min: 260, max: () => innerWidth * 0.5, sign: -1, initial: 380 });
  reset(); renderCode();

  return { cont, pause, step, toggleAttach, focus: () => (watches.length ? wl : bpList).focus() };
}
