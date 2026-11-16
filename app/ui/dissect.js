// Code analysis ("Dissect code"): pick modules, run with progress / cancel, then browse
// functions, referenced strings, referenced functions and code caves; the selected item's
// cross references are listed below. Enter jumps to the disassembler.
import { api, askPath } from './backend.js';
import { $, $$, h, fmtAddr, fmtSize, nf, attempt, toast, rafThrottle, busy, helpAdd } from './util.js';
import { state, on, emit } from './core.js';
import { vlist, pager } from './vlist.js';
import { progressStrip, runJob, listDialog } from './memtools.js';

const TABS = {
  functions: { label: 'Functions', cols: '128px minmax(0, 1fr) 72px', head: ['Address', 'Function', 'Callers'] },
  strings: { label: 'Strings', cols: '128px minmax(0, 1fr) 56px', head: ['Address', 'Text', 'Refs'] },
  called: { label: 'Referenced functions', cols: '128px minmax(0, 1fr) 72px', head: ['Address', 'Function', 'Callers'] },
  caves: { label: 'Code caves', cols: '128px 96px minmax(0, 1fr)', head: ['Address', 'Length', 'Filled with'] },
};
const KIND = { call: 'call', jump: 'jump', cond_jump: 'cond. jump', data: 'data' };

export function initDissect({ showView }) {
  const view = $('#view-code'), modList = $('#dc-mods'), filter = $('#dc-filter');
  let mods = [], summary = null, tab = 'functions', target = null; // target: {addr, len, label} whose xrefs are listed
  const strip = progressStrip('Dissect progress');
  $('#dc-progress').append(strip.wrap);

  const modName = (a) => {
    const n = BigInt(a), m = mods.find((x) => n >= BigInt(x.base) && n < BigInt(x.base) + BigInt(x.size));
    return m ? `${m.name}+${(n - BigInt(m.base)).toString(16).toUpperCase()}` : fmtAddr(a);
  };

  // ---------- modules ----------
  async function loadMods() {
    mods = (await api.modules().catch(() => [])) || [];
    const first = mods[0]?.name;
    modList.replaceChildren(...mods.map((m) => h('label.check.dc-mod', { title: m.path },
      h('input', { type: 'checkbox', value: m.name, checked: m.name === first }), h('span.name', null, m.name), h('span.muted.mono', null, fmtSize(m.size)))));
    if (!mods.length) modList.append(h('p.empty', null, 'Open a process to list its modules.'));
  }
  const checked = () => $$('input:checked', modList).map((i) => i.value);
  /** add: merge the modules into the current dissection instead of starting a new one. */
  async function run(names = checked(), add = false) {
    if (!names.length) { toast('Pick at least one module'); return; }
    if (add && !summary) add = false; // nothing to merge into yet: a plain run
    if (add) names = names.filter((n) => !summary.modules.includes(n));
    if (!names.length) { toast('Those modules are already in the dissection', 'info'); return; }
    $('#dc-run').disabled = addBtn.disabled = true;
    const opts = { recursive: $('#dc-rec').checked, min_string: +$('#dc-minstr').value || 4, min_cave: +$('#dc-mincave').value || 32 };
    const s = await runJob(() => busy(add ? 'Adding to the dissection' : 'Dissecting code', add ? api.dissectAdd(names, opts) : api.dissectRun(names, opts), { cancel: () => api.toolsCancel() }), strip, add ? 'Adding' : 'Dissecting');
    $('#dc-run').disabled = false;
    if (!s) { showSummary(); return; }
    summary = s;
    showSummary();
    reloadList();
    list.focus();
  }

  // ---------- save / load / add (side panel, under Run) ----------
  const FILTERS = [['HeapHook dissection', ['hhdis']], ['All files', ['*']]];
  async function save() {
    if (!summary) { toast('Nothing to save: dissect a module first'); return; }
    const p = await askPath({ save: true, title: 'Save dissection', filters: FILTERS, dflt: (summary.modules[0] || 'code').replace(/\.[^.]*$/, '') + '.hhdis' });
    if (!p) return;
    if (await attempt(async () => { await busy('Saving the dissection', api.dissectSave(p)); return true; })) toast(`Dissection saved to ${p}`, 'info');
  }
  async function load() {
    const p = await askPath({ save: false, title: 'Load dissection', filters: FILTERS });
    if (!p) return;
    const s = await attempt(() => busy('Loading the dissection', api.dissectLoad(p)));
    if (!s) return;
    summary = s;
    setTarget(null);
    showSummary(); reloadList(); list.focus();
    toast(`Loaded the dissection of ${s.modules.join(', ')}`, 'info');
  }
  const sbtn = (label, title, onclick, kbd) => h('button.btn' + (kbd ? '.wide' : ''), { type: 'button', title, onclick }, label, kbd ? ' ' : '', kbd ? h('kbd', null, kbd) : '');
  const addBtn = sbtn('Add modules', 'Dissect the ticked modules that are not in the dissection yet and merge them into it (Ctrl Shift Enter)', () => run(checked(), true), 'Ctrl Shift Enter');
  const cfBtn = sbtn('Code filter…', 'Find the functions that run only when you do something in the game (Alt C)', () => codeFilter(), 'Alt C');
  $('#dc-run').after(h('div.dc-more', { role: 'group', 'aria-label': 'Dissection' }, addBtn, cfBtn,
    sbtn('Save…', 'Save this dissection to a .hhdis file', save), sbtn('Load…', 'Load a dissection saved before (.hhdis)', load)));
  function showSummary() {
    const s = summary;
    $('#dc-summary').textContent = s
      ? `${s.modules.join(', ')} · ${fmtSize(s.code_bytes)} code · ${nf.format(s.instructions)} instructions · ${nf.format(s.functions)} functions · ${nf.format(s.refs)} references · ${nf.format(s.strings)} strings · ${nf.format(s.caves)} caves`
      : 'Not dissected yet. Pick modules and press Run, or load a saved dissection.';
    addBtn.disabled = !s;
    for (const [k, el] of Object.entries(counts)) el.textContent = s ? nf.format(k === 'functions' || k === 'called' ? s.functions : s[k]) : '';
  }

  // ---------- item list ----------
  const tabsEl = $('#dc-tabs'), counts = {};
  tabsEl.replaceChildren(...Object.entries(TABS).map(([k, t]) => {
    counts[k] = h('span.count.mono');
    return h('button', { role: 'tab', type: 'button', 'data-tab': k, 'aria-selected': String(k === tab), tabindex: k === tab ? '0' : '-1', 'aria-controls': 'dc-list' }, t.label, counts[k]);
  }));
  const src = pager((off, lim) => api.dissectList(tab, filter.value, off, lim), (e) => { if (e) toast(e); else { list.refresh(); if (list.sel < 0 && src.count()) list.select(0, { quiet: false }); } });
  let list = null;
  function buildList() {
    const t = TABS[tab];
    $('#dc-list').replaceChildren();
    list = vlist($('#dc-list'), {
      cols: t.cols, head: t.head, label: t.label,
      empty: () => (summary ? 'Nothing matches.' : !state.proc ? ['No process. Open one with ', h('kbd', null, 'Ctrl P'), ' to analyze its code.']
        : ['No dissection yet. Tick the modules on the left and press ', h('kbd', null, 'Ctrl Enter'), ' (Run): it finds functions, referenced strings, called functions and code caves, and lets the disassembler show who references an address.']),
      count: src.count, item: src.item,
      cells: (x) => tab === 'strings' ? [fmtAddr(x.addr), h('span', { role: 'gridcell', class: 'dc-str' }, JSON.stringify(x.text).slice(1, -1)), nf.format(x.refs)]
        : tab === 'caves' ? [fmtAddr(x.addr), fmtSize(x.len), x.byte === 0xcc ? 'CC (int3)' : x.byte.toString(16).toUpperCase().padStart(2, '0')]
          : [fmtAddr(x.addr), h('span', { role: 'gridcell', class: x.internal ? 'dc-fn' : 'dc-fn muted' }, x.name || modName(x.addr)), nf.format(x.callers)],
      onSelect: (i, x) => x && setTarget({ addr: x.addr, len: 1, label: tab === 'strings' ? `"${x.text.slice(0, 40)}"` : x.name || modName(x.addr) }),
      onActivate: (i, x) => x && activate(x),
    });
  }
  async function activate(x) {
    if (tab === 'strings') {
      const r = await attempt(() => api.dissectXrefs(x.addr, 1, 0, 1));
      if (r?.rows.length) emit('mem:goto', { addr: r.rows[0].from, pane: 'da' });
      else emit('mem:goto', { addr: x.addr, pane: 'hex' });
    } else emit('mem:goto', { addr: x.addr, pane: 'da' });
  }
  function reloadList() { src.reset(); list.refresh({ reset: true }); }
  function selectTab(k) {
    tab = k;
    for (const b of $$('[role=tab]', tabsEl)) { const s = b.dataset.tab === k; b.setAttribute('aria-selected', String(s)); b.tabIndex = s ? 0 : -1; }
    buildList();
    if (summary) reloadList();
  }
  tabsEl.addEventListener('click', (e) => { const b = e.target.closest('[role=tab]'); if (b) selectTab(b.dataset.tab); });
  tabsEl.addEventListener('keydown', (e) => {
    if (e.key !== 'ArrowLeft' && e.key !== 'ArrowRight') return;
    const ks = Object.keys(TABS), n = ks[(ks.indexOf(tab) + (e.key === 'ArrowRight' ? 1 : ks.length - 1)) % ks.length];
    selectTab(n); tabsEl.querySelector(`[data-tab="${n}"]`).focus();
  });
  filter.addEventListener('input', rafThrottle(() => { if (summary) reloadList(); }));
  filter.addEventListener('keydown', (e) => { if (e.key === 'ArrowDown' || e.key === 'Enter') { e.preventDefault(); list.focus(); list.select(Math.max(0, list.sel)); } });

  // ---------- cross references ----------
  const xsrc = pager((off, lim) => (target ? api.dissectXrefs(target.addr, target.len, off, lim) : Promise.resolve({ total: 0, rows: [] })), (e) => { if (e) toast(e); xlist.refresh(); $('#dc-xcount').textContent = target ? nf.format(xsrc.count()) : ''; });
  const xlist = vlist($('#dc-xrefs'), {
    cols: '128px 84px minmax(0, 1.4fr) minmax(0, 1fr)', head: ['From', 'Kind', 'Instruction', 'In function'], label: 'Cross references',
    empty: () => (target ? 'No references.' : 'Select an item to list what references it.'),
    count: xsrc.count, item: xsrc.item,
    cells: (x) => [fmtAddr(x.from), KIND[x.kind] || x.kind, h('span', { role: 'gridcell', class: 'c-text' }, ...instr(x.text)), x.func || ''],
    onActivate: (i, x) => x && emit('mem:goto', { addr: x.from, pane: 'da' }),
  });
  function instr(t) { const [m, ...rest] = t.split(' '); return [h('b', null, m), rest.length ? ' ' + rest.join(' ') : '']; }
  function setTarget(t) {
    target = t;
    $('#dc-xtitle').textContent = t ? `References to ${t.label}` : 'References';
    xsrc.reset();
    xlist.refresh({ reset: true });
  }

  /** "What references this address" from the disassembler / hex view. */
  on('code:xrefs', async (addr) => {
    showView('code');
    summary = await api.dissectSummary().catch(() => null);
    showSummary();
    if (!summary) { toast('Dissect the module first: pick it on the left and press Run', 'info'); $('#dc-run').focus(); return; }
    setTarget({ addr, len: 1, label: modName(addr) });
    xlist.focus();
  });
  on('code:dissect', async (name) => {
    showView('code');
    await loadMods();
    for (const i of $$('input', modList)) i.checked = i.value === name;
    run([name]);
  });
  on('process:closed', () => { summary = null; mods = []; modList.replaceChildren(h('p.empty', null, 'Open a process to list its modules.')); showSummary(); src.clear(); list.refresh({ reset: true }); setTarget(null); });
  on('process:opened', async () => { summary = null; target = null; await loadMods(); showSummary(); src.clear(); xsrc.clear(); list.refresh({ reset: true }); setTarget(null); });

  $('#dc-run').addEventListener('click', () => run());
  $('#dc-all').addEventListener('click', () => { const all = $$('input', modList); const on_ = all.some((i) => !i.checked); all.forEach((i) => { i.checked = on_; }); });
  view.addEventListener('keydown', (e) => {
    if (e.target.closest('input,select,textarea') && e.key !== 'Escape') return;
    const k = e.key.toLowerCase(), ctrl = e.ctrlKey || e.metaKey;
    if (ctrl && k === 'f') filter.focus();
    else if (ctrl && k === 'enter') run(checked(), e.shiftKey);
    else if (e.altKey && k === 'c') codeFilter();
    else if (e.altKey && k === 'x') xlist.focus();
    else if (e.altKey && k === 'l') list.focus();
    else return;
    e.preventDefault(); e.stopPropagation();
  });
  // ---------- code filter ----------
  /** Functions that ran in every "ran" recording and in none of the "did not run" ones. */
  async function codeFilter() {
    const { dialog, body } = listDialog('Code filter');
    let st = null, timer = 0;
    const status = h('p.cf-status.mono', { role: 'status' });
    const note = h('p.cf-note', { role: 'alert', hidden: true });
    const bStart = h('button.btn.primary', { type: 'button', onclick: () => act(api.codeFilterStart) }, 'Start recording ', h('kbd', null, 'R'));
    const bRan = h('button.btn.primary', { type: 'button', onclick: () => act(() => api.codeFilterStop(true)) }, 'Stop: it ran ', h('kbd', null, 'Y'));
    const bNot = h('button.btn', { type: 'button', onclick: () => act(() => api.codeFilterStop(false)) }, 'Stop: it did not run ', h('kbd', null, 'N'));
    const bReset = h('button.btn', { type: 'button', onclick: () => act(api.codeFilterReset) }, 'Reset ', h('kbd', null, 'Del'));
    const bAttach = h('button.btn', { type: 'button', onclick: async () => { emit('debug:attach'); setTimeout(refresh, 400); } }, 'Attach debugger');
    const csrc = pager((off, lim) => api.codeFilterList(off, lim), (e) => { if (e) toast(e); clist.refresh(); });
    const host = h('div.tool-list');
    const clist = vlist(host, {
      cols: '128px minmax(0, 1fr) 72px', head: ['Address', 'Function', 'Callers'], label: 'Functions left by the code filter',
      empty: () => (!st || !st.ran_sets ? 'Record a "ran" set first: start recording, do the action in the game, then stop with "it ran".' : 'No function is left: every one either missed a "ran" set or showed up in a "did not run" set. Reset and record again.'),
      count: csrc.count, item: csrc.item,
      cells: (x) => [fmtAddr(x.addr), h('span', { role: 'gridcell', class: x.internal ? 'dc-fn' : 'dc-fn muted' }, x.name || modName(x.addr)), nf.format(x.callers)],
      onActivate: (i, x) => { if (!x) return; dialog.close(); emit('mem:goto', { addr: x.addr, pane: 'da' }); },
    });
    body.append(
      h('p.hint', null, 'Finds the code behind one action. While recording, every function entry the current dissection found gets a one-shot breakpoint (int3): tens of thousands of them. ',
        'Each function is slowed only the first time it is called, then runs at full speed. Needs the debugger attached; nothing outside the dissection is ever touched.'),
      h('ol.cf-steps', null,
        h('li', null, 'Start recording, do the action in the game (for example jump), then stop with ', h('b', null, 'it ran'), '.'),
        h('li', null, 'Start again, do everything except that action (walk, open menus), then stop with ', h('b', null, 'it did not run'), '.'),
        h('li', null, 'Repeat until the list is short. It keeps functions that ran in every "ran" set and in no "did not run" set. ', h('kbd', null, 'Enter'), ' disassembles one.')),
      note, h('div.tool-bar', null, bStart, bRan, bNot, bReset, bAttach), status, host);
    function render() {
      const att = !!state.dbg?.attached, rec = !!st?.recording;
      note.hidden = att && !!summary;
      note.textContent = !state.proc ? 'Open a process first.' : state.proc.remote ? `The debugger works on local processes only; this target is on ${state.proc.remote}.`
        : !summary ? 'No dissection yet: dissect the game\'s module first (Run), the filter arms the functions it found.' : !att ? 'The debugger is not attached. Attach it to record.' : '';
      bAttach.hidden = att || !state.proc || !!state.proc.remote;
      bStart.disabled = rec || !att || !summary;
      bRan.disabled = bNot.disabled = !rec;
      bReset.disabled = rec || !st || !(st.ran_sets || st.not_ran_sets);
      status.textContent = !st ? '' : rec
        ? `Recording · ${nf.format(st.armed)} breakpoints armed · ${nf.format(st.last_hits)} functions hit so far`
        : `${nf.format(st.ran_sets)} "ran" set${st.ran_sets === 1 ? '' : 's'} · ${nf.format(st.not_ran_sets)} "did not run" set${st.not_ran_sets === 1 ? '' : 's'} · last recording hit ${nf.format(st.last_hits)} · ${nf.format(st.matches)} function${st.matches === 1 ? '' : 's'} left`;
    }
    async function refresh() {
      st = await api.codeFilterState().catch(() => null);
      render();
      clearTimeout(timer);
      if (st?.recording && dialog.open) timer = setTimeout(refresh, 500);
    }
    async function act(fn) {
      const r = await attempt(() => busy('Code filter', fn()));
      if (r) st = r;
      await refresh();
      csrc.reset(); clist.refresh({ reset: true });
      if (!st?.recording && st?.matches) clist.focus();
    }
    dialog.addEventListener('close', () => { clearTimeout(timer); if (st?.recording) toast('The code filter is still recording. Alt C in Code analysis opens it to stop.', 'info'); });
    dialog.addEventListener('keydown', (e) => {
      if (e.ctrlKey || e.metaKey || e.altKey || e.target.closest('input,select,textarea')) return;
      const k = e.key.toLowerCase(), b = k === 'r' ? bStart : k === 'y' ? bRan : k === 'n' ? bNot : e.key === 'Delete' ? bReset : null;
      if (!b) return;
      e.preventDefault(); e.stopPropagation();
      if (!b.disabled && !b.hidden) b.click();
    });
    await refresh();
    csrc.reset(); clist.refresh({ reset: true });
    (bStart.disabled ? (bRan.disabled ? clist : bRan) : bStart).focus();
  }
  helpAdd('Code analysis', [
    ['Ctrl Enter', 'Dissect the ticked modules'],
    ['Ctrl Shift Enter', 'Add the ticked modules to the dissection'],
    ['Alt C', 'Code filter: functions that run only on an action'],
    ['R / Y / N', 'Code filter: record, stop as "ran", stop as "did not run"'],
  ]);

  buildList();
  showSummary();
  return { focus: () => (summary ? list.focus() : $('#dc-run').focus()) };
}
