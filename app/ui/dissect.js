// Code analysis ("Dissect code"): pick modules, run with progress / cancel, then browse
// functions, referenced strings, referenced functions and code caves; the selected item's
// cross references are listed below. Enter jumps to the disassembler.
import { api } from './backend.js';
import { $, $$, h, fmtAddr, fmtSize, nf, attempt, toast, rafThrottle } from './util.js';
import { on, emit } from './core.js';
import { vlist, pager } from './vlist.js';
import { progressStrip, runJob } from './memtools.js';

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
  async function run(names = checked()) {
    if (!names.length) { toast('Pick at least one module'); return; }
    $('#dc-run').disabled = true;
    const opts = { recursive: $('#dc-rec').checked, min_string: +$('#dc-minstr').value || 4, min_cave: +$('#dc-mincave').value || 32 };
    const s = await runJob(() => api.dissectRun(names, opts), strip, 'Dissecting');
    $('#dc-run').disabled = false;
    if (!s) return;
    summary = s;
    showSummary();
    reloadList();
    list.focus();
  }
  function showSummary() {
    const s = summary;
    $('#dc-summary').textContent = s
      ? `${s.modules.join(', ')} · ${fmtSize(s.code_bytes)} code · ${nf.format(s.instructions)} instructions · ${nf.format(s.functions)} functions · ${nf.format(s.refs)} references · ${nf.format(s.strings)} strings · ${nf.format(s.caves)} caves`
      : 'Not dissected yet. Pick modules and press Run.';
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
      empty: () => (summary ? 'Nothing matches.' : 'Run a dissection first.'),
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
  on('process:opened', async () => { summary = null; target = null; await loadMods(); showSummary(); src.clear(); xsrc.clear(); list.refresh({ reset: true }); setTarget(null); });

  $('#dc-run').addEventListener('click', () => run());
  $('#dc-all').addEventListener('click', () => { const all = $$('input', modList); const on_ = all.some((i) => !i.checked); all.forEach((i) => { i.checked = on_; }); });
  view.addEventListener('keydown', (e) => {
    if (e.target.closest('input,select,textarea') && e.key !== 'Escape') return;
    const k = e.key.toLowerCase(), ctrl = e.ctrlKey || e.metaKey;
    if (ctrl && k === 'f') filter.focus();
    else if (ctrl && k === 'enter') run();
    else if (e.altKey && k === 'x') xlist.focus();
    else if (e.altKey && k === 'l') list.focus();
    else return;
    e.preventDefault(); e.stopPropagation();
  });
  buildList();
  showSummary();
  return { focus: () => (summary ? list.focus() : $('#dc-run').focus()) };
}
