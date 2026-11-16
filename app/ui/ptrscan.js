// Pointer scanner: options dialog, progress and cancel, a virtualized result list (millions
// of paths; only the visible window is fetched, again on every tick for live values), rescan,
// save / open results, save pointer map, compare against saved maps.
import { api, askPath } from './backend.js';
import { $, h, fmtAddr, nf, attempt, toast, rafThrottle, store, icon } from './util.js';
import { state, emit, on, addTicker } from './core.js';
import { VTYPES } from './table.js';

const ROW = 22, MAXPX = 4_000_000;
const PHASE = { collect: 'Collecting pointers', scan: 'Scanning paths', rescan: 'Rescanning' };
const MAP_FILTER = [['HeapHook pointer map', ['hhpmap']], ['All files', ['*']]];
const RES_FILTER = [['HeapHook pointer results', ['hhptr']], ['All files', ['*']]];

/** "10, -8 1C" -> [16, -8, 28] (hex). */
function hexList(s) {
  return String(s || '').split(/[\s,]+/).filter(Boolean).map((x) => {
    const v = parseInt(x.replace(/^[-+]?(0x)?/i, ''), 16);
    if (Number.isNaN(v)) throw `'${x}' is not a hex offset`;
    return x.startsWith('-') ? -v : v;
  });
}
const hexNum = (s, name) => {
  const v = parseInt(String(s).trim().replace(/^0x/i, '') || '0', 16);
  if (Number.isNaN(v)) throw `${name}: '${s}' is not hex`;
  return v;
};
const addrOrNull = (s) => (String(s || '').trim() ? '0x' + String(s).trim().replace(/^0x/i, '') : null);

export function initPtrscan({ showView }) {
  const vp = $('#ptr-vp'), spacer = $('.vl-spacer', vp), layer = $('.vl-rows', vp), head = $('#ptr-head'), vt = $('#ptr-vtype');
  vt.append(...VTYPES.filter(([v]) => v !== 'aob' && v !== 'binary').map(([v, l]) => h('option', { value: v }, l)));
  vt.value = store.get('ptr.vtype', '4bytes');
  head.setAttribute('role', 'row');
  let info = null, running = false, rows = [], rowsAt = 0, first = 0, vis = 1, cursor = -1, ignoreScroll = false, fetching = false, gen = 0, sort = null;
  const pool = [];

  const count = () => info?.count ?? 0;
  const scaled = () => count() * ROW > MAXPX;
  const totalPx = () => Math.min(count() * ROW, MAXPX);
  const maxFirst = () => Math.max(0, count() - vis);
  const range = () => Math.max(1, totalPx() - vp.clientHeight);
  const firstFromScroll = (st) => Math.min(maxFirst(), scaled() ? Math.round((st / range()) * maxFirst()) : Math.floor(st / ROW));
  const scrollFromFirst = (f) => (scaled() ? (f / Math.max(1, maxFirst())) * range() : f * ROW);
  const levels = () => Math.max(1, info?.max_level ?? 1);
  const cols = () => `minmax(170px, 1.6fr) repeat(${levels()}, minmax(52px, 0.5fr)) minmax(120px, 1fr) minmax(90px, 1fr)`;

  async function fetchRows() {
    if (!info || running || fetching || !count()) return;
    fetching = true;
    const g = gen, at = first;
    try {
      const r = await api.ptrResults(at, vis + 1, vt.value, {});
      if (g === gen) { rows = r; rowsAt = at; schedule(); }
    } finally { fetching = false; }
  }
  const fetchSoon = rafThrottle(() => attempt(fetchRows));

  // ---------- sorting (the backend reorders the whole result set) ----------
  const th = (label, key, col) => (key
    ? h('span', { role: 'columnheader', 'data-key': key, 'data-col': col, 'aria-sort': 'none' },
      h('button', { type: 'button', title: `Sort by ${label.toLowerCase()}`, style: 'display:inline-flex;align-items:center;gap:4px;cursor:pointer;background:none;border:0;padding:0;font:inherit;color:inherit;', onclick: () => sortBy(key, col) }, label, h('span.sort-ic', { style: 'display:inline-flex' })))
    : h('span', { role: 'columnheader' }, label));
  function markSort() {
    for (const c of head.children) {
      if (!c.dataset.key) continue;
      const on = sort && sort.key === c.dataset.key && sort.column === +c.dataset.col;
      c.setAttribute('aria-sort', on ? (sort.desc ? 'descending' : 'ascending') : 'none');
      c.querySelector('.sort-ic').innerHTML = on ? icon(sort.desc ? 'down' : 'up') : '';
      c.querySelector('button').disabled = running || !count();
    }
  }
  async function sortBy(key, column) {
    const next = { key, column, desc: sort?.key === key && sort.column === column ? !sort.desc : false };
    if (await op(() => api.ptrSort(key, column, next.desc, vt.value, null), true)) { sort = next; render(); }
  }

  const set = (el, t) => { if (el.textContent !== t) el.textContent = t; };
  function render() {
    const L = levels();
    $('#ptr-empty').hidden = !!info;
    vp.hidden = !info; head.hidden = !info;
    $('#ptr-count').textContent = info ? nf.format(count()) : '';
    $('#ptr-target').textContent = info ? '→ ' + fmtAddr(info.target) : '';
    $('#ptr-rescan').disabled = !info || running;
    $('#ptr-save').disabled = !info || running;
    if (head.dataset.l !== String(L)) {
      head.dataset.l = String(L);
      head.style.gridTemplateColumns = cols();
      head.replaceChildren(th('Base', 'base', 0), ...Array.from({ length: L }, (_, i) => th(`Offset ${i}`, 'offset', i)), th('Points to'), th('Value', 'value', 0));
      pool.length = 0; layer.replaceChildren();
    }
    spacer.style.height = totalPx() + 'px';
    layer.style.transform = `translateY(${scaled() ? vp.scrollTop : first * ROW}px)`;
    const n = Math.max(0, Math.min(vis + 1, count() - first));
    while (pool.length < n) {
      const r = h('div.vl-row.ptr-row', { role: 'row', id: 'ptr-r' + pool.length, style: `grid-template-columns:${cols()}` },
        h('span', { role: 'gridcell' }), ...Array.from({ length: L }, () => h('span.muted', { role: 'gridcell' })), h('span', { role: 'gridcell' }), h('span.c-val', { role: 'gridcell' }));
      pool.push(r); layer.append(r);
    }
    pool.forEach((r, k) => {
      const i = first + k;
      r.hidden = k >= n;
      if (r.hidden) return;
      r.dataset.i = i;
      r.setAttribute('aria-rowindex', i + 2);
      r.setAttribute('aria-selected', String(i === cursor));
      r.classList.toggle('cursor', i === cursor);
      const d = rows[i - rowsAt], c = r.children;
      if (!d) { for (const x of c) set(x, ''); set(c[0], '…'); return; }
      set(c[0], d.base);
      for (let o = 0; o < L; o++) set(c[1 + o], d.offsets[o] ?? '');
      set(c[L + 1], d.address ? fmtAddr(d.address) : '??');
      set(c[L + 2], d.value ?? '??');
    });
    const ci = cursor - first;
    if (ci >= 0 && ci < n) vp.setAttribute('aria-activedescendant', 'ptr-r' + ci); else vp.removeAttribute('aria-activedescendant');
    vp.setAttribute('aria-rowcount', count() + 1);
    markSort();
  }
  const schedule = rafThrottle(render);
  function measure() { vis = Math.max(1, Math.floor(vp.clientHeight / ROW)); layer.style.height = vp.clientHeight + 'px'; schedule(); fetchSoon(); }
  new ResizeObserver(measure).observe(vp);
  vp.addEventListener('scroll', () => {
    if (ignoreScroll) { ignoreScroll = false; return; }
    first = firstFromScroll(vp.scrollTop);
    schedule(); fetchSoon();
  }, { passive: true });
  function moveTo(i) {
    if (!count()) return;
    cursor = Math.max(0, Math.min(count() - 1, i));
    if (cursor < first) first = cursor;
    else if (cursor >= first + vis) first = cursor - vis + 1;
    const st = scrollFromFirst(first);
    if (Math.abs(vp.scrollTop - st) > 0.5) { ignoreScroll = true; vp.scrollTop = st; }
    schedule(); fetchSoon();
  }
  function setInfo(i) {
    info = i; sort = null; gen++; rows = []; first = 0; cursor = -1;
    ignoreScroll = vp.scrollTop !== 0; vp.scrollTop = 0;
    measure(); render();
  }

  async function addEntry() {
    // The list is focused before a scan's rows arrive, so there may be no cursor yet.
    if (cursor < 0) { if (!count()) return; moveTo(first); }
    const d = rows[cursor - rowsAt];
    const e = await attempt(() => api.ptrEntry(cursor, vt.value, d ? `Pointer ${d.text}` : 'Pointer path'));
    if (!e) return;
    if (e.vtype === 'string') e.len = 16;
    emit('table:add', [e]);
    toast('Added the pointer path to the table', 'info');
  }

  vp.addEventListener('keydown', (e) => {
    const k = e.key;
    if (e.ctrlKey || e.metaKey || e.altKey) return;
    if (k === 'ArrowDown') moveTo(cursor + 1);
    else if (k === 'ArrowUp') moveTo(cursor - 1);
    else if (k === 'PageDown') moveTo(cursor + vis);
    else if (k === 'PageUp') moveTo(cursor - vis);
    else if (k === 'Home') moveTo(0);
    else if (k === 'End') moveTo(count() - 1);
    else if (k === 'Enter' || k === 'Insert') addEntry();
    else if (k.toLowerCase() === 'n') scanDialog();
    else if (k.toLowerCase() === 'r' && info) rescanDialog();
    else if (k === 'Escape' && running) cancel();
    else return;
    e.preventDefault(); e.stopPropagation();
  });
  vp.addEventListener('focus', () => { if (cursor < 0 && count()) moveTo(first); });
  layer.addEventListener('mousedown', (e) => { const r = e.target.closest('.vl-row'); if (r) moveTo(+r.dataset.i); });
  layer.addEventListener('dblclick', (e) => { if (e.target.closest('.vl-row')) addEntry(); });
  vt.addEventListener('change', () => { store.set('ptr.vtype', vt.value); if (sort?.key === 'value') { sort = null; markSort(); } attempt(fetchRows); });

  // ---------- running operations ----------
  async function op(f, quiet = false) {
    if (running) { toast('A pointer scan is already running'); return false; }
    running = true;
    $('#ptr-progress').hidden = false;
    render();
    const poll = setInterval(progress, 200);
    try {
      const r = await attempt(f);
      if (r) { setInfo(r); if (!quiet) toast(`${nf.format(r.count)} pointer path${r.count === 1 ? '' : 's'}`, 'info'); }
      return !!r;
    } finally {
      clearInterval(poll);
      running = false;
      $('#ptr-progress').hidden = true;
      render(); fetchSoon();
      vp.focus();
    }
  }
  async function progress() {
    const p = await api.ptrProgress().catch(() => null);
    if (!p) return;
    const pct = p.total ? Math.min(100, (p.done / p.total) * 100) : 0;
    $('#ptr-bar').style.transform = `scaleX(${pct / 100})`;
    $('#ptr-bar-wrap').setAttribute('aria-valuenow', Math.round(pct));
    $('#ptr-phase').textContent = `${PHASE[p.phase] || 'Working'} · ${nf.format(p.found)} found`;
  }
  const cancel = () => attempt(() => api.ptrCancel());
  $('#ptr-cancel').addEventListener('click', cancel);

  // ---------- scan dialog ----------
  const dScan = $('#dlg-ptrscan'), fScan = dScan.querySelector('form'), cmp = $('#ps-cmp');
  function cmpRow(path = '', target = '') {
    const row = h('div.cmp-row', null,
      h('input.mono', { value: path, placeholder: 'pointer map file', 'aria-label': 'Pointer map file', spellcheck: 'false' }),
      h('input.mono', { value: target, placeholder: 'address there', 'aria-label': 'Address of the value in that map', spellcheck: 'false' }),
      h('button.btn', { type: 'button', onclick: async () => { const p = await askPath({ save: false, title: 'Pointer map to compare', filters: MAP_FILTER }); if (p) row.firstChild.value = p; } }, 'Browse'),
      h('button.btn.icon', { type: 'button', 'aria-label': 'Remove', html: icon('x'), onclick: () => row.remove() }));
    cmp.append(row);
    return row;
  }
  $('#ps-cmp-add').addEventListener('click', () => cmpRow().firstChild.focus());
  $('#ps-mapbrowse').addEventListener('click', async () => { const p = await askPath({ save: false, title: 'Scan a saved pointer map', filters: MAP_FILTER }); if (p) fScan.elements.map_path.value = p; });
  function scanDialog(d = {}) {
    if (!state.proc) { toast('Open a process first'); return; }
    const el = fScan.elements, saved = store.get('ptr.opts', null);
    if (saved) for (const [k, v] of Object.entries(saved)) { const x = el[k]; if (!x) continue; if (x.type === 'checkbox') x.checked = v; else x.value = v; }
    if (d.addr) el.target.value = fmtAddr(d.addr);
    if (d.vtype && [...vt.options].some((o) => o.value === d.vtype)) { vt.value = d.vtype; store.set('ptr.vtype', d.vtype); }
    cmp.replaceChildren();
    dScan.returnValue = '';
    dScan.onclose = () => {
      if (dScan.returnValue !== 'ok') return;
      let req;
      try {
        const keep = {};
        for (const x of el) if (x.name && x.name !== 'target' && x.name !== 'map_path') keep[x.name] = x.type === 'checkbox' ? x.checked : x.value;
        store.set('ptr.opts', keep);
        req = {
          target: addrOrNull(el.target.value) ?? (() => { throw 'Enter the address to find'; })(),
          opts: {
            max_level: Math.max(1, Math.min(16, +el.max_level.value || 5)), max_offset: hexNum(el.max_offset.value, 'Max offset'),
            allow_negative: el.allow_negative.checked, static_only: el.static_only.checked,
            base_modules: el.base_modules.value.split(',').map((x) => x.trim()).filter(Boolean),
            thread_stacks: el.thread_stacks.checked, stack_max: hexNum(el.stack_max.value, 'Stack size'), no_loops: el.no_loops.checked,
            max_children: +el.max_children.value || 0, last_offsets: hexList(el.last_offsets.value), ends_with: hexList(el.ends_with.value),
            heap_only: el.heap_only.checked, max_results: +el.max_results.value || 0, threads: +el.threads.value || 0,
          },
          base_start: addrOrNull(el.base_start.value), base_end: addrOrNull(el.base_end.value),
          alignment: +el.alignment.value || 0, writable_only: el.writable_only.checked,
          map_path: el.map_path.value.trim() || null,
          compare: [...cmp.children].map((r) => ({ path: r.children[0].value.trim(), target: addrOrNull(r.children[1].value) })).filter((c) => c.path),
        };
        if (req.compare.some((c) => !c.target)) throw 'Each compared pointer map needs the address of the value in it';
      } catch (err) { toast(err); return; }
      showView('ptr');
      op(() => api.ptrScan(req));
    };
    dScan.showModal();
    el.target.focus(); el.target.select();
  }
  $('#ptr-new').addEventListener('click', () => scanDialog());
  on('ptr:scan', scanDialog);

  // ---------- rescan dialog ----------
  const dRe = $('#dlg-ptrrescan'), fRe = dRe.querySelector('form');
  fRe.elements.vtype.append(...VTYPES.filter(([v]) => v !== 'binary').map(([v, l]) => h('option', { value: v }, l)));
  $('#pr-mapbrowse').addEventListener('click', async () => { const p = await askPath({ save: false, title: 'Rescan against a saved pointer map', filters: MAP_FILTER }); if (p) fRe.elements.map_path.value = p; });
  function rescanDialog() {
    if (!info) return;
    const el = fRe.elements;
    el.vtype.value = vt.value;
    dRe.returnValue = '';
    dRe.onclose = () => {
      if (dRe.returnValue !== 'ok') return;
      let req;
      try {
        const value = el.value.value.trim();
        req = {
          target: addrOrNull(el.target.value), value: value || null, vtype: value ? el.vtype.value : null,
          fmt: { utf16: false, hex: false, signed: false }, base_start: addrOrNull(el.base_start.value), base_end: addrOrNull(el.base_end.value),
          starts_with: hexList(el.starts_with.value), ends_with: hexList(el.ends_with.value), max_level: +el.max_level.value || 0,
          map_path: el.map_path.value.trim() || null,
        };
      } catch (err) { toast(err); return; }
      op(() => api.ptrRescan(req));
    };
    dRe.showModal();
    el.target.focus();
  }
  $('#ptr-rescan').addEventListener('click', rescanDialog);

  // ---------- files ----------
  $('#ptr-save').addEventListener('click', async () => {
    const p = await askPath({ save: true, title: 'Save pointer scan results', filters: RES_FILTER, dflt: 'pointers.hhptr' });
    if (p && await attempt(async () => { await api.ptrSaveResults(p); return true; })) toast(`Saved ${p}`, 'info');
  });
  $('#ptr-open').addEventListener('click', async () => {
    if (!state.proc) { toast('Open a process first'); return; }
    const p = await askPath({ save: false, title: 'Open pointer scan results', filters: RES_FILTER });
    const r = p && await attempt(() => api.ptrOpenResults(p));
    if (r) { setInfo(r); vp.focus(); }
  });
  $('#ptr-map').addEventListener('click', async () => {
    if (!state.proc) { toast('Open a process first'); return; }
    const p = await askPath({ save: true, title: 'Save pointer map', filters: MAP_FILTER, dflt: 'process.hhpmap' });
    if (p && await attempt(async () => { await api.ptrSaveMap(p); return true; })) toast(`Saved pointer map ${p}`, 'info');
  });

  addTicker(() => (state.view === 'ptr' && !running ? fetchRows() : null));
  on('process:opened', () => setInfo(null));
  render();

  return { get running() { return running; }, cancel, focus: () => vp.focus(), newScan: () => scanDialog() };
}
