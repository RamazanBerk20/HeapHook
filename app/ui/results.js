// Scan results: virtualized rows fetched in pages via scan_results, live values for the
// visible rows only. Above ~180k rows the scrollbar is scaled so any count fits.
import { api, askPath } from './backend.js';
import { $, h, fmtAddr, fmtSize, rafThrottle, nf, attempt, contextMenu, toast, busy, modal, icon, helpAdd } from './util.js';
import { state, addSource, emit } from './core.js';
import { listDialog } from './memtools.js';
import { vlist } from './vlist.js';

const ROW = 22, PAGE = 256, MAXPX = 4_000_000, MAX_ADD = 2000;
// Backend caps (hh-scan): sorting other than address ascending, and copying to the clipboard.
const SORT_MAX = 5_000_000, COPY_MAX = 1_000_000, REMOVE_MAX = 100_000;

export function initResults(root) {
  const vp = $('.vl-viewport', root), spacer = $('.vl-spacer', root), layer = $('.vl-rows', root);
  const countEl = $('#res-count'), savedSel = $('#res-saved'), empty = $('#res-empty');
  const headBit = $('.vl-head .c-bit', root), headSaved = $('.vl-head .c-saved', root);
  let scan = { count: 0, vtype: '4bytes', hex: false, len: 0, utf16: false, custom: null, custom_name: null, has: false };
  let busyScan = false, diff = '', isBinary = false, sorted = null; // sorted: {key, desc} until the results change
  let gen = 0, first = 0, vis = 0, cursor = -1, anchor = -1, ignoreScroll = false;
  const pages = new Map(), pending = new Set(), live = new Map(), pool = [];

  const count = () => scan.count;
  // "all" scans: each row says which type matched
  const rowType = (r) => (scan.vtype === 'all' ? r?.vtype || '4bytes' : scan.vtype);
  function columns() {
    isBinary = scan.has && scan.vtype === 'binary';
    headBit.hidden = !isBinary; headSaved.hidden = !diff;
    root.style.setProperty('--res-cols', `minmax(124px, 1.15fr)${isBinary ? ' 36px' : ''} 1fr 1fr 1fr${diff ? ' 1fr' : ''}`);
  }
  function showEmpty() {
    empty.hidden = !!count() && !busyScan;
    empty.innerHTML = !state.proc ? 'Open a process with <kbd>Ctrl P</kbd> to scan its memory.'
      : busyScan ? 'Scanning… <kbd>Esc</kbd> cancels.'
        : scan.has ? 'Nothing matched. <kbd>Ctrl Z</kbd> undoes the last scan, <kbd>Ctrl N</kbd> starts a new one.'
          : 'Type a value and press <kbd>Enter</kbd> for a first scan (<kbd>Alt 1</kbd> focuses it), or choose <b>Unknown initial value</b>. <kbd>Ctrl Enter</kbd> scans from anywhere.';
  }
  function resetRows() {
    gen++;
    pages.clear(); pending.clear(); live.clear();
  }
  savedSel.addEventListener('change', () => { diff = savedSel.value; resetRows(); columns(); schedule(); });
  const scaled = () => count() * ROW > MAXPX;
  const totalPx = () => Math.min(count() * ROW, MAXPX);
  const maxFirst = () => Math.max(0, count() - vis);
  const range = () => Math.max(1, totalPx() - vp.clientHeight);
  const firstFromScroll = (st) => Math.min(maxFirst(), scaled() ? Math.round((st / range()) * maxFirst()) : Math.floor(st / ROW));
  const scrollFromFirst = (f) => (scaled() ? (f / Math.max(1, maxFirst())) * range() : f * ROW);

  function rowData(i) {
    const p = (i / PAGE) | 0, page = pages.get(p);
    if (page) return page[i - p * PAGE];
    if (!pending.has(p)) {
      pending.add(p);
      const g = gen;
      (diff ? api.scanResultsSaved(p * PAGE, PAGE, diff) : api.scanResults(p * PAGE, PAGE)).then((rows) => {
        if (g !== gen) return;
        pending.delete(p);
        pages.set(p, rows);
        if (pages.size > 64) pages.delete(pages.keys().next().value);
        schedule();
      }, (e) => { pending.delete(p); toast(e); });
    }
    return null;
  }

  const set = (el, txt) => { if (el.textContent !== txt) el.textContent = txt; };
  function render() {
    spacer.style.height = totalPx() + 'px';
    const st = vp.scrollTop;
    layer.style.transform = `translateY(${scaled() ? st : first * ROW}px)`;
    const n = Math.max(0, Math.min(vis + 1, count() - first));
    while (pool.length < n) {
      const r = h('div.vl-row', { role: 'row', id: 'res-r' + pool.length },
        h('span.c-addr', { role: 'gridcell' }), h('span.c-val', { role: 'gridcell' }),
        h('span.c-prev', { role: 'gridcell' }), h('span.c-first', { role: 'gridcell' }), h('span.c-saved', { role: 'gridcell' }));
      r.children[0].after(h('span.c-bit', { role: 'gridcell' }));
      pool.push(r); layer.append(r);
    }
    for (let k = 0; k < pool.length; k++) {
      const r = pool[k], i = first + k;
      if (k >= n) { r.hidden = true; continue; }
      r.hidden = false;
      r.dataset.i = i;
      r.setAttribute('aria-rowindex', i + 2);
      const lo = Math.min(anchor, cursor), hi = Math.max(anchor, cursor);
      const selected = i >= lo && i <= hi && cursor >= 0;
      r.setAttribute('aria-selected', String(selected));
      r.classList.toggle('cursor', i === cursor);
      const d = rowData(i), [a, b, v, p, f, sv] = r.children;
      b.hidden = !isBinary; sv.hidden = !diff;
      if (!d) { set(a, '…'); set(b, ''); set(v, ''); set(p, ''); set(f, ''); set(sv, ''); continue; }
      const val = live.get(i) ?? d.value;
      set(a, fmtAddr(d.addr)); set(b, d.bit == null ? '' : String(d.bit)); set(v, val ?? '??'); set(p, d.previous); set(f, d.first);
      set(sv, diff ? d.saved ?? '–' : '');
      v.classList.toggle('chg', val !== d.previous);
      sv.classList.toggle('chg', !!diff && d.saved != null && val !== d.saved);
      a.title = scan.vtype === 'all' && d.vtype ? `${fmtAddr(d.addr)} · ${d.vtype}` : '';
    }
    const ci = cursor - first;
    if (ci >= 0 && ci < n) vp.setAttribute('aria-activedescendant', 'res-r' + ci);
    else vp.removeAttribute('aria-activedescendant');
    vp.setAttribute('aria-rowcount', count() + 1);
  }
  const schedule = rafThrottle(render);

  function measure() { vis = Math.max(1, Math.floor(vp.clientHeight / ROW)); layer.style.height = vp.clientHeight + 'px'; schedule(); }
  new ResizeObserver(measure).observe(vp);
  vp.addEventListener('scroll', () => {
    if (ignoreScroll) { ignoreScroll = false; return; }
    first = firstFromScroll(vp.scrollTop);
    schedule();
  }, { passive: true });

  function moveTo(i, extend) {
    if (!count()) return;
    i = Math.max(0, Math.min(count() - 1, i));
    cursor = i;
    if (!extend) anchor = i;
    if (i < first) first = i;
    else if (i >= first + vis) first = i - vis + 1;
    const st = scrollFromFirst(first);
    if (Math.abs(vp.scrollTop - st) > 0.5) { ignoreScroll = true; vp.scrollTop = st; }
    schedule();
  }

  async function selectedRows(max = MAX_ADD) {
    if (cursor < 0) return [];
    const lo = Math.min(anchor, cursor), n = Math.min(max, Math.abs(anchor - cursor) + 1);
    if (Math.abs(anchor - cursor) + 1 > max) toast(`Only the first ${nf.format(max)} selected rows are used`, 'info');
    return api.scanResults(lo, n);
  }
  async function addSelected() {
    const rows = await attempt(selectedRows);
    if (!rows?.length) return;
    emit('table:add', rows.map((r) => ({
      addr: fmtAddr(r.addr), vtype: rowType(r), len: scan.len, utf16: scan.utf16, hex: scan.hex,
      ...(scan.custom ? { custom: scan.custom, custom_name: scan.custom_name } : {}),
    })));
    toast(`Added ${rows.length} address${rows.length > 1 ? 'es' : ''} to the table`, 'info');
  }
  async function copySelected() {
    const rows = await attempt(selectedRows);
    if (rows?.length) await attempt(() => navigator.clipboard.writeText(rows.map((r) => fmtAddr(r.addr)).join('\n')));
  }
  async function browse() {
    const d = cursor >= 0 && rowData(cursor);
    if (d) emit('mem:goto', { addr: d.addr, pane: 'hex' });
  }
  function onAddr(event) {
    const d = cursor >= 0 && rowData(cursor);
    if (d) emit(event, { addr: d.addr, vtype: rowType(d), len: scan.len, utf16: scan.utf16, description: 'Pointer to ' + fmtAddr(d.addr) });
  }
  // ---------- whole-list actions (1.0) ----------
  function toTop() { first = 0; cursor = -1; anchor = -1; ignoreScroll = vp.scrollTop !== 0; vp.scrollTop = 0; }
  async function sortBy(key, desc) {
    if (!count() || busyScan) return;
    if ((key !== 'address' || desc) && count() > SORT_MAX) {
      toast(`Sorting ${nf.format(count())} results by ${key === 'value' ? 'value' : 'descending address'} is refused above ${nf.format(SORT_MAX)}: narrow them with a next scan first`, 'info');
      return;
    }
    const ok = await busy('Sorting results', () => attempt(async () => { await api.scanSort(key, desc); return true; }));
    if (!ok) return;
    sorted = key === 'address' && !desc ? null : { key, desc };
    resetRows(); toTop(); measure();
  }
  async function removeSelected() {
    if (cursor < 0 || busyScan) return;
    const rows = await attempt(() => selectedRows(REMOVE_MAX));
    if (!rows?.length) return;
    const removed = await attempt(() => api.scanRemove(rows.map((r) => r.addr)));
    if (removed == null) return;
    const at = Math.min(anchor, cursor);
    scan.count = Math.max(0, scan.count - removed);
    sorted = null; // a changed result set is back in address order
    resetRows();
    countEl.textContent = scan.count ? nf.format(scan.count) : '';
    showEmpty(); measure();
    cursor = anchor = -1;
    if (count()) moveTo(Math.min(at, count() - 1));
    emit('scan:removed', { count: scan.count });
    toast(`Removed ${nf.format(removed)} result${removed === 1 ? '' : 's'} (Ctrl Z brings them back)`, 'info');
  }
  async function exportAll() {
    if (!count()) return;
    const p = await askPath({ save: true, title: 'Export every result address', filters: [['Text', ['txt']], ['All files', ['*']]], dflt: 'addresses.txt' });
    if (!p) return;
    const n = await busy('Exporting addresses', () => attempt(() => api.scanExportAddresses(p)));
    if (n != null) toast(`Exported ${nf.format(n)} addresses to ${p}`, 'info');
  }
  async function copyAll() {
    if (!count() || busyScan) return;
    if (count() > COPY_MAX) {
      const r = await modal({ title: 'Too many to copy', text: `${nf.format(count())} addresses are more than the clipboard copy takes (${nf.format(COPY_MAX)}). Export them to a text file instead (one address per line)?`,
        buttons: [{ label: 'Export…', value: 'export', kbd: 'Enter', primary: true }, { label: 'Cancel', value: 'cancel', kbd: 'Esc' }] });
      if (r.value === 'export') exportAll();
      return;
    }
    const text = await busy('Copying addresses', () => attempt(() => api.scanCopyAddresses()));
    if (text == null) return;
    try { await navigator.clipboard.writeText(text); toast(`Copied ${nf.format(count())} addresses`, 'info'); } catch (e) { toast(e?.message || e); }
  }
  async function statsDialog() {
    if (!count()) return;
    const rows = await busy('Counting results per region', () => attempt(() => api.scanStats()));
    if (!rows) return;
    const { dialog, body } = listDialog('Results per region');
    const host = h('div.tool-list');
    const byRegion = [...rows].sort((a, b) => b.count - a.count);
    const mods = new Map();
    for (const r of rows) {
      const k = r.module || `${r.kind || 'Other'} memory, no module`;
      const m = mods.get(k) || mods.set(k, { name: k, regions: 0, count: 0 }).get(k);
      m.regions++; m.count += r.count;
    }
    const byModule = [...mods.values()].sort((a, b) => b.count - a.count);
    const total = rows.reduce((t, r) => t + r.count, 0);
    let list = null;
    function show(mode) {
      host.replaceChildren();
      list = mode === 'module'
        ? vlist(host, { cols: 'minmax(0, 1fr) 90px 110px', head: ['Module', 'Regions', 'Results'], label: 'Results per module', empty: 'No results.',
          count: () => byModule.length, item: (i) => byModule[i], cells: (m) => [m.name, nf.format(m.regions), nf.format(m.count)] })
        : vlist(host, { cols: '128px 80px 72px minmax(0, 1fr) 100px', head: ['Region', 'Size', 'Kind', 'Module / file', 'Results'], label: 'Results per region', empty: 'No results.',
          count: () => byRegion.length, item: (i) => byRegion[i],
          cells: (r) => [fmtAddr(r.start), r.size ? fmtSize(r.size) : 'unmapped', r.kind || '', r.module || r.path || '', nf.format(r.count)],
          onActivate: (i) => { dialog.close(); emit('mem:goto', { addr: byRegion[i].start, pane: 'hex' }); } });
      list.refresh({ reset: true });
      list.focus();
    }
    const mode = h('select.compact', { 'aria-label': 'Group the results by', onchange: () => show(mode.value) },
      h('option', { value: 'region' }, 'Per region'), h('option', { value: 'module' }, 'Per module'));
    body.append(h('div.tool-bar', null, mode,
      h('p.hint', null, `${nf.format(total)} results in ${nf.format(rows.length)} regions, most first. Enter on a region shows it in the hex view.`)), host);
    show('region');
  }
  /** Actions on the whole result list: the toolbar menu and the lower part of the row menu. */
  function listItems() {
    const none = !count() || busyScan, big = count() > SORT_MAX;
    const capped = (l) => (big ? `${l} (up to ${nf.format(SORT_MAX)} results)` : l);
    const sortItem = (key, desc, label) => ({
      label: key === 'address' && !desc ? label : capped(label), run: () => sortBy(key, desc),
      checked: sorted ? sorted.key === key && sorted.desc === desc : key === 'address' && !desc,
      disabled: none || ((key !== 'address' || desc) && big),
    });
    return [
      { label: 'Remove selected from the results', kbd: 'Del', run: removeSelected, disabled: none || cursor < 0 },
      '-',
      sortItem('address', false, 'Sort by address'),
      sortItem('address', true, 'Sort by address, descending'),
      sortItem('value', false, 'Sort by value (of the last scan)'),
      sortItem('value', true, 'Sort by value, descending'),
      '-',
      { label: count() > COPY_MAX ? 'Copy all addresses (too many: export)…' : 'Copy all addresses', kbd: 'Ctrl Shift C', run: copyAll, disabled: none },
      { label: 'Export all addresses to a file…', run: exportAll, disabled: none },
      { label: 'Results per region / module…', run: statsDialog, disabled: none },
    ];
  }
  const moreBtn = h('button.btn.ghost.icon#res-more', { type: 'button', 'aria-label': 'Result list actions: sort, remove, copy, export, summary', title: 'Sort, remove, copy, export, summary', 'aria-haspopup': 'menu', html: icon('more'),
    onclick: () => { const r = moreBtn.getBoundingClientRect(); contextMenu(r.left, r.bottom + 4, listItems(), moreBtn); } });
  $('.panel-head .hints', root).before(moreBtn);
  helpAdd('Results', [['Del', 'Remove selected results (Ctrl Z brings them back)'], ['Ctrl Shift C', 'Copy every result address']]);

  function menu(x, y) {
    contextMenu(x, y, [
      { label: 'Add to table', kbd: 'Enter', run: addSelected, disabled: cursor < 0 },
      { label: 'Browse memory here', kbd: 'Ctrl M', run: browse, disabled: cursor < 0 },
      { label: 'Copy addresses', kbd: 'Ctrl C', run: copySelected, disabled: cursor < 0 },
      '-',
      { label: 'Find out what accesses this address', kbd: 'F5', run: () => onAddr('debug:accesses'), disabled: cursor < 0 },
      { label: 'Find out what writes to this address', kbd: 'F6', run: () => onAddr('debug:writes'), disabled: cursor < 0 },
      { label: 'Pointer scan for this address…', run: () => onAddr('ptr:scan'), disabled: cursor < 0 },
      '-',
      ...listItems(),
    ], vp);
  }

  vp.addEventListener('keydown', (e) => {
    const k = e.key, ctrl = e.ctrlKey || e.metaKey;
    if (k === 'ArrowDown') moveTo(cursor + 1, e.shiftKey);
    else if (k === 'ArrowUp') moveTo(cursor - 1, e.shiftKey);
    else if (k === 'PageDown') moveTo(cursor + vis, e.shiftKey);
    else if (k === 'PageUp') moveTo(cursor - vis, e.shiftKey);
    else if (k === 'Home') moveTo(0, e.shiftKey);
    else if (k === 'End') moveTo(count() - 1, e.shiftKey);
    else if (k === 'Enter' || k === 'Insert') addSelected();
    else if (ctrl && e.shiftKey && k.toLowerCase() === 'c') copyAll();
    else if (ctrl && k.toLowerCase() === 'c') copySelected();
    else if (k === 'Delete') removeSelected();
    else if (ctrl && k.toLowerCase() === 'm') browse();
    else if (k === 'F5') onAddr('debug:accesses');
    else if (k === 'F6') onAddr('debug:writes');
    else if (ctrl && !e.shiftKey && k.toLowerCase() === 'a') { anchor = 0; moveTo(count() - 1, true); }
    else if (k === 'ContextMenu' || (e.shiftKey && k === 'F10')) {
      const r = vp.getBoundingClientRect();
      menu(r.left + 40, r.top + (cursor - first + 1) * ROW);
    } else return;
    e.preventDefault();
    e.stopPropagation();
  });
  vp.addEventListener('focus', () => { if (cursor < 0 && count()) moveTo(first); });
  const rowAt = (e) => e.target.closest('.vl-row');
  layer.addEventListener('mousedown', (e) => {
    const r = rowAt(e);
    if (!r || e.button === 1) return;
    if (e.button === 2 && r.getAttribute('aria-selected') === 'true') return;
    moveTo(+r.dataset.i, e.shiftKey);
  });
  layer.addEventListener('dblclick', (e) => { if (rowAt(e)) addSelected(); });
  layer.addEventListener('contextmenu', (e) => { if (!rowAt(e)) return; e.preventDefault(); menu(e.clientX, e.clientY); });

  addSource({
    idx: [],
    collect() {
      this.idx = [];
      if (state.view !== 'scan' || !count()) return [];
      const reqs = [];
      for (let i = first; i < Math.min(count(), first + vis + 1); i++) {
        const d = rowData(i);
        if (!d) continue;
        this.idx.push(i);
        reqs.push({ addr: d.addr, vtype: rowType(d), len: scan.len || undefined, utf16: scan.utf16, hex: scan.hex, ...(scan.custom ? { custom: scan.custom } : {}) });
      }
      return reqs;
    },
    apply(vals) { live.clear(); this.idx.forEach((i, k) => live.set(i, vals[k])); schedule(); },
  });

  columns(); showEmpty();
  return {
    /** New result set (or none). scan: {count, vtype, hex, len, utf16} */
    set(s) {
      scan = { ...scan, custom: null, custom_name: null, ...s, has: !!s.has };
      resetRows(); sorted = null;
      columns(); showEmpty();
      toTop();
      countEl.textContent = s.count ? nf.format(s.count) : '';
      measure();
      render();
    },
    focus: () => vp.focus(),
    /** The scanner is (not) running a scan: loading text in the empty pane. */
    setBusy(b) { busyScan = b; showEmpty(); },
    /** Saved scans [{name, count, kept}] for the "diff against" select. */
    setSaved(list) {
      const cur = savedSel.value;
      savedSel.replaceChildren(h('option', { value: '' }, 'No saved scan'), ...list.map((x) => h('option', { value: x.name }, x.name)));
      savedSel.value = list.some((x) => x.name === cur) ? cur : '';
      $('#res-saved-wrap').hidden = !list.length;
      if (savedSel.value !== diff) { diff = savedSel.value; resetRows(); columns(); schedule(); }
    },
  };
}
