// Scan results: virtualized rows fetched in pages via scan_results, live values for the
// visible rows only. Above ~180k rows the scrollbar is scaled so any count fits.
import { api } from './backend.js';
import { $, h, fmtAddr, rafThrottle, nf, attempt, contextMenu, toast } from './util.js';
import { state, addSource, emit } from './core.js';

const ROW = 22, PAGE = 256, MAXPX = 4_000_000, MAX_ADD = 2000;

export function initResults(root) {
  const vp = $('.vl-viewport', root), spacer = $('.vl-spacer', root), layer = $('.vl-rows', root);
  const countEl = $('#res-count'), savedSel = $('#res-saved'), empty = $('#res-empty');
  const headBit = $('.vl-head .c-bit', root), headSaved = $('.vl-head .c-saved', root);
  let scan = { count: 0, vtype: '4bytes', hex: false, len: 0, utf16: false, custom: null, custom_name: null, has: false };
  let busyScan = false, diff = '', isBinary = false;
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

  async function selectedRows() {
    if (cursor < 0) return [];
    const lo = Math.min(anchor, cursor), n = Math.min(MAX_ADD, Math.abs(anchor - cursor) + 1);
    if (Math.abs(anchor - cursor) + 1 > MAX_ADD) toast(`Only the first ${MAX_ADD} selected rows are used`, 'info');
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
  function menu(x, y) {
    contextMenu(x, y, [
      { label: 'Add to table', kbd: 'Enter', run: addSelected, disabled: cursor < 0 },
      { label: 'Browse memory here', kbd: 'Ctrl M', run: browse, disabled: cursor < 0 },
      { label: 'Copy addresses', kbd: 'Ctrl C', run: copySelected, disabled: cursor < 0 },
      '-',
      { label: 'Find out what accesses this address', kbd: 'F5', run: () => onAddr('debug:accesses'), disabled: cursor < 0 },
      { label: 'Find out what writes to this address', kbd: 'F6', run: () => onAddr('debug:writes'), disabled: cursor < 0 },
      { label: 'Pointer scan for this address…', run: () => onAddr('ptr:scan'), disabled: cursor < 0 },
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
    else if (ctrl && k.toLowerCase() === 'c') copySelected();
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
      resetRows();
      columns(); showEmpty();
      first = 0; cursor = -1; anchor = -1;
      ignoreScroll = vp.scrollTop !== 0;
      vp.scrollTop = 0;
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
