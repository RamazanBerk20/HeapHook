// Generic virtualized list: fixed row height, keyboard navigation, ARIA grid, rows rendered
// from a pool. Data comes from `count()` and `item(i)` (null = still loading); `pager()`
// turns a paged backend query into that pair.
import { h, rafThrottle } from './util.js';

let uid = 0;

/**
 * vlist(host, {cols, head: [labels]?, label, row = 22, cells(item, i) -> [Node|string],
 *   count(), item(i), onActivate(i, item, e), onSelect(i, item), onMenu(x, y, i, item), rowClass(item, i)})
 * `cols` is a grid-template-columns value. Returns {refresh, select(i), get sel, item, focus, el}.
 */
export function vlist(host, o) {
  const id = 'vl' + ++uid, ROW = o.row || 22;
  const head = o.head ? h('div.vl-head.vl-grid', { role: 'row', style: `grid-template-columns:${o.cols}` },
    ...o.head.map((x) => h('span', { role: 'columnheader' }, x))) : null;
  const vp = h('div.vl-viewport', { role: 'grid', tabindex: '0', 'aria-label': o.label || 'List' });
  const spacer = h('div.vl-spacer'), layer = h('div.vl-rows', { role: 'rowgroup' });
  vp.append(spacer, layer);
  const empty = h('p.empty', { hidden: true }, typeof o.empty === 'string' ? o.empty : 'Nothing to show.');
  host.append(...[head, vp, empty].filter(Boolean));
  let first = 0, vis = 1, sel = -1;
  const pool = [];

  const n = () => o.count();
  function render() {
    const total = n();
    spacer.style.height = total * ROW + 'px';
    layer.style.transform = `translateY(${first * ROW}px)`;
    empty.hidden = total > 0;
    if (o.empty) empty.textContent = typeof o.empty === 'function' ? o.empty() : o.empty;
    const k = Math.max(0, Math.min(vis + 1, total - first));
    while (pool.length < k) {
      const r = h('div.vl-row', { role: 'row', id: `${id}-r${pool.length}`, style: `grid-template-columns:${o.cols}` });
      pool.push(r); layer.append(r);
    }
    pool.forEach((r, j) => {
      const i = first + j;
      if (j >= k) { r.hidden = true; return; }
      r.hidden = false;
      r.dataset.i = i;
      r.setAttribute('aria-rowindex', i + 1);
      r.setAttribute('aria-selected', String(i === sel));
      r.classList.toggle('cursor', i === sel);
      const it = o.item(i);
      const key = it == null ? null : it;
      if (r._it !== key || r._force) {
        r._it = key; r._force = false;
        const cells = it == null ? ['…'] : o.cells(it, i);
        r.replaceChildren(...cells.map((c) => (c instanceof Node && c.getAttribute?.('role') === 'gridcell' ? c : h('span', { role: 'gridcell' }, c))));
        r.className = 'vl-row' + (it && o.rowClass ? ' ' + (o.rowClass(it, i) || '') : '');
        r.classList.toggle('cursor', i === sel);
      }
    });
    const ci = sel - first;
    if (sel >= 0 && ci >= 0 && ci < k) vp.setAttribute('aria-activedescendant', `${id}-r${ci}`); else vp.removeAttribute('aria-activedescendant');
    vp.setAttribute('aria-rowcount', total);
  }
  const schedule = rafThrottle(render);
  const measure = () => { vis = Math.max(1, Math.floor(vp.clientHeight / ROW)); schedule(); };
  new ResizeObserver(measure).observe(vp);
  vp.addEventListener('scroll', () => { first = Math.min(Math.floor(vp.scrollTop / ROW), Math.max(0, n() - 1)); schedule(); }, { passive: true });

  function select(i, { quiet } = {}) {
    const total = n();
    if (!total) { sel = -1; schedule(); return; }
    sel = Math.max(0, Math.min(total - 1, i));
    if (sel < first) vp.scrollTop = sel * ROW;
    else if (sel >= first + vis) vp.scrollTop = (sel - vis + 1) * ROW;
    first = Math.floor(vp.scrollTop / ROW);
    schedule();
    if (!quiet) o.onSelect?.(sel, o.item(sel));
  }
  vp.addEventListener('keydown', (e) => {
    if (e.ctrlKey || e.metaKey || e.altKey) { if (o.onKey?.(e, sel, o.item(sel))) { e.preventDefault(); e.stopPropagation(); } return; }
    const k = e.key;
    if (k === 'ArrowDown') select(sel + 1);
    else if (k === 'ArrowUp') select(sel - 1);
    else if (k === 'PageDown') select(sel + vis);
    else if (k === 'PageUp') select(sel - vis);
    else if (k === 'Home') select(0);
    else if (k === 'End') select(n() - 1);
    else if (k === 'Enter' && sel >= 0) o.onActivate?.(sel, o.item(sel), e);
    else if ((k === 'ContextMenu' || (e.shiftKey && k === 'F10')) && o.onMenu) {
      const r = vp.getBoundingClientRect();
      o.onMenu(r.left + 60, r.top + (sel - first + 1) * ROW, sel, o.item(sel));
    } else if (!o.onKey?.(e, sel, o.item(sel))) return;
    e.preventDefault(); e.stopPropagation();
  });
  vp.addEventListener('focus', () => { if (sel < 0 && n()) select(first); });
  const rowAt = (e) => e.target.closest('.vl-row');
  layer.addEventListener('mousedown', (e) => { const r = rowAt(e); if (r && e.button !== 1) select(+r.dataset.i); });
  layer.addEventListener('dblclick', (e) => { const r = rowAt(e); if (r) o.onActivate?.(+r.dataset.i, o.item(+r.dataset.i), e); });
  layer.addEventListener('contextmenu', (e) => {
    const r = rowAt(e);
    if (!r || !o.onMenu) return;
    e.preventDefault();
    select(+r.dataset.i);
    o.onMenu(e.clientX, e.clientY, sel, o.item(sel));
  });

  return {
    el: vp, head,
    /** Re-render; `reset` scrolls to the top and clears the selection. */
    refresh({ reset = false, force = false } = {}) {
      if (reset) { first = 0; sel = -1; vp.scrollTop = 0; }
      if (force) pool.forEach((r) => { r._force = true; });
      if (sel >= n()) sel = n() - 1;
      measure();
    },
    select,
    get sel() { return sel; },
    item: (i) => o.item(i),
    focus: () => vp.focus(),
  };
}

/** Paged backend source: fetch(offset, limit) -> {total, rows}. Call `reset()` when the query changes. */
export function pager(fetch, onLoad, PAGE = 200) {
  let total = 0, gen = 0;
  const pages = new Map(), pending = new Set();
  const load = (p) => {
    if (pending.has(p)) return;
    pending.add(p);
    const g = gen;
    fetch(p * PAGE, PAGE).then((r) => {
      if (g !== gen) return;
      pending.delete(p);
      total = r.total;
      pages.set(p, r.rows);
      if (pages.size > 64) pages.delete(pages.keys().next().value);
      onLoad();
    }, (e) => { pending.delete(p); onLoad(e); });
  };
  return {
    count: () => total,
    item(i) {
      const p = (i / PAGE) | 0, pg = pages.get(p);
      if (pg) return pg[i - p * PAGE] ?? null;
      load(p);
      return null;
    },
    /** Drops cached pages and loads the first one again. */
    reset() { gen++; pages.clear(); pending.clear(); total = 0; load(0); },
    clear() { gen++; pages.clear(); pending.clear(); total = 0; },
  };
}
