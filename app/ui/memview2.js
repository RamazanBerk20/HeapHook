// Second memory viewer: a small floating, non-modal hex pane with its own address, display type
// and cursor. Read-only; refreshed by the live ticker while it is open.
import { api } from './backend.js';
import { h, icon, fmtAddr, wire, prompt, attempt, rafThrottle } from './util.js';
import { state, addTicker, on } from './core.js';
import { TYPE_SIZE, cellValue } from './memfmt.js';

const BPR = 8;

/** host: the element it floats in; rowPx(): the current row height; onLeave(): focus goes back to the main view. */
export function initSecondViewer(host, { rowPx, onLeave }) {
  let top = null, cur = null, bytes = [], open = false;
  const type = h('select.compact', { 'aria-label': 'Second viewer display type' },
    Object.keys(TYPE_SIZE).map((t) => h('option', { value: t }, { byte: 'Hex bytes', '2bytes': '2 Bytes', '4bytes': '4 Bytes', '8bytes': '8 Bytes', float: 'Float', double: 'Double' }[t])));
  const pos = h('span.count.mono');
  const list = h('div.mv2-list.hx-list.mono', { role: 'grid', tabindex: '0', 'aria-label': 'Second hex dump', 'aria-roledescription': 'hex dump' });
  const gotoBtn = h('button.btn.ghost', { type: 'button', title: 'Go to (Ctrl G)', onclick: () => gotoPrompt() }, 'Go to');
  const closeBtn = h('button.btn.ghost.icon', { type: 'button', 'aria-label': 'Close the second viewer (Esc)', title: 'Close (Esc)', html: icon('x'), onclick: () => close() });
  const el = h('section.mv2.panel', { role: 'region', 'aria-label': 'Second memory viewer', hidden: true },
    h('div.panel-head', null, h('h2', null, 'Memory 2 ', pos), h('span.toolbar', null, type, gotoBtn, closeBtn)), list);
  host.append(el);

  const unit = () => TYPE_SIZE[type.value];
  const vis = () => Math.max(1, Math.floor(list.clientHeight / rowPx()));
  async function load() {
    if (!open || top == null || !state.proc) return;
    const t = top, s = await api.readMemory(wire(t), vis() * BPR).catch(() => null);
    if (s == null || t !== top) return;
    bytes = s.match(/../g) || [];
    render();
  }
  function render() {
    const u = unit(), n = vis(), rows = [];
    for (let r = 0; r < n; r++) {
      const cells = [];
      for (let c = 0; c < BPR; c += u) {
        const i = r * BPR + c, g = bytes.slice(i, i + u), at = top + BigInt(i), isCur = cur != null && cur >= at && cur < at + BigInt(u);
        const txt = g.length < u ? '' : g.includes('??') ? '?'.repeat(Math.min(8, u * 2)) : u === 1 && type.value === 'byte' ? g[0].toUpperCase() : cellValue(type.value, Uint8Array.from(g, (x) => parseInt(x, 16)));
        cells.push(h('span.hb' + (isCur ? '.cursor' : ''), { role: 'gridcell', id: isCur ? 'mv2-cur' : null }, txt));
      }
      rows.push(h('div.hx-row', { role: 'row' }, h('span.c-addr', { role: 'rowheader' }, fmtAddr(top + BigInt(r * BPR))),
        h('span.hx-bytes', { 'data-u': u, style: `grid-template-columns:repeat(${BPR / u}, ${{ 1: '2.4ch', 2: '7ch', 4: '13ch', 8: '22ch' }[u]})` }, cells)));
    }
    list.replaceChildren(...rows);
    list.setAttribute('aria-activedescendant', cur != null ? 'mv2-cur' : '');
    pos.textContent = cur != null ? fmtAddr(cur) : '';
  }
  const schedule = rafThrottle(render);
  function goto(addr) {
    cur = BigInt(addr); cur -= cur % BigInt(unit());
    top = cur - (cur % BigInt(BPR));
    load();
  }
  function move(d) {
    if (cur == null) return;
    const n = cur + BigInt(d);
    cur = n < 0n ? 0n : n;
    const span = BigInt(vis() * BPR);
    if (cur < top) top = cur - (cur % BigInt(BPR));
    else if (cur >= top + span) top = cur - (cur % BigInt(BPR)) - span + BigInt(BPR);
    load(); schedule();
  }
  async function gotoPrompt() {
    const s = await prompt('Go to address (second viewer)', cur != null ? fmtAddr(cur) : '', { label: 'Address or expression' });
    if (s) { const a = await attempt(() => api.resolveAddress(s)); if (a) goto(a); }
    list.focus();
  }
  function close() {
    open = false; el.hidden = true;
    onLeave();
  }
  list.addEventListener('keydown', (e) => {
    const u = unit(), ctrl = e.ctrlKey || e.metaKey;
    if (e.key === 'ArrowRight') move(u);
    else if (e.key === 'ArrowLeft') move(-u);
    else if (e.key === 'ArrowDown') move(BPR);
    else if (e.key === 'ArrowUp') move(-BPR);
    else if (e.key === 'PageDown') move(vis() * BPR);
    else if (e.key === 'PageUp') move(-vis() * BPR);
    else if (ctrl && e.key.toLowerCase() === 'g') gotoPrompt();
    else if (e.key === 'Escape') close();
    else if (ctrl && e.shiftKey && e.key.toLowerCase() === 'm') onLeave();
    else return;
    e.preventDefault(); e.stopPropagation();
  });
  list.addEventListener('wheel', (e) => { e.preventDefault(); if (top == null) return; const d = BigInt((e.deltaY > 0 ? 3 : -3) * BPR); top = top + d < 0n ? 0n : top + d; load(); }, { passive: false });
  list.addEventListener('mousedown', (e) => {
    const c = e.target.closest('.hb');
    if (!c) return;
    const r = [...list.children].indexOf(c.closest('.hx-row')), k = [...c.parentNode.children].indexOf(c);
    cur = top + BigInt(r * BPR + k * unit()); schedule();
  });
  type.addEventListener('change', () => { if (cur != null) cur -= cur % BigInt(unit()); render(); list.focus(); });
  new ResizeObserver(() => { if (open) load(); }).observe(list);
  addTicker(() => (open && state.view === 'mem' ? load() : null));
  on('process:closed', () => { top = cur = null; bytes = []; if (open) close(); });

  return {
    get open() { return open; },
    /** Opens the viewer at addr (when it was closed) or just focuses it, keeping its own place. */
    show(addr) {
      const was = open;
      open = true; el.hidden = false;
      list.focus();
      if (!was && addr != null) goto(addr); else load();
    },
    focused: () => el.contains(document.activeElement),
    refresh: () => { if (open) load(); },
  };
}
