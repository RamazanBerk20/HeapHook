// Memory tools: long-job progress, fill / copy, snapshots and diffs, "find what points to
// this address", save / load memory files, region protection, module headers, AOB
// signatures and AOB injection scripts. Dialogs are built here; memview.js wires the menus.
import { api, askPath } from './backend.js';
import { h, fmtAddr, fmtSize, nf, attempt, toast, modal, busy, wire, helpAdd } from './util.js';
import { emit, state } from './core.js';
import { vlist } from './vlist.js';

/** The session runs one long tool operation at a time; Esc cancels it (app.js). */
export const jobs = { running: false, cancel: () => api.toolsCancel() };

/** A progress strip: `.sp-progress` with a label, a bar and a cancel button. */
export function progressStrip(label) {
  const bar = h('div.bar'), text = h('span.muted.mono.job-text');
  const wrap = h('div.sp-progress.job', { hidden: true },
    text, h('div.bar-wrap', { role: 'progressbar', 'aria-label': label, 'aria-valuemin': 0, 'aria-valuemax': 100 }, bar),
    h('button.btn', { type: 'button', onclick: () => jobs.cancel() }, 'Cancel ', h('kbd', null, 'Esc')));
  return { wrap, bar, text };
}

/** Awaits `run()` while showing the backend job's progress in `ui`; undefined on error/cancel. */
export async function runJob(run, ui, what = 'Working') {
  jobs.running = true;
  if (ui) { ui.wrap.hidden = false; ui.bar.style.transform = 'scaleX(0)'; ui.text.textContent = what + '…'; }
  let done = false;
  const poll = async () => {
    while (!done) {
      const p = await api.toolsProgress().catch(() => null);
      if (p && ui && p.running) {
        const f = p.total ? p.done / p.total : 0;
        ui.bar.style.transform = `scaleX(${Math.min(1, f)})`;
        ui.bar.parentElement.setAttribute('aria-valuenow', Math.round(f * 100));
        ui.text.textContent = `${what} ${p.total ? Math.round(f * 100) + '%' : nf.format(p.done)}${p.found ? ' · ' + nf.format(p.found) + ' found' : ''}`;
      }
      await new Promise((r) => setTimeout(r, 150));
    }
  };
  poll();
  try { return await run(); } catch (e) {
    toast(/cancelled/.test(String(e)) ? 'Cancelled' : e, /cancelled/.test(String(e)) ? 'info' : 'error');
    return undefined;
  } finally {
    done = true; jobs.running = false;
    if (ui) ui.wrap.hidden = true;
  }
}

// ---------- small form dialog ----------
/**
 * fields: [{name, label, value?, type?: 'text'|'checkbox'|'select', options?: [[v, l]], mono?, hint?}]
 * Resolves to {name: value} or null.
 */
export function formDialog(title, fields, { ok = 'OK', text = '' } = {}) {
  return new Promise((resolve) => {
    const els = {};
    const rows = fields.map((f) => {
      if (f.type === 'checkbox') return h('label.check', null, (els[f.name] = h('input', { type: 'checkbox', checked: !!f.value })), ' ' + f.label);
      const el = f.type === 'select'
        ? h('select', null, f.options.map(([v, l]) => h('option', { value: v, selected: v === f.value }, l)))
        : h('input', { type: 'text', value: f.value ?? '', class: f.mono === false ? '' : 'mono', spellcheck: 'false', autocomplete: 'off', placeholder: f.placeholder || '' });
      els[f.name] = el;
      return h('label.field', null, h('span', null, f.label), el, f.hint ? h('span.hint', null, f.hint) : null);
    });
    const d = h('dialog.dlg.dlg-sm', { 'aria-label': title },
      h('form', { method: 'dialog' }, h('h2', null, title), text ? h('p.hint', null, text) : null, ...rows,
        h('div.dlg-actions', null,
          h('button.btn.primary', { value: 'ok', type: 'submit' }, ok + ' ', h('kbd', null, 'Enter')),
          h('button.btn', { value: 'cancel', type: 'submit', formnovalidate: true }, 'Cancel ', h('kbd', null, 'Esc')))));
    document.body.append(d);
    d.addEventListener('close', () => {
      const v = d.returnValue === 'ok' ? Object.fromEntries(Object.entries(els).map(([k, e]) => [k, e.type === 'checkbox' ? e.checked : e.value.trim()])) : null;
      d.remove();
      resolve(v);
    });
    d.showModal();
    Object.values(els)[0]?.focus();
    Object.values(els)[0]?.select?.();
  });
}

/** A dialog with a list (vlist) and a toolbar; returns {dialog, body, close}. */
export function listDialog(title, { wide = true } = {}) {
  const body = h('div.tool-body');
  const d = h('dialog.dlg' + (wide ? '.dlg-tool' : ''), { 'aria-label': title },
    h('div.dlg-head', null, h('h2', null, title), h('button.btn.ghost.icon', { type: 'button', 'aria-label': 'Close (Esc)', title: 'Close (Esc)', onclick: () => d.close(), html: '<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" aria-hidden="true"><path d="M18 6 6 18M6 6l12 12"/></svg>' })),
    body);
  document.body.append(d);
  d.addEventListener('close', () => d.remove());
  d.showModal();
  return { dialog: d, body };
}

const hexNum = (s) => { const t = String(s).trim().replace(/^0x/i, ''); return /^[0-9a-f]+$/i.test(t) ? parseInt(t, 16) : NaN; };
const resolve = async (expr) => attempt(() => api.resolveAddress(expr));

// ---------- fill / copy ----------
export async function fillDialog(at) {
  const v = await formDialog('Fill memory', [
    { name: 'addr', label: 'Address', value: at ? fmtAddr(at) : '' },
    { name: 'len', label: 'Length (hex bytes)', value: '10' },
    { name: 'pattern', label: 'Byte pattern (hex, repeated)', value: '90', hint: 'e.g. 00, 90 90, DE AD BE EF' },
  ], { ok: 'Fill' });
  if (!v) return false;
  const a = await resolve(v.addr), n = hexNum(v.len);
  if (!a) return false;
  if (!(n > 0)) { toast('Length must be a hex number above 0'); return false; }
  return !!(await attempt(async () => { await api.memFill(a, n, v.pattern); return true; }));
}

export async function copyDialog(at) {
  const v = await formDialog('Copy memory', [
    { name: 'src', label: 'From address', value: at ? fmtAddr(at) : '' },
    { name: 'dst', label: 'To address', value: '' },
    { name: 'len', label: 'Length (hex bytes)', value: '10' },
  ], { ok: 'Copy' });
  if (!v) return false;
  const [s, d] = [await resolve(v.src), await resolve(v.dst)], n = hexNum(v.len);
  if (!s || !d) return false;
  if (!(n > 0)) { toast('Length must be a hex number above 0'); return false; }
  return !!(await attempt(async () => { await api.memCopy(s, d, n); return true; }));
}

// ---------- allocate / free ----------
/** Allocates a block in the target; resolves to its address (hex) or null. */
export async function allocDialog() {
  const v = await formDialog('Allocate memory', [
    { name: 'size', label: 'Size (hex bytes, rounded up to whole pages)', value: '1000' },
    { name: 'prot', label: 'Protection', type: 'select', value: 'rwx', options: [['rwx', 'Read, write, execute (code caves)'], ['rw', 'Read and write'], ['r', 'Read only']] },
  ], { ok: 'Allocate' });
  if (!v) return null;
  const n = hexNum(v.size);
  if (!(n > 0)) { toast('Size must be a hex number above 0'); return null; }
  const a = await attempt(() => api.memAlloc(n, { r: true, w: v.prot !== 'r', x: v.prot === 'rwx' }));
  if (a) { navigator.clipboard?.writeText(fmtAddr(a)).catch(() => {}); toast(`Allocated ${fmtSize(n)} at ${fmtAddr(a)} (address copied)`, 'info'); }
  return a || null;
}

export async function freeDialog(at) {
  const v = await formDialog('Free memory', [
    { name: 'addr', label: 'Address of the block', value: at ? fmtAddr(at) : '' },
    { name: 'size', label: 'Size (hex bytes)', value: '1000' },
  ], { ok: 'Free', text: 'Releases a block, normally one you allocated. Freeing memory the program still uses crashes it.' });
  if (!v) return false;
  const a = await resolve(v.addr), n = hexNum(v.size);
  if (!a) return false;
  if (!(n > 0)) { toast('Size must be a hex number above 0'); return false; }
  const ok = await attempt(async () => { await api.memFree(a, n); return true; });
  if (ok) toast(`Freed ${fmtSize(n)} at ${fmtAddr(a)}`, 'info');
  return !!ok;
}

// ---------- save / load memory files ----------
export async function saveRegions(ranges, what) {
  const p = await askPath({ save: true, title: `Save ${what}`, filters: [['HeapHook memory', ['hhmem']]], dflt: 'memory.hhmem' });
  if (!p) return;
  const r = await runJob(() => api.memSave(ranges, p), null, 'Saving');
  if (r) toast(`Saved ${nf.format(r.blocks)} block(s), ${fmtSize(r.bytes)} to ${p}`, 'info');
}

const HHMEM = [['HeapHook memory', ['hhmem']], ['All files', ['*']]];

/** Plan, approve, then write: resolves true when at least one block was written. */
export async function loadMemoryFile() {
  const p = await askPath({ save: false, title: 'Load memory file', filters: HHMEM, dflt: 'memory.hhmem' });
  if (!p) return false;
  const v = await formDialog('Load memory file', [
    { name: 'relocate', label: 'Relocate to address (empty = where it was saved)', value: '', placeholder: 'original addresses' },
  ], { ok: 'Review blocks', text: `${p}\nNothing is written until you approve the blocks.` });
  if (!v) return false;
  const reloc = v.relocate || null;
  const plan = await attempt(() => api.memLoadPlan(p, reloc));
  if (!plan) return false;
  const chosen = await chooseBlocks(p, plan);
  if (!chosen?.length) return false;
  const r = await attempt(() => busy('Writing memory', api.memLoadApproved(p, reloc, chosen)));
  if (!r) return false;
  const msg = `Wrote ${nf.format(r.blocks)} of ${nf.format(chosen.length)} block(s), ${fmtSize(r.bytes)}.`;
  if (r.failed.length) await modal({ title: 'Memory file loaded with failures', text: `${msg} ${nf.format(r.failed.length)} block(s) could not be written at:`, pre: r.failed.map(fmtAddr).join('\n'), buttons: [{ label: 'Close', value: 'cancel', primary: true, kbd: 'Esc' }] });
  else toast(msg, 'info');
  return r.blocks > 0;
}

/** The load plan as a checklist; resolves to the approved plan blocks (as returned) or null. */
function chooseBlocks(path, plan) {
  return new Promise((done) => {
    const blocks = plan.blocks;
    const on = blocks.map((b) => b.mapped); // unmapped blocks cannot be written: off by default
    let result = null;
    const { dialog, body } = listDialog('Load memory file: choose blocks');
    const host = h('div.tool-list'), sum = h('p.hint', { 'aria-live': 'polite' });
    const writeBtn = h('button.btn.primary', { type: 'button', onclick: () => finish() }, 'Write chosen blocks ', h('kbd', null, 'Ctrl Enter'));
    const blockState = (b) => (!b.mapped ? ['ld-bad', 'Not mapped: cannot be written'] : !b.writable ? ['ld-ro', 'Read-only: protection is lifted for the write'] : ['', 'Writable']);
    const set = (f) => { blocks.forEach((b, i) => { on[i] = f(b, i); }); update(); };
    const toggle = (i) => { if (i >= 0) { on[i] = !on[i]; update(); } };
    function update() {
      const n = on.filter(Boolean).length, bytes = blocks.reduce((s, b, i) => s + (on[i] ? b.len : 0), 0);
      sum.textContent = `${nf.format(n)} of ${nf.format(blocks.length)} block(s) chosen, ${fmtSize(bytes)}` + (on.some((x, i) => x && !blocks[i].mapped) ? ' · some chosen blocks are not mapped and will fail' : '');
      writeBtn.disabled = !n;
      list.refresh({ force: true });
    }
    function finish() { result = blocks.filter((_, i) => on[i]); dialog.close(); }
    const list = vlist(host, {
      cols: '32px 128px 96px minmax(0, 1fr)', head: ['', 'Address', 'Size', 'State'], label: 'Blocks in the file',
      empty: 'The file has no blocks.', count: () => blocks.length, item: (i) => blocks[i],
      cells: (b, i) => {
        const [cls, text] = blockState(b);
        return [
          h('span', { role: 'gridcell' }, h('input', { type: 'checkbox', tabindex: '-1', checked: on[i], 'aria-label': `Write the block at ${fmtAddr(b.addr)}`, onclick: (e) => { e.stopPropagation(); on[i] = e.target.checked; update(); } })),
          fmtAddr(b.addr), fmtSize(b.len), h('span', { role: 'gridcell', class: cls }, text),
        ];
      },
      onActivate: (i) => toggle(i),
      onKey: (e, i) => {
        const k = e.key.toLowerCase();
        if ((e.ctrlKey || e.metaKey) && k === 'enter') { if (on.some(Boolean)) finish(); }
        else if (e.ctrlKey || e.metaKey || e.altKey) return false;
        else if (k === ' ') toggle(i);
        else if (k === 'a') set(() => true);
        else if (k === 'n') set(() => false);
        else return false;
        return true;
      },
    });
    const notes = [
      plan.unmapped ? `${nf.format(plan.unmapped)} block(s) are not mapped in the process and cannot be written.` : '',
      plan.read_only ? `${nf.format(plan.read_only)} block(s) are read-only: their protection is lifted for the write, then restored.` : '',
    ].filter(Boolean).join(' ');
    body.append(
      h('p.hint', null, `${path} · ${nf.format(blocks.length)} block(s), ${fmtSize(plan.bytes)}. ${notes}`),
      h('div.tool-bar', null,
        h('button.btn', { type: 'button', onclick: () => set(() => true) }, 'Select all ', h('kbd', null, 'A')),
        h('button.btn', { type: 'button', onclick: () => set(() => false) }, 'Select none ', h('kbd', null, 'N'))),
      h('p.hint', null, 'Space or Enter toggles the block under the cursor.'),
      host, sum,
      h('div.dlg-actions', null, writeBtn, h('button.btn', { type: 'button', onclick: () => dialog.close() }, 'Cancel ', h('kbd', null, 'Esc'))));
    dialog.addEventListener('close', () => done(result));
    update();
    list.focus();
  });
}

// ---------- search inside a saved memory file ----------
const FILE_TYPES = [['pattern', 'Byte pattern'], ['byte', 'Byte'], ['2bytes', '2 Bytes'], ['4bytes', '4 Bytes'], ['8bytes', '8 Bytes'], ['float', 'Float'], ['double', 'Double'], ['string', 'String']];
export async function searchFileDialog() {
  const p = await askPath({ save: false, title: 'Search a memory file', filters: HHMEM, dflt: 'memory.hhmem' });
  if (!p) return;
  const v = await formDialog('Search a memory file', [
    { name: 'kind', label: 'Search for', type: 'select', value: 'pattern', options: FILE_TYPES },
    { name: 'value', label: 'Pattern or value', value: '', hint: 'Pattern: hex bytes, ?? for any byte, e.g. 48 8B ?? 05' },
    { name: 'hex', label: 'Integer value is hexadecimal', type: 'checkbox', value: false },
    { name: 'max', label: 'Most results', value: '1000' },
  ], { ok: 'Search', text: `${p}\nSearches the saved file; no process needed.` });
  if (!v) return;
  if (!v.value) { toast('Give a byte pattern or a value'); return; }
  const pat = v.kind === 'pattern';
  const req = { path: p, pattern: pat ? v.value : '', vtype: pat ? null : v.kind, value: pat ? '' : v.value, fmt: { hex: v.hex }, max: Math.max(1, Math.min(100000, parseInt(v.max, 10) || 1000)) };
  const { dialog, body } = listDialog('Memory file search');
  const strip = progressStrip('File search progress'), host = h('div.tool-list'), head = h('p.hint');
  let hits = [];
  const list = vlist(host, {
    cols: 'minmax(0, 1fr)', head: ['Address'], label: 'Addresses found in the file',
    empty: () => 'No match in the file.', count: () => hits.length, item: (i) => hits[i], cells: (a) => [fmtAddr(a)],
    onActivate: (i) => {
      if (!state.proc) { toast('Open a process to view this address in the hex view'); return; }
      dialog.close(); emit('mem:goto', { addr: hits[i], pane: 'hex' });
    },
  });
  body.append(head, strip.wrap, host);
  head.textContent = `Searching ${p}`;
  const r = await runJob(() => api.memFileSearch(req), strip, 'Searching the file');
  if (!r) { head.textContent = `The search did not finish: ${p}`; return; }
  hits = r;
  head.textContent = `${nf.format(r.length)} match(es)${r.length >= req.max ? ` (stopped at ${nf.format(req.max)})` : ''} in ${p}` + (state.proc ? ' · Enter shows the address in the hex view' : '');
  list.refresh({ reset: true });
  list.focus();
}

// ---------- region totals ----------
export async function regionStatsDialog() {
  const s = await attempt(() => api.regionStats());
  if (!s) return;
  const { body } = listDialog('Memory region totals');
  const pct = (b) => (s.bytes ? ((b / s.bytes) * 100).toFixed(1) + ' %' : '');
  const table = (title, rows) => h('table.rs-table', null,
    h('caption', null, title),
    h('thead', null, h('tr', null, h('th', { scope: 'col' }, title.replace(/^By /, '')), h('th', { scope: 'col' }, 'Regions'), h('th', { scope: 'col' }, 'Size'), h('th', { scope: 'col' }, 'Share'))),
    h('tbody', null, rows.length ? [...rows].sort((a, b) => b.bytes - a.bytes).map((r) => h('tr', null, h('th.mono', { scope: 'row' }, r.key || '(none)'), h('td', null, nf.format(r.regions)), h('td', null, fmtSize(r.bytes)), h('td', null, pct(r.bytes))))
      : h('tr', null, h('td', { colspan: '4' }, 'None'))));
  body.append(
    h('p.hint', null, `${nf.format(s.regions)} region(s), ${fmtSize(s.bytes)} in all. Module totals leave out memory outside modules.`),
    h('div.rs-wrap', { tabindex: '0', role: 'region', 'aria-label': 'Region totals' },
      table('By protection', s.by_prot), table('By tag', s.by_tag), table('By kind', s.by_kind), table('By module', s.by_module)));
  body.querySelector('.rs-wrap').focus();
}

// ---------- protection ----------
export async function protectDialog(region) {
  const p = region.prot;
  const v = await formDialog(`Protection of ${fmtAddr(region.start)}`, [
    { name: 'r', label: 'Read', type: 'checkbox', value: p.r },
    { name: 'w', label: 'Write', type: 'checkbox', value: p.w },
    { name: 'x', label: 'Execute', type: 'checkbox', value: p.x },
  ], { ok: 'Apply', text: `${fmtSize(region.size)} · ${region.path || region.tag}` });
  if (!v) return false;
  const old = await attempt(() => api.memProtect(region.start, region.size, { r: v.r, w: v.w, x: v.x }));
  if (!old) return false;
  toast('Protection changed', 'info');
  return true;
}

// ---------- snapshots ----------
export async function snapshotsDialog({ at, region } = {}) {
  const { dialog, body } = listDialog('Snapshots');
  const strip = progressStrip('Snapshot progress');
  let snaps = [], diffs = [], diffOf = null;
  const listHost = h('div.tool-list.tool-list-sm'), diffHost = h('div.tool-list');
  const take = async (ranges, label) => {
    const s = await runJob(() => api.snapshotTake(ranges, label), strip, 'Reading');
    if (s) { await reload(); snapList.select(snaps.findIndex((x) => x.id === s.id)); }
  };
  const btns = h('div.tool-bar', null,
    h('button.btn', { type: 'button', disabled: !region, onclick: () => take([{ start: region.start, size: region.size }], `region ${fmtAddr(region.start)}`) }, 'Snapshot region at cursor'),
    h('button.btn', { type: 'button', onclick: () => take([], 'all writable memory') }, 'Snapshot all writable memory'),
    h('button.btn', { type: 'button', onclick: async () => {
      const v = await formDialog('Snapshot a range', [{ name: 'addr', label: 'Start address', value: at ? fmtAddr(at) : '' }, { name: 'size', label: 'Size (hex bytes)', value: '1000' }], { ok: 'Snapshot' });
      if (!v) return;
      const a = await resolve(v.addr), n = hexNum(v.size);
      if (a && n > 0) take([{ start: a, size: n }], `${fmtAddr(a)} +${n.toString(16).toUpperCase()}`);
    } }, 'Snapshot a range…'),
    h('button.btn', { type: 'button', onclick: () => compareTwo() }, 'Compare two snapshots… ', h('kbd', null, 'C')));
  const snapList = vlist(listHost, {
    cols: '48px minmax(0, 1fr) 90px 70px', head: ['#', 'Snapshot', 'Size', 'Blocks'], label: 'Snapshots',
    empty: 'No snapshots yet. Take one, change something in the game, then compare.',
    count: () => snaps.length, item: (i) => snaps[i],
    cells: (s) => [String(s.id), s.label, fmtSize(s.bytes), nf.format(s.blocks)],
    onActivate: (i) => compare(snaps[i]),
    onKey: (e, i) => {
      if (e.ctrlKey || e.metaKey || e.altKey) return false;
      if (e.key === 'Delete' && snaps[i]) { attempt(() => api.snapshotDelete(snaps[i].id)).then(reload); return true; }
      if (e.key.toLowerCase() === 'c') { compareTwo(snaps[i]); return true; }
      return false;
    },
  });
  const head = h('p.hint', null, 'Enter compares the selected snapshot with live memory · C compares two snapshots page by page · Del removes it');
  const mapHost = h('div.cm-host', { hidden: true });
  const showMap = (on) => { mapHost.hidden = !on; diffHead.hidden = on; diffHost.hidden = on; };
  async function compareTwo(sel) {
    if (snaps.length < 2) { toast('Take two snapshots first (before and after a change in the game)'); return; }
    const opts = snaps.map((s) => [String(s.id), `#${s.id} ${s.label}`]);
    const v = await formDialog('Compare two snapshots', [
      { name: 'old', label: 'Old snapshot', type: 'select', value: String((sel && sel !== snaps.at(-1) ? sel : snaps.at(-2)).id), options: opts },
      { name: 'new', label: 'New snapshot', type: 'select', value: String(snaps.at(-1).id), options: opts },
      { name: 'cells', label: 'Cells', type: 'select', value: '512', options: [['256', '256 (coarse)'], ['512', '512'], ['1024', '1024 (fine)']] },
    ], { ok: 'Compare', text: 'Counts the 4 KiB pages that changed between the two snapshots, over the old snapshot\'s address span.' });
    if (!v) { snapList.focus(); return; }
    if (v.old === v.new) { toast('Choose two different snapshots'); return; }
    const m = await runJob(() => api.snapshotChangeMap(+v.old, +v.new, null, null, +v.cells), strip, 'Comparing pages');
    if (m) renderMap(m, v.old, v.new);
  }
  function renderMap(m, a, b) {
    const COLS = 32, n = m.changed.length, start = BigInt(m.start), cs = BigInt(m.cell_size);
    const pages = Math.max(1, Math.round(m.cell_size / 4096));
    const sum = (x) => x.reduce((s, y) => s + y, 0);
    const level = (c, ch) => (!c ? 'none' : !ch ? 'l0' : ch / c <= 0.25 ? 'l1' : ch / c <= 0.75 ? 'l2' : 'l3');
    const lo = (i) => start + BigInt(i) * cs;
    const label = (i) => `${fmtAddr(lo(i))} to ${fmtAddr(lo(i + 1) - 1n)}: ` + (m.compared[i] ? `${m.changed[i]} of ${m.compared[i]} page(s) changed` : 'not in both snapshots');
    const readout = h('p.hint.mono', { 'aria-live': 'polite' }, label(0));
    const cells = [];
    const grid = h('div.cm-grid', { role: 'grid', 'aria-label': `Pages changed between snapshot ${a} and ${b}`, 'aria-rowcount': Math.ceil(n / COLS), 'aria-colcount': COLS });
    for (let r = 0; r * COLS < n; r++) {
      const row = h('div.cm-row', { role: 'row' });
      for (let i = r * COLS; i < Math.min(n, (r + 1) * COLS); i++) {
        const t = label(i);
        const c = h('span.cm-cell.cm-' + level(m.compared[i], m.changed[i]), { role: 'gridcell', tabindex: i ? '-1' : '0', 'aria-label': t, title: t, 'data-i': i });
        cells.push(c); row.append(c);
      }
      grid.append(row);
    }
    let cur = 0;
    const move = (i) => {
      i = Math.max(0, Math.min(n - 1, i));
      cells[cur].tabIndex = -1; cur = i; cells[cur].tabIndex = 0; cells[cur].focus();
      readout.textContent = label(cur);
    };
    const go = (i) => { dialog.close(); emit('mem:goto', { addr: wire(lo(i)), pane: 'hex' }); };
    grid.addEventListener('keydown', (e) => {
      const k = e.key, ctrl = e.ctrlKey || e.metaKey, col = cur % COLS;
      if (k === 'ArrowRight') move(cur + 1);
      else if (k === 'ArrowLeft') move(cur - 1);
      else if (k === 'ArrowDown') move(cur + COLS);
      else if (k === 'ArrowUp') move(cur - COLS);
      else if (k === 'Home') move(ctrl ? 0 : cur - col);
      else if (k === 'End') move(ctrl ? n - 1 : cur - col + COLS - 1);
      else if (k === 'PageDown') move(cur + COLS * 8);
      else if (k === 'PageUp') move(cur - COLS * 8);
      else if (k === 'Enter') go(cur);
      else return;
      e.preventDefault(); e.stopPropagation();
    });
    grid.addEventListener('click', (e) => { const c = e.target.closest('.cm-cell'); if (c) move(+c.dataset.i); });
    grid.addEventListener('dblclick', (e) => { const c = e.target.closest('.cm-cell'); if (c) go(+c.dataset.i); });
    const key = (cls, text) => h('span.cm-key', null, h('span.cm-cell.cm-' + cls, { 'aria-hidden': 'true' }), text);
    mapHost.replaceChildren(
      h('p.hint', null, `Snapshot ${a} to ${b} · ${nf.format(sum(m.changed))} of ${nf.format(sum(m.compared))} page(s) changed · one cell covers ${fmtSize(m.cell_size)} (${nf.format(pages)} page${pages > 1 ? 's' : ''}) from ${fmtAddr(m.start)} · arrows move, Enter shows the cell in the hex view`),
      h('div.cm-legend', { 'aria-label': 'Legend' }, key('none', 'Not in both'), key('l0', 'No change'), key('l1', 'Up to 25 % of pages'), key('l2', 'Up to 75 %'), key('l3', 'More')),
      h('div.cm-scroll', null, grid), readout,
      h('button.btn', { type: 'button', onclick: () => { showMap(false); snapList.focus(); } }, 'Back to the differences list'));
    showMap(true);
    if (n) cells[0].focus();
  }
  const diffHead = h('p.hint.mono');
  const diffList = vlist(diffHost, {
    cols: '128px 64px minmax(0, 1fr) minmax(0, 1fr)', head: ['Address', 'Bytes', 'Snapshot', 'Now'], label: 'Differences',
    empty: () => (diffOf ? 'No differences.' : 'Compare a snapshot to list what changed.'),
    count: () => diffs.length, item: (i) => diffs[i],
    cells: (d) => [fmtAddr(d.addr), nf.format(d.len), d.old, h('span', { role: 'gridcell', class: 'chg' }, d.new || 'unreadable')],
    onActivate: (i) => { dialog.close(); emit('mem:goto', { addr: diffs[i].addr, pane: 'hex' }); },
  });
  async function compare(s) {
    if (!s) return;
    const r = await runJob(() => api.snapshotDiff(s.id), strip, 'Comparing');
    if (!r) return;
    diffs = r; diffOf = s;
    showMap(false);
    diffHead.textContent = `${nf.format(r.length)} changed range(s) since snapshot ${s.id} · Enter jumps to the hex view`;
    diffList.refresh({ reset: true });
    diffList.focus();
  }
  async function reload() { snaps = (await attempt(() => api.snapshotList())) || []; snapList.refresh(); }
  body.append(btns, strip.wrap, head, listHost, diffHead, diffHost, mapHost);
  await reload();
  snapList.focus();
}

// ---------- find what points to this address ----------
export async function pointersDialog(at) {
  const v = await formDialog('Find what points to this address', [
    { name: 'target', label: 'Address', value: at ? fmtAddr(at) : '' },
    { name: 'max_offset', label: 'Also pointers up to this far below it (hex)', value: '0', hint: 'A structure base: 0 finds exact pointers only' },
    { name: 'static_only', label: 'Only static pointers (inside modules)', type: 'checkbox', value: false },
    { name: 'writable_only', label: 'Only in writable memory', type: 'checkbox', value: false },
  ], { ok: 'Find' });
  if (!v) return;
  const t = await resolve(v.target);
  if (!t) return;
  const { dialog, body } = listDialog(`Pointers to ${fmtAddr(t)}`);
  const strip = progressStrip('Pointer search progress');
  const host = h('div.tool-list');
  let hits = [];
  const list = vlist(host, {
    cols: '128px 128px 64px minmax(0, 1fr)', head: ['Pointer at', 'Value', 'Offset', 'Module'], label: 'Pointers',
    empty: 'Nothing points there.', count: () => hits.length, item: (i) => hits[i],
    cells: (x) => [fmtAddr(x.addr), fmtAddr(x.value), x.offset.toString(16).toUpperCase(), x.module || ''],
    onActivate: (i) => { dialog.close(); emit('mem:goto', { addr: hits[i].addr, pane: 'hex' }); },
    onKey: (e, i) => {
      if (e.key !== 'Insert' || !hits[i]) return false;
      const x = hits[i];
      emit('table:add', [{ description: `Pointer to ${fmtAddr(t)}`, addr: x.module || fmtAddr(x.addr), vtype: '8bytes', hex: true }]);
      toast('Added to the table', 'info');
      return true;
    },
  });
  body.append(h('p.hint', null, 'Enter shows the pointer in the hex view · Insert adds it to the cheat table'), strip.wrap, host);
  const r = await runJob(() => api.findPointers({ target: t, max_offset: hexNum(v.max_offset) || 0, static_only: v.static_only, writable_only: v.writable_only, max_results: 100000 }), strip, 'Searching');
  if (!r) return;
  hits = r;
  list.refresh({ reset: true });
  list.focus();
}

// ---------- module header ----------
export async function headerDialog(mod) {
  const s = await attempt(() => api.moduleHeader(mod.name));
  if (!s) return;
  const pad = (x, n) => String(x).padEnd(n);
  const lines = [
    `${s.format.toUpperCase()} ${s.is_64 ? '64' : '32'}-bit · ${s.machine} · ${s.kind}`,
    `Entry        ${fmtAddr(s.entry)}`,
    `Image base   ${fmtAddr(s.image_base)}`,
    s.imports != null ? `Imports      ${nf.format(s.imports)}${s.import_libs != null ? ' from ' + s.import_libs + ' libraries' : ''}` : null,
    s.exports != null ? `Exports      ${nf.format(s.exports)}` : null,
    `Read from    ${s.source}`,
    '',
    `${pad('Section', 20)}${pad('Address', 18)}${pad('Size', 12)}Prot`,
    ...s.sections.map((x) => `${pad(x.name || '-', 20)}${pad(fmtAddr(x.addr), 18)}${pad(fmtSize(x.size), 12)}${x.prot.r ? 'r' : '-'}${x.prot.w ? 'w' : '-'}${x.prot.x ? 'x' : '-'}`),
  ].filter((x) => x != null);
  await modal({ title: `${mod.name} header`, pre: lines.join('\n'), buttons: [{ label: 'Close', value: 'cancel', primary: true, kbd: 'Esc' }] });
}

// ---------- AOB signature / injection script ----------
const INJECT = { aob: 'AOB injection', code: 'Code injection', full: 'Full injection' };
/** Auto Assembler template at addr (kind aob | code | full) as a new table script entry. */
export async function injectScript(addr, kind = 'aob') {
  const script = await attempt(() => api.aaTemplate(addr, kind));
  if (script) emit('table:script', { description: `${INJECT[kind]} at ${fmtAddr(addr)}`, script });
}
export const aobScript = (addr) => injectScript(addr, 'aob');

export async function signatureDialog(addr) {
  const s = await attempt(() => api.aobSignature(addr));
  if (!s) return;
  const ok = s.unique && s.found.length === 1;
  const r = await modal({
    title: 'AOB signature',
    text: `${s.module}+${s.module_offset.toString(16).toUpperCase()} · ${ok ? 'unique in the module' : `not unique (${s.matches} matches)`}` +
      `\nVerified by scanning: ${s.found.length ? s.found.map(fmtAddr).join(', ') : 'no match'}`,
    pre: s.pattern,
    buttons: [{ label: 'Copy pattern', value: 'copy', primary: true, kbd: 'Enter' }, { label: 'Create AOB injection script', value: 'script' }, { label: 'Close', value: 'cancel', kbd: 'Esc' }],
  });
  if (r.value === 'copy') { await attempt(() => navigator.clipboard.writeText(s.pattern)); toast('Pattern copied', 'info'); }
  if (r.value === 'script') aobScript(addr);
}

export { hexNum };

if (document.getElementById('dlg-help')) helpAdd('Memory tools', [
  ['Space / A / N', 'Load memory file: toggle a block / all / none'],
  ['Ctrl Enter', 'Load memory file: write the chosen blocks'],
  ['C', 'Snapshots: compare two snapshots (page change map)'],
  ['Enter', 'Change map: show the cell in the hex view (arrows move)'],
]);
