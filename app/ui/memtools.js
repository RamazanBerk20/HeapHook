// Memory tools: long-job progress, fill / copy, snapshots and diffs, "find what points to
// this address", save / load memory files, region protection, module headers, AOB
// signatures and AOB injection scripts. Dialogs are built here; memview.js wires the menus.
import { api, askPath } from './backend.js';
import { h, fmtAddr, fmtSize, nf, attempt, toast, modal } from './util.js';
import { emit } from './core.js';
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
function listDialog(title, { wide = true } = {}) {
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

// ---------- save / load memory files ----------
export async function saveRegions(ranges, what) {
  const p = await askPath({ save: true, title: `Save ${what}`, filters: [['HeapHook memory', ['hhmem']]], dflt: 'memory.hhmem' });
  if (!p) return;
  const r = await runJob(() => api.memSave(ranges, p), null, 'Saving');
  if (r) toast(`Saved ${nf.format(r.blocks)} block(s), ${fmtSize(r.bytes)} to ${p}`, 'info');
}

export async function loadMemoryFile() {
  const p = await askPath({ save: false, title: 'Load memory file', filters: [['HeapHook memory', ['hhmem']], ['All files', ['*']]], dflt: 'memory.hhmem' });
  if (!p) return false;
  const v = await formDialog('Load memory file', [
    { name: 'relocate', label: 'Relocate to address (empty = where it was saved)', value: '', placeholder: 'original addresses' },
  ], { ok: 'Load', text: p });
  if (!v) return false;
  const r = await attempt(() => api.memLoad(p, v.relocate || null));
  if (!r) return false;
  toast(`Wrote ${nf.format(r.blocks)} block(s), ${fmtSize(r.bytes)}` + (r.failed.length ? `; ${r.failed.length} failed at ${r.failed.slice(0, 3).map(fmtAddr).join(', ')}` : ''), r.failed.length ? 'error' : 'info');
  return true;
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
    } }, 'Snapshot a range…'));
  const snapList = vlist(listHost, {
    cols: '48px minmax(0, 1fr) 90px 70px', head: ['#', 'Snapshot', 'Size', 'Blocks'], label: 'Snapshots',
    empty: 'No snapshots yet. Take one, change something in the game, then compare.',
    count: () => snaps.length, item: (i) => snaps[i],
    cells: (s) => [String(s.id), s.label, fmtSize(s.bytes), nf.format(s.blocks)],
    onActivate: (i) => compare(snaps[i]),
    onKey: (e, i) => { if (e.key === 'Delete' && snaps[i]) { attempt(() => api.snapshotDelete(snaps[i].id)).then(reload); return true; } return false; },
  });
  const head = h('p.hint', null, 'Enter compares the selected snapshot with live memory · Del removes it');
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
    diffHead.textContent = `${nf.format(r.length)} changed range(s) since snapshot ${s.id} · Enter jumps to the hex view`;
    diffList.refresh({ reset: true });
    diffList.focus();
  }
  async function reload() { snaps = (await attempt(() => api.snapshotList())) || []; snapList.refresh(); }
  body.append(btns, strip.wrap, head, listHost, diffHead, diffHost);
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
export async function aobScript(addr) {
  const script = await attempt(() => api.aaTemplate(addr, 'aob'));
  if (script) emit('table:script', { description: `AOB injection at ${fmtAddr(addr)}`, script });
}

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
