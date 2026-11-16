// Scan panel: value inputs, scan/value type, options, First/Next/Undo/New, progress, cancel.
import { api } from './backend.js';
import { $, $$, h, nf, toast, busy, fmtSize, icon, prompt, attempt } from './util.js';
import { state, on } from './core.js';
import { listCustomTypes, editCustomType } from './custom.js';
import { listDialog } from './memtools.js';

const FIRST = [['exact', 'Exact value'], ['bigger', 'Bigger than'], ['smaller', 'Smaller than'], ['between', 'Value between'], ['unknown', 'Unknown initial value']];
const NEXT = [...FIRST.slice(0, 4), ['increased', 'Increased'], ['increased_by', 'Increased by'], ['decreased', 'Decreased'],
  ['decreased_by', 'Decreased by'], ['changed', 'Changed'], ['unchanged', 'Unchanged'], ['same_as_first', 'Same as first scan']];
const NO_VALUE = new Set(['unknown', 'increased', 'decreased', 'changed', 'unchanged', 'same_as_first']);
const ALIGN = { byte: 1, binary: 1, '2bytes': 2, '4bytes': 4, '8bytes': 4, float: 4, double: 4, string: 1, aob: 1, all: 1, grouped: 1 };
const TRI_NEXT = { yes: 'no', no: 'any', any: 'yes' };
const TRI_ARIA = { yes: 'true', no: 'false', any: 'mixed' };
const FLOATY = ['float', 'double', 'all'];
const SUF = { k: 1024, m: 1 << 20, g: 1 << 30 };

/** "4096", "0x1000", "64K", "16M" -> bytes; "" -> null. */
function sizeOf(s, name) {
  const t = s.trim();
  if (!t) return null;
  const m = /^(0x[0-9a-f]+|\d+)\s*([kmg])?(?:i?b)?$/i.exec(t);
  if (!m) throw `${name}: '${t}' is not a size (4096, 0x1000, 64K, 16M)`;
  return Number(m[1]) * (SUF[m[2]?.toLowerCase()] || 1);
}
/** "400000-500000" per line (or comma separated), hex -> [{start, end}] ([start, end)). */
function rangesOf(text) {
  const out = [];
  for (const part of text.split(/[\n,;]+/).map((x) => x.trim()).filter(Boolean)) {
    const m = /^(?:0x)?([0-9a-f]+)\s*-\s*(?:0x)?([0-9a-f]+)$/i.exec(part);
    if (!m) throw `Range '${part}': write it as start-end in hex, e.g. 400000-500000`;
    if (BigInt('0x' + m[1]) >= BigInt('0x' + m[2])) throw `Range '${part}': the end must be above the start`;
    out.push({ start: '0x' + m[1], end: '0x' + m[2] });
  }
  if (out.length > 4096) throw 'At most 4096 address ranges';
  return out;
}

/** Checklist of the process's module names; resolves to the chosen names, or null on cancel. */
async function chooseModules(title, current) {
  if (!state.proc) { toast('Open a process first (Ctrl P)'); return null; }
  const mods = await attempt(() => api.modules());
  if (!mods) return null;
  const names = [...new Set(mods.map((m) => m.name))].sort((a, b) => a.localeCompare(b));
  const want = new Set(current.map((n) => n.toLowerCase()));
  return new Promise((resolve) => {
    const { dialog, body } = listDialog(title, { wide: false });
    const boxes = names.map((n) => h('label.check', { title: n }, h('input', { type: 'checkbox', checked: want.has(n.toLowerCase()) }), ' ' + n));
    const filter = h('input', { type: 'text', placeholder: 'Filter', 'aria-label': 'Filter modules', spellcheck: 'false', autocomplete: 'off',
      oninput: () => { const q = filter.value.toLowerCase(); boxes.forEach((b, i) => { b.hidden = !names[i].toLowerCase().includes(q); }); } });
    let done = false;
    const finish = (ok) => { done = true; resolve(ok ? names.filter((_, i) => boxes[i].firstChild.checked) : null); dialog.close(); };
    body.append(
      h('div.tool-bar', null, filter, h('button.btn', { type: 'button', onclick: () => boxes.forEach((b) => { b.firstChild.checked = false; }) }, 'Clear all')),
      names.length ? h('div.mod-pick', { role: 'group', 'aria-label': 'Modules' }, ...boxes) : h('p.hint', null, 'The process lists no modules.'),
      h('div.dlg-actions', null,
        h('button.btn.primary', { type: 'button', onclick: () => finish(true) }, 'OK ', h('kbd', null, 'Enter')),
        h('button.btn', { type: 'button', onclick: () => finish(false) }, 'Cancel ', h('kbd', null, 'Esc'))));
    dialog.addEventListener('keydown', (e) => { if (e.key === 'Enter' && e.target.tagName !== 'BUTTON') { e.preventDefault(); finish(true); } });
    dialog.addEventListener('close', () => { if (!done) resolve(null); });
    filter.focus();
  });
}
/** A "modules: any [Choose…]" field backed by chooseModules. */
function modulePick(label, onChange) {
  let list = [];
  const shown = h('span.mono.mod-sum');
  const show = () => { shown.textContent = list.length ? list.slice(0, 3).join(', ') + (list.length > 3 ? ` +${list.length - 3}` : '') : 'any'; shown.title = list.join(', '); };
  const btn = h('button.btn.ghost', { type: 'button', 'aria-label': `${label}: choose modules`, onclick: async () => {
    const r = await chooseModules(label, list);
    if (r) { list = r; show(); onChange?.(); }
    btn.focus();
  } }, 'Choose…');
  show();
  return { el: h('div.field', null, h('span', null, label), h('div.mod-row', null, shown, btn)), get list() { return list; } };
}

export function initScan(results) {
  const el = (id) => document.getElementById(id);
  const v1 = el('v1'), v2 = el('v2'), st = el('scan-type'), vt = el('vtype');
  const bFirst = el('btn-first'), bNext = el('btn-next'), bUndo = el('btn-undo'), bCancel = el('btn-cancel');
  const bar = el('scan-bar'), progWrap = el('scan-progress'), found = el('found');
  const bPause = el('btn-pause'), spill = el('scan-spill'), cmpTo = el('cmp-to'), savedList = el('saved-list'), ctGroup = el('vtype-custom');
  // Extra memory options built here: last hex digits of the address, and the grouped-scan syntax hint.
  const ldOn = h('input', { type: 'checkbox' }), ld = h('input.mono.num', { type: 'text', maxlength: '8', placeholder: 'A0', 'aria-label': 'Last digits of the address (hex)', spellcheck: 'false', autocomplete: 'off', style: 'width:72px' });
  el('o-fast').closest('.align-row').after(h('div.align-row', null, h('label.check', null, ldOn, ' Last digits (hex)'), ld));
  const gHint = h('p.hint.mono', { hidden: true }, "Grouped: 4:100 2:7 f:12.5 d:2.25 s:'text' su:'wide' w:8 2:*  (1 2 4 8 f d numbers, s / su text, w:n skips n bytes, * = any; BA:n OOO BS:n)");
  v1.after(gHint);
  // Region filters (1.0), collapsed under "More filters" in the memory options.
  const kindBoxes = ['Image', 'Mapped', 'Private'].map((k) => h('input', { type: 'checkbox', value: k }));
  const moreSum = h('span.muted');
  const incMods = modulePick('Only in modules', () => countFilters()), excMods = modulePick('Skip modules', () => countFilters());
  const rangesEl = h('textarea.mono#o-ranges', { rows: '2', spellcheck: 'false', autocomplete: 'off', placeholder: '400000-4FFFFF' });
  const minSz = h('input.mono#o-minsz', { type: 'text', spellcheck: 'false', autocomplete: 'off', placeholder: 'any' });
  const maxSz = h('input.mono#o-maxsz', { type: 'text', spellcheck: 'false', autocomplete: 'off', placeholder: 'any' });
  const more = h('details.scan-more', null, h('summary', null, 'More filters ', moreSum),
    h('div.field', { role: 'group', 'aria-label': 'Region kinds' }, h('span', null, 'Region kinds (none = all)'),
      h('div.checks', null, ...kindBoxes.map((b) => h('label.check', null, b, ' ' + b.value)))),
    incMods.el, excMods.el,
    h('div.field', null, h('label', { for: 'o-ranges' }, 'Only these ranges (hex start-end, one per line)'), rangesEl),
    h('div.range', null,
      h('div.field', null, h('label', { for: 'o-minsz' }, 'Min region size'), minSz),
      h('div.field', null, h('label', { for: 'o-maxsz' }, 'Max region size'), maxSz)),
    h('p.hint', null, 'Sizes in bytes: 4096, 0x1000, 64K, 16M. Every filter must hold.'));
  el('o-pause').closest('fieldset').append(more);
  function countFilters() {
    const n = [kindBoxes.some((b) => b.checked), incMods.list.length, excMods.list.length, rangesEl.value.trim(), minSz.value.trim(), maxSz.value.trim()].filter(Boolean).length;
    moreSum.textContent = n ? `(${n} on)` : '';
  }
  more.addEventListener('input', countFilters);
  // Float noise filter: lives with the float options.
  const simple = h('input', { type: 'checkbox' });
  el('o-round').after(h('label.check', { title: 'Matches must be zero or have a magnitude from 0.00001 to 10^15 (no exponent). Also applies to next scans.' }, simple, ' Simple values only'));
  // Pointer-value scan: "Pointer" in the Value type select, with its own target filters.
  vt.querySelector('option[value="8bytes"]').after(h('option', { value: 'pointer' }, 'Pointer'));
  const ptrMods = modulePick('Points into modules');
  const ptrRanges = h('textarea.mono#o-ptr-ranges', { rows: '2', spellcheck: 'false', autocomplete: 'off', placeholder: 'any' });
  const ptrBox = h('div.ptr-into', { hidden: true },
    h('p.hint', null, 'Finds pointer-sized values (8 bytes, 4 on 32-bit targets) that point into readable memory, or only into the modules and ranges below. Next scans then treat them as 8-byte (4-byte) values in hex: changed, unchanged, exact address.'),
    ptrMods.el,
    h('div.field', null, h('label', { for: 'o-ptr-ranges' }, 'Points into ranges (hex start-end, one per line)'), ptrRanges));
  vt.closest('.field').after(ptrBox);
  let hasScan = false, running = false, paused = false, canUndo = false, count = 0, prevCount = 0, scanMeta = {};
  let customs = [], lastVt = vt.value; // listCustomTypes() rows; option value "ct:<index>"

  // ---------- custom types in the Value type select ----------
  const customOf = (v = vt.value) => (v.startsWith('ct:') ? customs[+v.slice(3)] : null);
  async function loadCustoms(select) {
    const cur = customOf()?.name;
    customs = await listCustomTypes();
    ctGroup.replaceChildren(...customs.map((c, i) => h('option', { value: 'ct:' + i }, c.preset ? c.name : 'Custom: ' + c.name)), h('option', { value: 'ct:new' }, 'New custom type…'));
    const want = select ?? cur;
    const i = want ? customs.findIndex((c) => c.name === want) : -1;
    if (i >= 0) vt.value = 'ct:' + i; else if (vt.value.startsWith('ct:')) vt.value = '4bytes';
    lastVt = vt.value;
    sync();
  }

  // ---------- saved scans ----------
  async function refreshSaved() {
    const list = hasScan ? (await api.scanSaved().catch(() => [])) || [] : [];
    const cur = cmpTo.value;
    cmpTo.replaceChildren(h('option', { value: '' }, 'Previous scan'), h('option', { value: 'first' }, 'First scan'), ...list.map((s) => h('option', { value: s.name }, 'Saved: ' + s.name)));
    cmpTo.value = cur === '' || cur === 'first' || list.some((s) => s.name === cur) ? cur : '';
    savedList.replaceChildren(...(list.length ? list.map((s) => h('li', null,
      h('span.name', null, s.name), h('span.muted.mono', null, nf.format(s.count)),
      h('button.btn.ghost.icon', { type: 'button', 'aria-label': `Delete saved scan ${s.name}`, title: 'Delete', html: icon('trash'),
        onclick: async () => { if (await attempt(() => api.scanDeleteSaved(s.name)) !== undefined) refreshSaved(); } })))
      : [h('li.muted', null, 'None yet. Save the current results to compare later scans against them.')]));
    results.setSaved(list);
  }
  el('btn-save-scan').addEventListener('click', async () => {
    const name = (await prompt('Save scan', `Scan ${count ? nf.format(count) : ''}`.trim(), { label: 'Name', hint: 'Saved scans last until the next New scan or process change. "first" is reserved.', mono: false }))?.trim();
    if (!name) return;
    if (await attempt(() => api.scanSave(name)) !== undefined) { toast(`Saved the ${nf.format(count)} results as "${name}"`, 'info'); refreshSaved(); }
  });

  // tri-state option buttons
  const setTri = (b, v) => { b.dataset.v = v; b.setAttribute('aria-checked', TRI_ARIA[v]); b.querySelector('.tri-v').textContent = v; };
  for (const b of $$('.tri')) {
    setTri(b, b.dataset.v);
    b.addEventListener('click', () => setTri(b, TRI_NEXT[b.dataset.v]));
  }
  // Defaults come from Settings; changes made here last for the session.
  on('settings', (s) => {
    for (const b of $$('.tri')) setTri(b, s['scan_' + b.dataset.key] ?? b.dataset.v);
    el('o-fast').checked = s.fast_scan;
    el('o-align').value = s.scan_alignment;
  });

  function fillTypes() {
    const list = hasScan ? NEXT : FIRST, cur = st.value;
    st.replaceChildren(...list.map(([v, l]) => h('option', { value: v }, l)));
    st.value = list.some((x) => x[0] === cur) ? cur : 'exact';
    sync();
  }
  function sync() {
    const t = st.value, ty = vt.value, ptrFirst = ty === 'pointer' && !hasScan;
    el('v1-wrap').hidden = NO_VALUE.has(t) || ptrFirst;
    el('v2-wrap').hidden = t !== 'between' || ptrFirst;
    st.closest('.field').hidden = ptrFirst;
    el('o-not').closest('.checks').hidden = ptrFirst;
    ptrBox.hidden = !ptrFirst;
    el('v1-label').textContent = t === 'between' ? 'From' : t.endsWith('_by') ? 'By' : 'Value';
    vt.disabled = hasScan || running;
    el('opt-float').hidden = !['float', 'double', 'all'].includes(ty);
    el('opt-string').hidden = ty !== 'string';
    el('opt-binary').hidden = ty !== 'binary';
    el('opt-all').hidden = ty !== 'all';
    el('o-codepage').disabled = el('o-utf16').checked;
    el('saved-scans').hidden = !hasScan;
    bPause.innerHTML = icon(paused ? 'play' : 'pause');
    bPause.title = paused ? 'Resume the scan' : 'Pause the scan';
    bPause.setAttribute('aria-label', bPause.title);
    gHint.hidden = ty !== 'grouped';
    el('opt-percent').hidden = !['between', 'increased_by', 'decreased_by'].includes(t) || hasScan || ptrFirst;
    v1.placeholder = { string: 'text', aob: '8B 45 ?? 89', binary: '01001011' }[ty] || (el('o-hex').checked ? 'hex' : 'decimal');
    bFirst.innerHTML = hasScan ? 'New scan <kbd>Ctrl N</kbd>' : 'First scan <kbd>Enter</kbd>';
    bFirst.classList.toggle('primary', !hasScan);
    bNext.classList.toggle('primary', hasScan);
    bFirst.disabled = running;
    bNext.disabled = running || !hasScan;
    bUndo.disabled = running || !canUndo;
    progWrap.hidden = !running;
    found.textContent = running ? (paused ? 'Paused' : 'Scanning…') : hasScan ? `${nf.format(count)} found` : 'No scan yet';
    if (!running) spill.hidden = true;
  }

  function opts() {
    const tri = (k) => $(`.tri[data-key="${k}"]`).dataset.v;
    const fast = el('o-fast').checked, digits = ld.value.trim().replace(/^0x/i, '');
    const last = ldOn.checked && digits;
    if (last && !/^[0-9a-f]{1,8}$/i.test(last)) throw 'Last digits must be hex (0-9, A-F)';
    return {
      ...(last ? { last_digits: last } : {}),
      start: '0x' + (el('o-start').value.trim().replace(/^0x/i, '') || '0'),
      stop: '0x' + (el('o-stop').value.trim().replace(/^0x/i, '') || '7fffffffffff'),
      writable: tri('writable'), executable: tri('executable'), copy_on_write: tri('copy_on_write'),
      alignment: fast ? Math.max(1, +el('o-align').value || 1) : 1,
      hex: el('o-hex').checked, case_sensitive: el('o-case').checked, utf16: el('o-utf16').checked,
      rounding: el('o-round').value, percent: el('o-percent').checked, pause_while_scanning: el('o-pause').checked, threads: state.settings.scan_threads || null,
      priority: state.settings.scan_priority || 'normal', ...typeOpts(), ...regionOpts(),
    };
  }
  function regionOpts() {
    const min = sizeOf(minSz.value, 'Min region size'), max = sizeOf(maxSz.value, 'Max region size');
    if (min != null && max != null && min > max) throw 'Min region size is above max region size';
    return {
      kinds: kindBoxes.filter((b) => b.checked).map((b) => b.value), modules: incMods.list, exclude_modules: excMods.list,
      ranges: rangesOf(rangesEl.value), min_region_size: min, max_region_size: max, simple_values: simple.checked && FLOATY.includes(vt.value),
    };
  }
  // Options that depend on the value type.
  function typeOpts() {
    const ty = vt.value, c = customOf();
    if (c) return { custom: c.ct };
    if (ty === 'string') return el('o-utf16').checked ? {} : { codepage: +el('o-codepage').value };
    if (ty === 'all') return { all_types: $$('#opt-all input:checked').map((i) => i.value) };
    if (ty !== 'binary') return {};
    const len = el('o-bit-len').value.trim(), start = el('o-bit-start').value.trim();
    if (start && !(+start >= 0 && +start <= 7)) throw 'Start bit must be 0 to 7 (or empty for any)';
    return { binary_decimal: el('o-bin-dec').checked, ...(len ? { bit_len: Math.max(1, Math.round(+len)) } : {}), ...(start ? { bit_start: Math.round(+start) } : {}) };
  }

  async function run(kind) {
    if (running) return;
    if (!state.proc) { toast('Open a process first (Ctrl P)'); return; }
    const t = st.value, isPtr = kind === 'first' && vt.value === 'pointer';
    if (!isPtr && !NO_VALUE.has(t) && !v1.value.trim()) { toast('Enter a value to scan for'); v1.focus(); return; }
    const req = { scan_type: t, value: v1.value, value2: t === 'between' ? v2.value : null, not: el('o-not').checked };
    if (kind === 'next' && cmpTo.value) req.compare_to = cmpTo.value;
    running = true; paused = false; sync(); results.setBusy(true);
    bar.style.transform = 'scaleX(0)';
    const poll = setInterval(async () => {
      const p = await api.scanProgress().catch(() => null);
      if (!p) return;
      if (!!p.paused !== paused) { paused = !!p.paused; sync(); }
      spill.hidden = !(p.spilled > 0);
      if (p.spilled > 0) spill.textContent = `${fmtSize(p.spilled)} spilled to ${p.spill_dir}`;
      if (!p.total) return;
      bar.style.transform = `scaleX(${Math.min(1, p.done / p.total)})`;
      el('scan-bar-wrap').setAttribute('aria-valuenow', Math.round((100 * p.done) / p.total));
      found.textContent = `${paused ? 'Paused' : 'Scanning…'} ${nf.format(p.found)} so far`;
    }, 100);
    try {
      let r;
      if (isPtr) {
        const o = { ...opts(), hex: true }, ty = state.proc.is_64bit === false ? '4bytes' : '8bytes';
        const want = { opts: o, modules: ptrMods.list, ranges: rangesOf(ptrRanges.value) };
        r = await busy('Scanning for pointers', () => api.scanPointer(want), { cancel });
        scanMeta = { vtype: ty, hex: true, utf16: false, custom: null, custom_name: null, len: 0, pointer: true };
        vt.value = lastVt = ty; // next scans compare pointer-sized integers, in hex
        el('o-hex').checked = true;
        canUndo = false;
      } else if (kind === 'first') {
        const o = opts(), c = customOf();
        const ty = c ? '4bytes' : vt.value; // a custom type rides on a numeric placeholder; opts.custom decides
        r = await busy('Scanning', () => api.scanFirst({ vtype: ty, ...req, opts: o }), { cancel });
        scanMeta = {
          vtype: ty, hex: o.hex, utf16: o.utf16 && ty === 'string', custom: c?.ct || null, custom_name: c?.name || null,
          len: ty === 'string' ? v1.value.length : ty === 'aob' ? v1.value.trim().split(/\s+/).length : 0,
        };
        canUndo = false;
      } else {
        r = await busy('Scanning', () => api.scanNext(req), { cancel });
        prevCount = count; canUndo = true;
      }
      hasScan = true;
      count = r.count;
      results.set({ count, ...scanMeta, has: true });
    } catch (e) {
      toast(e);
    } finally {
      clearInterval(poll);
      running = false; paused = false;
      results.setBusy(false);
      fillTypes();
      refreshSaved();
    }
  }
  async function newScan() {
    if (running) return;
    try { await api.scanNew(); } catch (e) { toast(e); }
    hasScan = false; canUndo = false; count = 0;
    if (scanMeta.pointer) { vt.value = lastVt = 'pointer'; scanMeta = {}; }
    results.set({ count: 0 });
    fillTypes();
    refreshSaved();
    v1.focus();
  }
  async function undo() {
    if (running || !canUndo) return;
    try {
      await api.scanUndo();
      canUndo = false; count = prevCount;
      results.set({ count, ...scanMeta, has: true });
      sync();
      refreshSaved();
    } catch (e) { toast(e); }
  }
  // Results removed from the list (results.js): one more undo step.
  on('scan:removed', ({ count: n }) => { prevCount = count; count = n; canUndo = true; sync(); });
  const cancel = () => running && api.scanCancel().catch(toast);
  const togglePause = () => running && (paused ? api.scanResume() : api.scanPause()).then(() => { paused = !paused; sync(); }, toast);

  bFirst.addEventListener('click', () => (hasScan ? newScan() : run('first')));
  bNext.addEventListener('click', () => run('next'));
  bUndo.addEventListener('click', undo);
  bCancel.addEventListener('click', cancel);
  bPause.addEventListener('click', togglePause);
  st.addEventListener('change', sync);
  vt.addEventListener('change', async () => {
    if (vt.value === 'ct:new') {
      vt.value = lastVt;
      const r = await editCustomType(null);
      if (r) await loadCustoms(r.name);
      vt.focus();
      return;
    }
    lastVt = vt.value;
    const c = customOf();
    el('o-align').value = c ? Math.min(4, c.ct.size) : vt.value === 'pointer' ? (state.proc?.is_64bit === false ? 4 : 8) : ALIGN[vt.value] || 1;
    sync();
  });
  let tver = null; // the table's custom types change with the table
  on('table:version', (v) => { if (v !== tver) { tver = v; loadCustoms(); } });
  el('o-hex').addEventListener('change', sync);
  el('o-utf16').addEventListener('change', sync);
  for (const i of [v1, v2]) i.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { e.preventDefault(); run(hasScan ? 'next' : 'first'); }
  });
  on('process:opened', () => { hasScan = false; canUndo = false; count = 0; results.set({ count: 0 }); fillTypes(); refreshSaved(); });
  on('process:closed', () => { hasScan = false; canUndo = false; count = 0; results.set({ count: 0 }); fillTypes(); refreshSaved(); });

  fillTypes();
  loadCustoms();
  return {
    run: () => run(hasScan ? 'next' : 'first'), newScan, undo, cancel, togglePause,
    get running() { return running; },
    get hasScan() { return hasScan; },
    focusValue: () => (!el('v1-wrap').hidden ? v1 : st.closest('.field').hidden ? vt : st).focus(),
  };
}
