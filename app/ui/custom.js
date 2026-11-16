// Custom value types (Cheat Engine's "custom types"): the stock presets from the backend plus
// the live table's own `custom_types`. Shared by the scanner and the cheat table.
import { api } from './backend.js';
import { h } from './util.js';

const KEYS = ['size', 'big_endian', 'float', 'signed', 'scale', 'offset', 'bit_start', 'bit_len', 'binary'];
const strip = (t) => Object.fromEntries(KEYS.map((k) => [k, t[k]]));
let presetNames = new Set();

/** -> [{name, preset, ct}]: presets first, then the table's types. */
export async function listCustomTypes() {
  const [presets, live] = await Promise.all([api.customPresets().catch(() => []), api.tableGet().catch(() => null)]);
  presetNames = new Set(presets.map((p) => p.name));
  return [
    ...presets.map((p) => ({ name: p.name, preset: true, ct: strip(p) })),
    ...(live?.table?.custom_types || []).map((t) => ({ name: t.name, preset: false, ct: strip(t) })),
  ];
}

/** Short text for a type column: "4 Byte Big Endian", "Custom: name". No ct = unsupported CE type (caller adds that). */
export function ctLabel(name, ct) {
  if (name) return presetNames.has(name) ? name : `Custom: ${name}`;
  if (!ct) return 'Custom';
  return `${ct.float ? (ct.size === 8 ? 'Double' : 'Float') : ct.size + ' Byte'}${ct.big_endian ? ' Big Endian' : ''}${ct.bit_len ? ` bits ${ct.bit_start}+${ct.bit_len}` : ''}`;
}

/** Adds or replaces `{name, ...ct}` in the live table's custom_types (retries a stale version). */
async function saveToTable(name, ct, oldName) {
  for (let i = 0; ; i++) {
    const { version, table } = await api.tableGet();
    const list = (table.custom_types || []).filter((t) => t.name !== name && t.name !== oldName);
    try { await api.tablePut({ ...table, custom_types: [...list, { name, ...ct }] }, version); return; } catch (e) {
      if (!String(e).includes('stale') || i >= 2) throw e;
    }
  }
}

/** Editor dialog. initial: {name, ct} (or a listCustomTypes row) or null -> {name, ct} or null. */
export function editCustomType(initial = null) {
  const c = { size: 4, big_endian: false, float: false, signed: false, scale: 1, offset: 0, bit_start: 0, bit_len: 0, binary: false, ...(initial?.ct || {}) };
  const oldName = initial && !initial.preset ? initial.name : null;
  const num = (name, label, value, attrs = {}) => h('label.field', null, h('span', null, label), h('input.mono', { name, type: 'number', value: String(value), ...attrs }));
  const chk = (name, label) => h('label.check', null, h('input', { name, type: 'checkbox', checked: c[name] }), ' ' + label);
  const err = h('p.preview.err', { 'aria-live': 'polite' });
  const form = h('form', { method: 'dialog' },
    h('h2', null, initial?.name ? 'Edit custom type' : 'New custom type'),
    h('label.field', null, h('span', null, 'Name'), h('input', { name: 'name', type: 'text', value: initial?.name && !initial.preset ? initial.name : initial?.name ? initial.name + ' (copy)' : '', autocomplete: 'off', spellcheck: 'false', required: true })),
    h('div.grid3', null, num('size', 'Size (bytes, 1-8)', c.size, { min: 1, max: 8 }), num('scale', 'Scale (value × scale)', c.scale, { step: 'any' }), num('offset', 'Offset (+ after scaling)', c.offset, { step: 'any' })),
    h('div.row2.row2-even', null, num('bit_start', 'Bit start', c.bit_start, { min: 0, max: 63 }), num('bit_len', 'Bit length (0 = whole value)', c.bit_len, { min: 0, max: 64 })),
    h('div.checks', null, chk('big_endian', 'Big-endian'), chk('float', 'Float'), chk('signed', 'Signed'), chk('binary', 'Show as binary')),
    err,
    h('div.dlg-actions', null,
      h('button.btn.primary', { value: 'ok', type: 'submit' }, 'Save ', h('kbd', null, 'Enter')),
      h('button.btn', { value: 'cancel', type: 'submit', formnovalidate: true }, 'Cancel ', h('kbd', null, 'Esc'))));
  const d = h('dialog.dlg', { 'aria-label': 'Custom type' }, form);
  document.body.append(d);
  const f = form.elements;
  const read = () => ({
    size: Math.round(+f.size.value), big_endian: f.big_endian.checked, float: f.float.checked, signed: f.signed.checked,
    scale: +f.scale.value, offset: +f.offset.value, bit_start: Math.round(+f.bit_start.value || 0), bit_len: Math.round(+f.bit_len.value || 0), binary: f.binary.checked,
  });
  return new Promise((resolve) => {
    form.addEventListener('submit', async (e) => {
      if (e.submitter?.value !== 'ok') return;
      e.preventDefault();
      const name = f.name.value.trim(), ct = read();
      if (!name) { err.textContent = 'Give the type a name'; f.name.focus(); return; }
      try {
        const bad = await api.customValidate(ct);
        if (bad) { err.textContent = bad; return; }
        await saveToTable(name, ct, oldName);
      } catch (x) { err.textContent = String(x); return; }
      result = { name, ct };
      d.close();
    });
    let result = null;
    d.addEventListener('close', () => { d.remove(); resolve(result); });
    d.showModal();
    f.name.select();
  });
}
