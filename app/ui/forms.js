// Lua forms: the control trees table scripts build (createForm, createButton, …, trainers)
// rendered as floating panels in HeapHook's own style. The backend keeps the tree (hh-lua);
// this mirrors it from `ui_poll` (a snapshot first, then incremental changes) and sends user
// actions back with `ui_event` (OnClick, OnClose, …) and `ui_input` (Text, Checked, …).
// Geometry is CE's: absolute Left/Top/Width/Height in pixels inside the parent, plus Align.
import { api } from './backend.js';
import { h, icon, toast, contextMenu } from './util.js';
import { on } from './core.js';

const AL = { none: 0, top: 1, bottom: 2, left: 3, right: 4, client: 5 };
const CENTER = new Set([4, 5, 6, 7]); // poScreenCenter, poDesktopCenter, poMainFormCenter, poOwnerFormCenter
const MENU = new Set(['TMainMenu', 'TPopupMenu', 'TMenuItem']);
const TITLE_H = 30, TAB_H = 28, LEGEND_H = 18;

/** `&File` -> `File` (`&&` stays one `&`). */
const cap = (s) => String(s ?? '').replace(/&(&?)/g, (_, a) => a);
const num = (v, d = 0) => (Number.isFinite(+v) ? +v : d);
const list = (v) => (Array.isArray(v) ? v : v == null || v === '' ? [] : String(v).split('\n'));

export function initForms() {
  const layer = h('div.lf-layer', { 'aria-label': 'Lua forms' });
  document.body.append(layer);
  /** id -> {id, cls, parent, props, events: Set, kids: [id], el, body, skip} */
  const N = new Map();
  let since = 0, polling = false, again = false, z = 20;
  const images = new Map(); // path -> data URL or Promise
  const dirty = new Set(), menusDirty = { v: false };

  // ---------- sending user actions ----------
  let chain = Promise.resolve();
  const send = (f) => {
    chain = chain.then(f).catch((e) => toast(e?.message || e)).then(() => poll());
    return chain;
  };
  const fire = (id, ev, args = []) => send(() => api.uiEvent(id, ev, args));
  // The backend does not echo user input: keep the mirror in step so repaints show it.
  const input = (id, prop, value) => {
    const n = N.get(id);
    if (n) n.props[prop === 'Text' && n.cls === 'TMemo' ? 'Lines' : prop] = prop === 'Text' && n.cls === 'TMemo' ? String(value).split('\n') : value;
    return send(() => api.uiInput(id, prop, value));
  };
  const has = (n, ev) => n.events.has(ev);

  // ---------- tree ----------
  const formOf = (n) => { while (n && n.parent != null) n = N.get(n.parent); return n; };
  function create(c) {
    const old = N.get(c.id);
    if (old) destroy(c.id, true);
    const parent = c.parent != null ? N.get(c.parent) : null;
    const n = { id: c.id, cls: c.class, parent: c.parent ?? null, props: { ...c.props }, events: new Set(c.events || []), kids: [], el: null, body: null };
    n.skip = c.class === 'TMainForm' || !!parent?.skip; // HeapHook's own window as scripts see it: not drawn
    N.set(n.id, n);
    if (parent) parent.kids.push(n.id);
    if (n.skip) return;
    if (MENU.has(n.cls)) { menusDirty.v = true; return; }
    build(n);
    mount(n);
    paint(n);
    dirty.add(n.parent ?? n.id);
    if (n.cls === 'TTabSheet' && parent) paint(parent);
    if (n.cls === 'TCEForm' && n.props.Visible !== false) shown(n);
  }
  function mount(n) {
    if (!n.el) return;
    const p = n.parent != null ? N.get(n.parent) : null;
    if (!p) layer.append(n.el);
    else if (p.body) (p.tabs && n.cls === 'TTabSheet' ? p.pages : p.body).append(n.el);
  }
  function destroy(id, keepFocus = false) {
    const n = N.get(id);
    if (!n) return;
    for (const k of [...n.kids]) destroy(k, true);
    const p = n.parent != null ? N.get(n.parent) : null;
    if (p) p.kids = p.kids.filter((k) => k !== id);
    if (!keepFocus && n.el?.contains(document.activeElement)) n.prevFocus?.focus?.();
    n.el?.remove();
    N.delete(id);
    if (MENU.has(n.cls)) menusDirty.v = true;
    if (p) dirty.add(p.id);
  }
  function reparent(id, parent) {
    const n = N.get(id);
    if (!n) return;
    const old = n.parent != null ? N.get(n.parent) : null;
    if (old) { old.kids = old.kids.filter((k) => k !== id); dirty.add(old.id); }
    n.parent = parent ?? null;
    const p = parent != null ? N.get(parent) : null;
    if (p) p.kids.push(id);
    n.skip = n.cls === 'TMainForm' || !!p?.skip;
    if (MENU.has(n.cls)) { menusDirty.v = true; return; }
    if (n.skip) { n.el?.remove(); return; }
    if (!n.el) { build(n); paint(n); }
    mount(n);
    dirty.add(parent ?? id);
  }

  // ---------- elements ----------
  function build(n) {
    const id = n.id;
    const click = () => has(n, 'OnClick') && fire(id, 'OnClick');
    let el, body = null;
    switch (n.cls) {
      case 'TCEForm': {
        const title = h('span.lf-caption', { id: `lf-t-${id}` });
        const close = h('button.btn.ghost.icon.lf-close', { type: 'button', 'aria-label': 'Close', title: 'Close (Esc)', html: icon('x'), onclick: () => fire(id, 'OnClose') });
        const head = h('div.lf-head', null, title, close);
        n.menubar = h('div.lf-menubar', { role: 'menubar', hidden: true });
        body = h('div.lf-client');
        el = h('section.lf-form', { role: 'dialog', 'aria-labelledby': `lf-t-${id}`, tabindex: '-1' }, head, n.menubar, body);
        n.el = el;
        drag(n, head);
        el.addEventListener('pointerdown', () => front(n), true);
        el.addEventListener('focusin', () => front(n));
        el.addEventListener('keydown', (e) => {
          if (e.key === 'Escape' && !e.target.closest('.menu')) { e.preventDefault(); e.stopPropagation(); fire(id, 'OnClose'); }
          else if (e.key === 'F10' && !n.menubar.hidden) { e.preventDefault(); e.stopPropagation(); n.menubar.querySelector('button')?.focus(); }
          else e.stopPropagation(); // keys typed into a script form are not app shortcuts
        });
        break;
      }
      case 'TButton':
        el = h('button.btn.lf-ctl', { type: 'button', onclick: click });
        break;
      case 'TLabel':
        el = h('span.lf-ctl.lf-label', { onclick: click });
        break;
      case 'TEdit':
        el = h('input.lf-ctl', { type: 'text', spellcheck: 'false', autocomplete: 'off' });
        el.addEventListener('input', () => input(id, 'Text', el.value));
        el.addEventListener('keydown', (e) => { if (e.key === 'Enter' && has(n, 'OnKeyPress')) fire(id, 'OnKeyPress', ['\r']); });
        break;
      case 'TMemo':
        el = h('textarea.lf-ctl.lf-memo', { spellcheck: 'false' });
        el.addEventListener('input', () => input(id, 'Text', el.value));
        break;
      case 'TCheckBox': {
        n.box = h('input', { type: 'checkbox' });
        n.text = h('span');
        el = h('label.lf-ctl.lf-check', null, n.box, n.text);
        n.box.addEventListener('change', () => input(id, 'Checked', n.box.checked));
        break;
      }
      case 'TToggleBox':
        el = h('button.btn.lf-ctl.lf-toggle', { type: 'button', 'aria-pressed': 'false' });
        el.addEventListener('click', () => input(id, 'Checked', el.getAttribute('aria-pressed') !== 'true'));
        break;
      case 'TRadioGroup':
        n.legend = h('legend');
        n.items = h('div.lf-radios', { role: 'radiogroup' });
        el = h('fieldset.lf-ctl.lf-group', null, n.legend, n.items);
        break;
      case 'TListBox':
        el = h('div.lf-ctl.lf-list', { role: 'listbox', tabindex: '0' });
        el.addEventListener('click', (e) => { const o = e.target.closest('[data-i]'); if (o) input(id, 'ItemIndex', +o.dataset.i); });
        el.addEventListener('dblclick', (e) => { if (e.target.closest('[data-i]') && has(n, 'OnDblClick')) fire(id, 'OnDblClick'); });
        el.addEventListener('keydown', (e) => {
          const d = { ArrowDown: 1, ArrowUp: -1 }[e.key], cnt = list(n.props.Items).length;
          if (d && cnt) { e.preventDefault(); input(id, 'ItemIndex', Math.max(0, Math.min(cnt - 1, num(n.props.ItemIndex, -1) + d))); }
          else if (e.key === 'Enter' && has(n, 'OnDblClick')) { e.preventDefault(); fire(id, 'OnDblClick'); }
        });
        break;
      case 'TComboBox':
        el = h('select.lf-ctl');
        el.addEventListener('change', () => input(id, 'ItemIndex', el.selectedIndex));
        break;
      case 'TPanel':
        n.text = h('span.lf-panel-cap');
        body = el = h('div.lf-ctl.lf-panel', { role: 'group' }, n.text);
        break;
      case 'TGroupBox':
        n.legend = h('legend');
        body = el = h('fieldset.lf-ctl.lf-group.lf-box', null, n.legend);
        break;
      case 'TScrollBox':
        body = el = h('div.lf-ctl.lf-scroll', { role: 'group' });
        break;
      case 'TImage':
        el = h('img.lf-ctl.lf-img', { alt: '', onclick: click });
        break;
      case 'TProgressBar':
        n.bar = h('div.lf-bar');
        el = h('div.lf-ctl.lf-progress', { role: 'progressbar' }, n.bar);
        break;
      case 'TTrackBar':
        el = h('input.lf-ctl.lf-track', { type: 'range' });
        el.addEventListener('input', () => input(id, 'Position', +el.value));
        break;
      case 'TSplitter':
        el = h('div.lf-ctl.lf-split', { 'aria-hidden': 'true' });
        break;
      case 'TPageControl':
      case 'TTabControl':
        n.tabs = h('div.lf-tabs', { role: 'tablist' });
        n.pages = h('div.lf-pages');
        el = h('div.lf-ctl.lf-tabctl', null, n.tabs, n.pages);
        body = n.pages;
        n.tabs.addEventListener('click', (e) => {
          const t = e.target.closest('[data-i]');
          if (t) input(id, n.cls === 'TPageControl' ? 'ActivePageIndex' : 'TabIndex', +t.dataset.i);
        });
        n.tabs.addEventListener('keydown', (e) => {
          const d = { ArrowRight: 1, ArrowLeft: -1 }[e.key], all = [...n.tabs.children];
          if (!d || !all.length) return;
          e.preventDefault();
          const i = (Math.max(0, all.indexOf(document.activeElement)) + d + all.length) % all.length;
          all[i].click(); all[i].focus();
        });
        break;
      case 'TTabSheet':
        body = el = h('div.lf-sheet', { role: 'tabpanel' });
        break;
      default:
        // A class HeapHook does not draw yet: keep its children visible in a plain box.
        body = el = h('div.lf-ctl.lf-unknown', { title: n.cls });
    }
    el.dataset.lf = id;
    el.addEventListener('contextmenu', (e) => {
      const pm = n.props.PopupMenu;
      if (pm == null || !N.get(pm)) return;
      e.preventDefault(); e.stopPropagation();
      popup(N.get(pm), e.clientX, e.clientY, el);
    });
    n.el = el; n.body = body;
  }

  /** Copies every property onto the element (idempotent; geometry is `layout`'s job). */
  function paint(n) {
    const p = n.props, el = n.el;
    if (!el) return;
    el.hidden = p.Visible === false;
    const hint = p.Hint ? String(p.Hint) : '';
    if (hint && n.cls !== 'TCEForm') el.title = hint;
    const dis = p.Enabled === false;
    switch (n.cls) {
      case 'TCEForm': {
        el.querySelector('.lf-caption').textContent = cap(p.Caption) || 'Lua form';
        el.classList.toggle('lf-disabled', dis);
        break;
      }
      case 'TButton':
        el.textContent = cap(p.Caption); el.disabled = dis;
        el.classList.toggle('primary', p.Default === true);
        break;
      case 'TLabel':
        el.textContent = cap(p.Caption);
        el.classList.toggle('lf-link', has(n, 'OnClick'));
        el.classList.toggle('lf-wrap', p.WordWrap === true);
        el.style.textAlign = ['left', 'right', 'center'][num(p.Alignment)] || 'left';
        el.style.fontWeight = /fsBold/.test(String(p['Font.Style'] || '')) ? '600' : '';
        break;
      case 'TEdit':
        if (el.value !== String(p.Text ?? '')) el.value = String(p.Text ?? '');
        el.type = p.PasswordChar && String(p.PasswordChar) !== '\0' && String(p.PasswordChar) !== '#0' ? 'password' : 'text';
        el.readOnly = p.ReadOnly === true; el.disabled = dis;
        el.placeholder = p.TextHint ? String(p.TextHint) : '';
        el.setAttribute('aria-label', hint || p.Name || 'Text');
        break;
      case 'TMemo': {
        const t = list(p.Lines).join('\n');
        if (el.value !== t) el.value = t;
        el.readOnly = p.ReadOnly === true; el.disabled = dis;
        el.wrap = p.WordWrap === false ? 'off' : 'soft';
        el.setAttribute('aria-label', hint || p.Name || 'Text');
        break;
      }
      case 'TCheckBox':
        n.text.textContent = cap(p.Caption);
        n.box.checked = p.Checked === true; n.box.disabled = dis;
        el.classList.toggle('lf-disabled', dis);
        break;
      case 'TToggleBox':
        el.textContent = cap(p.Caption); el.disabled = dis;
        el.setAttribute('aria-pressed', String(p.Checked === true));
        break;
      case 'TRadioGroup': {
        n.legend.textContent = cap(p.Caption);
        const items = list(p.Items), cur = num(p.ItemIndex, -1), name = `lf-r-${n.id}`;
        n.items.style.gridTemplateColumns = `repeat(${Math.max(1, num(p.Columns, 1))}, minmax(0, 1fr))`;
        n.items.replaceChildren(...items.map((t, i) => {
          const r = h('input', { type: 'radio', name, checked: i === cur, disabled: dis, onchange: () => input(n.id, 'ItemIndex', i) });
          return h('label.lf-check', null, r, h('span', null, cap(t)));
        }));
        break;
      }
      case 'TListBox': {
        const items = list(p.Items), cur = num(p.ItemIndex, -1);
        el.replaceChildren(...items.map((t, i) => h('div.lf-opt', { role: 'option', id: `lf-o-${n.id}-${i}`, 'data-i': i, 'aria-selected': String(i === cur) }, String(t))));
        el.setAttribute('aria-activedescendant', cur >= 0 && cur < items.length ? `lf-o-${n.id}-${cur}` : '');
        el.setAttribute('aria-disabled', String(dis));
        el.setAttribute('aria-label', hint || p.Name || 'List');
        el.querySelector('[aria-selected=true]')?.scrollIntoView({ block: 'nearest' });
        break;
      }
      case 'TComboBox': {
        const items = list(p.Items), cur = num(p.ItemIndex, -1);
        const key = items.join('\n');
        if (el.dataset.items !== key) { el.replaceChildren(...items.map((t) => h('option', null, String(t)))); el.dataset.items = key; }
        el.selectedIndex = cur;
        el.disabled = dis;
        el.setAttribute('aria-label', hint || p.Name || 'Choice');
        break;
      }
      case 'TPanel':
        n.text.textContent = cap(p.Caption);
        el.classList.toggle('lf-flat', num(p.BevelOuter, 2) === 0);
        break;
      case 'TGroupBox':
        n.legend.textContent = cap(p.Caption);
        break;
      case 'TImage': {
        const f = String(p.Picture || '');
        el.style.objectFit = p.Stretch === true ? (p.Proportional === true ? 'contain' : 'fill') : p.Proportional === true ? 'contain' : 'none';
        el.alt = hint;
        if (!f) { el.removeAttribute('src'); break; }
        const c = images.get(f);
        if (typeof c === 'string') el.src = c;
        else if (!c) images.set(f, api.uiImage(f).then((u) => { images.set(f, u); paint(n); }, (e) => { images.set(f, ''); toast(e); }));
        break;
      }
      case 'TProgressBar': {
        const lo = num(p.Min), hi = num(p.Max, 100), v = Math.max(lo, Math.min(hi, num(p.Position)));
        n.bar.style.transform = `scaleX(${hi > lo ? (v - lo) / (hi - lo) : 0})`;
        el.setAttribute('aria-valuemin', lo); el.setAttribute('aria-valuemax', hi); el.setAttribute('aria-valuenow', v);
        el.setAttribute('aria-label', hint || p.Name || 'Progress');
        break;
      }
      case 'TTrackBar':
        el.min = num(p.Min); el.max = num(p.Max, 10); el.value = num(p.Position); el.disabled = dis;
        el.setAttribute('aria-label', hint || p.Name || 'Value');
        break;
      case 'TPageControl':
      case 'TTabControl': {
        const pc = n.cls === 'TPageControl';
        const names = pc ? n.kids.map((k) => N.get(k)).filter((k) => k?.cls === 'TTabSheet').map((k) => cap(k.props.Caption)) : list(p.Tabs).map(cap);
        let cur = num(pc ? p.ActivePageIndex : p.TabIndex, -1);
        if (cur < 0 && names.length && pc) cur = 0;
        n.tabs.replaceChildren(...names.map((t, i) => h('button', { type: 'button', role: 'tab', 'data-i': i, 'aria-selected': String(i === cur), tabindex: i === cur ? '0' : '-1' }, t || `Page ${i + 1}`)));
        if (pc) n.kids.map((k) => N.get(k)).filter((k) => k?.cls === 'TTabSheet').forEach((k, i) => { if (k.el) k.el.hidden = i !== cur || k.props.Visible === false; });
        break;
      }
    }
    if (n.cls !== 'TCEForm' && n.cls !== 'TTabSheet') el.classList.toggle('lf-disabled', dis);
  }

  /** Positions the children of `n` (or a form itself): Left/Top/Width/Height, Align. */
  function layout(n) {
    if (!n || n.skip || !n.el) return;
    const p = n.props;
    if (n.cls === 'TCEForm') {
      const w = Math.max(80, num(p.Width, 320)), hgt = Math.max(40, num(p.Height, 240));
      const mb = n.menubar.hidden ? 0 : 28;
      let x = num(p.Left), y = num(p.Top);
      if (CENTER.has(num(p.Position)) && !n.moved) { x = (innerWidth - w) / 2; y = (innerHeight - hgt - TITLE_H) / 2; }
      // Keep the title bar reachable whatever coordinates the script used (CE: screen pixels).
      x = Math.max(0, Math.min(innerWidth - Math.min(w, innerWidth) - 2, x));
      y = Math.max(0, Math.min(innerHeight - TITLE_H - 8, y));
      Object.assign(n.el.style, { left: x + 'px', top: y + 'px', width: w + 2 + 'px' });
      n.body.style.height = hgt + 'px';
      n.body.style.maxHeight = `calc(100vh - ${y + TITLE_H + mb + 12}px)`;
    }
    if (!n.body) return;
    // The client area children are placed in (group box legend, tab strip offsets).
    let W = num(p.Width), H = num(p.Height);
    if (n.cls === 'TGroupBox' || n.cls === 'TRadioGroup') H -= LEGEND_H;
    if (n.cls === 'TPageControl' || n.cls === 'TTabControl') H -= TAB_H;
    if (n.cls === 'TTabSheet') { const pc = N.get(n.parent); W = num(pc?.props.Width); H = num(pc?.props.Height) - TAB_H; }
    if (n.cls === 'TScrollBox') { W = 1e6; H = 1e6; }
    // Group boxes: CE coordinates start below the caption.
    const oy = n.cls === 'TGroupBox' || n.cls === 'TRadioGroup' ? LEGEND_H - 4 : 0;
    const r = { l: 0, t: 0, r: W, b: H }, client = [];
    for (const k of n.kids) {
      const c = N.get(k);
      if (!c?.el || MENU.has(c.cls) || c.cls === 'TTabSheet') continue;
      const q = c.props, s = c.el.style, al = num(q.Align);
      const cw = num(q.Width), ch = num(q.Height);
      const set = (x, y, w, hh) => Object.assign(s, { left: x + 'px', top: y + oy + 'px', width: w == null ? '' : Math.max(0, w) + 'px', height: hh == null ? '' : Math.max(0, hh) + 'px' });
      if (al === AL.top) { set(r.l, r.t, r.r - r.l, ch); r.t += ch; }
      else if (al === AL.bottom) { r.b -= ch; set(r.l, r.b, r.r - r.l, ch); }
      else if (al === AL.left) { set(r.l, r.t, cw, r.b - r.t); r.l += cw; }
      else if (al === AL.right) { r.r -= cw; set(r.r, r.t, cw, r.b - r.t); }
      else if (al === AL.client) client.push(c);
      else if (c.cls === 'TLabel' && q.AutoSize !== false && q.WordWrap !== true) set(num(q.Left), num(q.Top), null, null);
      else set(num(q.Left), num(q.Top), cw, ch);
    }
    for (const c of client) Object.assign(c.el.style, { left: r.l + 'px', top: r.t + oy + 'px', width: Math.max(0, r.r - r.l) + 'px', height: Math.max(0, r.b - r.t) + 'px' });
  }

  // ---------- forms: front, focus, drag ----------
  function front(n) {
    if (+n.el.style.zIndex !== z) n.el.style.zIndex = ++z;
    for (const f of layer.children) f.classList.toggle('lf-front', f === n.el);
  }
  function shown(n) {
    n.prevFocus = document.activeElement?.closest?.('.lf-form') ? n.prevFocus : document.activeElement;
    front(n);
    requestAnimationFrame(() => {
      if (n.el.hidden) return;
      (n.body.querySelector('input:not([disabled]), button:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex="0"]') || n.el).focus({ preventScroll: true });
    });
  }
  function drag(n, head) {
    head.addEventListener('pointerdown', (e) => {
      if (e.button !== 0 || e.target.closest('button')) return;
      e.preventDefault();
      head.setPointerCapture(e.pointerId);
      const r = n.el.getBoundingClientRect(), dx = e.clientX - r.left, dy = e.clientY - r.top;
      const move = (ev) => {
        n.moved = true;
        n.props.Left = Math.round(ev.clientX - dx); n.props.Top = Math.round(ev.clientY - dy);
        layout(n);
      };
      const up = () => {
        head.removeEventListener('pointermove', move); head.removeEventListener('pointerup', up);
        if (n.moved) { input(n.id, 'Left', n.props.Left); input(n.id, 'Top', n.props.Top); }
      };
      head.addEventListener('pointermove', move);
      head.addEventListener('pointerup', up);
    });
    // Keyboard move: Alt + arrows on the focused form.
    n.el.addEventListener('keydown', (e) => {
      const d = { ArrowLeft: [-16, 0], ArrowRight: [16, 0], ArrowUp: [0, -16], ArrowDown: [0, 16] }[e.key];
      if (!d || !e.altKey) return;
      e.preventDefault();
      n.moved = true;
      n.props.Left = num(n.props.Left) + d[0]; n.props.Top = num(n.props.Top) + d[1];
      layout(n);
      input(n.id, 'Left', n.props.Left); input(n.id, 'Top', n.props.Top);
    }, true);
  }

  // ---------- menus ----------
  const rootItem = (menu) => menu && N.get(menu.kids.find((k) => N.get(k)?.cls === 'TMenuItem'));
  const itemsOf = (it) => (it ? it.kids.map((k) => N.get(k)).filter((c) => c?.cls === 'TMenuItem' && c.props.Visible !== false) : []);
  function menuItems(item) {
    return itemsOf(item).map((c) => (cap(c.props.Caption) === '-' ? '-' : {
      label: cap(c.props.Caption) + (itemsOf(c).length ? ' …' : ''), disabled: c.props.Enabled === false,
      checked: c.props.Checked === true ? true : (c.props.AutoCheck || c.props.RadioItem) ? false : undefined,
      run: () => (itemsOf(c).length ? setTimeout(() => contextMenu(lastXY[0], lastXY[1], menuItems(c), lastFocus), 0) : fire(c.id, 'OnClick')),
    }));
  }
  let lastXY = [0, 0], lastFocus = null;
  function popup(menu, x, y, ret) {
    const items = menuItems(rootItem(menu));
    if (!items.length) return;
    lastXY = [x, y]; lastFocus = ret;
    if (has(menu, 'OnPopup')) fire(menu.id, 'OnPopup');
    contextMenu(x, y, items, ret);
  }
  function paintMenus() {
    for (const f of N.values()) {
      if (f.cls !== 'TCEForm' || !f.el) continue;
      const menu = f.props.Menu != null ? N.get(f.props.Menu) : null;
      const tops = itemsOf(rootItem(menu));
      const was = f.menubar.hidden;
      f.menubar.hidden = !tops.length;
      f.menubar.replaceChildren(...tops.map((c) => {
        const b = h('button.lf-mtop', { type: 'button', role: 'menuitem', disabled: c.props.Enabled === false, 'aria-haspopup': itemsOf(c).length ? 'menu' : null }, cap(c.props.Caption));
        b.addEventListener('click', () => {
          const r = b.getBoundingClientRect();
          if (itemsOf(c).length) { lastXY = [r.left, r.bottom + 2]; lastFocus = b; contextMenu(r.left, r.bottom + 2, menuItems(c), b); } else fire(c.id, 'OnClick');
        });
        b.addEventListener('keydown', (e) => {
          const all = [...f.menubar.children], i = all.indexOf(b);
          if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') { e.preventDefault(); all[(i + (e.key === 'ArrowRight' ? 1 : all.length - 1)) % all.length].focus(); }
          else if (e.key === 'ArrowDown') { e.preventDefault(); b.click(); }
        });
        return b;
      }));
      if (was !== f.menubar.hidden) dirty.add(f.id);
    }
  }

  // ---------- applying backend changes ----------
  function apply(c) {
    switch (c.op) {
      case 'create': create(c.control); break;
      case 'update': {
        const n = N.get(c.id);
        if (!n) break;
        const wasVis = n.props.Visible !== false;
        if (c.value == null) delete n.props[c.prop]; else n.props[c.prop] = c.value;
        if (n.skip) break;
        if (MENU.has(n.cls) || c.prop === 'Menu') { menusDirty.v = true; if (MENU.has(n.cls)) break; }
        paint(n);
        if (/^(Left|Top|Width|Height|Align|Visible|AutoSize|Position|Caption)$/.test(c.prop)) { dirty.add(n.parent ?? n.id); dirty.add(n.id); }
        if (n.cls === 'TTabSheet' || n.cls === 'TPageControl') paint(N.get(n.cls === 'TTabSheet' ? n.parent : n.id));
        if (n.cls === 'TCEForm' && c.prop === 'Visible') {
          if (!wasVis && c.value !== false) shown(n);
          else if (wasVis && c.value === false && n.el.contains(document.activeElement)) n.prevFocus?.focus?.();
        }
        break;
      }
      case 'event': { const n = N.get(c.id); if (n) { c.set ? n.events.add(c.event) : n.events.delete(c.event); if (n.el && !MENU.has(n.cls)) paint(n); } break; }
      case 'reparent': reparent(c.id, c.parent); break;
      case 'destroy': destroy(c.id); break;
      case 'call': {
        const n = N.get(c.id);
        if (!n || n.skip) break;
        const f = formOf(n);
        if (c.method === 'bringToFront' || c.method === 'showModal') { if (f?.el) { front(f); if (c.method === 'showModal') shown(f); } }
        else if (c.method === 'sendToBack') { if (f?.el) f.el.style.zIndex = 1; }
        else if (c.method === 'setFocus') n.el?.focus?.();
        else if (c.method === 'popup') popup(n, num(c.args?.[0], innerWidth / 2), num(c.args?.[1], innerHeight / 2), document.activeElement);
        break;
      }
    }
  }
  function flush() {
    if (menusDirty.v) { menusDirty.v = false; paintMenus(); }
    for (const id of dirty) layout(N.get(id));
    dirty.clear();
  }
  async function poll() {
    if (polling) { again = true; return; }
    polling = true;
    try {
      do {
        again = false;
        const r = await api.uiPoll(since);
        if (r.snapshot) {
          for (const id of [...N.keys()]) if (N.get(id)?.parent == null) destroy(id, true);
          N.clear();
          const walk = (node) => { create({ ...node, children: undefined }); node.children.forEach(walk); };
          r.snapshot.roots.forEach(walk);
        }
        for (const c of r.changes) apply(c);
        since = r.next;
        flush();
      } while (again);
    } catch (e) {
      console.warn('form poll failed:', e);
    } finally { polling = false; }
  }
  on('ui:seq', (seq) => { if (seq !== since) poll(); });
  window.addEventListener('resize', () => { for (const n of N.values()) if (n.cls === 'TCEForm') layout(n); });
  poll();

  /** Ctrl Shift L: focus the next visible Lua form (and back to the app after the last). */
  function cycle() {
    const forms = [...layer.children].filter((f) => !f.hidden).sort((a, b) => +a.style.zIndex - +b.style.zIndex);
    if (!forms.length) { toast('No Lua form is open', 'info'); return; }
    const i = forms.findIndex((f) => f.contains(document.activeElement));
    const next = forms[(i + 1) % forms.length];
    const n = N.get(+next.dataset.lf);
    if (n) shown(n);
  }
  return { cycle };
}
