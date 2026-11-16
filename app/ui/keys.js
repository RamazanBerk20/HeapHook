// Key combos as Cheat Engine virtual-key codes (what .CT hotkeys and createHotkey store).
const NAMED = {
  Backspace: 8, Tab: 9, Enter: 13, NumpadEnter: 13, ShiftLeft: 16, ShiftRight: 16, ControlLeft: 17, ControlRight: 17,
  AltLeft: 18, AltRight: 18, Pause: 19, Escape: 27, Space: 32, PageUp: 33, PageDown: 34, End: 35, Home: 36,
  ArrowLeft: 37, ArrowUp: 38, ArrowRight: 39, ArrowDown: 40, Insert: 45, Delete: 46, MetaLeft: 91, MetaRight: 92,
  NumpadMultiply: 106, NumpadAdd: 107, NumpadSubtract: 109, NumpadDecimal: 110, NumpadDivide: 111,
  Semicolon: 186, Equal: 187, Comma: 188, Minus: 189, Period: 190, Slash: 191, Backquote: 192,
  BracketLeft: 219, Backslash: 220, BracketRight: 221, Quote: 222,
};
const NAME = {
  8: 'Backspace', 9: 'Tab', 13: 'Enter', 16: 'Shift', 17: 'Ctrl', 18: 'Alt', 19: 'Pause', 27: 'Esc', 32: 'Space',
  33: 'PgUp', 34: 'PgDn', 35: 'End', 36: 'Home', 37: '←', 38: '↑', 39: '→', 40: '↓', 45: 'Ins', 46: 'Del',
  91: 'Win', 92: 'Win', 106: 'Num *', 107: 'Num +', 109: 'Num -', 110: 'Num .', 111: 'Num /',
  186: ';', 187: '=', 188: ',', 189: '-', 190: '.', 191: '/', 192: '`', 219: '[', 220: '\\', 221: ']', 222: "'",
};
export const MODS = new Set([16, 17, 18, 91, 92]);

/** KeyboardEvent.code -> virtual-key code, or undefined. */
export function vkOf(code) {
  let m;
  if ((m = /^Key([A-Z])$/.exec(code))) return m[1].charCodeAt(0);
  if ((m = /^Digit(\d)$/.exec(code))) return 48 + +m[1];
  if ((m = /^Numpad(\d)$/.exec(code))) return 96 + +m[1];
  if ((m = /^F(\d+)$/.exec(code)) && +m[1] >= 1 && +m[1] <= 24) return 111 + +m[1];
  return NAMED[code];
}

/** The pressed combo, sorted (the order keys are pressed in does not matter). */
export function comboOf(e) {
  const k = new Set();
  if (e.ctrlKey) k.add(17);
  if (e.shiftKey) k.add(16);
  if (e.altKey) k.add(18);
  if (e.metaKey) k.add(91);
  const v = vkOf(e.code);
  if (v != null) k.add(v);
  return [...k].sort((a, b) => a - b);
}

export const keyName = (vk) =>
  NAME[vk] ?? (vk >= 65 && vk <= 90 ? String.fromCharCode(vk) : vk >= 48 && vk <= 57 ? String(vk - 48)
    : vk >= 96 && vk <= 105 ? 'Num ' + (vk - 96) : vk >= 112 && vk <= 135 ? 'F' + (vk - 111) : '#' + vk);

/** Modifiers first, like "Ctrl Shift F1". */
export const comboText = (keys) =>
  [...keys].sort((a, b) => (MODS.has(b) - MODS.has(a)) || a - b).map(keyName).join(' ') || 'none';
