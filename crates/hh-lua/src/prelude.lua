-- HeapHook Lua prelude: Cheat Engine objects and helpers on top of the Rust primitives in H.
local H, STUBS, allow_os, RUST_GLOBALS = ...

local error, type, select, rawequal, rawget, rawset, setmetatable, tostring, tonumber, pairs, ipairs, xpcall =
  error, type, select, rawequal, rawget, rawset, setmetatable, tostring, tonumber, pairs, ipairs, xpcall
local co_create, co_resume, co_status, co_running, co_yield =
  coroutine.create, coroutine.resume, coroutine.status, coroutine.running, coroutine.yield
local spack, sunpack, sformat = string.pack, string.unpack, string.format
local tpack, tunpack, tconcat = table.pack, table.unpack, table.concat

debug = debug or {}
debug.traceback = debug.traceback or H.traceback
local traceback = debug.traceback

-------------------------------------------------------------------- aborts cannot be caught
-- Once the budget is exceeded or the script is interrupted, every protected call re-raises
-- the abort, so `while true do pcall(f) end` cannot keep a script alive.
local aborted = H.aborted
do
  local raw_pcall, raw_xpcall, raw_resume = pcall, xpcall, coroutine.resume
  local function rethrow(ok, ...)
    if not ok then
      local m = aborted()
      if m then error(m, 0) end
    end
    return ok, ...
  end
  -- (_G: the file-level locals named pcall/xpcall must keep the raw functions)
  _G.pcall = function(f, ...) return rethrow(raw_pcall(f, ...)) end
  _G.xpcall = function(f, h, ...)
    return rethrow(raw_xpcall(f, function(e) if aborted() then return e end return h(e) end, ...))
  end
  coroutine.resume = function(co, ...) return rethrow(raw_resume(co, ...)) end
end

-------------------------------------------------------------------- Rust errors -> strings
-- Errors from Rust functions arrive as userdata; CE scripts expect strings (err:find, ..).
do
  local errtext = H.errtext
  local function wrap(f, level)
    return function(...)
      local r = tpack(pcall(f, ...))
      if not r[1] then error(errtext(r[2]), level) end
      return tunpack(r, 2, r.n)
    end
  end
  for _, n in ipairs(RUST_GLOBALS) do _G[n] = wrap(_G[n], 2) end
  for k, f in pairs(H) do if k ~= 'errtext' and k ~= 'traceback' and k ~= 'aborted' then H[k] = wrap(f, 0) end end
end

-------------------------------------------------------------------- OS policy
os.exit = function() error('os.exit is disabled in HeapHook', 2) end

-- Text chunks only: Lua 5.3 does not verify bytecode, so a crafted binary chunk could
-- corrupt HeapHook's memory.
string.dump = nil
do
  local raw_load, raw_loadfile = load, loadfile
  -- (an explicit nil env differs from no env, so keep the arity)
  load = function(chunk, name, _, ...)
    if select('#', ...) > 0 then return raw_load(chunk, name, 't', (...)) end
    return raw_load(chunk, name, 't')
  end
  loadfile = raw_loadfile and function(file, _, ...)
    if select('#', ...) > 0 then return raw_loadfile(file, 't', (...)) end
    return raw_loadfile(file, 't')
  end
  dofile = raw_loadfile and function(file)
    local f, err = loadfile(file)
    if not f then error(err, 2) end
    return f()
  end
  if package then
    package.loadlib = nil
    local searchers = { package.searchers[1] }
    if allow_os and raw_loadfile and package.searchpath then
      searchers[2] = function(name)
        local path, err = package.searchpath(name, package.path)
        if not path then return '\n\t' .. tostring(err) end
        local f, lerr = raw_loadfile(path, 't')
        if not f then error(sformat("error loading module '%s' from file '%s':\n\t%s", name, path, lerr), 2) end
        return f, path
      end
    end
    package.searchers = searchers
  end
end

if not allow_os then
  io = nil
  os.execute, os.remove, os.rename, os.getenv, os.tmpname = nil, nil, nil, nil, nil
  dofile, loadfile = nil, nil
end

-------------------------------------------------------------------- stubs
for _, s in ipairs(STUBS) do
  local msg = s[2]
  if _G[s[1]] == nil then _G[s[1]] = function() error(msg, 2) end end
end

-------------------------------------------------------------------- object helpers
-- CE methods work with both obj.m(x) and obj:m(x).
local function method(obj, f)
  return function(a, ...)
    if rawequal(a, obj) then return f(...) end
    return f(a, ...)
  end
end

-- Object with properties (get/set tables of functions), methods, and an optional handler for
-- integer indexes (obj[0]). Every property P also gets getP/setP methods.
local function object(get, set, methods, idx)
  set = set or {}
  local o = {}
  for k, f in pairs(methods or {}) do rawset(o, k, method(o, f)) end
  for k, g in pairs(get) do if rawget(o, 'get' .. k) == nil then rawset(o, 'get' .. k, method(o, g)) end end
  for k, s in pairs(set) do if rawget(o, 'set' .. k) == nil then rawset(o, 'set' .. k, method(o, s)) end end
  return setmetatable(o, {
    __index = function(_, k)
      local g = get[k]
      if g then return g() end
      if idx and type(k) == 'number' then return idx(k) end
    end,
    __newindex = function(_, k, v)
      local s = set[k]
      if s then s(v)
      elseif get[k] then error('property ' .. tostring(k) .. ' is read-only', 2)
      else rawset(o, k, v) end
    end,
  })
end

local function indexed(get, set)
  return setmetatable({}, {
    __index = function(_, i) return get(i) end,
    __newindex = function(_, i, v)
      if not set then error('read-only property', 2) end
      set(i, v)
    end,
  })
end

local function toint(v)
  local i = math.tointeger(v)
  if i then return i end
  v = tonumber(v) or 0
  return math.tointeger(v >= 0 and math.floor(v) or math.ceil(v)) or 0
end

-------------------------------------------------------------------- string lists
local function splitlines(v)
  local t, str = {}, tostring(v)
  if str == '' then return t end
  if str:sub(-1) ~= '\n' then str = str .. '\n' end
  for line in str:gmatch('(.-)\r?\n') do t[#t + 1] = line end
  return t
end

-- A TStrings view: `get()` returns the current lines, `set(t)` stores them.
local function boundlist(get, set)
  local function L() return get() or {} end
  local function at(i) return L()[toint(i) + 1] end
  local function put(i, v)
    local t = L()
    i = toint(i)
    if i < 0 or i > #t then error('list index out of bounds (' .. i .. ')', 3) end
    t[i + 1] = tostring(v)
    set(t)
  end
  local l
  l = object(
    { Count = function() return #L() end, Text = function() local t = L(); return #t == 0 and '' or tconcat(t, '\n') .. '\n' end,
      String = function() return indexed(at, put) end, Strings = function() return indexed(at, put) end },
    { Text = function(v) set(splitlines(v)) end },
    { add = function(v) local t = L(); t[#t + 1] = tostring(v); set(t); return #t - 1 end,
      addText = function(v) local t = L(); for _, x in ipairs(splitlines(v)) do t[#t + 1] = x end; set(t) end,
      insert = function(i, v) local t = L(); i = math.max(0, math.min(toint(i), #t)); table.insert(t, i + 1, tostring(v)); set(t) end,
      getString = at, setString = put,
      delete = function(i) local t = L(); i = toint(i); if i >= 0 and i < #t then table.remove(t, i + 1); set(t) end end,
      exchange = function(a, b) local t = L(); a, b = toint(a) + 1, toint(b) + 1; t[a], t[b] = t[b], t[a]; set(t) end,
      indexOf = function(v) for i, x in ipairs(L()) do if x == v then return i - 1 end end return -1 end,
      clear = function() set({}) end,
      assign = function(o) local t = {} for i = 0, o.Count - 1 do t[#t + 1] = o[i] end set(t) end,
      sort = function() local t = L(); table.sort(t); set(t) end,
      beginUpdate = function() end, endUpdate = function() end, destroy = function() end },
    at)
  getmetatable(l).__len = function() return #L() end
  return l
end

local function stringlist(items)
  local s = items or {}
  return boundlist(function() return s end, function(t) s = t end)
end
function createStringlist() return stringlist({}) end
createStringList = createStringlist

-------------------------------------------------------------------- constants
soUnknownValue, soExactValue, soValueBetween, soBiggerThan, soSmallerThan = 0, 1, 2, 3, 4
soIncreasedValue, soIncreasedValueBy, soDecreasedValue, soDecreasedValueBy = 5, 6, 7, 8
soChanged, soUnchanged = 9, 10
vtByte, vtWord, vtDword, vtQword, vtSingle, vtDouble, vtString, vtUnicodeString = 0, 1, 2, 3, 4, 5, 6, 7
vtByteArray, vtBinary, vtAll, vtAutoAssembler, vtPointer, vtCustom, vtGrouped = 8, 9, 10, 11, 12, 13, 14
rtRounded, rtExtremerounded, rtTruncated = 0, 1, 2
fsmNotAligned, fsmAligned, fsmLastDigits = 0, 1, 2
mtWarning, mtError, mtInformation, mtConfirmation, mtCustom = 0, 1, 2, 3, 4
mbYes, mbNo, mbOK, mbCancel, mbAbort, mbRetry, mbIgnore, mbAll, mbNoToAll, mbYesToAll, mbHelp, mbClose =
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11
mrNone, mrOk, mrCancel, mrAbort, mrRetry, mrIgnore, mrYes, mrNo, mrAll, mrNoToAll, mrYesToAll, mrClose =
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11
VK_BACK, VK_TAB, VK_RETURN, VK_SHIFT, VK_CONTROL, VK_MENU, VK_PAUSE, VK_CAPITAL, VK_ESCAPE, VK_SPACE =
  8, 9, 13, 16, 17, 18, 19, 20, 27, 32
VK_PRIOR, VK_NEXT, VK_END, VK_HOME, VK_LEFT, VK_UP, VK_RIGHT, VK_DOWN, VK_INSERT, VK_DELETE =
  33, 34, 35, 36, 37, 38, 39, 40, 45, 46
VK_MULTIPLY, VK_ADD, VK_SEPARATOR, VK_SUBTRACT, VK_DECIMAL, VK_DIVIDE = 106, 107, 108, 109, 110, 111
VK_LBUTTON, VK_RBUTTON, VK_MBUTTON = 1, 2, 4
for i = 0, 9 do _G['VK_' .. i] = 48 + i; _G['VK_NUMPAD' .. i] = 96 + i end
for i = 1, 24 do _G['VK_F' .. i] = 111 + i end
for c = 65, 90 do _G['VK_' .. string.char(c)] = c end
mrhToggleActivation, mrhToggleActivationAllowIncrease, mrhToggleActivationAllowDecrease = 0, 1, 2
mrhActivate, mrhDeactivate, mrhSetValue, mrhIncreaseValue, mrhDecreaseValue = 3, 4, 5, 6, 7
bptExecute, bptAccess, bptWrite = 0, 1, 2
bpmInt3, bpmDebugRegister, bpmException = 0, 1, 2
co_run, co_stepinto, co_stepover, co_runtill = 0, 1, 2, 3
jtCall, jtUnconditional, jtConditional, jtMemory = 0, 1, 2, 3
caNone, caHide, caFree, caMinimize = 0, 1, 2, 3
poDesigned, poDefault, poDefaultPosOnly, poDefaultSizeOnly, poScreenCenter, poDesktopCenter, poMainFormCenter,
  poOwnerFormCenter = 0, 1, 2, 3, 4, 5, 6, 7
bsNone, bsSingle, bsSizeable, bsDialog, bsToolWindow, bsSizeToolWin = 0, 1, 2, 3, 4, 5
alNone, alTop, alBottom, alLeft, alRight, alClient, alCustom = 0, 1, 2, 3, 4, 5, 6
taLeftJustify, taRightJustify, taCenter = 0, 1, 2
csDropDown, csSimple, csDropDownList = 0, 1, 2
cbUnchecked, cbChecked, cbGrayed = 0, 1, 2
clBlack, clMaroon, clGreen, clOlive, clNavy, clPurple, clTeal, clGray =
  0, 0x80, 0x8000, 0x8080, 0x800000, 0x800080, 0x808000, 0x808080
clSilver, clRed, clLime, clYellow, clBlue, clFuchsia, clAqua, clWhite =
  0xC0C0C0, 0xFF, 0xFF00, 0xFFFF, 0xFF0000, 0xFF00FF, 0xFFFF00, 0xFFFFFF
clDefault, clNone, clBtnFace, clWindow, clWindowText, clHighlight = 0x20000000, 0x1FFFFFFF, 0x8000000F, 0x80000005, 0x80000008, 0x8000000D

-------------------------------------------------------------------- misc globals
function getCEVersion() return 7.5 end
function cheatEngineIs64Bit() return true end
function getOperatingSystem() return package.config:sub(1, 1) == '\\' and 0 or 1 end

function bAnd(a, b) return toint(a) & toint(b) end
function bOr(a, b) return toint(a) | toint(b) end
function bXor(a, b) return toint(a) ~ toint(b) end
function bShl(a, b) return toint(a) << toint(b) end
function bShr(a, b) return toint(a) >> toint(b) end
function bNot(a) return ~toint(a) end

-------------------------------------------------------------------- byte tables (1-based, like CE)
local function tobytes(s) local t = {} for i = 1, #s do t[i] = s:byte(i) end return t end
local function frombytes(t, n)
  local c = {}
  for i = 1, n or #t do c[i] = string.char(toint(t[i] or 0) & 0xff) end
  return tconcat(c)
end
local function utf16(s)
  local out = {}
  for _, cp in utf8.codes(s) do
    if cp >= 0x10000 then
      cp = cp - 0x10000
      out[#out + 1] = spack('<I2I2', 0xD800 + (cp >> 10), 0xDC00 + (cp & 0x3FF))
    else
      out[#out + 1] = spack('<I2', cp)
    end
  end
  return tconcat(out)
end
local function fromutf16(s)
  local out, i = {}, 1
  while i + 1 <= #s do
    local u = sunpack('<I2', s, i); i = i + 2
    if u == 0 then break end
    if u >= 0xD800 and u < 0xDC00 and i + 1 <= #s then
      local l = sunpack('<I2', s, i); i = i + 2
      u = 0x10000 + ((u - 0xD800) << 10) + (l - 0xDC00)
    end
    out[#out + 1] = utf8.char(u)
  end
  return tconcat(out)
end

function wordToByteTable(v) return tobytes(spack('<I2', toint(v) & 0xffff)) end
function dwordToByteTable(v) return tobytes(spack('<I4', toint(v) & 0xffffffff)) end
function qwordToByteTable(v) return tobytes(spack('<i8', toint(v))) end
function floatToByteTable(v) return tobytes(spack('<f', v)) end
function doubleToByteTable(v) return tobytes(spack('<d', v)) end
function stringToByteTable(s) return tobytes(s) end
function wideStringToByteTable(s) return tobytes(utf16(s)) end
function byteTableToWord(t, signed) return (sunpack(signed and '<i2' or '<I2', frombytes(t, 2))) end
function byteTableToDword(t, signed) return (sunpack(signed and '<i4' or '<I4', frombytes(t, 4))) end
function byteTableToQword(t) return (sunpack('<i8', frombytes(t, 8))) end
function byteTableToFloat(t) return (sunpack('<f', frombytes(t, 4))) end
function byteTableToDouble(t) return (sunpack('<d', frombytes(t, 8))) end
function byteTableToString(t) return frombytes(t) end
function byteTableToWideString(t) return fromutf16(frombytes(t)) end

-------------------------------------------------------------------- disassembler text
-- "address - bytes - opcode : extra" -> extra, opcode, bytes, address
function splitDisassembledString(s)
  local address, bytes, rest = s:match('^(.-) %- (.-) %- (.*)$')
  if not address then return '', s, '', '' end
  local opcode, extra = rest:match('^(.-) : (.*)$')
  return extra or '', opcode or rest, bytes, address
end

-------------------------------------------------------------------- AOB scan
function AOBScan(aob, ...)
  local args = { ... }
  if type(aob) == 'number' then -- AOBScan(0x11, 0x22, ...)
    local parts = { sformat('%02X', aob) }
    for i, b in ipairs(args) do parts[i + 1] = sformat('%02X', b) end
    aob, args = tconcat(parts, ' '), {}
  end
  local r = H.aobscan(aob, args[1], args[2], args[3])
  if not r or #r == 0 then return nil end
  local s = {}
  for i, a in ipairs(r) do s[i] = sformat('%08X', a) end
  return stringlist(s)
end

-------------------------------------------------------------------- memscan / foundlist
local myscans = {}  -- memscans created by createMemScan (freed by clear_table_state)

local function memscan(id, owned)
  local st = {}
  local ms
  local function done()
    if st.onlyone then st.result = (H.ms_row(id, 0)) end
    if st.ondone then st.ondone(ms) end
  end
  ms = object(
    { FoundCount = function() return H.ms_count(id) end, OnScanDone = function() return st.ondone end,
      CustomType = function() return st.ct end, Not = function() return st.isnot or false end,
      OnlyOneResult = function() return st.onlyone or false end, Result = function() return st.result end,
      RegionFilter = function() return st.filter end },
    { OnScanDone = function(f) st.ondone = f end, CustomType = function(v) st.ct = v end,
      RegionFilter = function(v) st.filter = v end,
      Not = function(v) st.isnot = v and true or false end, OnlyOneResult = function(v) st.onlyone = v and true or false end },
    { firstScan = function(so, vt, rt, i1, i2, start, stop, prot, at, ap, hex, nb, uni, cs)
        H.ms_first(id, so, vt, rt, i1, i2, start, stop, prot, at, ap, hex, nb, uni, cs, st.ct, st.isnot, st.filter); done()
      end,
      nextScan = function(so, rt, i1, i2, hex, nb, uni, cs, pct, saved)
        H.ms_next(id, so, rt, i1, i2, hex, nb, uni, cs, pct, saved, st.isnot); done()
      end,
      newScan = function() H.ms_newscan(id); st.result = nil end,
      waitTillDone = function() end,
      getAttachedFoundlist = function() return st.fl end,
      setOnlyOneResult = function(v) st.onlyone = v and true or false end,
      getOnlyResult = function() return st.result end,
      saveCurrentResults = function(name) H.ms_save(id, name) end,
      getSavedResultList = function() return stringlist(H.ms_saved(id)) end,
      deleteSavedResult = function(name) H.ms_delsaved(id, name) end,
      -- HeapHook: results order, removal and saved-scan values
      sortResults = function(byValue, descending) H.ms_sort(id, byValue ~= false, descending and true or false) end,
      removeResults = function(addrs) return H.ms_remove(id, addrs) end,
      getSavedResultValue = function(name, address) return H.ms_savedval(id, name, address) end,
      destroy = function() if owned then H.ms_free(id); myscans[id] = nil end end })
  rawset(ms, '__hh_id', id)
  rawset(ms, '__hh_st', st)
  return ms
end

function createMemScan()
  local id = H.ms_new()
  myscans[id] = true
  return memscan(id, true)
end

local hostscans = setmetatable({}, { __mode = 'v' })
function getCurrentMemscan()
  local id = H.ms_host()
  if not id then return nil end
  local ms = hostscans[id] or memscan(id, false)
  hostscans[id] = ms
  return ms
end

function createFoundList(ms)
  local id = rawget(ms, '__hh_id')
  local count = 0
  local function row(i)
    if i < 0 or i >= count then return nil end
    return H.ms_row(id, i)
  end
  local fl = object(
    { Count = function() return count end,
      Address = function() return indexed(function(i) local a = row(i); return a and sformat('%X', a) end) end,
      Value = function() return indexed(function(i) local _, v = row(i); return v end) end },
    nil,
    { initialize = function() count = H.ms_count(id) end,
      deinitialize = function() count = 0 end,
      getAddress = function(i) local a = row(i); return a and sformat('%X', a) end,
      getValue = function(i) local _, v = row(i); return v end,
      destroy = function() count = 0 end })
  rawget(ms, '__hh_st').fl = fl
  return fl
end

-------------------------------------------------------------------- timers
local timers = {}
local now = H.now
local ownedTimers = {}  -- control id -> { timer = true } (createTimer(form))
local isui              -- defined with the forms

function createTimer(owner, enabled, ...)
  if type(owner) == 'number' then -- createTimer(delay, function, ...): one shot
    local f, args, t = enabled, tpack(...), nil
    t = createTimer(nil, false)
    t.Interval = owner
    t.OnTimer = function() t.destroy(); f(tunpack(args, 1, args.n)) end
    t.Enabled = true
    return t
  end
  local st = { interval = 1000, enabled = enabled ~= false, due = 0 }
  local t
  t = object(
    { Interval = function() return st.interval end, Enabled = function() return st.enabled end,
      OnTimer = function() return st.ontimer end, Owner = function() return owner end },
    { Interval = function(v) st.interval = math.max(1, toint(v)); st.due = now() + st.interval end,
      Enabled = function(v) st.enabled = v and true or false; st.due = now() + st.interval end,
      OnTimer = function(f) st.ontimer = f end },
    { destroy = function() timers[t] = nil; st.enabled = false end })
  st.due = now() + st.interval
  timers[t] = st
  if isui(owner) then
    local oid = rawget(owner, '__id')
    ownedTimers[oid] = ownedTimers[oid] or {}
    ownedTimers[oid][t] = true
  end
  return t
end

-------------------------------------------------------------------- threads (cooperative)
local threads, threadOf = {}, setmetatable({}, { __mode = 'k' })

local function step(th, st)
  if st.finished then return end
  local ok, a, b = co_resume(st.co)
  if co_status(st.co) == 'dead' then
    st.finished = true
    threads[th] = nil
    if not ok then return 'thread: ' .. tostring(a) end
    if a == false then return 'thread: ' .. tostring(b) end
  else
    st.wake = now() + (tonumber(a) or 0)
  end
end

function createThread(f, ...)
  local args = tpack(...)
  local st = { terminated = false, finished = false, wake = 0 }
  local th
  th = object(
    { Terminated = function() return st.terminated end, Finished = function() return st.finished end,
      Name = function() return st.name end },
    { Name = function(v) st.name = v end },
    { terminate = function() st.terminated = true end,
      waitfor = function()
        while not st.finished do
          local w = st.wake - now()
          if w > 0 then H.sleep(w) end
          local e = step(th, st)
          if e then H.report(e) end
          local m = aborted()
          if m then error(m, 0) end
        end
      end,
      synchronize = function(fn, ...) return fn(...) end,
      queue = function(fn, ...) return fn(...) end,
      destroy = function() st.terminated = true end })
  st.co = co_create(function() return xpcall(f, traceback, th, tunpack(args, 1, args.n)) end)
  threadOf[st.co] = th
  threads[th] = st
  return th
end
createNativeThread = createThread

function sleep(ms)
  if threadOf[co_running()] then co_yield(ms or 0) else H.sleep(ms or 0) end
end
function synchronize(f, ...) return f(...) end
function queue(f, ...) return f(...) end
function inMainThread() return threadOf[co_running()] == nil end
function processMessages() end

-------------------------------------------------------------------- hotkeys
local hotkeys, hkid = {}, 0
function createHotkey(f, ...)
  local keys = { ... }
  if type(keys[1]) == 'table' then keys = keys[1] end
  hkid = hkid + 1
  local id, st = hkid, { f = f }
  local hk = object(
    { ID = function() return id end, OnHotkey = function() return st.f end, Keys = function() return keys end },
    { OnHotkey = function(v) st.f = v end },
    { destroy = function() hotkeys[id] = nil; H.hotkey_unregister(id) end })
  hotkeys[id] = { hk, st }
  H.hotkey_register(id, keys)
  return hk
end

local KEYNAMES = { [8] = 'Backspace', [9] = 'Tab', [13] = 'Enter', [16] = 'Shift', [17] = 'Ctrl', [18] = 'Alt',
  [19] = 'Pause', [20] = 'Caps Lock', [27] = 'Esc', [32] = 'Space', [33] = 'Page Up', [34] = 'Page Down',
  [35] = 'End', [36] = 'Home', [37] = 'Left', [38] = 'Up', [39] = 'Right', [40] = 'Down', [45] = 'Insert',
  [46] = 'Delete', [106] = 'Num *', [107] = 'Num +', [109] = 'Num -', [110] = 'Num .', [111] = 'Num /' }
local function keyname(k)
  k = toint(k)
  if KEYNAMES[k] then return KEYNAMES[k] end
  if (k >= 48 and k <= 57) or (k >= 65 and k <= 90) then return string.char(k) end
  if k >= 96 and k <= 105 then return 'Num ' .. (k - 96) end
  if k >= 112 and k <= 135 then return 'F' .. (k - 111) end
  return '#' .. k
end
function convertKeyComboToString(...)
  local keys = { ... }
  if type(keys[1]) == 'table' then keys = keys[1] end
  local parts = {}
  for i, k in ipairs(keys) do parts[i] = keyname(k) end
  return tconcat(parts, '+')
end

-------------------------------------------------------------------- memory records
local recs = setmetatable({}, { __mode = 'v' })
local cbs = {}       -- record id -> { OnActivate = f, ... }
local lastval = {}   -- record id -> value last seen by OnValueChanged
local hkcbs = {}     -- 'rec:hotkey' -> { OnHotkey = f, OnPostHotkey = f }
local setactive, mr

local function hotkeys_of(id) return H.mr_get(id, 'Hotkeys') or {} end

local rechotkey
local rhks = setmetatable({}, { __mode = 'v' })
local function rhk(id, hid)
  local key = id .. ':' .. hid
  if rhks[key] then return rhks[key] end
  local function find()
    for i, h in ipairs(hotkeys_of(id)) do if h.ID == hid then return h, i end end
  end
  local function g(k) return function() local h = find(); return h and h[k] end end
  local function s(k)
    return function(v)
      local list = hotkeys_of(id)
      for _, h in ipairs(list) do if h.ID == hid then h[k] = v end end
      H.mr_set(id, 'Hotkeys', list)
    end
  end
  local function cb(n) return function() return hkcbs[key] and hkcbs[key][n] end end
  local function setcb(n) return function(f) hkcbs[key] = hkcbs[key] or {}; hkcbs[key][n] = f end end
  local o = object(
    { ID = function() return hid end, Owner = function() return mr(id) end, Description = g 'Description',
      Keys = g 'Keys', Action = g 'Action', action = g 'Action', Value = g 'Value', value = g 'Value',
      HotkeyString = function() local h = find(); return h and convertKeyComboToString(h.Keys) end,
      OnHotkey = cb 'OnHotkey', OnPostHotkey = cb 'OnPostHotkey' },
    { Description = s 'Description', Keys = s 'Keys', Action = s 'Action', action = s 'Action',
      Value = function(v) s 'Value' (tostring(v)) end, value = function(v) s 'Value' (tostring(v)) end,
      OnHotkey = setcb 'OnHotkey', OnPostHotkey = setcb 'OnPostHotkey' },
    { doHotkey = function() rechotkey(id, hid) end,
      destroy = function()
        local list, out = hotkeys_of(id), {}
        for _, h in ipairs(list) do if h.ID ~= hid then out[#out + 1] = h end end
        H.mr_set(id, 'Hotkeys', out)
        hkcbs[key] = nil
      end })
  rhks[key] = o
  return o
end

-- Hotkey actions (CE mrh*); OnHotkey returning false skips the action.
rechotkey = function(id, hid)
  local h
  for _, x in ipairs(hotkeys_of(id)) do if x.ID == hid then h = x end end
  if not h then error('memory record ' .. tostring(id) .. ' has no hotkey ' .. tostring(hid), 2) end
  local o = rhk(id, hid)
  local c = hkcbs[id .. ':' .. hid]
  -- A record without capabilities never runs Lua callbacks (whoever registered them).
  if c and (c.OnHotkey or c.OnPostHotkey) and not H.mr_trusted(id) then H.report(H.mr_denied(id, 'hotkey callback')); return end
  if c and c.OnHotkey and c.OnHotkey(o) == false then return end
  local rec, a = mr(id), toint(h.Action)
  local function act(v)
    local ok, err = setactive(id, v)
    if not ok and err then H.report(err) end
  end
  if a <= 2 then act(not H.mr_get(id, 'Active'))
  elseif a == 3 then act(true)
  elseif a == 4 then act(false)
  elseif a == 5 then rec.Value = h.Value
  elseif (a == 6 or a == 7) and H.mr_get(id, 'Type') == vtCustom then
    local d = tonumber(h.Value) or 1
    H.mr_add(id, a == 6 and d or -d)
  elseif a == 6 or a == 7 then
    local base = rec.ShowAsHex and 16 or 10
    local cur, d = tonumber(rec.Value, base) or tonumber(rec.Value) or 0, tonumber(h.Value) or 1
    local v = a == 6 and cur + d or cur - d
    rec.Value = rec.ShowAsHex and sformat('%X', toint(v)) or v
  end
  if c and c.OnPostHotkey then c.OnPostHotkey(o) end
end

local function dropdown(id)
  local lines = H.mr_get(id, 'DropDownList') or {}
  local vals, descs = {}, {}
  for i, l in ipairs(lines) do
    local v, d = l:match('^(.-):(.*)$')
    vals[i], descs[i] = v or l, d or ''
  end
  return vals, descs
end

local function del_record(id)
  local c = cbs[id]
  if c and c.OnDestroy and H.mr_trusted(id) then c.OnDestroy(recs[id] or mr(id)) end
  H.mr_delete(id); recs[id] = nil; cbs[id] = nil; lastval[id] = nil
end

mr = function(id)
  if id == nil then return nil end
  local o = recs[id]
  if o then return o end
  local function g(k) return function() return H.mr_get(id, k) end end
  local function s(k) return function(v) H.mr_set(id, k, v) end end
  local function cb(name) return function() return cbs[id] and cbs[id][name] end end
  local function setcb(name)
    return function(f)
      cbs[id] = cbs[id] or {}
      cbs[id][name] = f
      if name == 'OnValueChanged' then lastval[id] = f and H.mr_get(id, 'Value') or nil end
    end
  end
  local function offsets() return H.mr_get(id, 'Offsets') or {} end
  o = object(
    { ID = function() return id end, Description = g 'Description', Address = g 'Address', Type = g 'Type',
      Value = g 'Value', Script = g 'Script', Color = g 'Color', Active = g 'Active',
      CurrentAddress = g 'CurrentAddress', ShowAsHex = g 'ShowAsHex', ShowAsSigned = g 'ShowAsSigned',
      IsGroupHeader = g 'IsGroupHeader', Options = g 'Options', Collapsed = g 'Collapsed',
      IsReadable = g 'IsReadable', Index = g 'Index', Async = function() return false end,
      DropDownReadOnly = g 'DropDownReadOnly', DropDownDescriptionOnly = g 'DropDownDescriptionOnly',
      DisplayAsDropDownListItem = g 'DisplayAsDropDownListItem',
      DropDownList = function()
        return boundlist(function() return H.mr_get(id, 'DropDownList') end, function(t) H.mr_set(id, 'DropDownList', t) end)
      end,
      DropDownCount = function() return #(H.mr_get(id, 'DropDownList') or {}) end,
      DropDownValue = function() return indexed(function(i) return (dropdown(id))[i + 1] end) end,
      DropDownDescription = function() return indexed(function(i) return select(2, dropdown(id))[i + 1] end) end,
      HotkeyCount = function() return #hotkeys_of(id) end,
      Hotkey = function() return indexed(function(i) local h = hotkeys_of(id)[i + 1]; return h and rhk(id, h.ID) end) end,
      OffsetCount = function() return #offsets() end,
      Offset = function()
        return indexed(function(i) return offsets()[i + 1] end,
          function(i, v) local t = offsets(); t[i + 1] = v; H.mr_set(id, 'Offsets', t) end)
      end,
      Count = function() return #(H.mr_get(id, 'Children') or {}) end,
      Child = function() return indexed(function(i) return mr((H.mr_get(id, 'Children') or {})[i + 1]) end) end,
      Parent = function() return mr(H.mr_get(id, 'Parent')) end,
      OnActivate = cb 'OnActivate', OnDeactivate = cb 'OnDeactivate', OnValueChanged = cb 'OnValueChanged',
      OnDestroy = cb 'OnDestroy',
      String = function() return object({ Size = g 'StringSize', Unicode = g 'Unicode' }, { Size = s 'StringSize', Unicode = s 'Unicode' }) end,
      Aob = function() return object({ Size = g 'AobSize' }, { Size = s 'AobSize' }) end },
    { Description = s 'Description', Address = s 'Address', Type = s 'Type', Value = s 'Value',
      CustomTypeName = s 'CustomTypeName',
      Script = s 'Script', Color = s 'Color', ShowAsHex = s 'ShowAsHex', ShowAsSigned = s 'ShowAsSigned',
      IsGroupHeader = s 'IsGroupHeader', Options = s 'Options', Collapsed = s 'Collapsed',
      DropDownReadOnly = s 'DropDownReadOnly', DropDownDescriptionOnly = s 'DropDownDescriptionOnly',
      DisplayAsDropDownListItem = s 'DisplayAsDropDownListItem',
      DropDownList = function(v)
        if type(v) == 'table' and rawget(v, 'getString') then local t = {} for i = 0, v.Count - 1 do t[#t + 1] = v[i] end v = t end
        H.mr_set(id, 'DropDownList', v)
      end,
      OffsetCount = function(n)
        local t = offsets()
        for i = #t + 1, n do t[i] = 0 end
        for i = #t, n + 1, -1 do t[i] = nil end
        H.mr_set(id, 'Offsets', t)
      end,
      Active = function(v)
        local ok, err = setactive(id, v and true or false)
        if not ok and err then H.report(err) end
      end,
      OnActivate = setcb 'OnActivate', OnDeactivate = setcb 'OnDeactivate', OnValueChanged = setcb 'OnValueChanged',
      OnDestroy = setcb 'OnDestroy' },
    { delete = function() del_record(id) end,
      destroy = function() del_record(id) end,
      appendToEntry = function(p) H.mr_set(id, 'Parent', p and p.ID) end,
      disableWithoutExecute = function() setactive(id, false, true) end,
      createHotkey = function(keys, action, value, description)
        local list, max = hotkeys_of(id), 0
        for _, h in ipairs(list) do if h.ID > max then max = h.ID end end
        list[#list + 1] = { ID = max + 1, Keys = keys or {}, Action = action or 0, Value = value ~= nil and tostring(value) or '',
          Description = description or '' }
        H.mr_set(id, 'Hotkeys', list)
        return rhk(id, max + 1)
      end,
      getHotkeyByID = function(hid)
        for _, h in ipairs(hotkeys_of(id)) do if h.ID == hid then return rhk(id, hid) end end
      end,
      beginEdit = function() end, endEdit = function() end, reinterpret = function() end })
  recs[id] = o
  return o
end

local function has_option(id, want)
  for _, o in ipairs(H.mr_get(id, 'OptionList') or {}) do if o == want then return true end end
  return false
end

-- OnActivate/OnDeactivate(memrec, before, currentstate): returning false before aborts. Then
-- the group options: moActivateChildrenAsWell / moDeactivateChildrenAsWell.
setactive = function(id, v, noexec)
  local cur = H.mr_get(id, 'Active')
  if cur == nil then return false, 'memory record was deleted' end
  if cur == v then return true end
  local name = v and 'OnActivate' or 'OnDeactivate'
  local f = cbs[id] and cbs[id][name]
  if f and not H.mr_trusted(id) then return false, H.mr_denied(id, name) end
  local rec = mr(id)
  if f and f(rec, true, cur) == false then return false end
  local ok, err = H.mr_apply(id, v, not noexec)
  if f then f(rec, false, H.mr_get(id, 'Active')) end
  if ok and has_option(id, v and 'moActivateChildrenAsWell' or 'moDeactivateChildrenAsWell') then
    for _, c in ipairs(H.mr_get(id, 'Children') or {}) do
      local cok, cerr = setactive(c, v, noexec)
      if not cok and cerr then H.report(cerr) end
    end
  end
  return ok, err
end

local al
function getAddressList()
  if al then return al end
  local ids = H.mr_ids
  local function selected()
    local t = {}
    for i, id in ipairs(H.al_selected()) do t[i] = mr(id) end
    return t
  end
  al = object(
    { Count = function() return #ids() end,
      MemoryRecord = function() return indexed(function(i) return mr(ids()[i + 1]) end) end,
      SelectedRecord = function() return mr(H.al_selected()[1]) end,
      SelectedRecords = selected,
      SelCount = function() return #H.al_selected() end },
    { SelectedRecord = function(r) H.al_select(r and { r.ID } or {}) end,
      SelectedRecords = function(t) local s = {} for i, r in ipairs(t or {}) do s[i] = r.ID end H.al_select(s) end },
    { getMemoryRecord = function(i) return mr(ids()[i + 1]) end,
      getMemoryRecordByDescription = function(d)
        for _, id in ipairs(ids()) do if H.mr_get(id, 'Description') == d then return mr(id) end end
      end,
      getMemoryRecordByID = function(want)
        for _, id in ipairs(ids()) do if id == want then return mr(id) end end
      end,
      createMemoryRecord = function() return mr(H.mr_create(nil)) end,
      createGroupHeader = function(desc)
        local r = mr(H.mr_create(nil)); r.IsGroupHeader = true; if desc then r.Description = desc end; return r
      end,
      getSelectedRecords = selected,
      setSelectedRecord = function(r) H.al_select(r and { r.ID } or {}) end,
      clearSelection = function() H.al_select({}) end,
      rebuildDescriptionCache = function() end,
      disableAllWithoutExecute = function()
        for _, id in ipairs(ids()) do setactive(id, false, true) end
      end },
    function(i) return mr(ids()[i + 1]) end)
  return al
end
function getTableEntry(d) return getAddressList().getMemoryRecordByDescription(d) end

-------------------------------------------------------------------- process / memory helpers
function getThreadlist(list)
  local out = list or createStringlist()
  out.clear()
  for _, tid in ipairs(H.threads()) do out.add(sformat('%X', tid)) end
  return out
end
function translate(s) return s end

-------------------------------------------------------------------- AA / symbol / structure hooks
-- Registered callbacks, in registration order: { id, f } lists (commands by lowercase name).
-- Rust gets a mirror of what is registered (H.hooks_sync) and calls the dispatchers in
-- `HOOKS` (registry `hh_hooks`).
local aacmds, aapro, symlk, addrlk, stov, stnm = {}, {}, {}, {}, {}, {}
local hookid = 0
local function hooksync()
  local names = {}
  for n in pairs(aacmds) do names[#names + 1] = n end
  H.hooks_sync(names, #aapro, #symlk, #addrlk, #stov, #stnm)
end
local function addhook(list, f)
  if type(f) ~= 'function' then error('a function is required', 3) end
  hookid = hookid + 1
  list[#list + 1] = { hookid, f }
  hooksync()
  return hookid
end
local function delhook(list, id)
  for i, e in ipairs(list) do
    if e[1] == id or e[2] == id then table.remove(list, i); hooksync(); return true end
  end
  return false
end

-- registerAutoAssemblerCommand(name, function(parameters, syntaxcheckonly)): the function
-- returns the replacement text, or nil and an error message.
function registerAutoAssemblerCommand(name, f)
  if type(f) ~= 'function' then error('registerAutoAssemblerCommand: a function is required', 2) end
  aacmds[tostring(name):lower()] = f
  hooksync()
end
function unregisterAutoAssemblerCommand(name)
  aacmds[tostring(name):lower()] = nil
  hooksync()
end
-- registerAutoAssemblerPrologue(function(script, syntaxcheck), postAOB): script is a
-- TStrings the function may change. (postAOB is ignored: prologues run before the script.)
function registerAutoAssemblerPrologue(f) return addhook(aapro, f) end
function unregisterAutoAssemblerPrologue(id) return delhook(aapro, id) end
-- registerSymbolLookupCallback(function(name): address, location): asked when nothing else
-- knows a name (every location counts as slFailure in HeapHook).
slStart, slNotInt, slNotModule, slNotUserdefinedSymbol, slNotSymbol, slFailure = 0, 1, 2, 3, 4, 5
function registerSymbolLookupCallback(f) return addhook(symlk, f) end
function unregisterSymbolLookupCallback(id) return delhook(symlk, id) end
-- registerAddressLookupCallback(function(address): name)
function registerAddressLookupCallback(f) return addhook(addrlk, f) end
function unregisterAddressLookupCallback(id) return delhook(addrlk, id) end
-- registerStructureDissectOverride(function(structure, baseaddress): handled)
function registerStructureDissectOverride(f) return addhook(stov, f) end
function unregisterStructureDissectOverride(id) return delhook(stov, id) end
-- registerStructureNameLookup(function(address): name, newaddress)
function registerStructureNameLookup(f) return addhook(stnm, f) end
function unregisterStructureNameLookup(id) return delhook(stnm, id) end

local HOOKS = {}
function HOOKS.command(name, args, check)
  local f = aacmds[name]
  if not f then return nil end
  local r, err = f(args, check)
  if r == nil and err ~= nil then error(tostring(err), 0) end
  return r ~= nil and tostring(r) or ''
end
function HOOKS.prologue(script, check)
  for _, e in ipairs(aapro) do
    local sl = stringlist(splitlines(script))
    e[2](sl, check)
    script = sl.Text
  end
  return script
end
function HOOKS.symbol(name)
  for _, e in ipairs(symlk) do
    local a = e[2](name)
    if a ~= nil then return a end
  end
end
function HOOKS.address(a)
  for _, e in ipairs(addrlk) do
    local n = e[2](a)
    if n ~= nil then return tostring(n) end
  end
end
local structoverride -- set with the structures
function HOOKS.structoverride(a, size) return structoverride(a, size) end
function HOOKS.structname(a)
  for _, e in ipairs(stnm) do
    local n, na = e[2](a)
    if n ~= nil then return tostring(n), na end
  end
end

-------------------------------------------------------------------- structures
local structobj = {}
local structure

-- Bit fields and arrays are HeapHook element properties: BitOffset / BitLength (a field of an
-- integer element, bits counted from the least significant; set BitLength first) and ArrayCount (the element
-- repeats back to back; getValue(base, index) reads element `index`).
local function element(sid, uid)
  local function g(k) return function() return H.st_elem_get(sid, uid, k) end end
  local function s(k) return function(v) H.st_elem_set(sid, uid, k, v) end end
  return object(
    { Owner = function() return structure(sid) end, Offset = g 'Offset', Name = g 'Name', Vartype = g 'Vartype',
      Bytesize = g 'Bytesize', DisplayMethod = g 'DisplayMethod', Index = function() return H.st_index_of(sid, uid) end,
      ChildStruct = function()
        local n = H.st_elem_get(sid, uid, 'ChildStruct')
        local gi = n and H.st_find(n)
        return gi and structure(H.st_global(gi)) or nil
      end,
      ChildStructStart = g 'ChildStructStart', BitOffset = g 'BitOffset', BitLength = g 'BitLength',
      ArrayCount = g 'ArrayCount' },
    { Offset = s 'Offset', Name = s 'Name', Vartype = s 'Vartype', Bytesize = s 'Bytesize', DisplayMethod = s 'DisplayMethod',
      ChildStruct = function(v) H.st_elem_set(sid, uid, 'ChildStruct', v and v.Name) end,
      ChildStructStart = s 'ChildStructStart', BitOffset = s 'BitOffset', BitLength = s 'BitLength',
      ArrayCount = s 'ArrayCount' },
    { getValue = function(a, i) return H.st_elem_value(sid, uid, a, i) end,
      setValue = function(a, v, i) return H.st_elem_setvalue(sid, uid, a, v, i) end,
      getValueFromBase = function(a, i) return H.st_elem_value(sid, uid, a, i) end,
      setValueFromBase = function(a, v, i) return H.st_elem_setvalue(sid, uid, a, v, i) end,
      destroy = function() H.st_elem_del(sid, uid) end })
end

structure = function(sid)
  if structobj[sid] then return structobj[sid] end
  local function el(i) local uid = H.st_uid_at(sid, toint(i)); return uid and element(sid, uid) or nil end
  local s
  s = object(
    { Name = function() return H.st_get(sid, 'Name') end, Size = function() return H.st_get(sid, 'Size') end,
      Count = function() return H.st_get(sid, 'Count') end, Element = function() return indexed(el) end },
    { Name = function(v) H.st_set_name(sid, tostring(v)) end },
    { getElement = el,
      addElement = function() return element(sid, H.st_add(sid)) end,
      getElementByOffset = function(o) local uid = H.st_uid_by_offset(sid, toint(o)); return uid and element(sid, uid) or nil end,
      -- registerStructureDissectOverride functions get the first try (with the guessed
      -- address); one returning true took care of it.
      autoGuess = function(base, off, size)
        local a = getAddress(base) + toint(off or 0)
        for _, e in ipairs(stov) do
          if e[2](s, a) then return end
        end
        H.st_autoguess(sid, base, off, size)
      end,
      fillFromDotNetAddress = function() error('not supported in HeapHook: fillFromDotNetAddress (mono/.NET inspection needs an injected data collector)', 2) end,
      addToGlobalStructureList = function() H.st_global_set(sid, true) end,
      removeFromGlobalStructureList = function() H.st_global_set(sid, false) end,
      beginUpdate = function() end, endUpdate = function() end,
      destroy = function() H.st_destroy(sid); structobj[sid] = nil end })
  rawset(s, '__hh_sid', sid)
  structobj[sid] = s
  return s
end

-- For Engine::structure_override: a scratch structure the first override that returns true
-- filled (its id; the engine takes it over), or nil.
structoverride = function(a, size)
  for _, e in ipairs(stov) do
    local sid = H.st_new('')
    local ok, r = pcall(e[2], structure(sid), a)
    if ok and r then structobj[sid] = nil; return sid end
    H.st_destroy(sid); structobj[sid] = nil
    if not ok then error(r, 0) end
  end
end

function createStructure(name) return structure(H.st_new(tostring(name or 'unnamed structure'))) end
function getStructureCount() return H.st_count() end
function getStructure(i) local sid = H.st_global(toint(i)); return sid and structure(sid) or nil end

-------------------------------------------------------------------- dissect code
local dc
function getDissectCode()
  if dc then return dc end
  dc = object({}, nil,
    { dissect = function(a, size) return H.dc_dissect(a, size) end,
      clear = function() H.dc_clear() end,
      getReferences = function(a) return H.dc_refs(a) end,
      getReferencedStrings = function() return H.dc_strings() end,
      getReferencedFunctions = function() return H.dc_funcs() end,
      saveToFile = function(f) return H.dc_save(f) end, loadFromFile = function(f) return H.dc_load(f) end,
      -- HeapHook: functions that ran an instruction of every `ran` address set and none of
      -- the `notRan` sets (code filter without tracing)
      codeFilter = function(ran, notRan) return H.dc_filter(ran, notRan) end,
      destroy = function() end })
  return dc
end

-------------------------------------------------------------------- pointer scan (HeapHook)
-- hhCreatePointerScan(options): HeapHook's own background pointer scan (Cheat Engine has no
-- stable Lua API for it). options: target (address, required), maxLevel, maxOffset,
-- allowNegative, staticOnly, baseModules, threadStacks, stackMax, noLoops, maxChildren,
-- lastOffsets, endsWith, startsWith, allowedOffsets, heapOnly, maxResults (default 100000),
-- threads (0 = all cores), stopAtStatic, timeLimit (seconds), alignment, writableOnly.
-- Object: getProgress() -> {Done, Total, Found, Paused, Cancelled, Finished}, isDone(),
-- waitTillDone(ms) -> count or nil on timeout, getResults(offset, limit) -> {{Base,
-- BaseOffset, Offsets, Text, Address, Value}}, Count, pause(), resume(), cancel(), destroy().
function hhCreatePointerScan(opts)
  if type(opts) ~= 'table' then error('hhCreatePointerScan: an options table is required', 2) end
  local id = H.ps_start(opts)
  local count
  return object(
    { Count = function() count = count or H.ps_wait(id); return count end, ID = function() return id end },
    nil,
    { getProgress = function() return H.ps_progress(id) end,
      isDone = function() return H.ps_done(id) end,
      waitTillDone = function(ms) local n = H.ps_wait(id, ms); if n then count = n end; return n end,
      getResults = function(offset, limit) return H.ps_results(id, offset, limit) end,
      pause = function() H.ps_pause(id) end, resume = function() H.ps_resume(id) end,
      cancel = function() H.ps_cancel(id) end,
      destroy = function() H.ps_free(id) end })
end

-------------------------------------------------------------------- debugger
local bpfuncs = {}

function debugProcess(interface) H.dbg_start(interface or 0); return true end
function debug_isDebugging() return H.dbg_is() end
function debug_canBreak() return H.dbg_is() end
function debug_isBroken() return H.dbg_broken() end
function debug_updateGUI() end
function debug_breakThread(tid) H.dbg_break(toint(tid)) end
function debug_getContext() return H.dbg_getctx() end
function debug_setContext() return H.dbg_setctx() end
function debug_continueFromBreakpoint(how) return H.dbg_continue(how or co_run) end
-- debug_setBreakpoint(address, size, trigger, method, function) -- every argument after the
-- address is optional, and the function may come earlier: (address, function).
function debug_setBreakpoint(address, ...)
  local a, fn = { ... }, nil
  for i = 1, 4 do
    if type(a[i]) == 'function' then fn = a[i]; for j = i, 4 do a[j] = nil end break end
  end
  local addr = getAddress(address)
  H.dbg_set(addr, a[1], a[2], a[3])
  bpfuncs[addr] = fn
  return true
end
function debug_removeBreakpoint(address)
  local addr = getAddress(address)
  bpfuncs[addr] = nil
  return H.dbg_remove(addr)
end
function debug_getBreakpointList() return H.dbg_list() end

-------------------------------------------------------------------- forms
-- Controls live in Rust (H.ui_*); these objects are views. Unknown properties are stored
-- (in the tree when they are plain values, here otherwise) and read back.
local uiobj = {}      -- id -> object
local uicls = {}      -- id -> class
local uievents = {}   -- id -> { OnClick = f, ... }
local uiextra = {}    -- id -> values a property cannot hold
local uiref = {}      -- id -> { prop = control object }
local uiowner = {}    -- id -> owner object
local menuroot = {}   -- menu id -> its root TMenuItem object
local mainform
local ui

isui = function(v)
  if type(v) ~= 'table' then return false end
  local id = rawget(v, '__id')
  return id ~= nil and uiobj[id] == v
end

local COMMON = { Left = 0, Top = 0, Visible = true, Enabled = true, Name = '' }
local NOGEOM = { TMainMenu = true, TPopupMenu = true, TMenuItem = true }
local DEFAULTS = {
  TCEForm = { Width = 320, Height = 240, Caption = '', Position = 0, BorderStyle = 2, ModalResult = 0 },
  TMainForm = { Width = 800, Height = 600, Caption = 'HeapHook' },
  TButton = { Width = 75, Height = 25, Caption = '', ModalResult = 0 },
  TLabel = { Width = 30, Height = 15, Caption = '', AutoSize = true },
  TEdit = { Width = 120, Height = 23, Text = '', ReadOnly = false },
  TMemo = { Width = 150, Height = 90, Lines = {}, ReadOnly = false, WordWrap = true },
  TCheckBox = { Width = 90, Height = 19, Caption = '', Checked = false, State = 0 },
  TToggleBox = { Width = 75, Height = 25, Caption = '', Checked = false },
  TRadioGroup = { Width = 185, Height = 105, Caption = '', Items = {}, ItemIndex = -1, Columns = 1 },
  TListBox = { Width = 100, Height = 80, Items = {}, ItemIndex = -1, MultiSelect = false },
  TComboBox = { Width = 100, Height = 23, Items = {}, ItemIndex = -1, Text = '', Style = 0 },
  TPanel = { Width = 185, Height = 41, Caption = '' },
  TGroupBox = { Width = 185, Height = 105, Caption = '' },
  TImage = { Width = 90, Height = 90, Stretch = false, Picture = '' },
  TProgressBar = { Width = 100, Height = 20, Min = 0, Max = 100, Position = 0, Step = 10 },
  TTrackBar = { Width = 100, Height = 25, Min = 0, Max = 10, Position = 0 },
  TSplitter = { Width = 5, Height = 100 },
  TScrollBox = { Width = 150, Height = 150 },
  TTabControl = { Width = 200, Height = 150, Tabs = {}, TabIndex = -1 },
  TPageControl = { Width = 200, Height = 150, ActivePageIndex = -1 },
  TTabSheet = { Caption = '' },
  TMenuItem = { Caption = '', Checked = false, Shortcut = 0, AutoCheck = false },
}
local TEXTKEY = { TEdit = 'Text', TComboBox = 'Text' }

local function alias(cls, k)
  if k == 'Caption' or k == 'Text' then return TEXTKEY[cls] or 'Caption' end
  if k == 'ClientWidth' then return 'Width' end
  if k == 'ClientHeight' then return 'Height' end
  return k
end

local function fire(o, id, ev, ...)
  local f = uievents[id] and uievents[id][ev]
  if f then return f(o, ...) end
end

-- What a changed property triggers (LCL fires these for changes by code too).
local function onchanged(o, id, cls, key, user)
  local ev
  if key == 'Checked' and (cls == 'TCheckBox' or cls == 'TToggleBox') then
    H.ui_set(id, 'State', H.ui_get(id, 'Checked') and 1 or 0)
    ev = 'OnChange'
  elseif key == 'Text' and (cls == 'TEdit' or cls == 'TComboBox') then ev = 'OnChange'
  elseif key == 'Lines' and cls == 'TMemo' then ev = 'OnChange'
  elseif key == 'ItemIndex' then
    if cls == 'TComboBox' then
      local items, i = H.ui_get(id, 'Items') or {}, toint(H.ui_get(id, 'ItemIndex'))
      H.ui_set(id, 'Text', items[i + 1] or '', true)
      ev = 'OnChange'
    elseif cls == 'TListBox' then ev = 'OnSelectionChange'
    elseif cls == 'TRadioGroup' then ev = 'OnClick' end
  elseif key == 'Position' and cls == 'TTrackBar' then ev = 'OnChange'
  elseif key == 'TabIndex' or key == 'ActivePageIndex' then ev = 'OnChange' end
  if ev then fire(o, id, ev) end
  if user and key == 'Checked' and (cls == 'TCheckBox' or cls == 'TToggleBox') then fire(o, id, 'OnClick') end
end

local function islist(v)
  local n = 0
  for _, x in pairs(v) do
    n = n + 1
    if type(x) ~= 'string' and type(x) ~= 'number' then return false end
  end
  return n == #v
end

local function uidestroy(id)
  local o = uiobj[id]
  if not o then return end
  if uievents[id] and uievents[id].OnDestroy then uievents[id].OnDestroy(o) end
  for _, gone in ipairs(H.ui_destroy(id)) do
    for t in pairs(ownedTimers[gone] or {}) do t.destroy() end
    ownedTimers[gone], uiobj[gone], uicls[gone], uievents[gone] = nil, nil, nil, nil
    uiextra[gone], uiref[gone], uiowner[gone], menuroot[gone] = nil, nil, nil, nil
    if mainform and rawget(mainform, '__id') == gone then mainform = nil end
  end
end

local function closeform(o, id)
  local action = caHide
  local f = uievents[id] and uievents[id].OnClose
  if f then
    local r = f(o)
    if r ~= nil then action = toint(r) end
  end
  if action == caFree then uidestroy(id)
  elseif action == caMinimize then H.ui_set(id, 'WindowState', 1)
  elseif action ~= caNone then o.Visible = false end
  return action
end

local function children(id)
  local t = {}
  for i, c in ipairs(H.ui_children(id)) do t[i] = ui(c) end
  return t
end

local function newcontrol(cls, owner, extra)
  local props = {}
  if not NOGEOM[cls] then for k, v in pairs(COMMON) do props[k] = v end end
  for k, v in pairs(DEFAULTS[cls] or {}) do props[k] = v end
  for k, v in pairs(extra or {}) do props[k] = v end
  local pid = isui(owner) and rawget(owner, '__id') or nil
  local id = H.ui_create(cls, pid, props)
  local o = ui(id, cls)
  uiowner[id] = owner
  return o
end

local function fontobj(id)
  local DEF = { Name = 'default', Size = 9, Color = clDefault, Style = '[]', Height = -12 }
  return setmetatable({}, {
    __index = function(_, k)
      local v = H.ui_get(id, 'Font.' .. k)
      if v == nil then return DEF[k] end
      return v
    end,
    __newindex = function(_, k, v) H.ui_set(id, 'Font.' .. k, v) end,
  })
end

local function menuitems(id)
  return indexed(function(i) return children(id)[toint(i) + 1] end)
end

-- Methods by class ('*' = every control). Each gets (o, id, ...).
local METHODS = {
  ['*'] = {
    show = function(o, id)
      if not H.ui_get(id, 'Visible') then H.ui_set(id, 'Visible', true); fire(o, id, 'OnShow') end
      H.ui_call(id, 'bringToFront')
    end,
    hide = function(o, id) if H.ui_get(id, 'Visible') then H.ui_set(id, 'Visible', false); fire(o, id, 'OnHide') end end,
    close = function(o, id) return closeform(o, id) end,
    showModal = function(o, id)
      -- shortcut: no nested event loop (events are delivered by the host between engine
      -- calls), so showModal shows the form and returns its current ModalResult.
      o.show()
      H.ui_call(id, 'showModal')
      return toint(H.ui_get(id, 'ModalResult'))
    end,
    centerScreen = function(o, id)
      local w, h = H.ui_screen()
      H.ui_set(id, 'Left', (w - toint(H.ui_get(id, 'Width'))) // 2)
      H.ui_set(id, 'Top', (h - toint(H.ui_get(id, 'Height'))) // 2)
    end,
    destroy = function(o, id) uidestroy(id) end,
    free = function(o, id) uidestroy(id) end,
    release = function(o, id) uidestroy(id) end,
    bringToFront = function(o, id) H.ui_call(id, 'bringToFront') end,
    sendToBack = function(o, id) H.ui_call(id, 'sendToBack') end,
    setFocus = function(o, id) H.ui_call(id, 'setFocus') end,
    repaint = function(o, id) H.ui_call(id, 'repaint') end,
    refresh = function(o, id) H.ui_call(id, 'repaint') end,
    update = function(o, id) H.ui_call(id, 'repaint') end,
    invalidate = function(o, id) H.ui_call(id, 'repaint') end,
    beginUpdate = function() end, endUpdate = function() end,
    setPosition = function(o, id, x, y) H.ui_set(id, 'Left', toint(x)); H.ui_set(id, 'Top', toint(y)) end,
    getPosition = function(o, id) return H.ui_get(id, 'Left'), H.ui_get(id, 'Top') end,
    setSize = function(o, id, w, h) H.ui_set(id, 'Width', toint(w)); H.ui_set(id, 'Height', toint(h)) end,
    getSize = function(o, id) return H.ui_get(id, 'Width'), H.ui_get(id, 'Height') end,
    doClick = function(o, id) return fire(o, id, 'OnClick') end,
    click = function(o, id) return fire(o, id, 'OnClick') end,
  },
  TEdit = { clear = function(o) o.Text = '' end, selectAll = function() end },
  TComboBox = { clear = function(o, id) H.ui_set(id, 'Items', {}); o.ItemIndex = -1; o.Text = '' end },
  TListBox = { clear = function(o, id) H.ui_set(id, 'Items', {}); o.ItemIndex = -1 end },
  TMemo = { clear = function(o) o.Lines.clear() end, append = function(o, id, s) o.Lines.add(s) end },
  TProgressBar = {
    stepIt = function(o, id) o.Position = math.min(toint(o.Max), toint(o.Position) + toint(o.Step)) end,
    stepBy = function(o, id, n) o.Position = math.min(toint(o.Max), toint(o.Position) + toint(n)) end,
  },
  TPageControl = {
    addTab = function(o, id) return newcontrol('TTabSheet', o) end,
  },
  TMenuItem = {
    add = function(o, id, item) H.ui_parent(rawget(item, '__id'), id) end,
    insert = function(o, id, _, item) H.ui_parent(rawget(item, '__id'), id) end,
    delete = function(o, id, i) local c = children(id)[toint(i) + 1]; if c then uidestroy(rawget(c, '__id')) end end,
    clear = function(o, id) for _, c in ipairs(children(id)) do uidestroy(rawget(c, '__id')) end end,
    indexOf = function(o, id, item) for i, c in ipairs(children(id)) do if c == item then return i - 1 end end return -1 end,
  },
  TPopupMenu = { popup = function(o, id, x, y) H.ui_call(id, 'popup', x, y) end },
}
METHODS.TRadioGroup = { clear = METHODS.TListBox.clear }

-- Properties that are not plain values. Getter returns (true, value) when it applies.
local SPECIAL_GET = {
  ClassName = function(o, id, cls) return true, cls end,
  Handle = function(o, id) return true, id end,
  Owner = function(o, id) return true, uiowner[id] end,
  Parent = function(o, id) local p = H.ui_parentof(id); return true, p and ui(p) or nil end,
  Font = function(o, id) return true, fontobj(id) end,
  ControlCount = function(o, id) return true, #H.ui_children(id) end,
  ComponentCount = function(o, id) return true, #H.ui_children(id) end,
  Control = function(o, id) return true, indexed(function(i) return children(id)[toint(i) + 1] end) end,
  Component = function(o, id) return true, indexed(function(i) return children(id)[toint(i) + 1] end) end,
  Items = function(o, id, cls)
    if cls == 'TMainMenu' or cls == 'TPopupMenu' then return true, menuroot[id] end
    if cls == 'TMenuItem' then return true, menuitems(id) end
    return true, boundlist(function() return H.ui_get(id, 'Items') end, function(t) H.ui_set(id, 'Items', t) end)
  end,
  Tabs = function(o, id)
    return true, boundlist(function() return H.ui_get(id, 'Tabs') end, function(t) H.ui_set(id, 'Tabs', t) end)
  end,
  Lines = function(o, id, cls)
    if cls ~= 'TMemo' then return false end
    return true, boundlist(function() return H.ui_get(id, 'Lines') end, function(t)
      if H.ui_set(id, 'Lines', t) then onchanged(o, id, cls, 'Lines', false) end
    end)
  end,
  Text = function(o, id, cls)
    if cls ~= 'TMemo' then return false end
    local t = H.ui_get(id, 'Lines') or {}
    return true, #t == 0 and '' or tconcat(t, '\n') .. '\n'
  end,
  Count = function(o, id, cls) if cls == 'TMenuItem' then return true, #H.ui_children(id) end return false end,
  Item = function(o, id, cls) if cls == 'TMenuItem' then return true, menuitems(id) end return false end,
  Picture = function(o, id, cls)
    if cls ~= 'TImage' then return false end
    return true, object({ FileName = function() return H.ui_get(id, 'Picture') end }, nil,
      { loadFromFile = function(f) H.ui_set(id, 'Picture', tostring(f)) end,
        clear = function() H.ui_set(id, 'Picture', '') end,
        loadFromStream = function() error('not implemented yet: Picture.loadFromStream', 2) end })
  end,
}

local SPECIAL_SET = {
  Parent = function(o, id, cls, v) H.ui_parent(id, isui(v) and rawget(v, '__id') or nil); return true end,
  Text = function(o, id, cls, v)
    if cls ~= 'TMemo' then return false end
    if H.ui_set(id, 'Lines', splitlines(v)) then onchanged(o, id, cls, 'Lines', false) end
    return true
  end,
  Lines = function(o, id, cls, v)
    if cls ~= 'TMemo' then return false end
    if type(v) == 'table' and not islist(v) then local t = {} for i = 0, v.Count - 1 do t[#t + 1] = v[i] end v = t end
    if H.ui_set(id, 'Lines', v) then onchanged(o, id, cls, 'Lines', false) end
    return true
  end,
  Items = function(o, id, cls, v)
    if type(v) == 'table' and not islist(v) and rawget(v, 'getString') then
      local t = {} for i = 0, v.Count - 1 do t[#t + 1] = v[i] end
      H.ui_set(id, 'Items', t)
      return true
    end
    return false
  end,
}

ui = function(id, cls)
  if id == nil then return nil end
  if uiobj[id] then return uiobj[id] end
  cls = cls or H.ui_class(id)
  if not cls then return nil end
  local o = { __id = id }
  uicls[id] = cls
  uievents[id], uiextra[id], uiref[id] = {}, {}, {}
  local cm, all = METHODS[cls] or {}, METHODS['*']
  setmetatable(o, {
    __index = function(_, k)
      local m = cm[k] or all[k]
      if m then
        local bound = method(o, function(...) return m(o, id, ...) end)
        rawset(o, k, bound)
        return bound
      end
      if type(k) ~= 'string' then return nil end
      local sp = SPECIAL_GET[k]
      if sp then
        local hit, v = sp(o, id, cls)
        if hit then return v end
      end
      if k:sub(1, 2) == 'On' then return uievents[id] and uievents[id][k] end
      local x = uiextra[id] and uiextra[id][k]
      if x ~= nil then return x end
      local r = uiref[id] and uiref[id][k]
      if r ~= nil then return r end
      local v = H.ui_get(id, alias(cls, k))
      if v ~= nil then return v end
      local p = k:match('^get(%u.*)$')
      if p then return function() return o[p] end end
      p = k:match('^set(%u.*)$')
      if p then return function(a, b) if rawequal(a, o) then o[p] = b else o[p] = a end end end
      return nil
    end,
    __newindex = function(_, k, v)
      if not uiobj[id] then error('control was destroyed', 2) end
      if type(k) ~= 'string' then rawset(o, k, v) return end
      if k:sub(1, 2) == 'On' and (type(v) == 'function' or v == nil) then
        uievents[id][k] = v
        H.ui_event(id, k, v ~= nil)
        return
      end
      local sp = SPECIAL_SET[k]
      if sp and sp(o, id, cls, v) then return end
      if isui(v) then
        uiref[id][k] = v
        uiextra[id][k] = nil
        H.ui_set(id, k, rawget(v, '__id'))
        return
      end
      if type(v) == 'function' or type(v) == 'userdata' or type(v) == 'thread' or (type(v) == 'table' and not islist(v)) then
        uiextra[id][k] = v
        return
      end
      uiextra[id][k], uiref[id][k] = nil, nil
      local key = alias(cls, k)
      if H.ui_set(id, key, v) then onchanged(o, id, cls, key, false) end
    end,
    __tostring = function() return cls .. ' ' .. id end,
  })
  uiobj[id] = o
  return o
end

function createForm(visible) return newcontrol('TCEForm', nil, { Visible = visible ~= false }) end
for name, cls in pairs({ createButton = 'TButton', createLabel = 'TLabel', createEdit = 'TEdit', createMemo = 'TMemo',
  createCheckBox = 'TCheckBox', createToggleBox = 'TToggleBox', createRadioGroup = 'TRadioGroup',
  createListBox = 'TListBox', createComboBox = 'TComboBox', createPanel = 'TPanel', createGroupBox = 'TGroupBox',
  createImage = 'TImage', createProgressBar = 'TProgressBar', createTrackBar = 'TTrackBar',
  createSplitter = 'TSplitter', createScrollBox = 'TScrollBox', createTabControl = 'TTabControl',
  createPageControl = 'TPageControl' }) do
  _G[name] = function(owner) return newcontrol(cls, owner) end
end
function createMainMenu(form)
  local m = newcontrol('TMainMenu', form)
  menuroot[rawget(m, '__id')] = newcontrol('TMenuItem', m)
  if isui(form) then form.Menu = m end
  return m
end
function createPopupMenu(owner)
  local m = newcontrol('TPopupMenu', owner)
  menuroot[rawget(m, '__id')] = newcontrol('TMenuItem', m)
  return m
end
function createMenuItem(menu) return newcontrol('TMenuItem', nil) end

function getMainForm()
  if not mainform then mainform = newcontrol('TMainForm', nil) end
  return mainform
end
local function forms()
  local t = {}
  for _, id in ipairs(H.ui_children(nil)) do
    local c = H.ui_class(id)
    if c == 'TCEForm' or c == 'TMainForm' then t[#t + 1] = ui(id) end
  end
  return t
end
function getFormCount() return #forms() end
function getForm(i) return forms()[toint(i) + 1] end
function getScreenWidth() return (H.ui_screen()) end
function getScreenHeight() return select(2, H.ui_screen()) end

local app
function getApplication()
  if app then return app end
  app = object({ MainForm = function() return getMainForm() end }, nil,
    { processMessages = function() end, minimize = function() end, bringToFront = function() end,
      terminate = function() error('not supported in HeapHook: Application.terminate (scripts cannot close HeapHook)', 2) end })
  rawset(app, 'Title', 'HeapHook')
  return app
end

-------------------------------------------------------------------- host entry points
local I = {}
I.mr = mr
I.hooks = HOOKS
I.setactive = setactive
I.rechotkey = rechotkey
function I.xcall(f, ...) return xpcall(f, traceback, ...) end

local function check_abort()
  local m = aborted()
  if m then error(m, 0) end
end

function I.tick()
  local errs, t = {}, now()
  local list = {}
  for tm, st in pairs(timers) do list[#list + 1] = { tm, st } end
  for _, e in ipairs(list) do
    local tm, st = e[1], e[2]
    if timers[tm] and st.enabled and st.ontimer and t >= st.due then
      st.due = t + st.interval
      local ok, err = xpcall(st.ontimer, traceback, tm)
      check_abort()
      if not ok then errs[#errs + 1] = 'timer: ' .. tostring(err) end
    end
  end
  list = {}
  for th, st in pairs(threads) do list[#list + 1] = { th, st } end
  for _, e in ipairs(list) do
    if now() >= e[2].wake then
      local err = step(e[1], e[2])
      check_abort()
      if err then errs[#errs + 1] = err end
    end
  end
  -- OnValueChanged(memrec, oldvalue, newvalue)
  list = {}
  for id, c in pairs(cbs) do if c.OnValueChanged then list[#list + 1] = id end end
  for _, id in ipairs(list) do
    local f, v = cbs[id] and cbs[id].OnValueChanged, H.mr_get(id, 'Value')
    if f and v ~= nil and H.mr_trusted(id) then
      local old = lastval[id]
      lastval[id] = v
      if old ~= nil and old ~= v then
        local ok, err = xpcall(f, traceback, mr(id), old, v)
        check_abort()
        if not ok then errs[#errs + 1] = 'OnValueChanged: ' .. tostring(err) end
      end
    end
  end
  return errs
end

function I.hotkey(id)
  local h = hotkeys[id]
  if h and h[2].f then h[2].f(h[1]) end
end

function I.uievent(id, ev, ...)
  local o = uiobj[id]
  if not o then return end
  if ev == 'OnClose' then return closeform(o, id) end
  if ev == 'OnClick' and uicls[id] == 'TMenuItem' and H.ui_get(id, 'AutoCheck') then
    H.ui_set(id, 'Checked', not H.ui_get(id, 'Checked'))
  end
  return fire(o, id, ev, ...)
end

function I.uiinput(id, prop, v)
  local o = uiobj[id]
  if not o then return end
  local cls = uicls[id]
  local key = alias(cls, prop)
  if cls == 'TMemo' and key == 'Caption' then key, v = 'Lines', splitlines(v) end
  if H.ui_set(id, key, v, false) then onchanged(o, id, cls, key, true) end
end

function I.breakpoint(addr)
  local f = bpfuncs[addr] or rawget(_G, 'debugger_onBreakpoint')
  if not f then return false end
  return f()
end

-- quiet: consent was withdrawn, so none of the table's Lua runs once more (no OnDestroy).
function I.clear(quiet)
  local errs = {}
  local function try(f, ...)
    local ok, err = xpcall(f, traceback, ...)
    check_abort()
    if not ok then errs[#errs + 1] = tostring(err) end
  end
  for id, c in pairs(cbs) do
    if c.OnDestroy and not quiet and H.mr_trusted(id) then try(c.OnDestroy, recs[id] or mr(id)) end
  end
  cbs, lastval, hkcbs = {}, {}, {}
  for k in pairs(recs) do recs[k] = nil end
  for k in pairs(rhks) do rhks[k] = nil end
  for tm, st in pairs(timers) do st.enabled = false; timers[tm] = nil end
  for th, st in pairs(threads) do st.terminated, st.finished = true, true; threads[th] = nil end
  for id in pairs(hotkeys) do H.hotkey_unregister(id) end
  hotkeys = {}
  for _, id in ipairs(H.ui_children(nil)) do
    if quiet then uievents[id] = nil end
    if uiobj[id] then try(uidestroy, id) else H.ui_destroy(id) end
  end
  H.dbg_clear()
  bpfuncs = {}
  for id in pairs(myscans) do H.ms_free(id) end
  myscans = {}
  aacmds, aapro, symlk, addrlk, stov, stnm = {}, {}, {}, {}, {}, {}
  hooksync()
  H.ext_clear()
  if #errs > 0 then error(tconcat(errs, '\n'), 0) end
end

return I
