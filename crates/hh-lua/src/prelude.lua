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
  for k, f in pairs(H) do if k ~= 'errtext' and k ~= 'traceback' then H[k] = wrap(f, 0) end end
end

-------------------------------------------------------------------- OS policy
os.exit = function() error('os.exit is disabled in HeapHook', 2) end
if not allow_os then
  io = nil
  os.execute, os.remove, os.rename, os.getenv, os.tmpname = nil, nil, nil, nil, nil
  dofile, loadfile = nil, nil
  if package then
    package.searchers = { package.searchers[1] }
    package.loadlib = nil
  end
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

-------------------------------------------------------------------- string list
local function stringlist(items)
  local s = items or {}
  return object(
    { Count = function() return #s end, Text = function() return tconcat(s, '\n') end,
      String = function() return indexed(function(i) return s[i + 1] end, function(i, v) s[i + 1] = tostring(v) end) end },
    nil,
    { add = function(v) s[#s + 1] = tostring(v); return #s - 1 end,
      getString = function(i) return s[i + 1] end,
      setString = function(i, v) s[i + 1] = tostring(v) end,
      delete = function(i) table.remove(s, i + 1) end,
      indexOf = function(v) for i, x in ipairs(s) do if x == v then return i - 1 end end return -1 end,
      clear = function() s = {} end,
      destroy = function() end },
    function(i) return s[i + 1] end)
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
function createMemScan()
  local id = H.ms_new()
  local st = {}
  local ms
  local function done() if st.ondone then st.ondone(ms) end end
  ms = object(
    { FoundCount = function() return H.ms_count(id) end, OnScanDone = function() return st.ondone end },
    { OnScanDone = function(f) st.ondone = f end },
    { firstScan = function(...) H.ms_first(id, ...); done() end,
      nextScan = function(...) H.ms_next(id, ...); done() end,
      newScan = function() H.ms_newscan(id) end,
      waitTillDone = function() end,
      getAttachedFoundlist = function() return st.fl end,
      destroy = function() H.ms_free(id) end })
  rawset(ms, '__hh_id', id)
  rawset(ms, '__hh_st', st)
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
      destroy = function() count = 0 end })
  rawget(ms, '__hh_st').fl = fl
  return fl
end

-------------------------------------------------------------------- timers
local timers = {}
local now = H.now

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
      OnTimer = function() return st.ontimer end },
    { Interval = function(v) st.interval = math.max(1, toint(v)); st.due = now() + st.interval end,
      Enabled = function(v) st.enabled = v and true or false; st.due = now() + st.interval end,
      OnTimer = function(f) st.ontimer = f end },
    { destroy = function() timers[t] = nil; st.enabled = false end })
  st.due = now() + st.interval
  timers[t] = st
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

-------------------------------------------------------------------- hotkeys
local hotkeys, hkid = {}, 0
function createHotkey(f, ...)
  local keys = { ... }
  if type(keys[1]) == 'table' then keys = keys[1] end
  hkid = hkid + 1
  local id, st = hkid, { f = f }
  local hk = object(
    { ID = function() return id end, OnHotkey = function() return st.f end },
    { OnHotkey = function(v) st.f = v end },
    { destroy = function() hotkeys[id] = nil; H.hotkey_unregister(id) end })
  hotkeys[id] = { hk, st }
  H.hotkey_register(id, keys)
  return hk
end

-------------------------------------------------------------------- memory records
local recs = setmetatable({}, { __mode = 'v' })
local cbs = {}
local setactive

local function mr(id)
  if id == nil then return nil end
  local o = recs[id]
  if o then return o end
  local function g(k) return function() return H.mr_get(id, k) end end
  local function s(k) return function(v) H.mr_set(id, k, v) end end
  local function cb(name) return function() return cbs[id] and cbs[id][name] end end
  local function setcb(name) return function(f) cbs[id] = cbs[id] or {}; cbs[id][name] = f end end
  local function offsets() return H.mr_get(id, 'Offsets') or {} end
  o = object(
    { ID = function() return id end, Description = g 'Description', Address = g 'Address', Type = g 'Type',
      Value = g 'Value', Script = g 'Script', Color = g 'Color', Active = g 'Active',
      CurrentAddress = g 'CurrentAddress', ShowAsHex = g 'ShowAsHex', ShowAsSigned = g 'ShowAsSigned',
      OffsetCount = function() return #offsets() end,
      Offset = function()
        return indexed(function(i) return offsets()[i + 1] end,
          function(i, v) local t = offsets(); t[i + 1] = v; H.mr_set(id, 'Offsets', t) end)
      end,
      Count = function() return #(H.mr_get(id, 'Children') or {}) end,
      Child = function() return indexed(function(i) return mr((H.mr_get(id, 'Children') or {})[i + 1]) end) end,
      Parent = function() return mr(H.mr_get(id, 'Parent')) end,
      OnActivate = cb 'OnActivate', OnDeactivate = cb 'OnDeactivate',
      String = function() return object({ Size = g 'StringSize', Unicode = g 'Unicode' }, { Size = s 'StringSize', Unicode = s 'Unicode' }) end,
      Aob = function() return object({ Size = g 'AobSize' }, { Size = s 'AobSize' }) end },
    { Description = s 'Description', Address = s 'Address', Type = s 'Type', Value = s 'Value',
      Script = s 'Script', Color = s 'Color', ShowAsHex = s 'ShowAsHex', ShowAsSigned = s 'ShowAsSigned',
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
      OnActivate = setcb 'OnActivate', OnDeactivate = setcb 'OnDeactivate' },
    { delete = function() H.mr_delete(id); recs[id] = nil; cbs[id] = nil end,
      destroy = function() H.mr_delete(id); recs[id] = nil; cbs[id] = nil end,
      appendToEntry = function(p) H.mr_set(id, 'Parent', p and p.ID) end,
      disableWithoutExecute = function() setactive(id, false, true) end })
  recs[id] = o
  return o
end

-- OnActivate/OnDeactivate(memrec, before, currentstate): returning false before aborts.
setactive = function(id, v, noexec)
  local cur = H.mr_get(id, 'Active')
  if cur == nil then return false, 'memory record was deleted' end
  if cur == v then return true end
  local name = v and 'OnActivate' or 'OnDeactivate'
  local f = cbs[id] and cbs[id][name]
  local rec = mr(id)
  if f and f(rec, true, cur) == false then return false end
  local ok, err = H.mr_apply(id, v, not noexec)
  if f then f(rec, false, H.mr_get(id, 'Active')) end
  return ok, err
end

local al
function getAddressList()
  if al then return al end
  local ids = H.mr_ids
  al = object(
    { Count = function() return #ids() end,
      MemoryRecord = function() return indexed(function(i) return mr(ids()[i + 1]) end) end,
      SelectedRecord = function() return nil end },
    nil,
    { getMemoryRecord = function(i) return mr(ids()[i + 1]) end,
      getMemoryRecordByDescription = function(d)
        for _, id in ipairs(ids()) do if H.mr_get(id, 'Description') == d then return mr(id) end end
      end,
      getMemoryRecordByID = function(want)
        for _, id in ipairs(ids()) do if id == want then return mr(id) end end
      end,
      createMemoryRecord = function() return mr(H.mr_create(nil)) end,
      disableAllWithoutExecute = function()
        for _, id in ipairs(ids()) do setactive(id, false, true) end
      end },
    function(i) return mr(ids()[i + 1]) end)
  return al
end
function getTableEntry(d) return getAddressList().getMemoryRecordByDescription(d) end

-------------------------------------------------------------------- host entry points
local I = {}
I.mr = mr
I.setactive = setactive
function I.xcall(f, ...) return xpcall(f, traceback, ...) end

function I.tick()
  local errs, t = {}, now()
  local list = {}
  for tm, st in pairs(timers) do list[#list + 1] = { tm, st } end
  for _, e in ipairs(list) do
    local tm, st = e[1], e[2]
    if timers[tm] and st.enabled and st.ontimer and t >= st.due then
      st.due = t + st.interval
      local ok, err = xpcall(st.ontimer, traceback, tm)
      if not ok then errs[#errs + 1] = 'timer: ' .. tostring(err) end
    end
  end
  list = {}
  for th, st in pairs(threads) do list[#list + 1] = { th, st } end
  for _, e in ipairs(list) do
    if now() >= e[2].wake then
      local err = step(e[1], e[2])
      if err then errs[#errs + 1] = err end
    end
  end
  return errs
end

function I.hotkey(id)
  local h = hotkeys[id]
  if h and h[2].f then h[2].f(h[1]) end
end

return I
