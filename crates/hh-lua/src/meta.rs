//! Library metatables, locked before any script runs, and the file finalizer.
//!
//! Lua 5.3 runs a `__gc` it finds in a metatable when the object is collected (and when the
//! state is closed), with hooks off: no time budget, no interrupt. The prelude's
//! `setmetatable` refuses `__gc` for tables a script makes, but metatables the libraries
//! made are reachable too: `getmetatable(io.stdout)` (the `FILE*` metatable, whose `__index`
//! is the metatable itself) and `getmetatable("")`. So every metatable a script can reach
//! is hardened here: `__metatable = false` (`getmetatable` returns false, `setmetatable` on
//! such a value errors) and an `__index` that is not the metatable itself.
//!
//! Which metatables exist in a fresh state: the registry's `luaL_newmetatable` ones (the
//! `__name` field: `FILE*` from io; mlua's userdata metatables, already locked by mlua) and
//! the type-wide ones (only strings have one; nil, booleans, numbers, functions, threads and
//! light userdata have none, and without `debug.setmetatable` a script cannot add one).

use mlua::{ffi, Lua};
use std::ffi::{c_int, c_void};
use std::sync::atomic::{AtomicUsize, Ordering};

/// liolib's `FILE*` finalizer (the same function in every state), captured at the first lock.
static FILE_GC: AtomicUsize = AtomicUsize::new(0);

/// `luaL_Stream` (lauxlib.h): the `FILE*` userdata.
#[repr(C)]
struct Stream {
    f: *mut c_void,
    closef: Option<ffi::lua_CFunction>,
}

/// Hardens every metatable a script can reach (see the module comment). Runs at interpreter
/// creation, before any script; engine code only.
pub(crate) fn lock(lua: &Lua) -> mlua::Result<()> {
    // SAFETY: inside mlua's protected call, stack balanced; only engine code runs here.
    unsafe {
        lua.exec_raw::<()>((), |l| {
            let top = ffi::lua_gettop(l);
            ffi::lua_pushstring(l, c"FILE*".as_ptr());
            if ffi::lua_rawget(l, ffi::LUA_REGISTRYINDEX) == ffi::LUA_TTABLE {
                ffi::lua_pushstring(l, c"__gc".as_ptr());
                ffi::lua_rawget(l, -2);
                if let Some(f) = ffi::lua_tocfunction(l, -1) {
                    let _ = FILE_GC.compare_exchange(0, f as usize, Ordering::SeqCst, Ordering::SeqCst);
                }
            }
            ffi::lua_settop(l, top);
            // The registry's named metatables.
            ffi::lua_pushnil(l);
            while ffi::lua_next(l, ffi::LUA_REGISTRYINDEX) != 0 {
                if ffi::lua_type(l, -1) == ffi::LUA_TTABLE {
                    ffi::lua_pushstring(l, c"__name".as_ptr());
                    let named = ffi::lua_rawget(l, -2) != ffi::LUA_TNIL;
                    ffi::lua_pop(l, 1);
                    if named {
                        harden(l, ffi::lua_gettop(l));
                    }
                }
                ffi::lua_pop(l, 1);
            }
            // Type-wide metatables: a string, nil, a boolean, a number, a C function, a thread,
            // a light userdata.
            ffi::lua_pushstring(l, c"".as_ptr());
            ffi::lua_pushnil(l);
            ffi::lua_pushboolean(l, 0);
            ffi::lua_pushinteger(l, 0);
            ffi::lua_pushcfunction(l, file_gc_nowait);
            ffi::lua_pushthread(l);
            ffi::lua_pushlightuserdata(l, std::ptr::null_mut());
            for i in top + 1..=top + 7 {
                if ffi::lua_getmetatable(l, i) != 0 {
                    harden(l, ffi::lua_gettop(l));
                    ffi::lua_pop(l, 1);
                }
            }
            ffi::lua_settop(l, top);
        })
    }
}

/// `__metatable = false`, and an `__index` that is not the metatable itself (liolib's is):
/// the methods, copied into a table of their own.
unsafe fn harden(l: *mut ffi::lua_State, mt: c_int) {
    unsafe {
        ffi::lua_pushstring(l, c"__index".as_ptr());
        ffi::lua_rawget(l, mt);
        let selfref = ffi::lua_rawequal(l, -1, mt) != 0;
        ffi::lua_pop(l, 1);
        if selfref {
            ffi::lua_newtable(l);
            let methods = ffi::lua_gettop(l);
            ffi::lua_pushnil(l);
            while ffi::lua_next(l, mt) != 0 {
                // Methods only: no `__gc`, `__index`, `__name`, ...
                let method = ffi::lua_type(l, -2) == ffi::LUA_TSTRING && {
                    let k = std::ffi::CStr::from_ptr(ffi::lua_tostring(l, -2));
                    !k.to_bytes().starts_with(b"__")
                };
                if method {
                    ffi::lua_pushvalue(l, -2);
                    ffi::lua_insert(l, -2);
                    ffi::lua_rawset(l, methods);
                } else {
                    ffi::lua_pop(l, 1);
                }
            }
            ffi::lua_pushstring(l, c"__index".as_ptr());
            ffi::lua_insert(l, -2);
            ffi::lua_rawset(l, mt);
        }
        ffi::lua_pushstring(l, c"__metatable".as_ptr());
        ffi::lua_rawget(l, mt);
        let locked = ffi::lua_type(l, -1) != ffi::LUA_TNIL;
        ffi::lua_pop(l, 1);
        if !locked {
            ffi::lua_pushstring(l, c"__metatable".as_ptr());
            ffi::lua_pushboolean(l, 0);
            ffi::lua_rawset(l, mt);
        }
    }
}

/// True when no metatable a script could have reached has a Lua function as `__gc`, and the
/// `FILE*` one is liolib's closer, [`file_gc_nowait`] or none. Raw reads only (no call, no
/// allocation, no hook): safe on a state being discarded. False means hostile: never close it.
pub(crate) fn finalizers_intact(lua: &Lua) -> bool {
    let orig = FILE_GC.load(Ordering::SeqCst);
    // SAFETY: raw reads with a balanced stack; nothing here can raise an error.
    lua.exec_raw_lua(|raw| unsafe {
        let l = raw.state();
        if ffi::lua_checkstack(l, 4) == 0 {
            return false;
        }
        let top = ffi::lua_gettop(l);
        let mut ok = true;
        ffi::lua_pushnil(l);
        while ffi::lua_next(l, ffi::LUA_REGISTRYINDEX) != 0 {
            // Named metatables only (`luaL_newmetatable`): the registry also holds `_G`.
            let named = ffi::lua_type(l, -1) == ffi::LUA_TTABLE && {
                ffi::lua_pushstring(l, c"__name".as_ptr());
                let n = ffi::lua_rawget(l, -2) != ffi::LUA_TNIL;
                ffi::lua_pop(l, 1);
                n
            };
            if named {
                ffi::lua_pushstring(l, c"__gc".as_ptr());
                match ffi::lua_rawget(l, -2) {
                    ffi::LUA_TNIL => {}
                    ffi::LUA_TFUNCTION if ffi::lua_iscfunction(l, -1) != 0 => {
                        // The FILE* metatable: only liolib's closer or ours.
                        ffi::lua_pushstring(l, c"__name".as_ptr());
                        ffi::lua_rawget(l, -3);
                        let file = ffi::lua_type(l, -1) == ffi::LUA_TSTRING && std::ffi::CStr::from_ptr(ffi::lua_tostring(l, -1)) == c"FILE*";
                        ffi::lua_pop(l, 1);
                        if file {
                            let f = ffi::lua_tocfunction(l, -1).map_or(0, |f| f as usize);
                            ok &= f == orig || f == file_gc_nowait as ffi::lua_CFunction as usize;
                        }
                    }
                    _ => ok = false,
                }
                ffi::lua_pop(l, 1);
            }
            ffi::lua_pop(l, 1);
        }
        ffi::lua_pushstring(l, c"".as_ptr());
        if ffi::lua_getmetatable(l, -1) != 0 {
            ffi::lua_pushstring(l, c"__gc".as_ptr());
            ok &= ffi::lua_rawget(l, -2) == ffi::LUA_TNIL;
        }
        ffi::lua_settop(l, top);
        ok
    })
}

/// For a clean interpreter about to be closed: files are closed (and flushed) as usual, but
/// a pipe from `io.popen` is left open and its child is not waited for (`pclose` would block
/// the close until the program exits). Raw writes to an existing key: no allocation.
pub(crate) fn no_wait(lua: &Lua) {
    // SAFETY: balanced stack; sets an existing key of the FILE* metatable to a C function.
    lua.exec_raw_lua(|raw| unsafe {
        let l = raw.state();
        if ffi::lua_checkstack(l, 3) == 0 {
            return;
        }
        let top = ffi::lua_gettop(l);
        ffi::lua_pushstring(l, c"FILE*".as_ptr());
        if ffi::lua_rawget(l, ffi::LUA_REGISTRYINDEX) == ffi::LUA_TTABLE {
            ffi::lua_pushstring(l, c"__gc".as_ptr());
            if ffi::lua_rawget(l, -2) != ffi::LUA_TNIL {
                ffi::lua_pop(l, 1);
                ffi::lua_pushstring(l, c"__gc".as_ptr());
                ffi::lua_pushcfunction(l, file_gc_nowait);
                ffi::lua_rawset(l, -3);
            }
        }
        ffi::lua_settop(l, top);
    })
}

/// liolib's finalizer, except for pipes and sockets: those are marked closed and left open
/// (the descriptor, and an `io.popen` child's zombie, are leaked until HeapHook exits).
/// shortcut: a FIFO opened with `io.open` is treated as a pipe too (not flushed), since
/// liolib's `io_pclose` is static and cannot be told apart otherwise.
unsafe extern "C-unwind" fn file_gc_nowait(l: *mut ffi::lua_State) -> c_int {
    unsafe {
        let p = ffi::luaL_testudata(l, 1, c"FILE*".as_ptr()) as *mut Stream;
        if p.is_null() || (*p).closef.is_none() || (*p).f.is_null() {
            return 0;
        }
        #[cfg(unix)]
        {
            let fd = libc::fileno((*p).f as *mut libc::FILE);
            let mut st: libc::stat = std::mem::zeroed();
            if fd >= 0 && libc::fstat(fd, &mut st) == 0 {
                let kind = st.st_mode & libc::S_IFMT;
                if kind == libc::S_IFIFO || kind == libc::S_IFSOCK {
                    (*p).closef = None;
                    return 0;
                }
            }
        }
        match FILE_GC.load(Ordering::SeqCst) {
            0 => 0,
            // SAFETY: the address of liolib's `lua_CFunction` finalizer, captured in `lock`.
            f => std::mem::transmute::<usize, ffi::lua_CFunction>(f)(l),
        }
    }
}
