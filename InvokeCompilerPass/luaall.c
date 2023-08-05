// SPDX-License-Identifier: Unlicense
#pragma warning(push)
#pragma warning(disable : 4244)
#pragma warning(disable : 4267)
#pragma warning(disable : 4310)
#pragma warning(disable : 4324)
#pragma warning(disable : 4334)
#pragma warning(disable : 4701)
#pragma warning(disable : 4702)
#pragma warning(disable : 4996)
// #include "lua/onelua.c"
#define MAKE_LIB // just in case this is used somewhere in the included files

#include "lprefix.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <float.h>
#include <limits.h>
#include <locale.h>
#include <math.h>
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* setup for luaconf.h */
#define LUA_CORE
#define LUA_LIB
#define ltable_c
#define lvm_c
#include "luaconf.h"

/* do not export internal symbols */
#undef LUAI_FUNC
#undef LUAI_DDEC
#undef LUAI_DDEF
#define LUAI_FUNC      static
#define LUAI_DDEC(def) /* empty */
#define LUAI_DDEF      static

/* core -- used by all */
#include "lzio.c"
#include "lctype.c"
#include "lopcodes.c"
#include "lmem.c"
#include "lundump.c"
#include "ldump.c"
#include "lstate.c"
#include "lgc.c"
#include "llex.c"
#include "lcode.c"
#include "lparser.c"
#include "ldebug.c"
#include "lfunc.c"
#include "lobject.c"
#include "ltm.c"
#include "lstring.c"
#include "ltable.c"
#include "ldo.c"
#include "lvm.c"
#include "lapi.c"

/* auxiliary library -- used by all */
#include "lauxlib.c"

/* standard library  -- not used by luac */
#include "lbaselib.c"
// #include "lcorolib.c"
#include "ldblib.c"
#include "liolib.c"
#include "lmathlib.c"
// #include "loadlib.c"
// #include "loslib.c"
#include "lstrlib.c"
#include "ltablib.c"
#include "lutf8lib.c"
// #include "linit.c"
static const luaL_Reg loadedlibs[] = {{LUA_GNAME, luaopen_base},
                                      {LUA_TABLIBNAME, luaopen_table},
                                      {LUA_IOLIBNAME, luaopen_io},
                                      {LUA_STRLIBNAME, luaopen_string},
                                      {LUA_MATHLIBNAME, luaopen_math},
                                      {LUA_UTF8LIBNAME, luaopen_utf8},
                                      {LUA_DBLIBNAME, luaopen_debug},
                                      {NULL, NULL}};

LUALIB_API void luaL_openlibs(lua_State* L)
{
    const luaL_Reg* lib;
    /* "require" functions from 'loadedlibs' and set results to global table */
    for (lib = loadedlibs; lib->func; lib++)
    {
        luaL_requiref(L, lib->name, lib->func, 1);
        lua_pop(L, 1); /* remove lib */
    }
}
#pragma warning(pop)
