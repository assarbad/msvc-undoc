///////////////////////////////////////////////////////////////////////////////
///
/// 2023 Oliver Schneider (assarbad.net) under the terms of the UNLICENSE
///
/// Based on http://blog.airesoft.co.uk/2013/01/plug-in-to-cls-kitchen/ and
/// subsequent own research.
///
/// SPDX-License-Identifier: Unlicense
///
///////////////////////////////////////////////////////////////////////////////

#include <Windows.h>
#include <string.h>
#include <tchar.h>
#include "LuaBridge.h"
#include "dllversion.h"
#ifndef GIT_COMMIT
#    error No Git commit set
#endif // !GIT_COMMIT
#include <fmt/format.h>
#include <fmt/xchar.h>
#include "ntpebldr.h"
#include "InvokeCompilerPass.h"

namespace
{
    namespace impl
    {
        // The technical maximum is 0x7FFF, but we add one as zero-terminator, just in case we happen to stumble upon an excessively long string
        // ... because we won't access this much as UNICODE_STRING and more as a wchar_t* ...
        constexpr USHORT MAX_US_WCHARS = 0x7FFF;
        constexpr USHORT MAX_US_WCHARS_PLUS_SAFETY = MAX_US_WCHARS + 1;
        static WCHAR ThisDllNameBuffer[MAX_US_WCHARS_PLUS_SAFETY]{};
        static WCHAR ThisProcessImageNameBuffer[MAX_US_WCHARS_PLUS_SAFETY]{};
        static UNICODE_STRING usThisDllName{0, MAX_US_WCHARS, &ThisDllNameBuffer[0]};
        static UNICODE_STRING usThisProcessImageName{0, MAX_US_WCHARS, &ThisProcessImageNameBuffer[0]};
    } // namespace impl
    static WCHAR const* lpwcThisDllName = &impl::ThisDllNameBuffer[0];
    static WCHAR const* lpwcThisProcessImageName = &impl::ThisProcessImageNameBuffer[0];
    static UNICODE_STRING const& usThisDllName = impl::usThisDllName;
    static UNICODE_STRING const& usThisProcessImageName = impl::usThisProcessImageName;
} // namespace

BOOL CopyFullDllName(NT::LDR_DATA_TABLE_ENTRY const* LdrDataEntry, UNICODE_STRING& usDestination)
{
    if (LdrDataEntry && LdrDataEntry->FullDllName.Buffer)
    {
        UNICODE_STRING const& usFullDllName = LdrDataEntry->FullDllName;
        if (usDestination.MaximumLength < usFullDllName.Length)
        {
            return FALSE;
        }
        (void)RtlMoveMemory(usDestination.Buffer, usFullDllName.Buffer, usFullDllName.Length);
        usDestination.Length = usFullDllName.Length;
        return TRUE;
    }
    return FALSE;
}

EXTERN_C_START

#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"

LPCWSTR WINAPI GetThisDllName()
{
    return lpwcThisDllName;
}

LPCWSTR WINAPI GetThisProcessImageName()
{
    return lpwcThisProcessImageName;
}

BOOL WINAPI InvokeCompilerPassW(int argc, wchar_t** argv, int unk, HMODULE* phCLUIMod)
{
#if 1
    _ftprintf(stderr, _T("[%hs] argc = %i\n"), __FUNCTION__, argc);
    for (int idx = 0; idx < argc; idx++)
    {
        _ftprintf(stderr, _T("[%hs] idx=%i: '%s'\n"), __FUNCTION__, idx, argv[idx]);
    }
    return TRUE;
#endif // 1
}

void WINAPI AbortCompilerPass(int how)
{
#if 1
    _ftprintf(stderr, _T("[%hs] how = %i\n"), __FUNCTION__, how);
#endif // 1
}

thread_local lua_State* lua = nullptr;
thread_local lua_CFunction old_panic = nullptr;

int panic(lua_State* L)
{
    auto const message = fmt::format(L"Lua panicked at {}.", fmt::ptr(L));
    ::OutputDebugStringW(message.c_str());
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hThisDll, DWORD fdwReason, LPVOID lpvReserved)
{
    // Perform actions based on the reason for calling.
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        {
            // We hold the loader lock, so it's safe to peek into the PEB without fear for something "going away"
            auto const* LdrDataEntryThisDll = NT::GetLdrDataEntryByModule(hThisDll);
            if (!CopyFullDllName(LdrDataEntryThisDll, impl::usThisDllName))
            {
                ::OutputDebugStringW(L"Failed to retrieve module name of current DLL during DllMain.");
                return FALSE;
            }
            auto const* LdrDataEntryThisProcessImage = NT::GetLdrDataEntryByLoadOrderIndex(0);
            if (!CopyFullDllName(LdrDataEntryThisProcessImage, impl::usThisProcessImageName))
            {
                ::OutputDebugStringW(L"Failed to retrieve module name of current process image during DllMain.");
                return FALSE;
            }
        }
        break;

    case DLL_THREAD_ATTACH:
        // Do thread-specific initialization.
        lua = luaL_newstate();
        old_panic = lua_atpanic(lua, panic);
        luaL_openlibs(lua);
        break;

    case DLL_THREAD_DETACH:
        // Do thread-specific cleanup.
        lua_close(lua);
        lua = nullptr;
        break;

    case DLL_PROCESS_DETACH:

        if (lpvReserved != nullptr)
        {
            break; // do not do cleanup if process termination scenario
        }

        // Perform any necessary cleanup.
        break;
    }
    return TRUE;
}

EXTERN_C_END
