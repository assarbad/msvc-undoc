///////////////////////////////////////////////////////////////////////////////
///
/// 2023 Oliver Schneider (assarbad.net) under the terms of the UNLICENSE
///
/// Based on http://blog.airesoft.co.uk/2013/01/plug-in-to-cls-kitchen/ and
/// subsequent own research.
///////////////////////////////////////////////////////////////////////////////

#include <Windows.h>
#include <cstdio>
#include <tchar.h>

EXTERN_C_START

__declspec(dllexport) BOOL WINAPI InvokeCompilerPassW(int argc, wchar_t** argv, int unk, HMODULE* phCLUIMod)
{
    _ftprintf(stderr, _T("[%hs] argc = %i\n"), __FUNCTION__, argc);
    for (int idx = 0; idx < argc; idx++)
    {
        _ftprintf(stderr, _T("[%hs] idx=%i: '%s'\n"), __FUNCTION__, idx, argv[idx]);
    }
    return TRUE;
}

__declspec(dllexport) void WINAPI AbortCompilerPass(int how)
{
    _ftprintf(stderr, _T("[%hs] how = %i\n"), __FUNCTION__, how);
}

BOOL WINAPI DllMain(HINSTANCE, DWORD /*fdwReason*/, LPVOID /*lpvReserved*/)
{
#if 0
    // Perform actions based on the reason for calling.
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        // Initialize once for each new process.
        // Return FALSE to fail DLL load.
        break;

    case DLL_THREAD_ATTACH:
        // Do thread-specific initialization.
        break;

    case DLL_THREAD_DETACH:
        // Do thread-specific cleanup.
        break;

    case DLL_PROCESS_DETACH:

        if (lpvReserved != nullptr)
        {
            break; // do not do cleanup if process termination scenario
        }

        // Perform any necessary cleanup.
        break;
    }
#endif
    return TRUE;
}

EXTERN_C_END
