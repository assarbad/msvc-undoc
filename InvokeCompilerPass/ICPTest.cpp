///////////////////////////////////////////////////////////////////////////////
///
/// 2023 Oliver Schneider (assarbad.net) under the terms of the UNLICENSE
///
/// SPDX-License-Identifier: Unlicense
///
///////////////////////////////////////////////////////////////////////////////

#include <Windows.h>
#include <cstdlib>
#include <cstdio>
#include "InvokeCompilerPass.h"

int wmain(int argc, wchar_t** argv)
{
    wprintf(L"DLL: %s\n", GetThisDllName());
    wprintf(L"Process: %s\n", GetThisProcessImageName());
    HMODULE hMod = nullptr;
    if (InvokeCompilerPassW(argc, argv, -1, &hMod))
    {
        return EXIT_SUCCESS;
    }
    return EXIT_FAILURE;
}
