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

 #ifdef _USRDLL
    #define DLLEXPORT __declspec(dllexport)
 #else
    #define DLLEXPORT __declspec(dllimport)
 #endif

EXTERN_C_START

DLLEXPORT BOOL WINAPI InvokeCompilerPassW(int, wchar_t**, int, HMODULE*);
DLLEXPORT void WINAPI AbortCompilerPass(int);

EXTERN_C_END
