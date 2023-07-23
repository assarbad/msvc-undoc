///////////////////////////////////////////////////////////////////////////////
///
/// 2023 Oliver Schneider (assarbad.net) under the terms of the UNLICENSE
///
///////////////////////////////////////////////////////////////////////////////
#ifndef __DLLVERSION_H_VER__
#define __DLLVERSION_H_VER__ 2023072321

#if defined(_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
#endif

// ---------------------------------------------------------------------------
// Several defines have to be given before including this file. These are:
// ---------------------------------------------------------------------------
#define TEXT_AUTHOR        Oliver Schneider  // author (optional value)
#define PRD_MAJVER         0                 // major product version
#define PRD_MINVER         1                 // minor product version
#define PRD_PATCH          0                 // patch number
#define PRD_BUILD          0                 // build number for product
#define FILE_MAJVER        PRD_MAJVER        // major file version
#define FILE_MINVER        PRD_MINVER        // minor file version
#define FILE_PATCH         PRD_PATCH         // patch number
#define FILE_BUILD         PRD_BUILD         // build number

// clang-format off
#define DLL_YEAR           2023   // current year or timespan (e.g. 2003-2007)
#define TEXT_WEBSITE       https:/##/assarbad.net // website
// clang-format on

#define TEXT_PRODUCTNAME   InvokeCompilerPass                       // product's name
#define TEXT_FILEDESC      DLL to research InvokeCompilerPassW of MSVC // component description
#define TEXT_COMPANY       Oliver Schneider (assarbad.net)          // company
#define TEXT_MODULE        InvokeCompilerPass                       // module name
#define TEXT_COPYRIGHT     Copyright \x00a9 DLL_YEAR TEXT_AUTHOR    // copyright information
#define TEXT_INTERNALNAME  InvokeCompilerPass.dll

#define _ANSISTRING(text) #text
#define ANSISTRING(text)  _ANSISTRING(text)

#define _WIDESTRING(text) L##text
#define WIDESTRING(text)  _WIDESTRING(text)

#define PRESET_UNICODE_STRING(symbol, buffer) \
    UNICODE_STRING symbol = {                 \
        sizeof(WIDESTRING(buffer)) - sizeof(WCHAR), sizeof(WIDESTRING(buffer)), WIDESTRING(buffer)};

#define CREATE_XVER(maj, min, patch, build) maj##, ##min##, ##patch##, ##build
#define CREATE_FVER(maj, min, patch, build) maj##.##min##.##patch##.##build
#define CREATE_PVER(maj, min, patch, build) maj##.##min##.##patch

#endif // __DLLVERSION_H_VER__
