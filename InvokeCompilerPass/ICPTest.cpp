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
#define PEBSTUFF 0

#if PEBSTUFF
#define NTPEBLDR_PRINT_FUNCS
#include "ntpebldr.h"

using NT::PebLdrOrder;

NTSTATUS CALLBACK printcb(NT::LDR_DATA_TABLE_ENTRY_CTX const& ldrctx, NT::LDR_DATA_TABLE_ENTRY const*, ULONG&)
{
    print_ldr_entry_ctx(ldrctx);
    return STATUS_NOT_FOUND;
}

template <PebLdrOrder order_v = PebLdrOrder::load> void showPebLdrData()
{
    ULONG ctx{};
    NT::IteratePebLdrDataTable<ULONG, order_v>(printcb, ctx);

}
#endif // PEBSTUFF

int wmain(int argc, wchar_t** argv)
{
#if PEBSTUFF

    auto* pebldr = NT::GetPebLdr();
    if (pebldr)
    {
        NT::print_ldr_data(*pebldr);
        showPebLdrData();
    }
#endif // PEBSTUFF

    HMODULE hMod = nullptr;
    if (InvokeCompilerPassW(argc, argv, -1, &hMod))
    {
        return EXIT_SUCCESS;
    }
    return EXIT_FAILURE;
}
