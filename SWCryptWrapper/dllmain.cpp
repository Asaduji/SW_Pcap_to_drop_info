#include <Windows.h>
#include "ISWCrypt.hpp"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    if (ul_reason_for_call != DLL_PROCESS_ATTACH) {
        return TRUE;
    }

    auto dll = LoadLibraryW(L"SWCrypt.dll");

    if (dll == NULL) {
        return TRUE;
    }

    auto create_crypt = GetProcAddress(dll, "CreateSWCrypt");

    if (create_crypt == NULL) {
        return TRUE;
    }

    ISWCrypt::s_pSingleton = reinterpret_cast<ISWCrypt*>(create_crypt());

    return TRUE;
}

extern "C" __declspec(dllexport) void Decrypt(uint8_t * packet, int32_t size, int32_t keyIndex) {
    if (ISWCrypt::s_pSingleton == nullptr) {
        return;
    }

    ISWCrypt::s_pSingleton->Decrypt(packet, size, keyIndex);
}
