#include "winhttp_api.h"

// LoadLibraryExW is exported by KernelBase but hidden by the phone partition.
typedef HMODULE (WINAPI *PFN_LoadLibraryExW)(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags);

// Returns the base address of the module containing the given address
static HMODULE GetBaseAddress(const void* address)
{
    MEMORY_BASIC_INFORMATION mbi = {};
    if (!VirtualQuery(address, &mbi, sizeof(mbi)))
        return nullptr;
    if (*reinterpret_cast<WORD*>(mbi.AllocationBase) != IMAGE_DOS_SIGNATURE)
        return nullptr;
    return reinterpret_cast<HMODULE>(mbi.AllocationBase);
}

template <typename T>
static bool Resolve(HMODULE module, const char* name, T* fn, const char** missing)
{
    *fn = reinterpret_cast<T>(GetProcAddress(module, name));
    if (!*fn)
        *missing = name;
    return *fn != nullptr;
}

bool LoadWinHttp(WinHttpApi* api, const char** missing)
{
    *missing = "LoadLibraryExW";
    HMODULE kernelBase = GetBaseAddress(reinterpret_cast<void*>(&::DisableThreadLibraryCalls));
    if (!kernelBase)
        return false;

    PFN_LoadLibraryExW pLoadLibraryExW =
        reinterpret_cast<PFN_LoadLibraryExW>(GetProcAddress(kernelBase, "LoadLibraryExW"));
    if (!pLoadLibraryExW)
        return false;

    // Kept loaded for the lifetime of the process
    *missing = "winhttp.dll";
    HMODULE winhttp = pLoadLibraryExW(L"winhttp.dll", nullptr, 0);
    if (!winhttp)
        return false;

    return Resolve(winhttp, "WinHttpCrackUrl",          &api->CrackUrl,          missing)
        && Resolve(winhttp, "WinHttpOpen",              &api->Open,              missing)
        && Resolve(winhttp, "WinHttpConnect",           &api->Connect,           missing)
        && Resolve(winhttp, "WinHttpOpenRequest",       &api->OpenRequest,       missing)
        && Resolve(winhttp, "WinHttpSetOption",         &api->SetOption,         missing)
        && Resolve(winhttp, "WinHttpSetTimeouts",       &api->SetTimeouts,       missing)
        && Resolve(winhttp, "WinHttpSetStatusCallback", &api->SetStatusCallback, missing)
        && Resolve(winhttp, "WinHttpAddRequestHeaders", &api->AddRequestHeaders, missing)
        && Resolve(winhttp, "WinHttpSendRequest",       &api->SendRequest,       missing)
        && Resolve(winhttp, "WinHttpWriteData",         &api->WriteData,         missing)
        && Resolve(winhttp, "WinHttpReceiveResponse",   &api->ReceiveResponse,   missing)
        && Resolve(winhttp, "WinHttpQueryHeaders",      &api->QueryHeaders,      missing)
        && Resolve(winhttp, "WinHttpReadData",          &api->ReadData,          missing)
        && Resolve(winhttp, "WinHttpCloseHandle",       &api->CloseHandle,       missing);
}
