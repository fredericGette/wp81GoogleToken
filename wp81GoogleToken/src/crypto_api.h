#pragma once

#include <windows.h>

// ─── CNG (BCrypt) declarations ───────────────────────────────────────────────
// The WP8.1 SDK ships bcrypt.h but hides almost all of it behind the desktop
// partition, although mincore.lib imports these functions from the phone's
// bcrypt.dll. Only what wp81GoogleToken uses is declared here, with the values
// of the desktop Windows 8.1 bcrypt.h.

#ifndef _NTDEF_
typedef LONG NTSTATUS;
#endif

typedef PVOID BCRYPT_ALG_HANDLE;
typedef PVOID BCRYPT_KEY_HANDLE;
typedef PVOID BCRYPT_HASH_HANDLE;

#define BCRYPT_SUCCESS(status)       ((status) >= 0)

#define BCRYPT_RSA_ALGORITHM         L"RSA"
#define BCRYPT_SHA256_ALGORITHM      L"SHA256"
#define BCRYPT_RSAPRIVATE_BLOB       L"RSAPRIVATEBLOB"
#define BCRYPT_RSAPRIVATE_MAGIC      0x32415352   // "RSA2"
#define BCRYPT_PAD_PKCS1             0x00000002

// Followed by PublicExponent, Modulus, Prime1, Prime2, all big-endian
typedef struct
{
    ULONG Magic;
    ULONG BitLength;
    ULONG cbPublicExp;
    ULONG cbModulus;
    ULONG cbPrime1;
    ULONG cbPrime2;
} BCRYPT_RSAKEY_BLOB;

typedef struct
{
    LPCWSTR pszAlgId;
} BCRYPT_PKCS1_PADDING_INFO;

extern "C"
{
__declspec(dllimport) NTSTATUS WINAPI BCryptOpenAlgorithmProvider(BCRYPT_ALG_HANDLE* phAlgorithm, LPCWSTR pszAlgId,
                                                                  LPCWSTR pszImplementation, ULONG dwFlags);
__declspec(dllimport) NTSTATUS WINAPI BCryptCloseAlgorithmProvider(BCRYPT_ALG_HANDLE hAlgorithm, ULONG dwFlags);

__declspec(dllimport) NTSTATUS WINAPI BCryptImportKeyPair(BCRYPT_ALG_HANDLE hAlgorithm, BCRYPT_KEY_HANDLE hImportKey,
                                                          LPCWSTR pszBlobType, BCRYPT_KEY_HANDLE* phKey,
                                                          PUCHAR pbInput, ULONG cbInput, ULONG dwFlags);
__declspec(dllimport) NTSTATUS WINAPI BCryptDestroyKey(BCRYPT_KEY_HANDLE hKey);

__declspec(dllimport) NTSTATUS WINAPI BCryptCreateHash(BCRYPT_ALG_HANDLE hAlgorithm, BCRYPT_HASH_HANDLE* phHash,
                                                       PUCHAR pbHashObject, ULONG cbHashObject, PUCHAR pbSecret,
                                                       ULONG cbSecret, ULONG dwFlags);
__declspec(dllimport) NTSTATUS WINAPI BCryptHashData(BCRYPT_HASH_HANDLE hHash, PUCHAR pbInput, ULONG cbInput,
                                                     ULONG dwFlags);
__declspec(dllimport) NTSTATUS WINAPI BCryptFinishHash(BCRYPT_HASH_HANDLE hHash, PUCHAR pbOutput, ULONG cbOutput,
                                                       ULONG dwFlags);
__declspec(dllimport) NTSTATUS WINAPI BCryptDestroyHash(BCRYPT_HASH_HANDLE hHash);

__declspec(dllimport) NTSTATUS WINAPI BCryptSignHash(BCRYPT_KEY_HANDLE hKey, VOID* pPaddingInfo, PUCHAR pbInput,
                                                     ULONG cbInput, PUCHAR pbOutput, ULONG cbOutput,
                                                     ULONG* pcbResult, ULONG dwFlags);
}
