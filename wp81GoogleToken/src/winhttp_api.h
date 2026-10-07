#pragma once

#include <windows.h>

// ─── WinHTTP declarations ────────────────────────────────────────────────────
// The WP8.1 SDK has neither winhttp.h nor winhttp.lib, although the phone
// ships C:\Windows\System32\winhttp.dll (WinHTTP 6.3, same as desktop 8.1).
// Copied from wp81Curl: only what it uses is declared here, with the values of the desktop
// Windows 8.1 winhttp.h. The functions are resolved at run time (LoadWinHttp).

typedef LPVOID HINTERNET;
typedef WORD   INTERNET_PORT;
typedef int    INTERNET_SCHEME;

#define INTERNET_SCHEME_HTTP                    1
#define INTERNET_SCHEME_HTTPS                   2

#define WINHTTP_ACCESS_TYPE_DEFAULT_PROXY       0
#define WINHTTP_FLAG_SECURE                     0x00800000
#define WINHTTP_FLAG_ESCAPE_DISABLE             0x00000040
#define WINHTTP_FLAG_ESCAPE_DISABLE_QUERY       0x00000080

#define WINHTTP_ADDREQ_FLAG_ADD                 0x20000000
#define WINHTTP_ADDREQ_FLAG_REPLACE             0x80000000

#define WINHTTP_QUERY_STATUS_CODE               19
#define WINHTTP_QUERY_RAW_HEADERS_CRLF          22
#define WINHTTP_QUERY_FLAG_NUMBER               0x20000000

#define WINHTTP_OPTION_SECURITY_FLAGS           31
#define WINHTTP_OPTION_DISABLE_FEATURE          63
#define WINHTTP_OPTION_SECURE_PROTOCOLS         84

#define WINHTTP_DISABLE_COOKIES                 0x00000001
#define WINHTTP_DISABLE_REDIRECTS               0x00000002

#define WINHTTP_FLAG_SECURE_PROTOCOL_TLS1       0x00000080
#define WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_1     0x00000200
#define WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2     0x00000800

#define SECURITY_FLAG_IGNORE_UNKNOWN_CA         0x00000100
#define SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE   0x00000200
#define SECURITY_FLAG_IGNORE_CERT_CN_INVALID    0x00001000
#define SECURITY_FLAG_IGNORE_CERT_DATE_INVALID  0x00002000

// Status callback, only used to learn why a TLS handshake failed
#define WINHTTP_CALLBACK_STATUS_SECURE_FAILURE  0x00010000
#define WINHTTP_CALLBACK_FLAG_SECURE_FAILURE    WINHTTP_CALLBACK_STATUS_SECURE_FAILURE

#define WINHTTP_CALLBACK_STATUS_FLAG_CERT_REV_FAILED         0x00000001
#define WINHTTP_CALLBACK_STATUS_FLAG_INVALID_CERT            0x00000002
#define WINHTTP_CALLBACK_STATUS_FLAG_CERT_REVOKED            0x00000004
#define WINHTTP_CALLBACK_STATUS_FLAG_INVALID_CA              0x00000008
#define WINHTTP_CALLBACK_STATUS_FLAG_CERT_CN_INVALID         0x00000010
#define WINHTTP_CALLBACK_STATUS_FLAG_CERT_DATE_INVALID       0x00000020
#define WINHTTP_CALLBACK_STATUS_FLAG_SECURITY_CHANNEL_ERROR  0x80000000

#define ERROR_WINHTTP_TIMEOUT                   12002
#define ERROR_WINHTTP_INVALID_URL               12005
#define ERROR_WINHTTP_UNRECOGNIZED_SCHEME       12006
#define ERROR_WINHTTP_NAME_NOT_RESOLVED         12007
#define ERROR_WINHTTP_OPERATION_CANCELLED       12017
#define ERROR_WINHTTP_CANNOT_CONNECT            12029
#define ERROR_WINHTTP_CONNECTION_ERROR          12030
#define ERROR_WINHTTP_SECURE_CERT_DATE_INVALID  12037
#define ERROR_WINHTTP_SECURE_CERT_CN_INVALID    12038
#define ERROR_WINHTTP_SECURE_INVALID_CA         12045
#define ERROR_WINHTTP_SECURE_CERT_REV_FAILED    12057
#define ERROR_WINHTTP_INVALID_SERVER_RESPONSE   12152
#define ERROR_WINHTTP_REDIRECT_FAILED           12156
#define ERROR_WINHTTP_SECURE_CHANNEL_ERROR      12157
#define ERROR_WINHTTP_SECURE_INVALID_CERT       12169
#define ERROR_WINHTTP_SECURE_CERT_REVOKED       12170
#define ERROR_WINHTTP_SECURE_FAILURE            12175

typedef struct
{
    DWORD           dwStructSize;
    LPWSTR          lpszScheme;
    DWORD           dwSchemeLength;
    INTERNET_SCHEME nScheme;
    LPWSTR          lpszHostName;
    DWORD           dwHostNameLength;
    INTERNET_PORT   nPort;
    LPWSTR          lpszUserName;
    DWORD           dwUserNameLength;
    LPWSTR          lpszPassword;
    DWORD           dwPasswordLength;
    LPWSTR          lpszUrlPath;
    DWORD           dwUrlPathLength;
    LPWSTR          lpszExtraInfo;
    DWORD           dwExtraInfoLength;
} URL_COMPONENTS;

typedef VOID (CALLBACK *WINHTTP_STATUS_CALLBACK)(HINTERNET hInternet, DWORD_PTR dwContext, DWORD dwInternetStatus,
                                                 LPVOID lpvStatusInformation, DWORD dwStatusInformationLength);

// ─── Function table ──────────────────────────────────────────────────────────
struct WinHttpApi
{
    BOOL      (WINAPI *CrackUrl)(LPCWSTR pwszUrl, DWORD dwUrlLength, DWORD dwFlags, URL_COMPONENTS* lpUrlComponents);
    HINTERNET (WINAPI *Open)(LPCWSTR pszAgentW, DWORD dwAccessType, LPCWSTR pszProxyW, LPCWSTR pszProxyBypassW,
                             DWORD dwFlags);
    HINTERNET (WINAPI *Connect)(HINTERNET hSession, LPCWSTR pswzServerName, INTERNET_PORT nServerPort,
                                DWORD dwReserved);
    HINTERNET (WINAPI *OpenRequest)(HINTERNET hConnect, LPCWSTR pwszVerb, LPCWSTR pwszObjectName,
                                    LPCWSTR pwszVersion, LPCWSTR pwszReferrer, LPCWSTR* ppwszAcceptTypes,
                                    DWORD dwFlags);
    BOOL      (WINAPI *SetOption)(HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, DWORD dwBufferLength);
    BOOL      (WINAPI *SetTimeouts)(HINTERNET hInternet, int nResolveTimeout, int nConnectTimeout,
                                    int nSendTimeout, int nReceiveTimeout);
    WINHTTP_STATUS_CALLBACK (WINAPI *SetStatusCallback)(HINTERNET hInternet, WINHTTP_STATUS_CALLBACK lpfnCallback,
                                                        DWORD dwNotificationFlags, DWORD_PTR dwReserved);
    BOOL      (WINAPI *AddRequestHeaders)(HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength,
                                          DWORD dwModifiers);
    BOOL      (WINAPI *SendRequest)(HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength,
                                    LPVOID lpOptional, DWORD dwOptionalLength, DWORD dwTotalLength,
                                    DWORD_PTR dwContext);
    BOOL      (WINAPI *WriteData)(HINTERNET hRequest, LPCVOID lpBuffer, DWORD dwNumberOfBytesToWrite,
                                  LPDWORD lpdwNumberOfBytesWritten);
    BOOL      (WINAPI *ReceiveResponse)(HINTERNET hRequest, LPVOID lpReserved);
    BOOL      (WINAPI *QueryHeaders)(HINTERNET hRequest, DWORD dwInfoLevel, LPCWSTR pwszName, LPVOID lpBuffer,
                                     LPDWORD lpdwBufferLength, LPDWORD lpdwIndex);
    BOOL      (WINAPI *ReadData)(HINTERNET hRequest, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead,
                                 LPDWORD lpdwNumberOfBytesRead);
    BOOL      (WINAPI *CloseHandle)(HINTERNET hInternet);
};

// Loads winhttp.dll and fills the table. On failure returns false and leaves
// the missing function name (or "winhttp.dll") in *missing.
bool LoadWinHttp(WinHttpApi* api, const char** missing);
