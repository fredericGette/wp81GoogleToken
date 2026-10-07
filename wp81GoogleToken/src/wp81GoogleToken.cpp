/**
 * Context:
 * win32 console application,
 * linked with Msvcr110.dll,
 * architecture ARM 32bit little endian.
 * Use secure functions when possible, example: _snprintf_s instead of _snprintf
 *
 * Prints an OAuth 2.0 access token for a Google service account, like this
 * script does with jq, openssl and curl:
 *
 *   HDR=$(printf '{"alg":"RS256","typ":"JWT"}' | b64url)
 *   CLM=$(printf '{"iss":"%s","scope":"...","aud":"https://oauth2.googleapis.com/token",
 *                  "iat":%d,"exp":%d}' "$EMAIL" "$NOW" $((NOW+3600)) | b64url)
 *   SIG=$(printf '%s.%s' "$HDR" "$CLM" | openssl dgst -sha256 -sign "$PEM" -binary | b64url)
 *   curl -s https://oauth2.googleapis.com/token \
 *     -d "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=$HDR.$CLM.$SIG"
 *
 * Steps:
 * 1. Read client_email and private_key from the key file (cJSON).
 * 2. Import the private key into CNG (rsa_key.cpp).
 * 3. Build the JWT, valid one hour, and sign it with RS256: SHA-256 then
 *    RSA PKCS#1 v1.5 (BCrypt, declared in crypto_api.h).
 * 4. POST it to the token endpoint (WinHTTP, loaded at run time, see winhttp_api.h).
 * 5. Print access_token alone on stdout, so a script can do
 *    TOKEN=$(wp81GoogleToken.exe key.json). Messages go to stderr.
 *
 * The phone clock must be right: Google refuses a JWT whose iat is in the future
 * or whose exp has passed (invalid_grant).
 *
 * Usage: see PrintUsage() or run "wp81GoogleToken.exe --help".
 */

#include <windows.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <wchar.h>
#include "byte_buffer.h"
#include "crypto_api.h"
#include "rsa_key.h"
#include "winhttp_api.h"
#include "cJSON/cJSON.h"

// ─── Configuration ────────────────────────────────────────────────────────────
static const char*    PROGRAM_NAME     = "wp81GoogleToken";
static const char*    VERSION          = "1.0";
static const wchar_t* USER_AGENT       = L"wp81GoogleToken/1.0";
static const char*    DEFAULT_SCOPE    = "https://www.googleapis.com/auth/devstorage.read_write";
static const char*    TOKEN_URL        = "https://oauth2.googleapis.com/token";   // also the JWT "aud"
static const wchar_t* TOKEN_HOST       = L"oauth2.googleapis.com";
static const wchar_t* TOKEN_PATH       = L"/token";
static const int      LIFETIME_SECONDS = 3600;   // the maximum Google accepts
static const DWORD    IO_CHUNK_BYTES   = 16 * 1024;
// ─────────────────────────────────────────────────────────────────────────────

enum ExitCode
{
    EXIT_OK       = 0,
    EXIT_USAGE    = 1,
    EXIT_KEY_FILE = 2,   // key file unreadable or invalid
    EXIT_CRYPTO   = 3,   // key import or signature failed
    EXIT_NETWORK  = 4,   // no answer from the token endpoint
    EXIT_REFUSED  = 5,   // the token endpoint answered without a token
};

static const int CONTINUE = -1;   // ParseArgs(): no exit code, go on

// ─── Command line ────────────────────────────────────────────────────────────
struct Options
{
    bool           verbose;
    const wchar_t* keyFile;
    ByteBuffer     scope;   // UTF-8

    Options() : verbose(false), keyFile(nullptr) {}
};

static void PrintUsage()
{
    printf("Usage: %s [options...] KEYFILE\n", PROGRAM_NAME);
    printf("Prints an OAuth 2.0 access token for the Google service account of KEYFILE\n");
    printf("(the JSON key downloaded from the Google Cloud console).\n");
    printf(" -s, --scope SCOPE   scopes requested, space separated\n");
    printf("                     (default %s)\n", DEFAULT_SCOPE);
    printf(" -v, --verbose       show the steps on stderr\n");
    printf(" -h, --help          this help\n");
    printf(" -V, --version       version\n");
}

static int Error(int code, const char* format, ...)
{
    fprintf(stderr, "%s: ", PROGRAM_NAME);
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    fputc('\n', stderr);
    return code;
}

static int UsageError(const char* format, ...)
{
    fprintf(stderr, "%s: ", PROGRAM_NAME);
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    fprintf(stderr, "\n%s: try '%s --help' for more information\n", PROGRAM_NAME, PROGRAM_NAME);
    return EXIT_USAGE;
}

static bool AppendUtf8(ByteBuffer* out, const wchar_t* text)
{
    int needed = WideCharToMultiByte(CP_UTF8, 0, text, -1, nullptr, 0, nullptr, nullptr);
    if (needed <= 0)
        return false;
    char* utf8 = static_cast<char*>(malloc(needed));
    if (!utf8)
        return false;
    WideCharToMultiByte(CP_UTF8, 0, text, -1, utf8, needed, nullptr, nullptr);
    bool ok = out->Append(utf8, needed - 1);
    free(utf8);
    return ok;
}

static int ParseArgs(int argc, wchar_t* argv[], Options* o)
{
    const wchar_t* scope = nullptr;
    for (int i = 1; i < argc; ++i)
    {
        const wchar_t* arg = argv[i];
        if (wcscmp(arg, L"-h") == 0 || wcscmp(arg, L"--help") == 0)
        {
            PrintUsage();
            return EXIT_OK;
        }
        if (wcscmp(arg, L"-V") == 0 || wcscmp(arg, L"--version") == 0)
        {
            printf("%s %s (Windows Phone 8.1 ARM, CNG, WinHTTP)\n", PROGRAM_NAME, VERSION);
            return EXIT_OK;
        }
        if (wcscmp(arg, L"-v") == 0 || wcscmp(arg, L"--verbose") == 0)
            o->verbose = true;
        else if (wcscmp(arg, L"-s") == 0 || wcscmp(arg, L"--scope") == 0)
        {
            if (i + 1 >= argc)
                return UsageError("option %ls: requires parameter", arg);
            scope = argv[++i];
        }
        else if (arg[0] == L'-' && arg[1] != L'\0')
            return UsageError("option %ls: is unknown", arg);
        else if (o->keyFile)
            return UsageError("only one key file is supported (got %ls and %ls)", o->keyFile, arg);
        else
            o->keyFile = arg;
    }

    if (!o->keyFile)
        return UsageError("no key file specified");
    bool ok = scope ? AppendUtf8(&o->scope, scope) : o->scope.Append(DEFAULT_SCOPE);
    if (!ok)
        return Error(EXIT_USAGE, "Out of memory");
    return CONTINUE;
}

// ─── Key file ────────────────────────────────────────────────────────────────
static bool ReadAll(const wchar_t* path, ByteBuffer* out)
{
    FILE* f = nullptr;
    if (_wfopen_s(&f, path, L"rb") != 0 || !f)
        return false;

    char   chunk[4096];
    bool   ok = true;
    size_t read;
    while (ok && (read = fread(chunk, 1, sizeof(chunk), f)) > 0)
        ok = out->Append(chunk, read);
    ok = ok && !ferror(f);
    fclose(f);
    return ok;
}

// Returns the string member, or null if it is missing or not a non-empty string
static const char* GetString(const cJSON* object, const char* name)
{
    const char* value = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(object, name));
    return value && *value ? value : nullptr;
}

// ─── JWT ─────────────────────────────────────────────────────────────────────
// Base64url without '=' padding (RFC 7515)
static bool AppendBase64Url(ByteBuffer* out, const void* data, size_t size)
{
    static const char ALPHABET[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    const unsigned char* p = static_cast<const unsigned char*>(data);
    for (size_t i = 0; i < size; i += 3)
    {
        size_t   left  = size - i;
        unsigned value = (p[i] << 16) | (left > 1 ? p[i + 1] << 8 : 0) | (left > 2 ? p[i + 2] : 0);
        char     quad[4] = { ALPHABET[(value >> 18) & 63], ALPHABET[(value >> 12) & 63],
                             ALPHABET[(value >> 6) & 63],  ALPHABET[value & 63] };
        // 1 byte gives 2 characters, 2 bytes give 3
        if (!out->Append(quad, left > 2 ? 4 : left + 1))
            return false;
    }
    return true;
}

// {"iss":EMAIL,"scope":SCOPE,"aud":TOKEN_URL,"iat":NOW,"exp":NOW+LIFETIME}
// cJSON escapes the strings; the numbers stay below 2^53, so they print exactly.
static char* BuildClaims(const char* email, const char* scope, __int64 now)
{
    cJSON* claims = cJSON_CreateObject();
    if (!claims)
        return nullptr;

    char* text = nullptr;
    if (cJSON_AddStringToObject(claims, "iss", email) && cJSON_AddStringToObject(claims, "scope", scope) &&
        cJSON_AddStringToObject(claims, "aud", TOKEN_URL) &&
        cJSON_AddNumberToObject(claims, "iat", static_cast<double>(now)) &&
        cJSON_AddNumberToObject(claims, "exp", static_cast<double>(now + LIFETIME_SECONDS)))
        text = cJSON_PrintUnformatted(claims);

    cJSON_Delete(claims);
    return text;
}

// Releases the CNG handles when leaving the scope
struct CngHandles
{
    BCRYPT_ALG_HANDLE  rsa;
    BCRYPT_ALG_HANDLE  sha256;
    BCRYPT_KEY_HANDLE  key;
    BCRYPT_HASH_HANDLE hash;

    CngHandles() : rsa(nullptr), sha256(nullptr), key(nullptr), hash(nullptr) {}
    ~CngHandles()
    {
        if (hash)   BCryptDestroyHash(hash);
        if (key)    BCryptDestroyKey(key);
        if (sha256) BCryptCloseAlgorithmProvider(sha256, 0);
        if (rsa)    BCryptCloseAlgorithmProvider(rsa, 0);
    }

private:
    CngHandles(const CngHandles&);
    CngHandles& operator=(const CngHandles&);
};

// Appends "." + base64url(RS256 signature of jwt's content) to jwt
static int SignJwt(const char* pem, ByteBuffer* jwt)
{
    CngHandles cng;
    NTSTATUS   status;

    if (!BCRYPT_SUCCESS(status = BCryptOpenAlgorithmProvider(&cng.rsa, BCRYPT_RSA_ALGORITHM, nullptr, 0)))
        return Error(EXIT_CRYPTO, "BCryptOpenAlgorithmProvider(RSA) failed: 0x%08lX", status);

    char error[128];
    if (!ImportRsaPrivateKey(cng.rsa, pem, &cng.key, error, sizeof(error)))
        return Error(EXIT_CRYPTO, "%s", error);

    // SHA-256 of "header.claims"
    UCHAR digest[32];
    if (!BCRYPT_SUCCESS(status = BCryptOpenAlgorithmProvider(&cng.sha256, BCRYPT_SHA256_ALGORITHM, nullptr, 0)))
        return Error(EXIT_CRYPTO, "BCryptOpenAlgorithmProvider(SHA256) failed: 0x%08lX", status);
    if (!BCRYPT_SUCCESS(status = BCryptCreateHash(cng.sha256, &cng.hash, nullptr, 0, nullptr, 0, 0)) ||
        !BCRYPT_SUCCESS(status = BCryptHashData(cng.hash, reinterpret_cast<PUCHAR>(jwt->data),
                                                static_cast<ULONG>(jwt->size), 0)) ||
        !BCRYPT_SUCCESS(status = BCryptFinishHash(cng.hash, digest, sizeof(digest), 0)))
        return Error(EXIT_CRYPTO, "SHA-256 failed: 0x%08lX", status);

    // RSASSA-PKCS1-v1_5, what openssl dgst -sha256 -sign does
    BCRYPT_PKCS1_PADDING_INFO padding = { BCRYPT_SHA256_ALGORITHM };
    ULONG signatureSize = 0;
    if (!BCRYPT_SUCCESS(status = BCryptSignHash(cng.key, &padding, digest, sizeof(digest), nullptr, 0,
                                                &signatureSize, BCRYPT_PAD_PKCS1)))
        return Error(EXIT_CRYPTO, "BCryptSignHash failed: 0x%08lX", status);

    UCHAR* signature = static_cast<UCHAR*>(malloc(signatureSize));
    if (!signature)
        return Error(EXIT_CRYPTO, "Out of memory");
    status = BCryptSignHash(cng.key, &padding, digest, sizeof(digest), signature, signatureSize, &signatureSize,
                            BCRYPT_PAD_PKCS1);
    bool appended = BCRYPT_SUCCESS(status) && jwt->Append(".", 1) &&
                    AppendBase64Url(jwt, signature, signatureSize);
    free(signature);

    if (!BCRYPT_SUCCESS(status))
        return Error(EXIT_CRYPTO, "BCryptSignHash failed: 0x%08lX", status);
    if (!appended)
        return Error(EXIT_CRYPTO, "Out of memory");
    return CONTINUE;
}

// Builds the signed JWT "header.claims.signature"
static int BuildAssertion(const Options& o, const char* email, const char* pem, ByteBuffer* jwt)
{
    static const char HEADER[] = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";

    __int64 now    = _time64(nullptr);
    char*   claims = BuildClaims(email, o.scope.data, now);
    if (!claims)
        return Error(EXIT_CRYPTO, "Out of memory");
    if (o.verbose)
        fprintf(stderr, "* JWT claims: %s\n", claims);

    bool ok = AppendBase64Url(jwt, HEADER, sizeof(HEADER) - 1) && jwt->Append(".", 1) &&
              AppendBase64Url(jwt, claims, strlen(claims));
    cJSON_free(claims);
    if (!ok)
        return Error(EXIT_CRYPTO, "Out of memory");

    return SignJwt(pem, jwt);
}

// ─── WinHTTP errors ──────────────────────────────────────────────────────────
// Detail of a failed TLS handshake, reported by the status callback
static volatile DWORD g_secureFailureFlags = 0;

static void CALLBACK OnStatus(HINTERNET, DWORD_PTR, DWORD status, LPVOID info, DWORD infoLength)
{
    if (status == WINHTTP_CALLBACK_STATUS_SECURE_FAILURE && info && infoLength >= sizeof(DWORD))
        g_secureFailureFlags = *static_cast<DWORD*>(info);
}

static int ReportWinHttpError(const char* step, DWORD error)
{
    switch (error)
    {
    case ERROR_WINHTTP_NAME_NOT_RESOLVED:
        return Error(EXIT_NETWORK, "Could not resolve host: %ls (no network?)", TOKEN_HOST);
    case ERROR_WINHTTP_CANNOT_CONNECT:
        return Error(EXIT_NETWORK, "Failed to connect to %ls port 443", TOKEN_HOST);
    case ERROR_WINHTTP_TIMEOUT:
        return Error(EXIT_NETWORK, "Operation timed out");
    case ERROR_WINHTTP_CONNECTION_ERROR:
        return Error(EXIT_NETWORK, "Connection closed or reset");
    case ERROR_WINHTTP_SECURE_FAILURE:
    case ERROR_WINHTTP_SECURE_CHANNEL_ERROR:
    case ERROR_WINHTTP_SECURE_INVALID_CA:
    case ERROR_WINHTTP_SECURE_CERT_DATE_INVALID:
    case ERROR_WINHTTP_SECURE_CERT_CN_INVALID:
    case ERROR_WINHTTP_SECURE_INVALID_CERT:
    case ERROR_WINHTTP_SECURE_CERT_REV_FAILED:
    case ERROR_WINHTTP_SECURE_CERT_REVOKED:
    {
        DWORD flags = g_secureFailureFlags;
        if (error == ERROR_WINHTTP_SECURE_INVALID_CA)        flags |= WINHTTP_CALLBACK_STATUS_FLAG_INVALID_CA;
        if (error == ERROR_WINHTTP_SECURE_CERT_DATE_INVALID) flags |= WINHTTP_CALLBACK_STATUS_FLAG_CERT_DATE_INVALID;

        char reasons[160] = "";
        if (flags & WINHTTP_CALLBACK_STATUS_FLAG_INVALID_CA)
            strcat_s(reasons, " [unknown certificate authority: root missing from the phone store]");
        if (flags & WINHTTP_CALLBACK_STATUS_FLAG_CERT_DATE_INVALID)
            strcat_s(reasons, " [expired or not yet valid: check the phone clock]");
        return Error(EXIT_NETWORK, "TLS failure with %ls, WinHTTP error %lu%s", TOKEN_HOST, error, reasons);
    }
    default:
        return Error(EXIT_NETWORK, "%s failed: WinHTTP error %lu", step, error);
    }
}

// ─── Token request ───────────────────────────────────────────────────────────
// Closes a WinHTTP handle when leaving the scope
class InternetHandle
{
public:
    InternetHandle(const WinHttpApi& api, HINTERNET handle) : m_api(api), m_handle(handle) {}
    ~InternetHandle()
    {
        if (m_handle)
            m_api.CloseHandle(m_handle);
    }
    operator HINTERNET() const { return m_handle; }

private:
    const WinHttpApi& m_api;
    HINTERNET         m_handle;

    InternetHandle(const InternetHandle&);
    InternetHandle& operator=(const InternetHandle&);
};

// POSTs the form body to the token endpoint, returns the status and the response body
static int PostToken(const Options& o, const ByteBuffer& body, DWORD* status, ByteBuffer* response)
{
    WinHttpApi  api     = {};
    const char* missing = nullptr;
    if (!LoadWinHttp(&api, &missing))
        return Error(EXIT_NETWORK, "Cannot load WinHTTP: %s not found (error %lu)", missing, GetLastError());

    InternetHandle session(api, api.Open(USER_AGENT, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, nullptr, nullptr, 0));
    if (!session)
        return ReportWinHttpError("WinHttpOpen", GetLastError());

    // Google requires TLS 1.2
    DWORD protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;
    if (!api.SetOption(session, WINHTTP_OPTION_SECURE_PROTOCOLS, &protocols, sizeof(protocols)) && o.verbose)
        fprintf(stderr, "* could not select TLS 1.2 (error %lu), using the system default\n", GetLastError());

    InternetHandle connection(api, api.Connect(session, TOKEN_HOST, 443, 0));
    if (!connection)
        return ReportWinHttpError("WinHttpConnect", GetLastError());

    InternetHandle request(api, api.OpenRequest(connection, L"POST", TOKEN_PATH, nullptr, nullptr, nullptr,
                                                WINHTTP_FLAG_SECURE));
    if (!request)
        return ReportWinHttpError("WinHttpOpenRequest", GetLastError());

    api.SetStatusCallback(request, OnStatus, WINHTTP_CALLBACK_FLAG_SECURE_FAILURE, 0);

    DWORD features = WINHTTP_DISABLE_COOKIES | WINHTTP_DISABLE_REDIRECTS;
    api.SetOption(request, WINHTTP_OPTION_DISABLE_FEATURE, &features, sizeof(features));

    DWORD addFlags = WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE;
    api.AddRequestHeaders(request, L"Accept: application/json", static_cast<DWORD>(-1), addFlags);
    if (!api.AddRequestHeaders(request, L"Content-Type: application/x-www-form-urlencoded",
                               static_cast<DWORD>(-1), addFlags))
        return ReportWinHttpError("WinHttpAddRequestHeaders", GetLastError());

    if (o.verbose)
        fprintf(stderr, "* POST %s (%u bytes)\n", TOKEN_URL, static_cast<unsigned>(body.size));

    DWORD length = static_cast<DWORD>(body.size);
    if (!api.SendRequest(request, nullptr, 0, body.data, length, length, 0))
        return ReportWinHttpError("WinHttpSendRequest", GetLastError());
    if (!api.ReceiveResponse(request, nullptr))
        return ReportWinHttpError("WinHttpReceiveResponse", GetLastError());

    DWORD statusSize = sizeof(*status);
    if (!api.QueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, nullptr, status,
                          &statusSize, nullptr))
        return Error(EXIT_NETWORK, "No HTTP status in the response");
    if (o.verbose)
        fprintf(stderr, "* HTTP status %lu\n", *status);

    char* chunk = static_cast<char*>(malloc(IO_CHUNK_BYTES));
    if (!chunk)
        return Error(EXIT_NETWORK, "Out of memory");

    int result = CONTINUE;
    for (;;)
    {
        DWORD read = 0;
        if (!api.ReadData(request, chunk, IO_CHUNK_BYTES, &read))
        {
            result = ReportWinHttpError("WinHttpReadData", GetLastError());
            break;
        }
        if (read == 0)
            break;
        if (!response->Append(chunk, read))
        {
            result = Error(EXIT_NETWORK, "Out of memory");
            break;
        }
    }
    free(chunk);
    return result;
}

// Prints access_token, or explains why there is none
static int HandleResponse(const Options& o, DWORD status, const ByteBuffer& response)
{
    cJSON* root = response.size ? cJSON_Parse(response.data) : nullptr;

    const char* token = status == 200 ? GetString(root, "access_token") : nullptr;
    if (token)
    {
        if (o.verbose)
        {
            const cJSON* expiresIn = cJSON_GetObjectItemCaseSensitive(root, "expires_in");
            if (cJSON_IsNumber(expiresIn))
                fprintf(stderr, "* token expires in %d s\n", expiresIn->valueint);
        }
        printf("%s\n", token);
        cJSON_Delete(root);
        return EXIT_OK;
    }

    // Google's errors: {"error":"invalid_grant","error_description":"Invalid JWT Signature."}
    const char* error       = GetString(root, "error");
    const char* description = GetString(root, "error_description");
    if (error)
        Error(EXIT_REFUSED, "HTTP %lu: %s%s%s", status, error, description ? ": " : "", description ? description : "");
    else
        Error(EXIT_REFUSED, "HTTP %lu, no access_token in the response: %s", status,
              response.size ? response.data : "(empty body)");

    if (error && strcmp(error, "invalid_grant") == 0)
        Error(EXIT_REFUSED, "check the phone clock (UTC %I64d) and that the key was not deleted", _time64(nullptr));

    cJSON_Delete(root);
    return EXIT_REFUSED;
}

// ─── Entry point ─────────────────────────────────────────────────────────────
int wmain(int argc, wchar_t* argv[])
{
    Options o;
    int     result = ParseArgs(argc, argv, &o);
    if (result != CONTINUE)
        return result;

    ByteBuffer file;
    if (!ReadAll(o.keyFile, &file) || file.size == 0)
        return Error(EXIT_KEY_FILE, "Cannot read %ls", o.keyFile);

    cJSON* key = cJSON_Parse(file.data);
    SecureZeroMemory(file.data, file.size);
    if (!key)
        return Error(EXIT_KEY_FILE, "%ls is not valid JSON", o.keyFile);

    const char* email = GetString(key, "client_email");
    const char* pem   = GetString(key, "private_key");
    if (!email || !pem)
    {
        cJSON_Delete(key);
        return Error(EXIT_KEY_FILE, "%ls has no client_email or private_key: not a service account key?",
                     o.keyFile);
    }
    if (o.verbose)
        fprintf(stderr, "* service account: %s\n", email);

    // grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=JWT
    // The JWT only has base64url characters and dots: no URL encoding needed
    ByteBuffer body;
    ByteBuffer jwt;
    if (!body.Append("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion="))
        result = Error(EXIT_CRYPTO, "Out of memory");
    else
        result = BuildAssertion(o, email, pem, &jwt);

    // The private key is no longer needed
    SecureZeroMemory(const_cast<char*>(pem), strlen(pem));
    cJSON_Delete(key);
    if (result != CONTINUE)
        return result;
    if (!body.Append(jwt.data, jwt.size))
        return Error(EXIT_CRYPTO, "Out of memory");

    DWORD      status = 0;
    ByteBuffer response;
    if ((result = PostToken(o, body, &status, &response)) != CONTINUE)
        return result;

    return HandleResponse(o, status, response);
}
