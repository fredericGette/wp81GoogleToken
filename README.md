# wp81GoogleToken

A Win32 console application for **Windows Phone 8.1 (ARM32)** that prints an
OAuth 2.0 access token for a Google service account. It takes the JSON key
file downloaded from the Google Cloud console and does what this script does
with `jq`, `openssl` and `curl`:

```
HDR=$(printf '{"alg":"RS256","typ":"JWT"}' | b64url)
CLM=$(printf '{"iss":"%s","scope":"...","aud":"https://oauth2.googleapis.com/token","iat":%d,"exp":%d}' \
      "$EMAIL" "$NOW" $((NOW+3600)) | b64url)
SIG=$(printf '%s.%s' "$HDR" "$CLM" | openssl dgst -sha256 -sign "$PEM" -binary | b64url)
TOKEN=$(curl -s https://oauth2.googleapis.com/token \
  -d "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=$HDR.$CLM.$SIG" | jq -r .access_token)
```

The token is printed alone on stdout, so it can be captured by a script and
passed to [wp81Curl](../wp81Curl) to upload a file to Google Cloud Storage.

This has been tested on a phone against Google: the token was accepted by
`https://oauth2.googleapis.com/tokeninfo`, and an upload with wp81Curl
returned `200 OK`.

---

## Usage

```
wp81GoogleToken.exe [options...] KEYFILE
```

| Option | Meaning |
|---|---|
| `-s, --scope SCOPE` | scopes requested, space separated (default `https://www.googleapis.com/auth/devstorage.read_write`) |
| `-v, --verbose` | show the steps on stderr: service account, JWT claims, HTTP status, token lifetime |
| `-h, --help`, `-V, --version` | |

The token is valid for one hour. Messages go to stderr as
`wp81GoogleToken: message`, so a failed run prints nothing on stdout.

### Example: upload a file to Google Cloud Storage

The phone's shell is `cmd.exe`, so the token is captured with `for /f`:

```
for /f "delims=" %T in ('wp81GoogleToken.exe key.json') do set TOKEN=%T

wp81Curl --fail -X PUT ^
  -H "Authorization: Bearer %TOKEN%" ^
  -H "Content-Type: text/plain; charset=utf-8" ^
  -T daily.txt ^
  https://storage.googleapis.com/YOUR_BUCKET/public/daily.txt
```

In a `.cmd` file, write `%%T` instead of `%T`. To stop when no token was
obtained, check the exit code first:

```
wp81GoogleToken.exe key.json > token.txt
if errorlevel 1 exit /b 1
set /p TOKEN=<token.txt
del token.txt
```

Without the `Content-Type` header, Cloud Storage stores the file as
`application/octet-stream`.

### Checking a token

```
wp81Curl "https://oauth2.googleapis.com/tokeninfo?access_token=%TOKEN%"
```

The answer shows the scope and the remaining lifetime (`expires_in`).

Do not share the output of `wp81GoogleToken.exe` or of `wp81Curl -v` while the
token is valid: anyone holding it has the service account's access.

---

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success, the token is on stdout |
| 1 | bad command line |
| 2 | key file unreadable, not JSON, or without `client_email` / `private_key` |
| 3 | private key invalid, or signature failed |
| 4 | network error: no WinHTTP, host not resolved, cannot connect, TLS failure, timeout |
| 5 | the token endpoint answered without a token (its `error` and `error_description` are shown) |

`invalid_grant` usually means a wrong phone clock: Google refuses a JWT whose
`iat` is in the future or whose `exp` has passed. Check the date and time in
Settings. It can also mean the key was deleted in the Google Cloud console.

---

## How it works

1. **Key file**: `client_email` and `private_key` are read with cJSON, which
   also turns the `\n` of the JSON string back into line breaks.
2. **Private key**: the PEM body is base64-decoded and the DER structure is
   parsed by hand (`src/rsa_key.cpp`): PKCS#8 `PrivateKeyInfo`, which is what
   Google keys contain, then the PKCS#1 `RSAPrivateKey` inside it. A bare
   `RSA PRIVATE KEY` (PKCS#1) is accepted too. The modulus, exponent and
   primes are imported into CNG as a `BCRYPT_RSAPRIVATE_BLOB` with
   `BCryptImportKeyPair`.
3. **JWT**: the header `{"alg":"RS256","typ":"JWT"}` and the claims (`iss`,
   `scope`, `aud`, `iat`, `exp` = `iat` + 3600) are base64url-encoded without
   padding. The claims are built with cJSON, which escapes the strings.
4. **Signature (RS256)**: SHA-256 with `BCryptCreateHash` / `BCryptHashData` /
   `BCryptFinishHash`, then RSA PKCS#1 v1.5 with `BCryptSignHash`. This is the
   same signature as `openssl dgst -sha256 -sign`.
5. **Token request**: `POST https://oauth2.googleapis.com/token` with
   `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=JWT`,
   sent with WinHTTP over TLS 1.2. The JWT only contains base64url characters
   and dots, so it needs no URL encoding.
6. **Response**: `access_token` is read with cJSON and printed.

The key file buffer, the decoded key and the CNG key blob are erased with
`SecureZeroMemory` once used.

### Windows Phone 8.1 SDK limits

- **CNG**: the SDK's `bcrypt.h` hides almost everything behind the desktop
  partition, although `mincore.lib` imports the functions from the phone's
  `bcrypt.dll`. The declarations used are in `src/crypto_api.h`, with the
  values of the desktop Windows 8.1 `bcrypt.h`.
- **Crypt32**: the SDK has no `wincrypt.h`. Rather than declaring
  `CryptStringToBinary` and `CryptDecodeObjectEx` and relying on the phone
  supporting the PKCS#8 decoders, the PEM and DER are decoded in code (about
  100 lines).
- **WinHTTP**: the SDK has no `winhttp.h` nor `winhttp.lib`, but the phone
  ships `winhttp.dll` (WinHTTP 6.3). The declarations and the run-time loading
  come from wp81Curl (`src/winhttp_api.h`). See the
  [wp81Curl README](../wp81Curl/README.md) for details, including how TLS
  certificate errors are reported.

---

## Building

Requirements (paths are hard-coded in `CMakeLists.txt` and `CMakePresets.json`):

- Windows Phone 8.1 SDK
  (`C:/Program Files (x86)/Windows Phone Kits/8.1`)
- Visual Studio 2012 WP SDK headers and libraries
  (`C:/Program Files (x86)/Microsoft Visual Studio 11.0/VC/WPSDK`)
- LLVM (`clang-cl` and `lld-link` in `C:/Program Files/LLVM/bin`)
- CMake 3.20+ and Ninja

```
cd wp81GoogleToken
cmake --preset arm32-windows
cmake --build build
```

This produces `build/wp81GoogleToken.exe`, an ARM32 console executable linked
against `msvcr110.dll`, `bcrypt.dll` and Windows API sets present on the
phone. `winhttp.dll` is loaded at run time.

---

## Project layout

```
wp81GoogleToken/
  CMakeLists.txt          build definition (all src/*.cpp and src/*.c)
  CMakePresets.json       arm32-windows preset (clang-cl, lld-link, Ninja)
  src/
    wp81GoogleToken.cpp   entry point, command line, JWT, signature, token request
    rsa_key.cpp/.h        PEM / DER decoding and import of the RSA key into CNG
    crypto_api.h          CNG (BCrypt) declarations hidden by the phone SDK
    winhttp_api.h/.cpp    WinHTTP declarations and run-time loading (from wp81Curl)
    byte_buffer.h         growable byte buffer (avoids depending on msvcp110.dll)
    cJSON/                cJSON library (MIT, see its LICENSE)
```

---

## Deployment

Copy `wp81GoogleToken.exe` and the key file to the phone, for example in
`C:\Data\USERS\Public\Documents`, and run it from a console session.

The key file gives permanent access to the service account until the key is
deleted in the Google Cloud console: give the account only the roles it needs
(for example Storage Object Creator on one bucket).

- [Install a telnet server on the phone](https://github.com/fredericGette/wp81documentation/tree/main/telnetOverUsb#readme), in order to run the application.
