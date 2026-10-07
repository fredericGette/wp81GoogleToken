#include "rsa_key.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "byte_buffer.h"

// ─── PEM ─────────────────────────────────────────────────────────────────────
// The SDK has no CryptStringToBinary / CryptDecodeObjectEx declarations and
// the PEM and DER formats used here are small: both are decoded by hand.

static int Base64Value(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+')             return 62;
    if (c == '/')             return 63;
    return -1;
}

// Standard base64, whitespace ignored, stops at the '=' padding
static bool Base64Decode(const char* text, const char* end, ByteBuffer* out)
{
    unsigned value = 0;
    int      bits  = 0;
    for (; text < end && *text != '='; ++text)
    {
        if (*text == ' ' || *text == '\t' || *text == '\r' || *text == '\n')
            continue;
        int v = Base64Value(*text);
        if (v < 0)
            return false;
        value = (value << 6) | static_cast<unsigned>(v);
        bits += 6;
        if (bits >= 8)
        {
            bits -= 8;
            char byte = static_cast<char>((value >> bits) & 0xFF);
            if (!out->Append(&byte, 1))
                return false;
        }
    }
    return true;
}

// Finds the base64 body between the BEGIN and END lines
static bool FindPemBody(const char* pem, bool* pkcs1, const char** body, const char** bodyEnd)
{
    static const char PKCS8_BEGIN[] = "-----BEGIN PRIVATE KEY-----";
    static const char PKCS1_BEGIN[] = "-----BEGIN RSA PRIVATE KEY-----";

    const char* begin = strstr(pem, PKCS8_BEGIN);
    *pkcs1 = false;
    if (begin)
        begin += sizeof(PKCS8_BEGIN) - 1;
    else if ((begin = strstr(pem, PKCS1_BEGIN)) != nullptr)
    {
        begin += sizeof(PKCS1_BEGIN) - 1;
        *pkcs1 = true;
    }
    else
        return false;

    const char* end = strstr(begin, "-----END ");
    if (!end)
        return false;
    *body    = begin;
    *bodyEnd = end;
    return true;
}

// ─── DER ─────────────────────────────────────────────────────────────────────
struct DerReader
{
    const unsigned char* p;
    const unsigned char* end;
};

// Reads one tag-length-value with the expected tag, the reader moves past it
static bool ReadTlv(DerReader* r, unsigned char tag, DerReader* value)
{
    if (r->end - r->p < 2 || r->p[0] != tag)
        return false;

    const unsigned char* q      = r->p + 2;
    size_t               length = r->p[1];
    if (length & 0x80)
    {
        int count = length & 0x7F;
        if (count == 0 || count > 4 || r->end - q < count)
            return false;
        length = 0;
        while (count--)
            length = (length << 8) | *q++;
    }
    if (static_cast<size_t>(r->end - q) < length)
        return false;

    value->p   = q;
    value->end = q + length;
    r->p       = q + length;
    return true;
}

// A positive INTEGER as big-endian bytes, without its leading zeros
static bool ReadUnsigned(DerReader* r, DerReader* value)
{
    if (!ReadTlv(r, 0x02, value) || value->p == value->end || (value->p[0] & 0x80))
        return false;
    while (value->end - value->p > 1 && value->p[0] == 0)
        ++value->p;
    return true;
}

// PKCS#8 PrivateKeyInfo ::= SEQUENCE { version, AlgorithmIdentifier, OCTET STRING privateKey }
// Moves r onto the PKCS#1 key held by the OCTET STRING
static bool UnwrapPkcs8(DerReader* r)
{
    // 1.2.840.113549.1.1.1 rsaEncryption
    static const unsigned char RSA_OID[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };

    DerReader info, version, algorithm, oid, key;
    if (!ReadTlv(r, 0x30, &info) || !ReadUnsigned(&info, &version) || !ReadTlv(&info, 0x30, &algorithm) ||
        !ReadTlv(&algorithm, 0x06, &oid))
        return false;
    if (static_cast<size_t>(oid.end - oid.p) != sizeof(RSA_OID) || memcmp(oid.p, RSA_OID, sizeof(RSA_OID)) != 0)
        return false;
    if (!ReadTlv(&info, 0x04, &key))
        return false;
    *r = key;
    return true;
}

// ─── CNG blob ────────────────────────────────────────────────────────────────
static size_t Size(const DerReader& value)
{
    return static_cast<size_t>(value.end - value.p);
}

// Copies a big-endian number right-aligned in size bytes (leading zeros added)
static unsigned char* PutNumber(unsigned char* out, const DerReader& value, size_t size)
{
    memcpy(out + size - Size(value), value.p, Size(value));
    return out + size;
}

bool ImportRsaPrivateKey(BCRYPT_ALG_HANDLE rsa, const char* pem, BCRYPT_KEY_HANDLE* key,
                         char* error, size_t errorSize)
{
    *key = nullptr;

    bool        pkcs1;
    const char* body;
    const char* bodyEnd;
    if (!FindPemBody(pem, &pkcs1, &body, &bodyEnd))
    {
        _snprintf_s(error, errorSize, _TRUNCATE, "private_key is not a PEM \"PRIVATE KEY\"");
        return false;
    }

    ByteBuffer der;
    if (!Base64Decode(body, bodyEnd, &der))
    {
        _snprintf_s(error, errorSize, _TRUNCATE, "private_key has invalid base64");
        SecureZeroMemory(der.data, der.size);
        return false;
    }

    // RSAPrivateKey ::= SEQUENCE { version, n, e, d, p, q, dp, dq, qinv }
    DerReader r = { reinterpret_cast<const unsigned char*>(der.data),
                    reinterpret_cast<const unsigned char*>(der.data) + der.size };
    DerReader rsaKey, version, n, e, d, p, q;
    bool parsed = (pkcs1 || UnwrapPkcs8(&r)) && ReadTlv(&r, 0x30, &rsaKey) && ReadUnsigned(&rsaKey, &version) &&
                  ReadUnsigned(&rsaKey, &n) && ReadUnsigned(&rsaKey, &e) && ReadUnsigned(&rsaKey, &d) &&
                  ReadUnsigned(&rsaKey, &p) && ReadUnsigned(&rsaKey, &q);
    if (!parsed)
    {
        _snprintf_s(error, errorSize, _TRUNCATE, "private_key is not a valid RSA private key");
        SecureZeroMemory(der.data, der.size);
        return false;
    }

    // BCRYPT_RSAPRIVATE_BLOB: header, e, n, p, q. Both primes get the size of half the modulus.
    size_t primeSize = (Size(n) + 1) / 2;
    if (Size(p) > primeSize) primeSize = Size(p);
    if (Size(q) > primeSize) primeSize = Size(q);
    size_t         blobSize = sizeof(BCRYPT_RSAKEY_BLOB) + Size(e) + Size(n) + 2 * primeSize;
    unsigned char* blob     = static_cast<unsigned char*>(calloc(1, blobSize));
    if (!blob)
    {
        _snprintf_s(error, errorSize, _TRUNCATE, "Out of memory");
        SecureZeroMemory(der.data, der.size);
        return false;
    }

    ULONG bitLength = static_cast<ULONG>(Size(n) * 8);
    for (unsigned char top = n.p[0]; !(top & 0x80) && bitLength > 0; top <<= 1)
        --bitLength;

    BCRYPT_RSAKEY_BLOB* header = reinterpret_cast<BCRYPT_RSAKEY_BLOB*>(blob);
    header->Magic       = BCRYPT_RSAPRIVATE_MAGIC;
    header->BitLength   = bitLength;
    header->cbPublicExp = static_cast<ULONG>(Size(e));
    header->cbModulus   = static_cast<ULONG>(Size(n));
    header->cbPrime1    = static_cast<ULONG>(primeSize);
    header->cbPrime2    = static_cast<ULONG>(primeSize);

    unsigned char* out = blob + sizeof(BCRYPT_RSAKEY_BLOB);
    out = PutNumber(out, e, Size(e));
    out = PutNumber(out, n, Size(n));
    out = PutNumber(out, p, primeSize);
    PutNumber(out, q, primeSize);

    NTSTATUS status = BCryptImportKeyPair(rsa, nullptr, BCRYPT_RSAPRIVATE_BLOB, key, blob,
                                          static_cast<ULONG>(blobSize), 0);

    SecureZeroMemory(blob, blobSize);
    free(blob);
    SecureZeroMemory(der.data, der.size);

    if (!BCRYPT_SUCCESS(status))
    {
        *key = nullptr;
        _snprintf_s(error, errorSize, _TRUNCATE, "BCryptImportKeyPair failed: 0x%08lX", status);
        return false;
    }
    return true;
}
