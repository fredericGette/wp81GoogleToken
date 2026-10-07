#pragma once

#include <stddef.h>
#include "crypto_api.h"

// Imports the RSA private key of a PEM text into CNG. Accepts "PRIVATE KEY"
// (PKCS#8, what Google service account keys contain) and "RSA PRIVATE KEY"
// (PKCS#1). rsa is a provider opened with BCRYPT_RSA_ALGORITHM. On failure
// returns false and writes the reason to error.
bool ImportRsaPrivateKey(BCRYPT_ALG_HANDLE rsa, const char* pem, BCRYPT_KEY_HANDLE* key,
                         char* error, size_t errorSize);
