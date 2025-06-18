#ifndef RSA_H
#define RSA_H

#include "bignum.h"
#include <stddef.h>

#define RSA_KEY_BITS 1024
#define RSA_KEY_BYTES (RSA_KEY_BITS / 8)

// For RSA, key is composed of the exponent and the modulus
typedef struct {
    Bignum modulus;
    Bignum exponent;
} RsaKey;

// RSA encryption/decryption function. Uses PKCS#1 v1.5 padding.
// Returns 0 on success, -1 on failure.
int rsa_crypt(uint8_t* out, size_t* out_len, const uint8_t* in, size_t in_len, const RsaKey* key);

#endif // RSA_H