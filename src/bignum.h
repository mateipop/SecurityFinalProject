#ifndef BIGNUM_H
#define BIGNUM_H

#include <stdint.h>
#include <stddef.h>

// A simple bignum structure. For 1024-bit keys, we need 1024/32 = 32 words.
// We'll use a bit more for safety.
#define BIGNUM_WORDS 36 

typedef struct {
    uint32_t words[BIGNUM_WORDS];
} Bignum;

// --- Public Functions ---

// Creates a bignum from a byte array (big-endian)
void bignum_from_bytes(Bignum* n, const uint8_t* bytes, size_t len);

// Converts a bignum to a byte array (big-endian)
void bignum_to_bytes(const Bignum* n, uint8_t* bytes, size_t len);

// Modular exponentiation: res = base^exp % mod
void bignum_mod_exp(Bignum* res, const Bignum* base, const Bignum* exp, const Bignum* mod);

#endif // BIGNUM_H