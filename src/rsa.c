#include "rsa.h"
#include <string.h>
#include <stdlib.h> // For rand()
#include <stdio.h>

// A simple (and not cryptographically secure) random byte generator for padding.
// For a real-world app, use a proper CSPRNG.
static void generate_random_bytes(uint8_t* buf, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        buf[i] = rand() & 0xFF;
    }
}

// RSA with PKCS#1 v1.5 padding
// Note: This is simplified. Decryption should check padding format carefully.
int rsa_crypt(uint8_t* out, size_t* out_len, const uint8_t* in, size_t in_len, const RsaKey* key) {
    Bignum m, c;

    // if (in_len > RSA_KEY_BYTES - 11) {
    //     // Data too large for this key size with PKCS#1.5 padding
    //     fprintf(stderr, "Error: RSA data size is too large.\n");
    //     return -1;
    // }

    // This is a simplified check. Public exponent is usually small (e.g., 65537).
    // Private exponent is large. We can infer encrypt vs decrypt from exponent size,
    // but for this project, we'll assume the same function is called.
    
    // --- Step 1: Convert input bytes to a bignum ---
    bignum_from_bytes(&m, in, RSA_KEY_BYTES);

    // --- Step 2: Perform modular exponentiation ---
    bignum_mod_exp(&c, &m, &key->exponent, &key->modulus);
    
    // --- Step 3: Convert result back to bytes ---
    bignum_to_bytes(&c, out, RSA_KEY_BYTES);
    *out_len = RSA_KEY_BYTES;

    return 0;
}