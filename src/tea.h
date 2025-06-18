#ifndef TEA_H
#define TEA_H

#include <stdint.h>
#include <stddef.h>

// TEA uses a 64-bit block and a 128-bit key.
#define TEA_BLOCK_SIZE 8
#define TEA_KEY_SIZE 16

// Encrypts a single 8-byte block using a 16-byte key.
void tea_encrypt(uint32_t* v, const uint32_t* k);

// Decrypts a single 8-byte block using a 16-byte key.
void tea_decrypt(uint32_t* v, const uint32_t* k);

#endif // TEA_H