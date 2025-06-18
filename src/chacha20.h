#ifndef CHACHA20_H
#define CHACHA20_H

#include <stdint.h>
#include <stddef.h>

#define CHACHA20_KEY_SIZE 32 // 256 bits
#define CHACHA20_NONCE_SIZE 12 // 96 bits

// The core function. Generates a 64-byte keystream block.
void chacha20_block(uint8_t output[64], const uint8_t key[32], uint32_t counter, const uint8_t nonce[12]);

// Encrypts or decrypts data using the ChaCha20 stream cipher.
// The operation is the same for both encryption and decryption.
void chacha20_crypt(uint8_t *out, const uint8_t *in, size_t len, const uint8_t key[32], const uint8_t nonce[12]);

#endif // CHACHA20_H