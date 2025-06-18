#include "tea.h"

// Encrypt a 64-bit block with a 128-bit key.
// v is a 2-element array of 32-bit unsigned integers.
// k is a 4-element array of 32-bit unsigned integers.
void tea_encrypt(uint32_t* v, const uint32_t* k) {
    uint32_t v0 = v[0], v1 = v[1], sum = 0;
    // The magical constant delta for TEA
    uint32_t delta = 0x9e3779b9;
    
    // 32 rounds are standard
    for (int i = 0; i < 32; i++) {
        sum += delta;
        v0 += ((v1 << 4) + k[0]) ^ (v1 + sum) ^ ((v1 >> 5) + k[1]);
        v1 += ((v0 << 4) + k[2]) ^ (v0 + sum) ^ ((v0 >> 5) + k[3]);
    }
    v[0] = v0;
    v[1] = v1;
}

// Decrypt a 64-bit block. This is the inverse of encryption.
void tea_decrypt(uint32_t* v, const uint32_t* k) {
    uint32_t v0 = v[0], v1 = v[1];
    // Initial sum for decryption is delta * 32
    uint32_t sum = 0xC6EF3720;
    uint32_t delta = 0x9e3779b9;

    for (int i = 0; i < 32; i++) {
        v1 -= ((v0 << 4) + k[2]) ^ (v0 + sum) ^ ((v0 >> 5) + k[3]);
        v0 -= ((v1 << 4) + k[0]) ^ (v1 + sum) ^ ((v1 >> 5) + k[1]);
        sum -= delta;
    }
    v[0] = v0;
    v[1] = v1;
}