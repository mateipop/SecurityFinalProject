#include "chacha20.h"
#include <string.h>

// Macro for 32-bit rotation
#define ROTL32(x, n) ((x << n) | (x >> (32 - n)))

// Helper to load 4 bytes into a uint32_t (little-endian)
static uint32_t U8TO32_LE(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

// Helper to store a uint32_t into 4 bytes (little-endian)
static void U32TO8_LE(uint8_t *p, uint32_t v) {
    p[0] = v;
    p[1] = v >> 8;
    p[2] = v >> 16;
    p[3] = v >> 24;
}

// The ChaCha20 quarter round function
static void chacha20_quarter_round(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
    *a += *b; *d ^= *a; *d = ROTL32(*d, 16);
    *c += *d; *b ^= *c; *b = ROTL32(*b, 12);
    *a += *b; *d ^= *a; *d = ROTL32(*d, 8);
    *c += *d; *b ^= *c; *b = ROTL32(*b, 7);
}

void chacha20_block(uint8_t output[64], const uint8_t key[32], uint32_t counter, const uint8_t nonce[12]) {
    uint32_t state[16];
    const uint8_t *constants = (const uint8_t *)"expand 32-byte k";

    // Initialize state
    state[0] = U8TO32_LE(constants + 0);
    state[1] = U8TO32_LE(constants + 4);
    state[2] = U8TO32_LE(constants + 8);
    state[3] = U8TO32_LE(constants + 12);
    state[4] = U8TO32_LE(key + 0);
    state[5] = U8TO32_LE(key + 4);
    state[6] = U8TO32_LE(key + 8);
    state[7] = U8TO32_LE(key + 12);
    state[8] = U8TO32_LE(key + 16);
    state[9] = U8TO32_LE(key + 20);
    state[10] = U8TO32_LE(key + 24);
    state[11] = U8TO32_LE(key + 28);
    state[12] = counter;
    state[13] = U8TO32_LE(nonce + 0);
    state[14] = U8TO32_LE(nonce + 4);
    state[15] = U8TO32_LE(nonce + 8);

    uint32_t working_state[16];
    memcpy(working_state, state, sizeof(state));

    // 20 rounds (10 column rounds and 10 diagonal rounds)
    for (int i = 0; i < 10; ++i) {
        // Column round
        chacha20_quarter_round(&working_state[0], &working_state[4], &working_state[8], &working_state[12]);
        chacha20_quarter_round(&working_state[1], &working_state[5], &working_state[9], &working_state[13]);
        chacha20_quarter_round(&working_state[2], &working_state[6], &working_state[10], &working_state[14]);
        chacha20_quarter_round(&working_state[3], &working_state[7], &working_state[11], &working_state[15]);
        // Diagonal round
        chacha20_quarter_round(&working_state[0], &working_state[5], &working_state[10], &working_state[15]);
        chacha20_quarter_round(&working_state[1], &working_state[6], &working_state[11], &working_state[12]);
        chacha20_quarter_round(&working_state[2], &working_state[7], &working_state[8], &working_state[13]);
        chacha20_quarter_round(&working_state[3], &working_state[4], &working_state[9], &working_state[14]);
    }

    // Add initial state to the final state and serialize
    for (int i = 0; i < 16; ++i) {
        U32TO8_LE(output + i * 4, working_state[i] + state[i]);
    }
}

void chacha20_crypt(uint8_t *out, const uint8_t *in, size_t len, const uint8_t key[32], const uint8_t nonce[12]) {
    uint8_t block[64];
    uint32_t counter = 1;
    size_t processed = 0;

    while (processed < len) {
        chacha20_block(block, key, counter++, nonce);
        size_t remaining = len - processed;
        size_t to_xor = (remaining < 64) ? remaining : 64;

        for (size_t i = 0; i < to_xor; ++i) {
            out[processed + i] = in[processed + i] ^ block[i];
        }
        processed += to_xor;
    }
}