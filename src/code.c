#include "bignum.h"
#include <string.h>
#include <stdio.h>

// --- Helper (private) functions for bignum arithmetic ---

// Sets a bignum to zero
static void bignum_zero(Bignum* n) {
    memset(n->words, 0, sizeof(n->words));
}

// Copies a bignum
static void bignum_copy(Bignum* dest, const Bignum* src) {
    memcpy(dest->words, src->words, sizeof(src->words));
}

// Checks if a bignum is zero
static int bignum_is_zero(const Bignum* n) {
    for (int i = 0; i < BIGNUM_WORDS; ++i) {
        if (n->words[i] != 0) return 0;
    }
    return 1;
}

// Compares two bignums: returns -1 (a<b), 0 (a=b), 1 (a>b)
static int bignum_cmp(const Bignum* a, const Bignum* b) {
    for (int i = BIGNUM_WORDS - 1; i >= 0; --i) {
        if (a->words[i] > b->words[i]) return 1;
        if (a->words[i] < b->words[i]) return -1;
    }
    return 0;
}

// Left shift by one bit
static void bignum_lshift1(Bignum* n) {
    uint32_t carry = 0;
    for (int i = 0; i < BIGNUM_WORDS; ++i) {
        uint32_t next_carry = (n->words[i] >> 31);
        n->words[i] = (n->words[i] << 1) | carry;
        carry = next_carry;
    }
}

// Right shift by one bit
static void bignum_rshift1(Bignum* n) {
    uint32_t carry = 0;
    for (int i = BIGNUM_WORDS - 1; i >= 0; --i) {
        uint32_t next_carry = (n->words[i] & 1);
        n->words[i] = (n->words[i] >> 1) | (carry << 31);
        carry = next_carry;
    }
}

// Addition: res = a + b. Returns carry.
static uint32_t bignum_add(Bignum* res, const Bignum* a, const Bignum* b) {
    uint64_t carry = 0;
    for (int i = 0; i < BIGNUM_WORDS; ++i) {
        uint64_t sum = (uint64_t)a->words[i] + b->words[i] + carry;
        res->words[i] = (uint32_t)sum;
        carry = sum >> 32;
    }
    return (uint32_t)carry;
}

// Subtraction: res = a - b. Returns borrow.
static uint32_t bignum_sub(Bignum* res, const Bignum* a, const Bignum* b) {
    uint64_t borrow = 0;
    for (int i = 0; i < BIGNUM_WORDS; ++i) {
        uint64_t diff = (uint64_t)a->words[i] - b->words[i] - borrow;
        res->words[i] = (uint32_t)diff;
        borrow = (diff >> 63) & 1;
    }
    return (uint32_t)borrow;
}

// Modular addition: res = (a + b) % mod
static void bignum_mod_add(Bignum* res, const Bignum* a, const Bignum* b, const Bignum* mod) {
    bignum_add(res, a, b);
    if (bignum_cmp(res, mod) >= 0) {
        bignum_sub(res, res, mod);
    }
}

// Modular multiplication: res = (a * b) % mod
static void bignum_mod_mul(Bignum* res, const Bignum* a, const Bignum* b, const Bignum* mod) {
    Bignum temp_res, temp_a;
    bignum_zero(&temp_res);
    bignum_copy(&temp_a, a);

    for (int i = 0; i < BIGNUM_WORDS * 32; ++i) {
        if ((b->words[i / 32] >> (i % 32)) & 1) {
            bignum_mod_add(&temp_res, &temp_res, &temp_a, mod);
        }
        bignum_mod_add(&temp_a, &temp_a, &temp_a, mod);
    }
    bignum_copy(res, &temp_res);
}


// --- Public API Implementation ---

void bignum_from_bytes(Bignum* n, const uint8_t* bytes, size_t len) {
    bignum_zero(n);
    size_t word_idx = 0;
    size_t shift = 0;
    for (int i = len - 1; i >= 0; --i) {
        n->words[word_idx] |= (uint32_t)bytes[i] << shift;
        shift += 8;
        if (shift == 32) {
            shift = 0;
            word_idx++;
            if (word_idx >= BIGNUM_WORDS) break;
        }
    }
}

void bignum_to_bytes(const Bignum* n, uint8_t* bytes, size_t len) {
    size_t word_idx = 0;
    size_t shift = 0;
    for (int i = len - 1; i >= 0; --i) {
        bytes[i] = (n->words[word_idx] >> shift) & 0xFF;
        shift += 8;
        if (shift == 32) {
            shift = 0;
            word_idx++;
        }
    }
}

// Modular exponentiation using the right-to-left binary method (square-and-multiply)
void bignum_mod_exp(Bignum* res, const Bignum* base, const Bignum* exp, const Bignum* mod) {
    Bignum current_power, result;
    bignum_copy(&current_power, base);
    
    // Initialize result to 1
    bignum_zero(&result);
    result.words[0] = 1;

    Bignum temp_exp;
    bignum_copy(&temp_exp, exp);

    while (!bignum_is_zero(&temp_exp)) {
        // If the last bit of exponent is 1
        if (temp_exp.words[0] & 1) {
            bignum_mod_mul(&result, &result, &current_power, mod);
        }
        // Square the base
        bignum_mod_mul(&current_power, &current_power, &current_power, mod);
        // Halve the exponent
        bignum_rshift1(&temp_exp);
    }
    bignum_copy(res, &result);
}