#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#include "tea.h"
#include "chacha20.h"
#include "rsa.h"

#define CHUNK_SIZE 65536 // 64 KB chunk for file processing

// For TEA CBC mode, we need to XOR blocks
void xor_blocks(uint8_t* a, const uint8_t* b, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        a[i] ^= b[i];
    }
}

void print_usage(const char* prog_name) {
    fprintf(stderr, "Usage: %s -e|-d -a <alg> -i <infile> -k <keyfile> -o <outfile>\n", prog_name);
    fprintf(stderr, "  -e: encrypt\n");
    fprintf(stderr, "  -d: decrypt\n");
    fprintf(stderr, "  -a <alg>: algorithm (tea, chacha20, rsa)\n");
    fprintf(stderr, "  -i <infile>: input file\n");
    fprintf(stderr, "  -k <keyfile>: key file\n");
    fprintf(stderr, "  -o <outfile>: output file\n");
}

int handle_tea(FILE* in_f, FILE* out_f, const uint8_t* key, int encrypt_mode) {
    uint8_t in_buf[TEA_BLOCK_SIZE];
    uint8_t out_buf[TEA_BLOCK_SIZE];
    uint8_t iv[TEA_BLOCK_SIZE];
    uint8_t prev_cipher_block[TEA_BLOCK_SIZE];

    if (encrypt_mode) {
        // Generate and write a random IV to the start of the output file
        srand(time(NULL));
        for(int i=0; i<TEA_BLOCK_SIZE; ++i) iv[i] = rand() % 256;
        
        if (fwrite(iv, 1, TEA_BLOCK_SIZE, out_f) != TEA_BLOCK_SIZE) {
            perror("Failed to write IV");
            return -1;
        }
        memcpy(prev_cipher_block, iv, TEA_BLOCK_SIZE);

        size_t bytes_read;
        while ((bytes_read = fread(in_buf, 1, TEA_BLOCK_SIZE, in_f)) > 0) {
            // PKCS#7 Padding
            if (bytes_read < TEA_BLOCK_SIZE) {
                uint8_t padding_val = TEA_BLOCK_SIZE - bytes_read;
                memset(in_buf + bytes_read, padding_val, padding_val);
            }
            
            xor_blocks(in_buf, prev_cipher_block, TEA_BLOCK_SIZE);
            memcpy(out_buf, in_buf, TEA_BLOCK_SIZE);
            tea_encrypt((uint32_t*)out_buf, (const uint32_t*)key);
            
            if (fwrite(out_buf, 1, TEA_BLOCK_SIZE, out_f) != TEA_BLOCK_SIZE) return -1;
            
            memcpy(prev_cipher_block, out_buf, TEA_BLOCK_SIZE);

            if (bytes_read < TEA_BLOCK_SIZE) break; // Last block was padded
        }
        // If file size is a multiple of block size, add a full padding block
        if (bytes_read == TEA_BLOCK_SIZE) {
             memset(in_buf, TEA_BLOCK_SIZE, TEA_BLOCK_SIZE);
             xor_blocks(in_buf, prev_cipher_block, TEA_BLOCK_SIZE);
             tea_encrypt((uint32_t*)in_buf, (const uint32_t*)key);
             fwrite(in_buf, 1, TEA_BLOCK_SIZE, out_f);
        }

    } else { // Decrypt
        if (fread(iv, 1, TEA_BLOCK_SIZE, in_f) != TEA_BLOCK_SIZE) {
            fprintf(stderr, "Error: Input file too small for TEA decryption (missing IV).\n");
            return -1;
        }
        memcpy(prev_cipher_block, iv, TEA_BLOCK_SIZE);

        uint8_t temp_cipher_block[TEA_BLOCK_SIZE];
        size_t bytes_written = 0;
        size_t total_bytes_read = TEA_BLOCK_SIZE;

        fseek(in_f, 0, SEEK_END);
        long file_size = ftell(in_f);
        fseek(in_f, total_bytes_read, SEEK_SET);


        while (fread(in_buf, 1, TEA_BLOCK_SIZE, in_f) == TEA_BLOCK_SIZE) {
            total_bytes_read += TEA_BLOCK_SIZE;
            memcpy(temp_cipher_block, in_buf, TEA_BLOCK_SIZE);
            memcpy(out_buf, in_buf, TEA_BLOCK_SIZE);

            tea_decrypt((uint32_t*)out_buf, (const uint32_t*)key);
            xor_blocks(out_buf, prev_cipher_block, TEA_BLOCK_SIZE);
            
            memcpy(prev_cipher_block, temp_cipher_block, TEA_BLOCK_SIZE);

            // Handle unpadding on the last block
            if (total_bytes_read == (size_t)file_size) {
                uint8_t padding_val = out_buf[TEA_BLOCK_SIZE - 1];
                 if (padding_val > 0 && padding_val <= TEA_BLOCK_SIZE) {
                     bytes_written = TEA_BLOCK_SIZE - padding_val;
                 }
            } else {
                bytes_written = TEA_BLOCK_SIZE;
            }
             if (fwrite(out_buf, 1, bytes_written, out_f) != bytes_written) return -1;
        }
    }
    return 0;
}


int handle_chacha20(FILE* in_f, FILE* out_f, const uint8_t* key, int encrypt_mode) {
    uint8_t in_buf[CHUNK_SIZE];
    uint8_t out_buf[CHUNK_SIZE];
    uint8_t nonce[CHACHA20_NONCE_SIZE];

    if (encrypt_mode) {
        // Generate and write a random nonce
        srand(time(NULL));
        for(int i=0; i<CHACHA20_NONCE_SIZE; ++i) nonce[i] = rand() % 256;
        if (fwrite(nonce, 1, CHACHA20_NONCE_SIZE, out_f) != CHACHA20_NONCE_SIZE) {
            perror("Failed to write nonce");
            return -1;
        }
    } else {
        if (fread(nonce, 1, CHACHA20_NONCE_SIZE, in_f) != CHACHA20_NONCE_SIZE) {
            fprintf(stderr, "Error: Input file too small (missing nonce).\n");
            return -1;
        }
    }
    
    size_t bytes_read;
    while ((bytes_read = fread(in_buf, 1, CHUNK_SIZE, in_f)) > 0) {
        chacha20_crypt(out_buf, in_buf, bytes_read, key, nonce);
        if (fwrite(out_buf, 1, bytes_read, out_f) != bytes_read) {
            perror("File write error");
            return -1;
        }
    }
    return 0;
}


int handle_rsa(FILE* in_f, FILE* out_f, const uint8_t* key_bytes, int encrypt_mode) {
    RsaKey key;
    uint8_t in_buf[RSA_KEY_BYTES];
    uint8_t out_buf[RSA_KEY_BYTES];
    
    // Key file format: 128 bytes modulus, then 128 bytes exponent
    bignum_from_bytes(&key.modulus, key_bytes, RSA_KEY_BYTES);
    bignum_from_bytes(&key.exponent, key_bytes + RSA_KEY_BYTES, RSA_KEY_BYTES);

    if (encrypt_mode) {
        // Pad and encrypt. PKCS#1.5 requires 11 bytes of overhead.
        const size_t max_data_len = RSA_KEY_BYTES - 11;
        uint8_t padded_block[RSA_KEY_BYTES] = {0};

        size_t bytes_read = fread(in_buf, 1, max_data_len, in_f);
        if (bytes_read == 0) {
             fprintf(stderr, "Input file is empty.\n");
             return -1;
        }
        
        // PKCS#1 v1.5 Encryption Padding
        padded_block[0] = 0x00;
        padded_block[1] = 0x02; // Block type 2 for encryption
        // Fill with random non-zero bytes
        for (size_t i = 2; i < RSA_KEY_BYTES - bytes_read - 1; ++i) {
            do {
                padded_block[i] = rand() % 256;
            } while (padded_block[i] == 0);
        }
        padded_block[RSA_KEY_BYTES - bytes_read - 1] = 0x00;
        memcpy(padded_block + RSA_KEY_BYTES - bytes_read, in_buf, bytes_read);

        size_t out_len;
        if (rsa_crypt(out_buf, &out_len, padded_block, RSA_KEY_BYTES, &key) != 0) {
            return -1;
        }
        if (fwrite(out_buf, 1, out_len, out_f) != out_len) return -1;

    } else { // Decrypt
        size_t bytes_read = fread(in_buf, 1, RSA_KEY_BYTES, in_f);
         if (bytes_read == 0) return 0;
         if (bytes_read != RSA_KEY_BYTES) {
              fprintf(stderr, "Error: Invalid RSA ciphertext size.\n");
              return -1;
         }

        size_t out_len;
        if (rsa_crypt(out_buf, &out_len, in_buf, bytes_read, &key) != 0) return -1;
        
        // Unpad PKCS#1 v1.5
        if (out_buf[0] != 0x00 || out_buf[1] != 0x02) {
            fprintf(stderr, "Decryption error or invalid padding.\n");
            return -1;
        }
        
        // Find the 0x00 separator
        size_t i = 2;
        while(i < out_len && out_buf[i] != 0x00) { i++; }
        
        if (i >= out_len || i < 10) { // At least 8 random bytes + separator
            fprintf(stderr, "Padding error.\n");
            return -1;
        }
        i++; // Move past the separator
        
        if (fwrite(out_buf + i, 1, out_len - i, out_f) != (out_len - i)) return -1;
    }
    return 0;
}


int main(int argc, char *argv[]) {
    if (argc != 10) {
        print_usage(argv[0]);
        return 1;
    }

    int encrypt_mode = -1;
    char* alg = NULL, *infile = NULL, *keyfile = NULL, *outfile = NULL;

    for (int i = 1; i < argc; i += 2) {
        if (strcmp(argv[i], "-e") == 0) { encrypt_mode = 1; i--; }
        else if (strcmp(argv[i], "-d") == 0) { encrypt_mode = 0; i--; }
        else if (strcmp(argv[i], "-a") == 0) { alg = argv[i+1]; }
        else if (strcmp(argv[i], "-i") == 0) { infile = argv[i+1]; }
        else if (strcmp(argv[i], "-k") == 0) { keyfile = argv[i+1]; }
        else if (strcmp(argv[i], "-o") == 0) { outfile = argv[i+1]; }
    }
    
    if (encrypt_mode == -1 || !alg || !infile || !keyfile || !outfile) {
        print_usage(argv[0]);
        return 1;
    }

    FILE* in_f = fopen(infile, "rb");
    if (!in_f) { perror(infile); return 1; }
    
    FILE* key_f = fopen(keyfile, "rb");
    if (!key_f) { perror(keyfile); fclose(in_f); return 1; }
    
    FILE* out_f = fopen(outfile, "wb");
    if (!out_f) { perror(outfile); fclose(in_f); fclose(key_f); return 1; }

    int status = 0;
    
    // Read the key
    fseek(key_f, 0, SEEK_END);
    long key_size = ftell(key_f);
    fseek(key_f, 0, SEEK_SET);
    uint8_t* key_data = malloc(key_size);
    if (!key_data) { fprintf(stderr, "Memory allocation failed\n"); status = 1; goto cleanup; }
    if (fread(key_data, 1, key_size, key_f) != (size_t)key_size) {
        fprintf(stderr, "Failed to read key file.\n"); status = 1; goto cleanup;
    }

    // Dispatch to correct handler
    if (strcmp(alg, "tea") == 0) {
        if (key_size < TEA_KEY_SIZE) { fprintf(stderr, "TEA key must be %d bytes.\n", TEA_KEY_SIZE); status=1; goto cleanup; }
        status = handle_tea(in_f, out_f, key_data, encrypt_mode);
    } else if (strcmp(alg, "chacha20") == 0) {
        if (key_size < CHACHA20_KEY_SIZE) { fprintf(stderr, "ChaCha20 key must be %d bytes.\n", CHACHA20_KEY_SIZE); status=1; goto cleanup; }
        status = handle_chacha20(in_f, out_f, key_data, encrypt_mode);
    } else if (strcmp(alg, "rsa") == 0) {
        if (key_size < 2 * RSA_KEY_BYTES) { fprintf(stderr, "RSA key file must be %d bytes.\n", 2*RSA_KEY_BYTES); status=1; goto cleanup; }
        status = handle_rsa(in_f, out_f, key_data, encrypt_mode);
    } else {
        fprintf(stderr, "Unknown algorithm: %s\n", alg);
        status = 1;
    }
    
    if (status == 0) {
        printf("Operation completed successfully.\n");
    } else {
        fprintf(stderr, "An error occurred during the operation.\n");
    }

cleanup:
    if (key_data) free(key_data);
    fclose(in_f);
    fclose(key_f);
    fclose(out_f);
    return status;
}