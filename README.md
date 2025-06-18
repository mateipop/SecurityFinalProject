# C Cryptography Project

This project implements modern symmetric and asymmetric cryptographic algorithms in C. It was developed for the Third Year IE Security and Cryptography course. All algorithms are implemented from scratch, without external crypto libraries.

## Overview

The project includes:

* Two symmetric algorithms: **TEA** (Tiny Encryption Algorithm) using CBC mode, and **ChaCha20** (stream cipher).
* One asymmetric algorithm: **RSA** with PKCS#1 v1.5 padding and a custom BigNum implementation.
* A command-line interface (CLI) for encryption/decryption.
* Support for large file encryption (up to 4 GB).

## Structure

```
/
|-- src/          -> All C source files
|-- bin/          -> Compiled executable
|-- build/        -> Temporary object files
|-- data/         -> Keys and test files
|-- Makefile      -> Build script
|-- convert_key.py-> RSA key converter
|-- README.md
```

## Requirements

Install:

* `gcc`, `make`, `openssl`
* `python3` and `cryptography` module:

```bash
pip install cryptography
```

## Build

```bash
make         # Compile program
make clean   # Clean build files
```

## Keys

**TEA key (16 bytes):**

```bash
dd if=/dev/urandom of=data/tea.key bs=16 count=1
```

**ChaCha20 key (32 bytes):**

```bash
dd if=/dev/urandom of=data/chacha20.key bs=32 count=1
```

**RSA keys:**

```bash
openssl genrsa -out data/rsa_private.pem 1024
openssl rsa -in data/rsa_private.pem -pubout -out data/rsa_public.pem
python3 convert_key.py public data/rsa_public.pem data/rsa_pub.key
python3 convert_key.py private data/rsa_private.pem data/rsa_priv.key
```

## Usage

```bash
./bin/crypto -e|-d -a <alg> -i <infile> -k <keyfile> -o <outfile>
```

**Example - ChaCha20:**

```bash
echo "Secret" > data/plaintext.txt
./bin/crypto -e -a chacha20 -i data/plaintext.txt -k data/chacha20.key -o data/ciphertext.chacha
./bin/crypto -d -a chacha20 -i data/ciphertext.chacha -k data/chacha20.key -o data/decrypted.txt
diff data/plaintext.txt data/decrypted.txt
```

**Example - RSA:**

```bash
./bin/crypto -e -a rsa -i data/plaintext.txt -k data/rsa_pub.key -o data/ciphertext.rsa
./bin/crypto -d -a rsa -i data/ciphertext.rsa -k data/rsa_priv.key -o data/decrypted_rsa.txt
diff data/plaintext.txt data/decrypted_rsa.txt
```

---

This project is for educational purposes and demonstrates how cryptographic algorithms work at a low level.
