# ChaCha20 Algorithm: C and C++ Implementations

[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![C++17 Ready](https://img.shields.io/badge/C%2B%2B-17-blue.svg)](https://en.cppreference.com/w/cpp/17)
[![C99 Ready](https://img.shields.io/badge/C-99-blue.svg)](https://en.cppreference.com/w/c/99)
[![ChaCha20 Algorithm](https://img.shields.io/badge/algorithm-ChaCha20-lightgrey.svg)](https://en.wikipedia.org/wiki/Salsa20#ChaCha_variant)
[![Key Sizes: 256-bit](https://img.shields.io/badge/key%20size-256--bit-green.svg)](https://en.wikipedia.org/wiki/Salsa20#ChaCha_variant)
[![Nonce Sizes: 96/192-bit](https://img.shields.io/badge/nonce%20size-96/192--bit-green.svg)](https://en.wikipedia.org/wiki/Salsa20#ChaCha_variant)
[![Type: Stream Cipher](https://img.shields.io/badge/type-stream--cipher-important.svg)](https://en.wikipedia.org/wiki/Stream_cipher)
[![Header-only (C++)](https://img.shields.io/badge/header--only-yes-critical.svg)](https://github.com/MrkFrcsl98/ChaCha20_Algorithm/tree/main/c++)
[![Status: Educational](https://img.shields.io/badge/status-educational-important.svg)](#security-notes)
---

## Table of Contents

- [Introduction](#introduction)
- [ChaCha20 History](#chacha20-history)
- [Mathematics and Operations](#mathematics-and-operations)
  - [ChaCha20 State Matrix](#chacha20-state-matrix)
  - [Quarter-Round Function](#quarter-round-function)
  - [Block Function and Keystream Generation](#block-function-and-keystream-generation)
  - [Diagram: State Matrix and Rounds](#diagram-state-matrix-and-rounds)
  - [XChaCha20 and Extended Nonce](#xchacha20-and-extended-nonce)
  - [Diagram: HChaCha20 and XChaCha20](#diagram-hchacha20-and-xchacha20)
- [Project Structure](#project-structure)
- [Build & Usage](#build--usage)
  - [C Example](#c-example)
  - [C++ Example](#c-example-1)
- [API Documentation](#api-documentation)
- [Security Notes](#security-notes)
- [References](#references)
- [License](#license)

---

## Introduction

This repository provides **pure C and C++ implementations** of the [ChaCha20](https://cr.yp.to/chacha/chacha-20080128.pdf) stream cipher and the XChaCha20 variant, designed for portability, clarity, and ease of integration. ChaCha20 is a modern, high-speed, and highly secure cipher used in TLS, SSH, VPNs, and many modern protocols.

---

## ChaCha20 History

ChaCha20 was designed by **Daniel J. Bernstein** in 2008 as a refinement of his earlier Salsa20 cipher. The main goals were to improve diffusion per round and resistance to cryptanalysis, while maintaining simple and fast software implementation on a wide range of CPUs.

ChaCha20 and its authenticated mode (ChaCha20-Poly1305) are standardized by the IETF and are widely adopted in security protocols such as TLS 1.3, OpenSSH, and WireGuard VPNs. The XChaCha20 variant extends the nonce size for safer key management in large-scale systems or random nonces [[1]](https://cr.yp.to/chacha/chacha-20080128.pdf)[[2]](https://loup-vaillant.fr/tutorials/chacha20-design)[[3]](https://protonvpn.com/blog/chacha20/).

---

## Mathematics and Operations

### ChaCha20 State Matrix

ChaCha20 operates on a 512-bit (16 × 32-bit) state matrix, initialized as follows:

```
|  c0 |  c1 |  c2 |  c3 |   (constants: "expa", "nd 3", "2-by", "te k")
|  k0 |  k1 |  k2 |  k3 |   (256-bit key)
|  k4 |  k5 |  k6 |  k7 |   (256-bit key)
| ctr | n0  | n1  | n2  |   (32-bit block counter, 96-bit nonce)
```

#### Diagram: State Matrix

```
+------+------+------+------+------+------+------+------+------+------+------+------+------+------+------+------+------+
| c0   | c1   | c2   | c3   | k0   | k1   | k2   | k3   | k4   | k5   | k6   | k7   | ctr  | n0   | n1   | n2   |
+------+------+------+------+------+------+------+------+------+------+------+------+------+------+------+------+------+
```

- `c0...c3`: Constants (`0x61707865`, `0x3320646e`, `0x79622d32`, `0x6b206574`)
- `k0...k7`: 256-bit key
- `ctr`: 32-bit block counter (prevents keystream reuse)
- `n0...n2`: 96-bit nonce (prevents nonce reuse)

### Quarter-Round Function

The **quarter-round** function is the heart of ChaCha20, mixing four 32-bit words (`a, b, c, d`) using only addition, XOR, and bitwise rotation:

```c
a += b; d ^= a; d = ROTL32(d, 16);
c += d; b ^= c; b = ROTL32(b, 12);
a += b; d ^= a; d = ROTL32(d, 8);
c += d; b ^= c; b = ROTL32(b, 7);
```

- `ROTL32(x, n)` = rotate-left 32-bit integer `x` by `n` bits.

This operation is repeated in a specific pattern (column rounds and diagonal rounds) over the state matrix for 20 rounds (10 double rounds).

#### Diagram: Quarter-Round

```
Input:   a  b  c  d
Step 1:  a += b;  d ^= a;  d <<<= 16;
Step 2:  c += d;  b ^= c;  b <<<= 12;
Step 3:  a += b;  d ^= a;  d <<<= 8;
Step 4:  c += d;  b ^= c;  b <<<= 7;
```

### Block Function and Keystream Generation

After 20 rounds (10 column rounds, 10 diagonal rounds), each word of the original state is added to the corresponding word of the working state. The state is serialized in little-endian order to produce a 64-byte keystream block.

Encryption/decryption:

```
ciphertext = plaintext XOR keystream
plaintext  = ciphertext XOR keystream
```

The block counter is incremented for each 64-byte block.

#### Diagram: ChaCha20 Block

```
Initial State --> 20 Rounds of Quarter-Rounds --> Add original state --> Serialize --> 64-byte keystream block
```

### XChaCha20 and Extended Nonce

**XChaCha20** is a variant that uses a 192-bit (24-byte) nonce (compared to ChaCha20's 96-bit/12-byte nonce), allowing random nonces or unique message IDs without risk of nonce reuse.

- The **HChaCha20** function is used with the first 16 bytes of the nonce and the key to derive a subkey.
- The last 8 bytes of the nonce are used as the nonce for a ChaCha20 operation with the subkey.

#### Diagram: XChaCha20 Construction

```
Original Key + First 16 bytes of XNonce (24 bytes) --[HChaCha20]--> Subkey (32 bytes)
Subkey + Last 8 bytes of XNonce + Counter --[ChaCha20]--> Keystream
```

---

## Project Structure

```
C/          # Pure C implementation (chacha2.c)
c++/        # C++ implementation (chacha20.hpp)
README.md  
LICENSE
```

---

## Build & Usage

### C Example

```c
#include "chacha2.c"
#include <stdio.h>
#include <string.h>

int main() {
    unsigned char key[32] = {0};
    unsigned char nonce[12] = {0};
    const char *message = "Hello, ChaCha20!";
    size_t msg_len = strlen(message);
    unsigned char ciphertext[msg_len], decrypted[msg_len];

    chacha20_xor(ciphertext, (const unsigned char *)message, msg_len, key, nonce, 1);
    printf("Ciphertext (hex): ");
    for (size_t i = 0; i < msg_len; ++i) printf("%02x", ciphertext[i]);
    printf("\n");

    chacha20_xor(decrypted, ciphertext, msg_len, key, nonce, 1);
    printf("Decrypted: %.*s\n", (int)msg_len, decrypted);
    return 0;
}
```

#### XChaCha20 in C

```c
#include "chacha2.c"
#include <stdio.h>
#include <string.h>

int main() {
    unsigned char key[32] = {0};
    unsigned char xnonce[24] = {0}; // 24-byte nonce
    const char *msg = "XChaCha20 with 24-byte nonce!";
    size_t msg_len = strlen(msg);
    unsigned char ciphertext[msg_len], decrypted[msg_len];

    xchacha20_xor(ciphertext, (const unsigned char *)msg, msg_len, key, xnonce, 1);
    printf("Ciphertext (hex): ");
    for (size_t i = 0; i < msg_len; ++i) printf("%02x", ciphertext[i]);
    printf("\n");

    xchacha20_xor(decrypted, ciphertext, msg_len, key, xnonce, 1);
    printf("Decrypted: %.*s\n", (int)msg_len, decrypted);
    return 0;
}
```

### C++ Example

```cpp
#include "chacha20.hpp"
#include <iostream>
#include <string>

int main() {
    std::string key(32, 0);
    std::string iv(12, 0);
    std::string plaintext = "Hello, ChaCha20 C++!";

    ChaCha20 chacha;
    std::string ciphertext = chacha.encrypt(plaintext, key, iv, 1).asString();
    std::string decrypted  = chacha.decrypt(ciphertext, key, iv, 1).asString();

    std::cout << "Decrypted: " << decrypted << std::endl;

    // XChaCha20 Example
    std::string xkey(32, 0);
    std::string xnonce(24, 0);
    XChaCha20 xchacha;
    std::string xct = xchacha.encrypt(plaintext, xkey, xnonce, 1).asString();
    std::string xpt = xchacha.decrypt(xct, xkey, xnonce, 1).asString();
    std::cout << "XChaCha20 decrypted: " << xpt << std::endl;

    return 0;
}
```

---

## API Documentation

### C API

#### ChaCha20

```c
void chacha20_xor(unsigned char *out,
                  const unsigned char *in,
                  size_t len,
                  const unsigned char key[32],
                  const unsigned char nonce[12],
                  uint32_t counter);
```
- Encrypts/decrypts `len` bytes from `in` to `out` using the provided key, nonce, and block counter.

#### XChaCha20

```c
void xchacha20_xor(unsigned char *out,
                   const unsigned char *in,
                   size_t len,
                   const unsigned char key[32],
                   const unsigned char xnonce[24],
                   uint32_t counter);
```
- Encrypts/decrypts with a 24-byte nonce using the XChaCha20 construction.

#### Helpers

- `void generate_key(unsigned char key[32]);`
- `void generate_iv(unsigned char iv[12]);`
- `void generate_xnonce(unsigned char xnonce[24]);`
- `void to_hex(const unsigned char *data, size_t len, char *out);`

### C++ API

#### ChaCha20

```cpp
ChaCha20Result ChaCha20::encrypt(const std::string &plaintext, const std::string &key, const std::string &iv, uint32_t counter = 0) const;
ChaCha20Result ChaCha20::decrypt(const std::string &ciphertext, const std::string &key, const std::string &iv, uint32_t counter = 0) const;
```

#### XChaCha20

```cpp
ChaCha20Result XChaCha20::encrypt(const std::string &plaintext, const std::string &key, const std::string &xnonce, uint32_t counter = 0) const;
ChaCha20Result XChaCha20::decrypt(const std::string &ciphertext, const std::string &key, const std::string &xnonce, uint32_t counter = 0) const;
```

#### Utilities

- Hex/Base64/binary conversion functions and random key/nonce generators.

---

## Security Notes

- **Never reuse a key/nonce pair.** This can be catastrophic for stream ciphers.
- Use a secure random number generator for keys and nonces. (This repo provides helpers for that.)
- For authenticated encryption, use ChaCha20-Poly1305 or XChaCha20-Poly1305.

---

## References

1. [ChaCha20 Design Paper (D.J. Bernstein)](https://cr.yp.to/chacha/chacha-20080128.pdf)
2. [ChaCha20 on Cryptography Primer](https://www.cryptography-primer.info/algorithms/chacha/)
3. [Loup Vaillant, The design of Chacha20](https://loup-vaillant.fr/tutorials/chacha20-design)
4. [ProtonVPN: What is ChaCha20?](https://protonvpn.com/blog/chacha20/)
5. [IETF ChaCha20 and Poly1305 for IETF protocols (RFC 8439)](https://datatracker.ietf.org/doc/html/rfc8439)

---

## License

This repository is licensed under the MIT License. See [LICENSE](LICENSE) for details.
