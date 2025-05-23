#ifndef CHACHA20_FULL_H
#define CHACHA20_FULL_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

// ========== Attribute Macros ==========
#if defined(__GNUC__) || defined(__clang__)
#define __attr_nodiscard __attribute__((warn_unused_result))
#define __attr_malloc __attribute__((malloc))
#define __attr_hot __attribute__((hot))
#define __attr_cold __attribute__((cold))
#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#else
#define __attr_nodiscard
#define __attr_malloc
#define __attr_hot
#define __attr_cold
#define likely(x)   (x)
#define unlikely(x) (x)
#endif

#ifdef __cplusplus
#define __restrict__ __restrict
#define __noexcept noexcept
#define __const_noexcept const noexcept
#else
#define __restrict__ restrict
#define __noexcept
#define __const_noexcept
#endif

#define CHACHA20_KEY_SIZE 32
#define CHACHA20_NONCE_SIZE 12
#define CHACHA20_XNONCE_SIZE 24
#define CHACHA20_BLOCK_SIZE 64
#define POLY1305_TAG_SIZE 16

// ========== Secure Randomness ==========
__attr_hot static inline void get_secure_random_bytes(void *buf, size_t len) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (unlikely(fd < 0)) {
        perror("open /dev/urandom");
        abort();
    }
    ssize_t r = read(fd, buf, len);
    if (unlikely(r != (ssize_t)len)) {
        perror("read /dev/urandom");
        close(fd);
        abort();
    }
    close(fd);
}

// ========== Encoding Utilities ==========

static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char b64_pad = '=';

// Hex encode
__attr_hot static inline void to_hex(const unsigned char * __restrict__ data, size_t len, char * __restrict__ out) __noexcept {
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < len; ++i) {
        out[2*i]   = hex[data[i] >> 4];
        out[2*i+1] = hex[data[i] & 0xF];
    }
    out[2*len] = 0;
}

// Hex decode
__attr_hot static inline int from_hex(const char * __restrict__ hexstr, unsigned char * __restrict__ out, size_t outlen) __noexcept {
    size_t len = strlen(hexstr);
    if (len % 2 != 0 || outlen < len/2) return -1;
    for (size_t i = 0; i < len; i += 2) {
        unsigned int hi, lo;
        if (sscanf(hexstr + i, "%1x%1x", &hi, &lo) != 2) return -1;
        out[i/2] = (hi << 4) | lo;
    }
    return 0;
}

// Base64 encode
__attr_hot static inline void to_base64(const unsigned char * __restrict__ data, size_t len, char * __restrict__ out) __noexcept {
    size_t i, j;
    for (i = 0, j = 0; i < len;) {
        uint32_t octet_a = i < len ? data[i++] : 0;
        uint32_t octet_b = i < len ? data[i++] : 0;
        uint32_t octet_c = i < len ? data[i++] : 0;
        uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;
        out[j++] = b64_table[(triple >> 18) & 0x3F];
        out[j++] = b64_table[(triple >> 12) & 0x3F];
        out[j++] = (i > len+1) ? b64_pad : b64_table[(triple >> 6) & 0x3F];
        out[j++] = (i > len)   ? b64_pad : b64_table[triple & 0x3F];
    }
    out[j] = 0;
}

// Base64 decode
__attr_hot static inline int from_base64(const char * __restrict__ in, unsigned char * __restrict__ out, size_t *outlen) __noexcept {
    size_t len = strlen(in), j = 0;
    int val = 0, valb = -8;
    for (size_t i = 0; i < len; ++i) {
        unsigned char c = in[i];
        int d;
        if (c >= 'A' && c <= 'Z') d = c - 'A';
        else if (c >= 'a' && c <= 'z') d = c - 'a' + 26;
        else if (c >= '0' && c <= '9') d = c - '0' + 52;
        else if (c == '+') d = 62;
        else if (c == '/') d = 63;
        else if (c == b64_pad) break;
        else continue;
        val = (val << 6) + d;
        valb += 6;
        if (valb >= 0) {
            out[j++] = (unsigned char)((val >> valb) & 0xFF);
            valb -= 8;
        }
    }
    *outlen = j;
    return 0;
}

// Binary encode
__attr_hot static inline void to_binary(const unsigned char * __restrict__ data, size_t len, char * __restrict__ out) __noexcept {
    for (size_t i = 0; i < len; ++i)
        for (int j = 7; j >= 0; --j)
            *out++ = (data[i] & (1 << j)) ? '1' : '0';
    *out = 0;
}

// Binary decode
__attr_hot static inline int from_binary(const char * __restrict__ bin, unsigned char * __restrict__ out, size_t outlen) __noexcept {
    size_t len = strlen(bin);
    if (len % 8 != 0 || outlen < len/8) return -1;
    for (size_t i = 0; i < len; i += 8) {
        unsigned char val = 0;
        for (int j = 0; j < 8; ++j)
            val = (val << 1) | (bin[i+j] == '1' ? 1 : 0);
        out[i/8] = val;
    }
    return 0;
}

// ========== Key/IV/XNonce Utilities ==========

__attr_hot static inline void generate_key(unsigned char key[32]) {
    get_secure_random_bytes(key, 32);
}
__attr_hot static inline void generate_iv(unsigned char iv[12]) {
    get_secure_random_bytes(iv, 12);
}
__attr_hot static inline void generate_xnonce(unsigned char xnonce[24]) {
    get_secure_random_bytes(xnonce, 24);
}

// ========== ChaCha20 Core ==========

__attr_hot static inline uint32_t le32(const unsigned char *p) __noexcept {
    return ((uint32_t)p[0]) | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
__attr_hot static inline void store32(unsigned char *p, uint32_t x) __noexcept {
    p[0] = (x) & 0xff; p[1] = (x>>8) & 0xff; p[2] = (x>>16) & 0xff; p[3] = (x>>24) & 0xff;
}
__attr_hot static inline void store64(unsigned char *p, uint64_t x) __noexcept {
    for (int i = 0; i < 8; ++i) p[i] = (x>>(8*i))&0xFF;
}
__attr_hot static inline void chacha20_quarterround(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) __noexcept {
    *a += *b; *d ^= *a; *d = (*d << 16) | (*d >> 16);
    *c += *d; *b ^= *c; *b = (*b << 12) | (*b >> 20);
    *a += *b; *d ^= *a; *d = (*d << 8) | (*d >> 24);
    *c += *d; *b ^= *c; *b = (*b << 7) | (*b >> 25);
}
__attr_hot static inline void chacha20_block(uint32_t out[16], const unsigned char key[32], const unsigned char nonce[12], uint32_t counter) __noexcept {
    static const uint32_t c[4] = {0x61707865,0x3320646e,0x79622d32,0x6b206574};
    int i;
    uint32_t state[16];
    state[0]=c[0]; state[1]=c[1]; state[2]=c[2]; state[3]=c[3];
    for(i=0;i<8;++i) state[4+i]=le32(key+4*i);
    state[12]=counter;
    state[13]=le32(nonce+0); state[14]=le32(nonce+4); state[15]=le32(nonce+8);

    for (i=0;i<16;++i) out[i]=state[i];
    for (i=0;i<10;++i) {
        chacha20_quarterround(&out[0],&out[4],&out[8],&out[12]);
        chacha20_quarterround(&out[1],&out[5],&out[9],&out[13]);
        chacha20_quarterround(&out[2],&out[6],&out[10],&out[14]);
        chacha20_quarterround(&out[3],&out[7],&out[11],&out[15]);
        chacha20_quarterround(&out[0],&out[5],&out[10],&out[15]);
        chacha20_quarterround(&out[1],&out[6],&out[11],&out[12]);
        chacha20_quarterround(&out[2],&out[7],&out[8],&out[13]);
        chacha20_quarterround(&out[3],&out[4],&out[9],&out[14]);
    }
    for (i=0;i<16;++i) out[i]+=state[i];
}
__attr_hot static inline void chacha20_xor(unsigned char * __restrict__ out, const unsigned char * __restrict__ in, size_t len,
    const unsigned char key[32], const unsigned char nonce[12], uint32_t counter) __noexcept
{
    size_t offset = 0;
    uint32_t block[16];
    unsigned char keystream[64];
    while (offset < len) {
        chacha20_block(block, key, nonce, counter++);
        for (size_t i=0;i<16;++i) {
            keystream[i*4+0]=(block[i]>>0)&0xff;
            keystream[i*4+1]=(block[i]>>8)&0xff;
            keystream[i*4+2]=(block[i]>>16)&0xff;
            keystream[i*4+3]=(block[i]>>24)&0xff;
        }
        size_t n = len-offset > 64 ? 64 : len-offset;
        for (size_t i = 0; i < n; ++i)
            out[offset+i]=in[offset+i]^keystream[i];
        offset += n;
    }
}

// ========== XChaCha20 ==========

__attr_hot static inline void hchacha20_block(unsigned char out[32], const unsigned char key[32], const unsigned char nonce[16]) __noexcept {
    static const uint32_t c[4]={0x61707865,0x3320646e,0x79622d32,0x6b206574};
    uint32_t state[16], i;
    state[0]=c[0]; state[1]=c[1]; state[2]=c[2]; state[3]=c[3];
    for(i=0;i<8;++i) state[4+i]=le32(key+4*i);
    for(i=0;i<4;++i) state[12+i]=le32(nonce+4*i);
    for(i=0;i<10;++i) {
        chacha20_quarterround(&state[0],&state[4],&state[8],&state[12]);
        chacha20_quarterround(&state[1],&state[5],&state[9],&state[13]);
        chacha20_quarterround(&state[2],&state[6],&state[10],&state[14]);
        chacha20_quarterround(&state[3],&state[7],&state[11],&state[15]);
        chacha20_quarterround(&state[0],&state[5],&state[10],&state[15]);
        chacha20_quarterround(&state[1],&state[6],&state[11],&state[12]);
        chacha20_quarterround(&state[2],&state[7],&state[8],&state[13]);
        chacha20_quarterround(&state[3],&state[4],&state[9],&state[14]);
    }
    for(i=0;i<4;++i) store32(out+4*i,state[i]);
    for(i=0;i<4;++i) store32(out+16+4*i,state[12+i]);
}

__attr_hot static inline void xchacha20_xor(unsigned char * __restrict__ out, const unsigned char * __restrict__ in, size_t len,
    const unsigned char key[32], const unsigned char xnonce[24], uint32_t counter) __noexcept
{
    unsigned char subkey[32];
    hchacha20_block(subkey, key, xnonce);
    unsigned char nonce[12];
    memset(nonce, 0, 4); // counter=0 in nonce, counter parameter is used in chacha20_xor
    memcpy(nonce+4, xnonce+16, 8);
    chacha20_xor(out, in, len, subkey, nonce, counter);
}

// ========== Poly1305 MAC ==========

__attr_hot static inline void poly1305_mac(unsigned char out[16], const unsigned char *m, size_t mlen, const unsigned char key[32]) __noexcept {
    uint32_t r[5], h[5] = {0}, pad[4];
    uint64_t d[5], c;
    size_t i, blocks = mlen / 16;

    r[0] = (key[0] | (key[1] << 8) | (key[2] << 16) | (key[3] << 24)) & 0x3ffffff;
    r[1] = ((key[3] >> 2) | (key[4] << 6) | (key[5] << 14) | (key[6] << 22)) & 0x3ffff03;
    r[2] = ((key[6] >> 4) | (key[7] << 4) | (key[8] << 12) | (key[9] << 20)) & 0x3ffc0ff;
    r[3] = ((key[9] >> 6) | (key[10] << 2) | (key[11] << 10) | (key[12] << 18)) & 0x3f03fff;
    r[4] = (key[13] | (key[14] << 8) | (key[15] << 16)) & 0x00fffff;

    pad[0] = (key[16] | (key[17] << 8) | (key[18] << 16) | (key[19] << 24));
    pad[1] = (key[20] | (key[21] << 8) | (key[22] << 16) | (key[23] << 24));
    pad[2] = (key[24] | (key[25] << 8) | (key[26] << 16) | (key[27] << 24));
    pad[3] = (key[28] | (key[29] << 8) | (key[30] << 16) | (key[31] << 24));

    const unsigned char *ptr = m;
    size_t rem = mlen;
    while (rem >= 16) {
        uint32_t t0 = ptr[0] | (ptr[1] << 8) | (ptr[2] << 16) | (ptr[3] << 24);
        uint32_t t1 = ptr[4] | (ptr[5] << 8) | (ptr[6] << 16) | (ptr[7] << 24);
        uint32_t t2 = ptr[8] | (ptr[9] << 8) | (ptr[10] << 16) | (ptr[11] << 24);
        uint32_t t3 = ptr[12] | (ptr[13] << 8) | (ptr[14] << 16) | (ptr[15] << 24);

        h[0] += t0 & 0x3ffffff;
        h[1] += ((t0 >> 26) | (t1 << 6)) & 0x3ffffff;
        h[2] += ((t1 >> 20) | (t2 << 12)) & 0x3ffffff;
        h[3] += ((t2 >> 14) | (t3 << 18)) & 0x3ffffff;
        h[4] += (t3 >> 8) | (1 << 24);

        d[0] = (uint64_t)h[0] * r[0] + (uint64_t)h[1] * 5 * r[4] + (uint64_t)h[2] * 5 * r[3] + (uint64_t)h[3] * 5 * r[2] + (uint64_t)h[4] * 5 * r[1];
        d[1] = (uint64_t)h[0] * r[1] + (uint64_t)h[1] * r[0] + (uint64_t)h[2] * 5 * r[4] + (uint64_t)h[3] * 5 * r[3] + (uint64_t)h[4] * 5 * r[2];
        d[2] = (uint64_t)h[0] * r[2] + (uint64_t)h[1] * r[1] + (uint64_t)h[2] * r[0] + (uint64_t)h[3] * 5 * r[4] + (uint64_t)h[4] * 5 * r[3];
        d[3] = (uint64_t)h[0] * r[3] + (uint64_t)h[1] * r[2] + (uint64_t)h[2] * r[1] + (uint64_t)h[3] * r[0] + (uint64_t)h[4] * 5 * r[4];
        d[4] = (uint64_t)h[0] * r[4] + (uint64_t)h[1] * r[3] + (uint64_t)h[2] * r[2] + (uint64_t)h[3] * r[1] + (uint64_t)h[4] * r[0];

        c = d[0] >> 26; h[0] = d[0] & 0x3ffffff; d[1] += c;
        c = d[1] >> 26; h[1] = d[1] & 0x3ffffff; d[2] += c;
        c = d[2] >> 26; h[2] = d[2] & 0x3ffffff; d[3] += c;
        c = d[3] >> 26; h[3] = d[3] & 0x3ffffff; d[4] += c;
        c = d[4] >> 26; h[4] = d[4] & 0x3ffffff; h[0] += c * 5;
        c = h[0] >> 26; h[0] &= 0x3ffffff; h[1] += c;

        ptr += 16;
        rem -= 16;
    }
    if (rem) {
        unsigned char block[16] = {0};
        memcpy(block, ptr, rem);
        block[rem] = 1;
        uint32_t t0 = block[0] | (block[1] << 8) | (block[2] << 16) | (block[3] << 24);
        uint32_t t1 = block[4] | (block[5] << 8) | (block[6] << 16) | (block[7] << 24);
        uint32_t t2 = block[8] | (block[9] << 8) | (block[10] << 16) | (block[11] << 24);
        uint32_t t3 = block[12] | (block[13] << 8) | (block[14] << 16) | (block[15] << 24);
        h[0] += t0 & 0x3ffffff;
        h[1] += ((t0 >> 26) | (t1 << 6)) & 0x3ffffff;
        h[2] += ((t1 >> 20) | (t2 << 12)) & 0x3ffffff;
        h[3] += ((t2 >> 14) | (t3 << 18)) & 0x3ffffff;
        h[4] += (t3 >> 8);
    }
    c = h[1] >> 26; h[1] &= 0x3ffffff; h[2] += c;
    c = h[2] >> 26; h[2] &= 0x3ffffff; h[3] += c;
    c = h[3] >> 26; h[3] &= 0x3ffffff; h[4] += c;
    c = h[4] >> 26; h[4] &= 0x3ffffff; h[0] += c * 5;
    c = h[0] >> 26; h[0] &= 0x3ffffff; h[1] += c;

    uint32_t g[5];
    g[0] = h[0] + 5;
    c = g[0] >> 26; g[0] &= 0x3ffffff;
    g[1] = h[1] + c;
    c = g[1] >> 26; g[1] &= 0x3ffffff;
    g[2] = h[2] + c;
    c = g[2] >> 26; g[2] &= 0x3ffffff;
    g[3] = h[3] + c;
    c = g[3] >> 26; g[3] &= 0x3ffffff;
    g[4] = h[4] + c - (1UL << 26);

    uint32_t mask = (g[4] >> 31) - 1;
    for (i = 0; i < 5; ++i) h[i] = (h[i] & ~mask) | (g[i] & mask);

    uint64_t f0 = ((uint64_t)h[0]) | ((uint64_t)h[1] << 26);
    uint64_t f1 = ((uint64_t)h[1] >> 6) | ((uint64_t)h[2] << 20);
    uint64_t f2 = ((uint64_t)h[2] >> 12) | ((uint64_t)h[3] << 14);
    uint64_t f3 = ((uint64_t)h[3] >> 18) | ((uint64_t)h[4] << 8);

    f0 = (f0 + pad[0]) & 0xffffffff;
    f1 = (f1 + pad[1]) & 0xffffffff;
    f2 = (f2 + pad[2]) & 0xffffffff;
    f3 = (f3 + pad[3]) & 0xffffffff;

    out[0] = f0 & 0xff;   out[1] = (f0 >> 8) & 0xff;   out[2] = (f0 >> 16) & 0xff;   out[3] = (f0 >> 24) & 0xff;
    out[4] = f1 & 0xff;   out[5] = (f1 >> 8) & 0xff;   out[6] = (f1 >> 16) & 0xff;   out[7] = (f1 >> 24) & 0xff;
    out[8] = f2 & 0xff;   out[9] = (f2 >> 8) & 0xff;   out[10] = (f2 >> 16) & 0xff;  out[11] = (f2 >> 24) & 0xff;
    out[12] = f3 & 0xff;  out[13] = (f3 >> 8) & 0xff;  out[14] = (f3 >> 16) & 0xff;  out[15] = (f3 >> 24) & 0xff;
}

// ========== AEAD: XChaCha20-Poly1305 ==========

__attr_hot static inline int xchacha20poly1305_encrypt(
    const unsigned char * __restrict__ plaintext, size_t plen,
    const unsigned char key[32], const unsigned char xnonce[24],
    const unsigned char * __restrict__ aad, size_t aadlen,
    unsigned char * __restrict__ out, unsigned char tag[16]) __noexcept
{
    unsigned char block[64] = {0};
    xchacha20_xor(block, block, 64, key, xnonce, 0);
    const unsigned char *polykey = block;

    xchacha20_xor(out, plaintext, plen, key, xnonce, 1);

    size_t maclen = ((aadlen+15)/16)*16 + ((plen+15)/16)*16 + 16;
    unsigned char *macdata = (unsigned char*)malloc(maclen);
    size_t m = 0;
    memcpy(macdata+m, aad, aadlen); m += aadlen;
    if (aadlen%16) { memset(macdata+m, 0, 16-(aadlen%16)); m += 16-(aadlen%16);}
    memcpy(macdata+m, out, plen); m += plen;
    if (plen%16) { memset(macdata+m, 0, 16-(plen%16)); m += 16-(plen%16);}
    store64(macdata+m, aadlen); store64(macdata+m+8, plen); m+=16;

    poly1305_mac(tag, macdata, m, polykey);

    free(macdata);
    return 0;
}

__attr_hot static inline int xchacha20poly1305_decrypt(
    const unsigned char * __restrict__ ciphertext, size_t clen,
    const unsigned char key[32], const unsigned char xnonce[24],
    const unsigned char * __restrict__ aad, size_t aadlen,
    const unsigned char tag[16],
    unsigned char * __restrict__ out) __noexcept
{
    unsigned char block[64] = {0};
    xchacha20_xor(block, block, 64, key, xnonce, 0);
    const unsigned char *polykey = block;

    size_t maclen = ((aadlen+15)/16)*16 + ((clen+15)/16)*16 + 16;
    unsigned char *macdata = (unsigned char*)malloc(maclen);
    size_t m = 0;
    memcpy(macdata+m, aad, aadlen); m += aadlen;
    if (aadlen%16) { memset(macdata+m, 0, 16-(aadlen%16)); m += 16-(aadlen%16);}
    memcpy(macdata+m, ciphertext, clen); m += clen;
    if (clen%16) { memset(macdata+m, 0, 16-(clen%16)); m += 16-(clen%16);}
    store64(macdata+m, aadlen); store64(macdata+m+8, clen); m+=16;

    unsigned char computed_tag[16];
    poly1305_mac(computed_tag, macdata, m, polykey);

    int ok = memcmp(tag, computed_tag, 16) == 0;
    free(macdata);

    if (!ok) return -1;
    xchacha20_xor(out, ciphertext, clen, key, xnonce, 1);
    return 0;
}

#endif // CHACHA20_FULL_H
