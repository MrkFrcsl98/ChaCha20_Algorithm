#include "chacha20.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int main()
{
    srand((unsigned)time(NULL)); // For random_fill demo

    uint8_t key[32];
    uint8_t xnonce[24];
    generate_key(key);
    generate_xnonce(xnonce);

    const char *msg = "Secret message, with AEAD and XChaCha20!";
    size_t msglen = strlen(msg);

    uint8_t aad[] = "authdata";
    size_t aadlen = sizeof(aad) - 1;

    uint8_t ciphertext[256];
    uint8_t tag[16];
    uint8_t decrypted[256];

    xchacha20poly1305_encrypt((const uint8_t *)msg, msglen, key, xnonce, aad, aadlen, ciphertext, tag);

    printf("Ciphertext (hex): ");
    char hex[1024];
    to_hex(ciphertext, msglen, hex);
    puts(hex);
    printf("Tag: ");
    to_hex(tag, 16, hex);
    puts(hex);

    if (xchacha20poly1305_decrypt(ciphertext, msglen, key, xnonce, aad, aadlen, tag, decrypted) == 0)
    {
        printf("Decrypted: %.*s\n", (int)msglen, decrypted);
    }
    else
    {
        printf("Auth failed\n");
    }

    // Show base64 example
    char b64[1024];
    to_base64(ciphertext, msglen, b64);
    printf("Base64: %s\n", b64);

    size_t blen;
    uint8_t decoded[256];
    from_base64(b64, decoded, &blen);
    printf("Decoded matches: %s\n", memcmp(ciphertext, decoded, msglen) == 0 ? "yes" : "no");

    return 0;
}
