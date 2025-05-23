#include "chacha20.hpp"
#include <iostream>

int main()
{
    // AEAD example
    auto key = ChaCha20KeyIVGen::generateKey();
    auto xnonce = ChaCha20KeyIVGen::generateXNonce();
    std::string aad = "header";
    std::string plaintext = "secret message";

    auto enc = XChaCha20Poly1305::aead_encrypt(plaintext, key, xnonce, aad);
    auto dec = XChaCha20Poly1305::aead_decrypt(enc.asString(), key, xnonce, aad);
    std::cout << dec.asString() << std::endl; // "secret message"

    return 0;
}
