#include <stdint.h>
#include <stddef.h>

// Encrypts data and returns a pointer to the ciphertext
uint8_t* encrypt_vault_data(
    const uint8_t* key_ptr,
    const uint8_t* data_ptr,
    size_t data_len,
    const uint8_t* nonce_ptr,
    size_t* out_len
);

// Decrypts data and returns a pointer to the plaintext
uint8_t* decrypt_vault_data(
    const uint8_t* key_ptr,
    const uint8_t* cipher_ptr,
    size_t cipher_len,
    const uint8_t* nonce_ptr,
    size_t* out_len
);

// Frees memory allocated by Rust
void free_vault_buffer(uint8_t* ptr, size_t len);