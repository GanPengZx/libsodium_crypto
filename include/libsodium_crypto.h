#ifndef LIBSODIUM_CRYPTO_H
#define LIBSODIUM_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LIBSODIUM_CRYPTO_VERSION_MAJOR 3
#define LIBSODIUM_CRYPTO_VERSION_MINOR 1
#define LIBSODIUM_CRYPTO_VERSION_PATCH 5

typedef enum {
    LS_CRYPTO_SUCCESS = 0,
    LS_CRYPTO_ERR_MEMORY = 1,
    LS_CRYPTO_ERR_PASSWORD_WEAK = 2,
    LS_CRYPTO_ERR_ENCRYPTION_FAILED = 3,
    LS_CRYPTO_ERR_DECRYPTION_FAILED = 4,
    LS_CRYPTO_ERR_INVALID_DATA = 5,
    LS_CRYPTO_ERR_VERSION_MISMATCH = 6,
    LS_CRYPTO_ERR_INIT_FAILED = 7
} ls_crypto_error_t;

typedef struct {
    size_t max_plaintext_size;
    int min_password_length;
    int argon_ops_limit;
    int argon_mem_limit;
    int decryption_delay_ms;
} ls_crypto_config_t;

ls_crypto_config_t ls_crypto_default_config(void);

int ls_crypto_init(void);
void ls_crypto_cleanup(void);

int ls_crypto_check_password_strength(const char *password);

int ls_crypto_encrypt(
    const char *password,
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t **ciphertext,
    size_t *ciphertext_len,
    const ls_crypto_config_t *config
);

int ls_crypto_decrypt(
    const char *password,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    uint8_t **plaintext,
    size_t *plaintext_len,
    const ls_crypto_config_t *config
);

void ls_crypto_free(void *ptr);

int ls_crypto_base64_encode(
    const uint8_t *data,
    size_t data_len,
    char **encoded
);

int ls_crypto_base64_decode(
    const char *encoded,
    uint8_t **data,
    size_t *data_len
);

void ls_crypto_get_version(int *major, int *minor, int *patch);

#ifdef __cplusplus
}
#endif

#endif
