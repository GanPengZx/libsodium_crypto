#define _POSIX_C_SOURCE 200809L
#include "libsodium_crypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>

#ifdef _WIN32
#include <windows.h>
#define SLEEP(ms) Sleep(ms)
#else
#include <unistd.h>
#define SLEEP(ms) usleep((ms) * 1000)
#endif

#include <sodium.h>

#define DEFAULT_MAX_PLAINTEXT_SIZE (10 * 1024 * 1024)
#define DEFAULT_MIN_PASSWORD_LEN 12
#define DEFAULT_ARGON_OPS_LIMIT crypto_pwhash_OPSLIMIT_MODERATE
#define DEFAULT_ARGON_MEM_LIMIT crypto_pwhash_MEMLIMIT_MODERATE
#define DEFAULT_DECRYPTION_DELAY_MS 500

#define WEAK_PASS_COUNT 11
static const char *weak_passwords[WEAK_PASS_COUNT] = {
    "password", "123456", "qwerty", "admin", "login", "abc123",
    "letmein", "welcome", "Aa11111111", "Password123!", "12345678"
};

#pragma pack(push, 1)
typedef struct {
    uint8_t version;
    uint8_t salt[crypto_pwhash_SALTBYTES];
    uint8_t nonce[crypto_secretbox_NONCEBYTES];
} encryption_header_t;
#pragma pack(pop)

#ifdef __GNUC__
#define SECURE_MEMZERO(p, n) do { \
    memset((p), 0, (n)); \
    __asm__ __volatile__("" : : "r"(p) : "memory"); \
} while (0)
#elif defined(_WIN32) && defined(_MSC_VER)
#include <windows.h>
#define SECURE_MEMZERO(p, n) SecureZeroMemory((p), (n))
#else
#define SECURE_MEMZERO(p, n) sodium_memzero((p), (n))
#endif

static size_t safe_strlen(const char *str);
static int safe_strcasecmp(const char *a, const char *b);
static int check_password_internal(const char *password);
static char* base64_encode_wrapper(const uint8_t *data, size_t len);
static int base64_decode_wrapper(const char *encoded, uint8_t **data, size_t *len);

static int g_initialized = 0;

ls_crypto_config_t ls_crypto_default_config(void) {
    ls_crypto_config_t config;
    config.max_plaintext_size = DEFAULT_MAX_PLAINTEXT_SIZE;
    config.min_password_length = DEFAULT_MIN_PASSWORD_LEN;
    config.argon_ops_limit = DEFAULT_ARGON_OPS_LIMIT;
    config.argon_mem_limit = DEFAULT_ARGON_MEM_LIMIT;
    config.decryption_delay_ms = DEFAULT_DECRYPTION_DELAY_MS;
    return config;
}

int ls_crypto_init(void) {
    if (g_initialized) return LS_CRYPTO_SUCCESS;
    
    if (sodium_init() < 0) {
        return LS_CRYPTO_ERR_INIT_FAILED;
    }
    
    g_initialized = 1;
    return LS_CRYPTO_SUCCESS;
}

void ls_crypto_cleanup(void) {
    g_initialized = 0;
}

static size_t safe_strlen(const char *str) {
    if (!str) return 0;
    size_t len = 0;
    while (str[len] != '\0' && len < 4096) {
        len++;
    }
    return len;
}

static int safe_strcasecmp(const char *a, const char *b) {
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) {
            return *a - *b;
        }
        a++;
        b++;
    }
    return *a - *b;
}

int ls_crypto_check_password_strength(const char *password) {
    return check_password_internal(password);
}

static int check_password_internal(const char *password) {
    size_t len = safe_strlen(password);
    if (len < DEFAULT_MIN_PASSWORD_LEN) return 0;

    for (size_t i = 0; i < WEAK_PASS_COUNT; i++) {
        if (safe_strcasecmp(password, weak_passwords[i]) == 0) {
            return 0;
        }
    }

    int has_upper = 0, has_lower = 0, has_digit = 0, has_special = 0;
    for (size_t i = 0; i < len; i++) {
        if (isupper(password[i])) has_upper = 1;
        else if (islower(password[i])) has_lower = 1;
        else if (isdigit(password[i])) has_digit = 1;
        else has_special = 1;
    }

    int diversity = has_upper + has_lower + has_digit + has_special;
    if (diversity < 3) return 0;

    int repeat_count = 1;
    for (size_t i = 1; i < len; i++) {
        if (password[i] == password[i-1]) {
            repeat_count++;
            if (repeat_count >= 4) return 0;
        } else {
            repeat_count = 1;
        }
    }
    
    if (len >= 4) {
        int is_sequential = 1;
        for (size_t i = 1; i < 4; i++) {
            if (password[i] != password[i-1] + 1) {
                is_sequential = 0;
                break;
            }
        }
        if (is_sequential) return 0;
        
        is_sequential = 1;
        for (size_t i = 1; i < 4; i++) {
            if (password[i] != password[i-1] - 1) {
                is_sequential = 0;
                break;
            }
        }
        if (is_sequential) return 0;
    }

    return 1;
}

int ls_crypto_encrypt(
    const char *password,
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t **ciphertext,
    size_t *ciphertext_len,
    const ls_crypto_config_t *config
) {
    if (!g_initialized) return LS_CRYPTO_ERR_INIT_FAILED;
    if (!password || !plaintext || !ciphertext || !ciphertext_len) {
        return LS_CRYPTO_ERR_INVALID_DATA;
    }

    ls_crypto_config_t cfg = config ? *config : ls_crypto_default_config();
    
    if (plaintext_len > cfg.max_plaintext_size) {
        return LS_CRYPTO_ERR_INVALID_DATA;
    }

    uint8_t key[crypto_secretbox_KEYBYTES];
    uint8_t salt[crypto_pwhash_SALTBYTES];
    uint8_t nonce[crypto_secretbox_NONCEBYTES];
    
    *ciphertext_len = sizeof(encryption_header_t) + plaintext_len + crypto_secretbox_MACBYTES;
    *ciphertext = (uint8_t *)sodium_malloc(*ciphertext_len);
    if (!*ciphertext) return LS_CRYPTO_ERR_MEMORY;

    randombytes_buf(salt, sizeof salt);
    randombytes_buf(nonce, sizeof nonce);

    if (crypto_pwhash(key, sizeof key, password, safe_strlen(password), salt,
        cfg.argon_ops_limit, cfg.argon_mem_limit,
        crypto_pwhash_ALG_ARGON2ID13) != 0) {
        SECURE_MEMZERO(key, sizeof key);
        sodium_free(*ciphertext);
        *ciphertext = NULL;
        return LS_CRYPTO_ERR_ENCRYPTION_FAILED;
    }

    encryption_header_t *header = (encryption_header_t *)*ciphertext;
    header->version = 1;
    memcpy(header->salt, salt, sizeof salt);
    memcpy(header->nonce, nonce, sizeof nonce);

    crypto_secretbox_easy(
        (*ciphertext) + sizeof(encryption_header_t),
        plaintext,
        plaintext_len,
        nonce,
        key
    );

    SECURE_MEMZERO(key, sizeof key);
    return LS_CRYPTO_SUCCESS;
}

int ls_crypto_decrypt(
    const char *password,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    uint8_t **plaintext,
    size_t *plaintext_len,
    const ls_crypto_config_t *config
) {
    if (!g_initialized) return LS_CRYPTO_ERR_INIT_FAILED;
    if (!password || !ciphertext || !plaintext || !plaintext_len) {
        return LS_CRYPTO_ERR_INVALID_DATA;
    }

    ls_crypto_config_t cfg = config ? *config : ls_crypto_default_config();
    
    if (ciphertext_len < sizeof(encryption_header_t)) {
        return LS_CRYPTO_ERR_INVALID_DATA;
    }
    
    const encryption_header_t *header = (const encryption_header_t *)ciphertext;
    const uint8_t *cipher_data = ciphertext + sizeof(encryption_header_t);
    size_t cipher_data_len = ciphertext_len - sizeof(encryption_header_t);
    
    if (cipher_data_len < crypto_secretbox_MACBYTES) {
        return LS_CRYPTO_ERR_DECRYPTION_FAILED;
    }

    uint8_t expected_version = 1;
    if (sodium_memcmp(&header->version, &expected_version, 1) != 0) {
        return LS_CRYPTO_ERR_VERSION_MISMATCH;
    }

    uint8_t key[crypto_secretbox_KEYBYTES];
    
    if (crypto_pwhash(key, sizeof key, password, safe_strlen(password), header->salt,
        cfg.argon_ops_limit, cfg.argon_mem_limit,
        crypto_pwhash_ALG_ARGON2ID13) != 0) {
        SECURE_MEMZERO(key, sizeof key);
        return LS_CRYPTO_ERR_DECRYPTION_FAILED;
    }

    *plaintext_len = cipher_data_len - crypto_secretbox_MACBYTES;
    
    *plaintext = (uint8_t *)sodium_malloc(*plaintext_len);
    if (!*plaintext) {
        SECURE_MEMZERO(key, sizeof key);
        return LS_CRYPTO_ERR_MEMORY;
    }

    if (crypto_secretbox_open_easy(*plaintext, cipher_data, cipher_data_len, 
                                   header->nonce, key) != 0) {
        sodium_free(*plaintext);
        *plaintext = NULL;
        SECURE_MEMZERO(key, sizeof key);
        
        if (cfg.decryption_delay_ms > 0) {
            SLEEP(cfg.decryption_delay_ms);
        }
        
        return LS_CRYPTO_ERR_DECRYPTION_FAILED;
    }

    SECURE_MEMZERO(key, sizeof key);
    return LS_CRYPTO_SUCCESS;
}

void ls_crypto_free(void *ptr) {
    if (ptr) {
        sodium_free(ptr);
    }
}

int ls_crypto_base64_encode(
    const uint8_t *data,
    size_t data_len,
    char **encoded
) {
    if (!g_initialized || !data || !encoded) {
        return LS_CRYPTO_ERR_INVALID_DATA;
    }

    char *result = base64_encode_wrapper(data, data_len);
    if (!result) {
        return LS_CRYPTO_ERR_MEMORY;
    }

    *encoded = result;
    return LS_CRYPTO_SUCCESS;
}

int ls_crypto_base64_decode(
    const char *encoded,
    uint8_t **data,
    size_t *data_len
) {
    if (!g_initialized || !encoded || !data || !data_len) {
        return LS_CRYPTO_ERR_INVALID_DATA;
    }

    return base64_decode_wrapper(encoded, data, data_len);
}

void ls_crypto_get_version(int *major, int *minor, int *patch) {
    if (major) *major = LIBSODIUM_CRYPTO_VERSION_MAJOR;
    if (minor) *minor = LIBSODIUM_CRYPTO_VERSION_MINOR;
    if (patch) *patch = LIBSODIUM_CRYPTO_VERSION_PATCH;
}

static char* base64_encode_wrapper(const uint8_t *data, size_t len) {
    size_t b64_len = sodium_base64_encoded_len(len, sodium_base64_VARIANT_ORIGINAL);
    char *b64 = (char *)sodium_malloc(b64_len);
    if (!b64) return NULL;
    
    sodium_bin2base64(b64, b64_len, data, len, sodium_base64_VARIANT_ORIGINAL);
    return b64;
}

static int base64_decode_wrapper(const char *encoded, uint8_t **data, size_t *len) {
    if (!encoded || !data || !len) {
        return LS_CRYPTO_ERR_INVALID_DATA;
    }
    size_t encoded_len = strlen(encoded);
    size_t max_decoded_len = (encoded_len * 3) / 4 + 1;
    uint8_t *decoded = (uint8_t *)sodium_malloc(max_decoded_len);
    if (!decoded) {
        return LS_CRYPTO_ERR_MEMORY;
    }
    if (sodium_base642bin(decoded, max_decoded_len, encoded, encoded_len,
                          NULL, len, NULL,
                          sodium_base64_VARIANT_ORIGINAL) != 0) {
        sodium_free(decoded);
        return LS_CRYPTO_ERR_INVALID_DATA;
    }
    
    *data = decoded;
    return LS_CRYPTO_SUCCESS;
}
