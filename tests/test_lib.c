#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "libsodium_crypto.h"

void test_password_strength() {
    assert(ls_crypto_check_password_strength("password") == 0);
    assert(ls_crypto_check_password_strength("123456") == 0);
    assert(ls_crypto_check_password_strength("Aa11111111") == 0);
    assert(ls_crypto_check_password_strength("MyStrongPass123!") == 1);
    printf("[+] Password strength test passed\n");
}

void test_encrypt_decrypt() {
    printf("[*] Testing encryption and decryption...\n");
    
    ls_crypto_init();
    
    const char *password = "TestPassword123!";
    const char *original = "Test data";
    
    uint8_t *ciphertext = NULL;
    size_t ciphertext_len = 0;
    
    int result = ls_crypto_encrypt(
        password,
        (const uint8_t*)original,
        strlen(original),
        &ciphertext,
        &ciphertext_len,
        NULL
    );
    
    assert(result == LS_CRYPTO_SUCCESS);
    assert(ciphertext != NULL);
    assert(ciphertext_len > 0);
    
    uint8_t *plaintext = NULL;
    size_t plaintext_len = 0;
    
    result = ls_crypto_decrypt(
        password,
        ciphertext,
        ciphertext_len,
        &plaintext,
        &plaintext_len,
        NULL
    );
    
    assert(result == LS_CRYPTO_SUCCESS);
    assert(plaintext != NULL);
    assert(plaintext_len == strlen(original));
    assert(memcmp(plaintext, original, plaintext_len) == 0);
    
    ls_crypto_free(ciphertext);
    ls_crypto_free(plaintext);
    ls_crypto_cleanup();
    
    printf("[+] Encryption and decryption test passed\n");
}

void test_wrong_password() {
    printf("[*] Testing wrong password...\n");
    
    ls_crypto_init();
    
    const char *password = "CorrectPassword123!";
    const char *wrong_password = "WrongPassword123!";
    const char *data = "Test data";
    
    uint8_t *ciphertext = NULL;
    size_t ciphertext_len = 0;
    
    ls_crypto_encrypt(password, (const uint8_t*)data, strlen(data),
                     &ciphertext, &ciphertext_len, NULL);
    
    uint8_t *plaintext = NULL;
    size_t plaintext_len = 0;
    
    int result = ls_crypto_decrypt(wrong_password, ciphertext, ciphertext_len,
                                  &plaintext, &plaintext_len, NULL);
    
    assert(result == LS_CRYPTO_ERR_DECRYPTION_FAILED);
    assert(plaintext == NULL);
    
    ls_crypto_free(ciphertext);
    ls_crypto_cleanup();
    
    printf("[+] Wrong password test passed\n");
}

int main() {
    printf("[*] Running libsodium_crypto tests...\n\n");
    
    test_password_strength();
    test_encrypt_decrypt();
    test_wrong_password();
    
    printf("\n[+] All tests passed!\n");
    return 0;
}
