#include <stdio.h>
#include <stdlib.h>
#include "libsodium_crypto.h"

int main() {
    int result;
    
    result = ls_crypto_init();
    if (result != LS_CRYPTO_SUCCESS) {
        printf("[-] Initialization failed:%d\n", result);
        return 1;
    }
    
    const char *password = "MyStrongPassword123!";
    const char *message = "This is a confidential message!";
    
    if (!ls_crypto_check_password_strength(password)) {
        printf("[-] The password strength is insufficient!\n");
        ls_crypto_cleanup();
        return 1;
    }
    
    uint8_t *ciphertext = NULL;
    size_t ciphertext_len = 0;
    
    result = ls_crypto_encrypt(
        password,
        (const uint8_t*)message,
        strlen(message),
        &ciphertext,
        &ciphertext_len,
        NULL
    );
    
    if (result != LS_CRYPTO_SUCCESS) {
        printf("[-] Encryption failed:%d\n", result);
        ls_crypto_cleanup();
        return 1;
    }
    
    printf("[+] Encryption successful! Ciphertext length: %zu bytes\n", ciphertext_len);
    
    char *encoded = NULL;
    result = ls_crypto_base64_encode(ciphertext, ciphertext_len, &encoded);
    if (result == LS_CRYPTO_SUCCESS) {
        printf("[+] Base64 encoding:%s\n", encoded);
        ls_crypto_free(encoded);
    }
    
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
    
    if (result != LS_CRYPTO_SUCCESS) {
        printf("[-] Decryption failed:%d\n", result);
        ls_crypto_free(ciphertext);
        ls_crypto_cleanup();
        return 1;
    }
    
    printf("[+] Decryption successful! Plaintext: %.*s\n", (int)plaintext_len, plaintext);
    
    ls_crypto_free(ciphertext);
    ls_crypto_free(plaintext);
    ls_crypto_cleanup();
    
    return 0;
}
