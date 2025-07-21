#ifndef apptest_h__
#define apptest_h__
#include <stdint.h>
#include <sys/types.h>

#if defined(__cplusplus)
extern "C" {
#endif
int ocall_decryptkeyring(char *path, uint8_t *keyvalue, uint8_t *cipher, uint8_t *plaintext, int path_len, int keyvalue_len, int cipher_len, int plain_len);
int ocall_decrypt_store_keyring(char *path, uint8_t *keyvalue, uint8_t *cipher, uint8_t *plaintext, int path_len, int keyvalue_len, int cipher_len, int plain_len, int *term);
int ocall_encryptkeyring(char *path, uint32_t term, uint8_t *keyvalue, uint8_t *plain, uint8_t *ciphertext, int path_len, int keyvalue_len, int plain_len, int cipher_len);
int ocall_crypto(char *path, uint32_t term, uint8_t *plain, uint8_t *ciphertext, int path_len, int plain_len, int cipher_len, int encryptmode);

#if defined(__cplusplus)
}
#endif

#endif /* !apptest_h__ */
