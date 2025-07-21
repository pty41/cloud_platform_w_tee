#ifndef cryptoaes_h__
#define cryptoaes_h__
#include <sys/types.h>
#include <stdint.h>

#define KEY_LEN       32

#if defined(__cplusplus)
extern "C" {
#endif

void expandkeyasm(int nr, char *xk, uint32_t *enc, uint32_t *dec);
void gcmaesinit(char (*pTable)[256], uint32_t *enc, int kslen);
void gcmaesdata(char (*pTable)[256], char *data, char (*tptr)[16], int datalen);
void gcmaesfinish(char (*pTable)[256], char (*tagmask)[16], char (*tptr)[16], uint64_t pLen, uint64_t dLen);
void aesencblock(char (*tagmask)[16], char (*tptr)[16], uint32_t *enc, int kslen);
void gcmaesenc(char (*pTable)[256], char *dst, char *src, char (*tptr)[16], char (*ctr)[16], uint32_t *enc, int pxlen, int kslen);
void gcmaesdec(char (*pTable)[256], char *dst, char *src, char (*tptr)[16], char (*ctr)[16], uint32_t *enc, int pxlen, int kslen);

int encrypt_asm(char *path, char *nonce, uint32_t term, uint8_t *keyvalue, uint8_t *plain, uint8_t *ciphertext, int path_len, int keyvalue_len, int plain_len, int cipher_len);
int decrypt_asm(char *path, uint8_t *keyvalue, uint8_t *cipher, uint8_t *plaintext, int path_len, int keyvalue_len, int cipher_len, int plain_len);

#if defined(__cplusplus)
}
#endif

#endif /* !cryptoaes_h__ */
