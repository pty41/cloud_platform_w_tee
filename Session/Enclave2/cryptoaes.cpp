#include <sys/types.h>
#include <stdint.h>
#include <cstring>
#include "./cryptoaes.h"


#define GCMSTANDARDNONCESIZE 12
#define GCMTAGSIZE 16
#define BLOCKSIZE 16
#define GCMBLOCKSIZE 16
#define TERMSIZE 4
#define AESGCMVERISON1 0x1
#define AESGCMVERISON2 0x2
#define SGX_ERROR_INVALID_PARAMETER -1
#define SGX_SUCCESS 0

static void testcombine(char (*pTable)[256], char *key, int gcmAsm_len, uint32_t *enc, uint32_t *dec) {
  int rounds=10;
	switch (gcmAsm_len-28) {
	case 128 / 8:
		rounds = 10;
	case 192 / 8:
		rounds = 12;
	case 256 / 8:
		rounds = 14;
	}
  expandkeyasm(rounds, &key[0], &enc[0], &dec[0]);
  gcmaesinit(&pTable[0], enc, gcmAsm_len);
}

static void bigEndian_PutUint32(char *buf, uint32_t v) {
  buf[0] = (v >> 24);
	buf[1] = (v >> 16);
	buf[2] = (v >> 8);
	buf[3] = (v);
}

// Refer to the Go cryptography: src/crypto/aes/aes_gcm.go
int encrypt_asm(char *path, char *nonce, uint32_t term, uint8_t *keyvalue, uint8_t *plain, uint8_t *ciphertext, int path_len, int keyvalue_len, int plain_len, int cipher_len) {
  int capacity = TERMSIZE + 1 + GCMSTANDARDNONCESIZE + GCMTAGSIZE + path_len;
	int size = TERMSIZE + 1 + GCMSTANDARDNONCESIZE;

  char out[capacity]; 
  char tagMask[GCMBLOCKSIZE] = {0};
  char counter[GCMBLOCKSIZE] = {0};
  char tagOut [GCMTAGSIZE] = {0};
  char pTablett[256] = {0};

  char out_tmp[4] = {0};
  int nonce_len = GCMSTANDARDNONCESIZE;

  int tail_len = cipher_len-size;
  char tail[tail_len];
  int expand_len = keyvalue_len + 28;
  uint32_t encgo[expand_len];
  uint32_t decgo[expand_len];
  
  testcombine(&pTablett, (char *)keyvalue, expand_len, encgo, decgo);
  bigEndian_PutUint32(out_tmp, term);
	memcpy(out, out_tmp, 4);
  out[4] = AESGCMVERISON2;
  
  memcpy(out+5, nonce, GCMSTANDARDNONCESIZE);
 
  if (nonce_len == GCMSTANDARDNONCESIZE) {
		// Init counter to nonce||1
		memcpy(counter, nonce, nonce_len);
		counter[GCMBLOCKSIZE-1] = 1;
	} else {
		gcmaesdata(&pTablett, nonce, &counter, nonce_len);
		gcmaesfinish(&pTablett, &tagMask, &counter, uint64_t(nonce_len), uint64_t(0));
		// Otherwise counter = GHASH(nonce)
	}

  aesencblock(&tagMask, &counter, encgo, expand_len);
  gcmaesdata(&pTablett, path, &tagOut, path_len);

  // generate the head and tail
  memcpy(tail, out+size, tail_len);

	if (plain_len > 0) {
		gcmaesenc(&pTablett, tail, (char *)plain, &counter, &tagOut, encgo, plain_len, expand_len);
	}

	gcmaesfinish(&pTablett, &tagMask, &tagOut, uint64_t(plain_len), uint64_t(path_len));
  memcpy(tail + plain_len, tagOut, GCMTAGSIZE);
  memcpy((char *)ciphertext, out, cipher_len);
  memcpy((char *)ciphertext+size, tail, tail_len);

  return SGX_SUCCESS;
}

// Refer to the Go cryptography: src/crypto/aes/aes_gcm.go
int decrypt_asm(char *path, uint8_t *keyvalue, uint8_t *cipher, uint8_t *plaintext, int path_len, int keyvalue_len, int cipher_len, int plain_len) {
  
  int expand_len = keyvalue_len + 28;
  char pTablett[256] = {0};
  char nonce[GCMSTANDARDNONCESIZE] = {0};
  int raw_len = cipher_len-5-GCMSTANDARDNONCESIZE;
  char raw[raw_len];

  int nonce_len = GCMSTANDARDNONCESIZE;
  char tag[GCMTAGSIZE] = {0};
  char subciphertext[raw_len-GCMTAGSIZE];
  char tagMask[GCMBLOCKSIZE] = {0};
  char counter[GCMBLOCKSIZE] = {0};
  char expectedTag[GCMTAGSIZE] = {0};

  uint32_t encgo[expand_len];
  uint32_t decgo[expand_len];
  testcombine(&pTablett, (char *)keyvalue, expand_len, encgo, decgo);
 
  memcpy(nonce, (char *)cipher+5, GCMSTANDARDNONCESIZE);
  memcpy(raw, (char *)cipher+5+GCMSTANDARDNONCESIZE, raw_len);

	if (uint64_t(raw_len) > ((11UL<<32)-2)*BLOCKSIZE+GCMTAGSIZE) {
		return SGX_ERROR_INVALID_PARAMETER;
	}
  
  cipher_len = raw_len-GCMTAGSIZE;
  
  memcpy(tag, raw + cipher_len, GCMTAGSIZE);
  memcpy(subciphertext, raw, cipher_len);
  
  if (nonce_len == GCMSTANDARDNONCESIZE) {
		// Init counter to nonce||1§§
		memcpy(counter, nonce, nonce_len);
		counter[GCMBLOCKSIZE-1] = 1;
	} else {
		gcmaesdata(&pTablett, nonce, &counter, nonce_len);
		gcmaesfinish(&pTablett, &tagMask, &counter, uint64_t(nonce_len), uint64_t(0));
		// Otherwise counter = GHASH(nonce)
	}
  aesencblock(&tagMask, &counter, encgo, expand_len);
  gcmaesdata(&pTablett, path, &expectedTag, path_len);

  if (cipher_len > 0) {
    gcmaesdec(&pTablett, (char *)plaintext, subciphertext, &counter, &expectedTag, encgo, cipher_len, expand_len);
	}
	gcmaesfinish(&pTablett, &tagMask, &expectedTag, uint64_t(cipher_len), uint64_t(path_len));

  return SGX_SUCCESS;
  
}


