#ifndef __RIJNDAEL_H
#define __RIJNDAEL_H

#include <stdint.h>

#define AES_KEY_LEN_128	(128)
#define AES_KEY_LEN_192	(192)
#define AES_KEY_LEN_256	(256)

#define AES_BUFFER_SIZE (16)

#define AES_MAXKEYBITS	(256)
#define AES_MAXKEYBYTES	(AES_MAXKEYBITS/8)
/* for 256-bit keys, fewer for less */
#define AES_MAXROUNDS	14
#define pwuAESContextBuffer rijndael_ctx

/*  The structure for key information */
typedef struct 
{
	int	enc_only;		/* context contains only encrypt schedule */
	int	Nr;			/* key-length-dependent number of rounds */
	uint32_t	ek[4*(AES_MAXROUNDS + 1)];	/* encrypt key schedule */
	uint32_t	dk[4*(AES_MAXROUNDS + 1)];	/* decrypt key schedule */
} rijndael_ctx;

typedef struct 
{
	int	enc_only;		/* context contains only encrypt schedule */
	int	Nr;			/* key-length-dependent number of rounds */
	uint32_t	ek[4*(AES_MAXROUNDS + 1)];	/* encrypt key schedule */
	uint32_t	dk[4*(AES_MAXROUNDS + 1)];	/* decrypt key schedule */
} AES_ctx;

int rijndael_set_key(rijndael_ctx *, const uint8_t *, int);
int	rijndael_set_key_enc_only(rijndael_ctx *, const uint8_t *, int);
void rijndael_decrypt(rijndael_ctx *, const uint8_t *, uint8_t *);
void rijndael_encrypt(rijndael_ctx *, const uint8_t *, uint8_t *);

int AES_set_key(AES_ctx *ctx, const uint8_t *key, int bits);
void AES_encrypt(AES_ctx *ctx, const uint8_t *src, uint8_t *dst);
void AES_decrypt(AES_ctx *ctx, const uint8_t *src, uint8_t *dst);
void AES_cbc_encrypt(AES_ctx *ctx, const uint8_t *src, uint8_t *dst, int size);
void AES_cbc_decrypt(AES_ctx *ctx, const uint8_t *src, uint8_t *dst, int size);
void AES_CMAC(AES_ctx *ctx, unsigned char *input, int length, unsigned char *mac);

#endif /* __RIJNDAEL_H */
