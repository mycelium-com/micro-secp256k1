/* Copyright 2014, Kenneth MacKay. Licensed under the BSD 2-clause license. */

#include "uECC.h"

#include <stdio.h>
#include <string.h>

#define SHA256_BLOCK_LENGTH  64
#define SHA256_DIGEST_LENGTH 32

typedef struct SHA256_CTX {
	uint32_t	state[8];
	uint64_t	bitcount;
	uint8_t	buffer[SHA256_BLOCK_LENGTH];
} SHA256_CTX;

extern void SHA256_Init(SHA256_CTX *ctx);
extern void SHA256_Update(SHA256_CTX *ctx, const uint8_t *message, size_t message_size);
extern void SHA256_Final(uint8_t digest[SHA256_DIGEST_LENGTH], SHA256_CTX *ctx);

typedef struct SHA256_HashContext {
    uECC_HashContext uECC;
    SHA256_CTX ctx;
} SHA256_HashContext;

static void init_SHA256(const uECC_HashContext *base) {
    SHA256_HashContext *context = (SHA256_HashContext *)base;
    SHA256_Init(&context->ctx);
}

static void update_SHA256(const uECC_HashContext *base,
                          const uint8_t *message,
                          unsigned message_size) {
    SHA256_HashContext *context = (SHA256_HashContext *)base;
    SHA256_Update(&context->ctx, message, message_size);
}

static void finish_SHA256(const uECC_HashContext *base, uint8_t *hash_result) {
    SHA256_HashContext *context = (SHA256_HashContext *)base;
    SHA256_Final(hash_result, &context->ctx);
}

int main() {
    int i, c;
    uint8_t private[32] = {0xE9,0x87,0x3D,0x79,0xC6,0xD8,0x7D,0xC0,0xFB,0x6A,0x57,0x78,0x63,0x33,0x89,0xF4,0x45,0x32,0x13,0x30,0x3D,0xA6,0x1F,0x20,0xBD,0x67,0xFC,0x23,0x3A,0xA3,0x32,0x62};
    uint8_t public[64] = {0};
    uint8_t hash[32] = {0};
    uint8_t sig[64] = {0};
    
    uint8_t tmp[2 * SHA256_DIGEST_LENGTH + SHA256_BLOCK_LENGTH];
    SHA256_HashContext ctx = {{
        &init_SHA256,
        &update_SHA256,
        &finish_SHA256,
        SHA256_BLOCK_LENGTH,
        SHA256_DIGEST_LENGTH,
        tmp
    }};

    const struct uECC_Curve_t * curve = uECC_secp256k1();
    
    printf("Testing 4096 signatures\n");
    for (i = 0; i < 4096; ++i) {
        printf(".");
        fflush(stdout);

        if (!uECC_compute_public_key(private, public, curve)) {
            printf("uECC_make_key() failed\n");
            return 1;
        }
        memcpy(hash, public, sizeof(hash));

        if (!uECC_sign_deterministic(private, hash, sizeof(hash), &ctx.uECC, sig, curve)) {
            printf("uECC_sign() failed\n");
            return 1;
        }

        uECC_normalize_signature(sig, curve);

        if (!uECC_verify(public, hash, sizeof(hash), sig, curve)) {
            printf("uECC_verify() failed\n");
            return 1;
        }
    }
    printf("\n");
    
    return 0;
}
