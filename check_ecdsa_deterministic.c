/* Copyright 2014, Kenneth MacKay. Licensed under the BSD 2-clause license. */

#include "uECC.h"

#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/ecdsa.h>

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
    uint8_t public[65] = {0x04};
    uint8_t public_c[33] = {0x00};
    const uint8_t *pp = &public[0];
    const uint8_t *ppc = &public_c[0];
    uint8_t hash[32] = {0};
    uint8_t sig[64] = {0};
    uint8_t serialized[70] = {0};
    const uint8_t *pser = &serialized[0];

    uint8_t tmp[2 * SHA256_DIGEST_LENGTH + SHA256_BLOCK_LENGTH];
    SHA256_HashContext ctx = {{
        &init_SHA256,
        &update_SHA256,
        &finish_SHA256,
        SHA256_BLOCK_LENGTH,
        SHA256_DIGEST_LENGTH,
        tmp
    }};

    if (!uECC_compute_public_key(private, public + 1)) {
        printf("uECC_make_key() failed\n");
        return 1;
    }
    memcpy(hash, public, sizeof(hash));

    printf("pubkey long:\n");
    for (int j = 0; j < 65; ++j) {
        printf("%02x", public[j]);
    }
    printf("\n");

    if (!uECC_sign_deterministic(private, hash, sizeof(hash), &ctx.uECC, sig)) {
        printf("uECC_sign_deterministic() failed\n");
        return 1;
    }

    // Serialize
    uECC_compact_to_der(sig, serialized);

    printf("DER sig:\n");
    for (int j = 0; j < 70; ++j) {
        printf("%02x", serialized[j]);
    }
    printf("\n");

    printf("CPT sig:\n");
    for (int j = 0; j < 64; ++j) {
        printf("%02x", sig[j]);
    }
    printf("\n");

    // Deserialize
    ECDSA_SIG *ossl_sig = ECDSA_SIG_new();
    d2i_ECDSA_SIG(&ossl_sig, &pser, sizeof(serialized));

    EC_KEY *pkey = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!pkey) {
        printf("EC_KEY_new() failed\n");
        return 1;
    }

    if (!o2i_ECPublicKey(&pkey, &pp, sizeof(public))) {
        printf("o2i_ECPublicKey() failed\n");
        return 1;
    }

    if (!ECDSA_do_verify(hash, sizeof(hash), ossl_sig, pkey)) {
        printf("ECDSA_do_verify() failed\n");
        return 1;
    }

    // Compressed pubkey
    uECC_compress(public + 1, public_c);

    printf("pubkey short:\n");
    for (int j = 0; j < 33; ++j) {
        printf("%02x", public_c[j]);
    }
    printf("\n");

    EC_KEY *pkey_c = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!pkey) {
        printf("EC_KEY_new() failed\n");
        return 1;
    }

    if (!o2i_ECPublicKey(&pkey_c, &ppc, sizeof(public_c))) {
        printf("o2i_ECPublicKey() failed\n");
        return 1;
    }

    if (!ECDSA_do_verify(hash, sizeof(hash), ossl_sig, pkey_c)) {
        printf("ECDSA_do_verify() failed\n");
        return 1;
    }


    printf("PASS\n");
    return 0;
}
