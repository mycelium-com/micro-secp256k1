/* Copyright 2014, Kenneth MacKay. Licensed under the BSD 2-clause license. */

#include "uECC.h"

#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

static void init_HMAC(const struct uECC_HashContext *base, const uint8_t *key, int key_len) {
    HMAC_Init((HMAC_CTX *)base->ctx, key, key_len, EVP_sha256());
}

static void update_HMAC(const struct uECC_HashContext *base, const uint8_t *data, int len) {
    HMAC_Update((HMAC_CTX *)base->ctx, data, len);
}

static void finish_HMAC(const struct uECC_HashContext *base, uint8_t *digest) {
    uint32_t len;
    HMAC_Final((HMAC_CTX *) base->ctx, digest, &len);
}

int main() {
    int i, c;
    uint8_t private[32] = {0xE9,0x87,0x3D,0x79,0xC6,0xD8,0x7D,0xC0,0xFB,0x6A,0x57,0x78,0x63,0x33,0x89,0xF4,0x45,0x32,0x13,0x30,0x3D,0xA6,0x1F,0x20,0xBD,0x67,0xFC,0x23,0x3A,0xA3,0x32,0x62};
    uint8_t public[64] = {0};
    uint8_t hash[32] = {0};
    uint8_t sig[64] = {0};
    uint8_t serialized[70] = {0};

    uint8_t tmp[2 * SHA256_DIGEST_LENGTH + 1];
    HMAC_CTX hmac_ctx;
    uECC_HashContext ctx = {
        &init_HMAC,
        &update_HMAC,
        &finish_HMAC,
        &hmac_ctx,
        SHA256_DIGEST_LENGTH,
        tmp
    };

    printf("Testing 4096 signatures\n");
    for (i = 0; i < 4096; ++i) {
        printf(".");
        fflush(stdout);

        if (!uECC_compute_public_key(private, public)) {
            printf("uECC_make_key() failed\n");
            return 1;
        }

        if (i > 0) {
            memcpy(hash, sig, sizeof(hash));
        }

        if (!uECC_sign_deterministic(private, hash, sizeof(hash), &ctx, sig)) {
            printf("uECC_sign() failed\n");
            return 1;
        }

        // Serialize
        uECC_compact_to_der(sig, serialized);

/*
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
*/
        // Deserialize
        if (!uECC_der_to_compact(serialized, sizeof(serialized), sig)) {
            printf("uECC_der_to_compact() failed\n");
            return 1;
        }

        if (!uECC_verify(public, hash, sizeof(hash), sig)) {
            printf("uECC_verify() failed\n");
            return 1;
        }
    }
    printf("\n");

    return 0;
}
