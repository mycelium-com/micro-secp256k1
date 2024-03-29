/* Copyright 2014, Kenneth MacKay. Licensed under the BSD 2-clause license. */

#ifndef _UECC_H_
#define _UECC_H_

#include <stdint.h>
#include <stddef.h>

/* Platform selection options.
If uECC_PLATFORM is not defined, the code will try to guess it based on compiler macros.
Possible values for uECC_PLATFORM are defined below: */
#define uECC_arch_other 0
#define uECC_x86        1
#define uECC_x86_64     2
#define uECC_arm        3
#define uECC_arm_thumb  4
#define uECC_arm_thumb2 5
#define uECC_arm64      6
#define uECC_avr        7

/* If desired, you can define uECC_WORD_SIZE as appropriate for your platform (1, 4, or 8 bytes).
If uECC_WORD_SIZE is not explicitly defined then it will be automatically set based on your
platform. */

/* Optimization level; trade speed for code size.
   Larger values produce code that is faster but larger.
   Currently supported values are 0 - 4; 0 is unusably slow for most applications.
   Optimization level 4 currently only has an effect ARM platforms where more than one
   curve is enabled. */
#ifndef uECC_OPTIMIZATION_LEVEL
    #define uECC_OPTIMIZATION_LEVEL 2
#endif

/* uECC_SQUARE_FUNC - If enabled (defined as nonzero), this will cause a specific function to be
used for (scalar) squaring instead of the generic multiplication function. This can make things
faster somewhat faster, but increases the code size. */
#ifndef uECC_SQUARE_FUNC
    #define uECC_SQUARE_FUNC 0
#endif

struct uECC_Curve_t;
typedef const struct uECC_Curve_t * uECC_Curve;
extern const struct uECC_Curve_t curve_secp256k1;

#ifdef __cplusplus
extern "C"
{
#endif

/* uECC_curve_private_key_size() function.

Returns the size of a private key for the curve in bytes.
*/
int uECC_curve_private_key_size();

/* uECC_curve_public_key_size() function.

Returns the size of a public key for the curve in bytes.
*/
int uECC_curve_public_key_size();

/* uECC_shared_secret() function.
Compute a shared secret given your secret key and someone else's public key. If the public key
is not from a trusted source and has not been previously verified, you should verify it first
using uECC_valid_public_key().
Note: It is recommended that you hash the result of uECC_shared_secret() before using it for
symmetric encryption or HMAC.
Inputs:
    public_key  - The public key of the remote party.
    private_key - Your private key.
Outputs:
    secret - Will be filled in with the shared secret value. Must be the same size as the
             curve size; for example, if the curve is secp256r1, secret must be 32 bytes long.
Returns 1 if the shared secret was generated successfully, 0 if an error occurred.
*/
int uECC_shared_secret(const uint8_t *public_key, const uint8_t *private_key, uint8_t *secret);

/* uECC_compress() function.
Compress a public key.

Inputs:
    public_key - The public key to compress.

Outputs:
    compressed - Will be filled in with the compressed public key. Must be at least
                 (curve size + 1) bytes long; for example, if the curve is secp256r1,
                 compressed must be 33 bytes long.
*/
void uECC_compress(const uint8_t *public_key, uint8_t *compressed);

/* uECC_decompress() function.
Decompress a compressed public key.

Inputs:
    compressed - The compressed public key.

Outputs:
    public_key - Will be filled in with the decompressed public key.
*/
void uECC_decompress(const uint8_t *compressed, uint8_t *public_key);

/* uECC_valid_public_key() function.
Check to see if a public key is valid.

Note that you are not required to check for a valid public key before using any other uECC
functions. However, you may wish to avoid spending CPU time computing a shared secret or
verifying a signature using an invalid public key.

Inputs:
    public_key - The public key to check.

Returns 1 if the public key is valid, 0 if it is invalid.
*/
int uECC_valid_public_key(const uint8_t *public_key);

/* uECC_valid_private_key() function.
Check to see if a private key is valid.

Note that you are not required to check for a valid private key before using any other uECC
functions.

Inputs:
    private_key - The private key to check.

Returns 1 if the private key is valid, 0 if it is invalid.
*/
int uECC_valid_private_key(const uint8_t *private_key);

/* uECC_compute_public_key() function.
Compute the corresponding public key for a private key.

Inputs:
    private_key - The private key to compute the public key for

Outputs:
    public_key - Will be filled in with the corresponding public key

Returns 1 if the key was computed successfully, 0 if an error occurred.
*/
int uECC_compute_public_key(const uint8_t *private_key, uint8_t *public_key);

/* uECC_HashContext structure.
This is used to pass in an arbitrary hash function to uECC_sign_deterministic().
The structure will be used for multiple hash computations; each time a new hash
is computed, init_hmac() will be called, followed by one or more calls to
update_hmac(), and finally a call to finish_hmac) to produce the resulting hash.

The intention is that you will create a structure that includes uECC_HashContext
followed by any hash-specific data. For example:

static void init_HMAC(void *ctx, const uint8_t *key, int key_len) {
    HMAC_Init((HMAC_CTX *)ctx, key, key_len, EVP_sha256());
}

static void update_HMAC(void *ctx, const uint8_t *data, int len) {
    HMAC_Update((HMAC_CTX *)ctx, data, len);
}

static void finish_HMAC(void *ctx, uint8_t *digest) {
    uint32_t len;
    HMAC_Final((HMAC_CTX *) ctx, digest, &len);
}

... when signing ...
{
    HMAC_CTX hmac_ctx;
    uECC_HashContext ctx = {{
        &init_HMAC,
        &update_HMAC,
        &finish_HMAC,
        &hmac_ctx,
        SHA256_DIGEST_SIZE
    }};
    uECC_sign_deterministic(key, message_hash, &ctx, signature);
}
*/
typedef struct uECC_HashContext {
    void (*hmac_init)(const struct uECC_HashContext *context, const uint8_t *key, int key_size);
    void (*hmac_update)(const struct uECC_HashContext *context, const uint8_t *message, int message_size);
    void (*hmac_finish)(const struct uECC_HashContext *context, uint8_t *hash_result);
    void *ctx;
    int digest_size;
    uint8_t *tmp;
} uECC_HashContext;

/* uECC_sign_deterministic() function.
Generate an ECDSA signature for a given hash value, using a deterministic algorithm
(see RFC 6979). You do not need to set the RNG using uECC_set_rng() before calling
this function; however, if the RNG is defined it will improve resistance to side-channel
attacks.

Usage: Compute a hash of the data you wish to sign (SHA-2 is recommended) and pass it to
this function along with your private key and a hash context. Note that the message_hash
does not need to be computed with the same hash function used by hash_context.

Inputs:
    private_key  - Your private key.
    message_hash - The hash of the message to sign.
    hash_size    - The size of message_hash in bytes.
    hash_context - A hash context to use.

Outputs:
    signature - Will be filled in with the signature value.

Returns 1 if the signature generated successfully, 0 if an error occurred.
*/
int uECC_sign_deterministic(const uint8_t *private_key,
                            const uint8_t *message_hash,
                            unsigned hash_size,
                            const uECC_HashContext *hash_context,
                            uint8_t *signature);

/* uECC_verify() function.
Verify an ECDSA signature.

Usage: Compute the hash of the signed data using the same hash as the signer and
pass it to this function along with the signer's public key and the signature values (r and s).

Inputs:
    public_key   - The signer's public key.
    message_hash - The hash of the signed data.
    hash_size    - The size of message_hash in bytes.
    signature    - The signature value.

Returns 1 if the signature is valid, 0 if it is invalid.
*/
int uECC_verify(const uint8_t *public_key,
                const uint8_t *message_hash,
                unsigned hash_size,
                const uint8_t *signature);

// Serialize signature using the DER encoding
void uECC_compact_to_der(const uint8_t *compact, uint8_t *der);

// Deserialize DER encoded signature
int uECC_der_to_compact(const uint8_t *input, unsigned inputlen, uint8_t *compact);

// Private key tweak by scalar
int uECC_private_scalar_tweak(uint8_t *result, const uint8_t *private_key, const uint8_t *scalar);

// EC public key tweak by scalar
int uECC_public_point_tweak(uint8_t *result, const uint8_t *public_key, const uint8_t *scalar);

#ifdef __cplusplus
} /* end of extern "C" */
#endif

#endif /* _UECC_H_ */
