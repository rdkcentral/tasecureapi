/* Ed25519 Hash adapter using mbedTLS SHA-512 */
#ifndef ED25519_HASH_CUSTOM_H
#define ED25519_HASH_CUSTOM_H

#include "mbedtls/sha512.h"
#include <string.h>

typedef struct {
    mbedtls_sha512_context ctx;
} ed25519_hash_context;

/* hash_512bits is already defined in ed25519-donna.h */

static void ed25519_hash_init(ed25519_hash_context *ctx) {
    mbedtls_sha512_init(&ctx->ctx);
    mbedtls_sha512_starts(&ctx->ctx, 0);  // 0 = SHA-512, not SHA-384
}

static void ed25519_hash_update(ed25519_hash_context *ctx, 
                                 const unsigned char *in, size_t inlen) {
    mbedtls_sha512_update(&ctx->ctx, in, inlen);
}

static void ed25519_hash_final(ed25519_hash_context *ctx, 
                                unsigned char *hash) {
    mbedtls_sha512_finish(&ctx->ctx, hash);
    mbedtls_sha512_free(&ctx->ctx);
}

static void ed25519_hash(unsigned char *hash, 
                         const unsigned char *in, size_t inlen) {
    mbedtls_sha512(in, inlen, hash, 0);  // 0 = SHA-512
}

#endif /* ED25519_HASH_CUSTOM_H */
