/* Ed25519 Random adapter using taimpl's porting layer (mbedTLS CTR-DRBG) */
#ifndef ED25519_RANDOMBYTES_CUSTOM_H
#define ED25519_RANDOMBYTES_CUSTOM_H

#include "porting/rand.h"

/*
 * Ed25519 random byte generation using taimpl's rand_bytes() porting function.
 * This uses mbedTLS CTR-DRBG seeded from hardware entropy sources.
 * 
 * Note: Function name ends with "_unsafe" per ed25519-donna convention,
 * but the implementation IS cryptographically secure.
 */
void ed25519_randombytes_unsafe(void *p, size_t len) {
    rand_bytes(p, len);
}

#endif /* ED25519_RANDOMBYTES_CUSTOM_H */
