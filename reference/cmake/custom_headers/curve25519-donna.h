/**
 * curve25519-donna: Curve25519 elliptic curve Diffie-Hellman
 *
 * Public domain by Adam Langley <agl@imperialviolet.org>
 * See http://code.google.com/p/curve25519-donna/
 */

#ifndef CURVE25519_DONNA_H
#define CURVE25519_DONNA_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint8_t u8;

/**
 * Perform Curve25519 scalar multiplication: mypublic = secret * basepoint
 * 
 * @param mypublic  Output: 32-byte public key
 * @param secret    Input: 32-byte secret/private key
 * @param basepoint Input: 32-byte basepoint (use {9, 0, 0, ..., 0} for standard base)
 */
void curve25519_donna(u8 *mypublic, const u8 *secret, const u8 *basepoint);

#ifdef __cplusplus
}
#endif

#endif /* CURVE25519_DONNA_H */
