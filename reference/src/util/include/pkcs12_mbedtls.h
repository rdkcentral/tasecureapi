/*
 * PKCS#12 Parser using mbedTLS
 * Header file
 */

#ifndef PKCS12_MBEDTLS_H
#define PKCS12_MBEDTLS_H

#include <mbedtls/aes.h>
#include <mbedtls/cipher.h>
#include <mbedtls/error.h>
#include <mbedtls/gcm.h>
#include <mbedtls/platform.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

#include <mbedtls/cipher.h>
#include <mbedtls/aes.h>
#include <mbedtls/gcm.h>
#include <mbedtls/chacha20.h>
#include <mbedtls/chachapoly.h>

#include <mbedtls/cmac.h>

#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Load a secret key from a PKCS#12 file using mbedTLS APIs only.
 *
 * This is a pure mbedTLS implementation that replaces OpenSSL's PKCS#12 parsing.
 * Compatible with OpenSSL's load_pkcs12_secret_key() interface.
 *
 * @param key           Buffer to store the extracted key
 * @param key_length    [in/out] Size of key buffer / actual key length
 * @param name          [in/out] Input: name pattern to match (e.g., "commonroot")
 *                               Output: extracted key's friendly name
 * @param name_length   [in/out] Size of name buffer / actual name length
 *
 * @return              true on success, false on failure
 */
bool load_pkcs12_secret_key_mbedtls(
        void* key,
        size_t* key_length,
        char* name,
        size_t* name_length);

#ifdef __cplusplus
}
#endif

#endif /* PKCS12_MBEDTLS_H */
