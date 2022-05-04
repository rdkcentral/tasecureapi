/**
 * Copyright 2019-2022 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SA_COMMON_H
#define SA_COMMON_H

#include "sa.h"
#include <openssl/evp.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AES_BLOCK_SIZE 16
#define SYM_128_KEY_SIZE 16
#define SYM_160_KEY_SIZE 20
#define SYM_256_KEY_SIZE 32
#define SYM_MAX_KEY_SIZE 32UL
#define SHA1_DIGEST_LENGTH 20
#define SHA256_DIGEST_LENGTH 32
#define SHA384_DIGEST_LENGTH 48
#define SHA512_DIGEST_LENGTH 64
#define RSA_1024_BYTE_LENGTH 128
#define RSA_2048_BYTE_LENGTH 256
#define RSA_3072_BYTE_LENGTH 384
#define RSA_4096_BYTE_LENGTH 512
#define DH_768_BYTE_LENGTH 96L
#define DH_1024_BYTE_LENGTH 128UL
#define DH_1536_BYTE_LENGTH 192UL
#define DH_2048_BYTE_LENGTH 256UL
#define DH_3072_BYTE_LENGTH 384UL
#define DH_4096_BYTE_LENGTH 512UL
#define EC_P256_KEY_SIZE 32
#define EC_P384_KEY_SIZE 48
#define EC_P521_KEY_SIZE 66
#define EC_25519_KEY_SIZE 32
#define EC_ED448_KEY_SIZE 57
#define EC_X448_KEY_SIZE 56
#define GCM_IV_LENGTH 12
#define MAX_NUM_SLOTS 256
#define DH_MAX_MOD_SIZE 512
#define RSA_PKCS1_PADDING_SIZE 11
#define RSA_OAEP_PADDING_SIZE 42
#define CHACHA20_NONCE_LENGTH 12
#define CHACHA20_COUNTER_LENGTH 4
#define CHACHA20_TAG_LENGTH 16

#if OPENSSL_VERSION_NUMBER < 0x10100000
#define RSA_PSS_SALTLEN_DIGEST -1
#define RSA_PSS_SALTLEN_AUTO -2
#define RSA_PSS_SALTLEN_MAX -3
#endif

/**
 * Imports an RSA public key.
 *
 * @param[in] in the RSA public key bytes.
 * @param[in] in_length the length of the RSA public key bytes.
 * @return an EVP_PKEY encapsulating the RSA public key.
 */
EVP_PKEY* rsa_import_public(
        const uint8_t* in,
        size_t in_length);

/**
 * Deteremines if the curve is a P-256, P-384, or P-521 curve.
 *
 * @param[in] curve the EC curve.
 * @return true if it is.
 */
bool is_pcurve(sa_elliptic_curve curve);

/**
 * Returns the size of the EC key based on the curve.
 *
 * @param[in] curve the EC curve.
 * @return the size of the EC curve.
 */
size_t ec_get_key_size(sa_elliptic_curve curve);

/**
 * Returns the OpenSSL key type (NID value).
 *
 * @param[in] curve the EC curve.
 * @return the OpenSSL type.
 */
int ec_get_type(sa_elliptic_curve curve);

/**
 * Imports an RSA public key.
 *
 * @param[in] curve the EC curve.
 * @param[in] in the RSA public key bytes.
 * @param[in] in_length the length of the RSA public key bytes.
 * @return an EVP_PKEY encapsulating the RSA public key.
 */
EVP_PKEY* ec_import_public(
        sa_elliptic_curve curve,
        const uint8_t* in,
        size_t in_length);

/**
 * Encodes an EC signature in OpenSSL format ASN.1{r,s}.
 *
 * @param[out] out the EC signature encoded in OpenSSL format.
 * @param[out] out_length the length of the encoded signature.
 * @param[in] in the raw signature {r,s} to encode.
 * @param[in] in_length
 * @return true if succesful, false if not.
 */
bool ec_encode_signature(
        void* out,
        size_t* out_length,
        const void* in,
        size_t in_length);

/**
 * Import DH public key.
 *
 * @param[in] in the DH public key bytes.
 * @param[in] in_length the length of DH public key bytes
 * @param[in] p the DH p value.
 * @param[in] p_length the length of the DH p value.
 * @param[in] g the DH g value.
 * @param[in] g_length the length of the DH g value.
 * @return
 */
EVP_PKEY* dh_import_public(
        const uint8_t* in,
        size_t in_length,
        const uint8_t* p,
        size_t p_length,
        const uint8_t* g,
        size_t g_length);

/**
 * Creates an EVP_PKEY public key from an sa_key.
 *
 * @param[in] key the sa_key to create an EVP_PKEY from.
 * @return the EVP_PKEY.
 */
EVP_PKEY* get_public_key(sa_key key);

/**
 * Set key rights to allow all operations.
 *
 * @param[out] rights key rights
 */
void rights_set_allow_all(sa_rights* rights);

#ifdef __cplusplus
}
#endif

#endif // SA_COMMON_H
