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

/** @section Description
 * @file rsa.h
 *
 * This file contains the functions and structures implementing RSA cryptographic operations.
 */

#ifndef RSA_H
#define RSA_H

#include "sa_types.h"
#include "stored_key.h"

#ifdef __cplusplus

#include <cstdbool>
#include <cstddef>

extern "C" {
#else
#include <stdbool.h>
#include <stddef.h>
#endif

/**
 * Validates an RSA private key and returns its size.
 *
 * @param[in] in input data.
 * @param[in] in_length input data length.
 * @return the size of the valid key. If 0 is returned, the key is not a valid RSA key.
 */
size_t rsa_validate_private(
        const void* in,
        size_t in_length);

/**
 * Get public RSA key.
 *
 * @param[out] out public key.
 * @param[in/out] out_length public key length. Set to bytes written on completion.
 * @param[in] stored_key private key.
 * @return status of the operation.
 */
sa_status rsa_get_public(
        void* out,
        size_t* out_length,
        const stored_key_t* stored_key);

/**
 * Verifies that the RSA cipher operation can be performed.
 *
 * @param cipher_algorithm the cipher algorithm.
 * @param cipher_mode the cipher mode.
 * @param stored_key the stored key to use in the cipher.
 * @return the status of the cipher operation.
 */
sa_status rsa_verify_cipher(
        sa_cipher_algorithm cipher_algorithm,
        sa_cipher_mode cipher_mode,
        const stored_key_t* stored_key);

/**
 * Decrypt using RSA and PKCS1v15 padding.
 *
 * @param[out] out output buffer.
 * @param[in,out] out_length output buffer length.
 * @param[in] stored_key RSA key.
 * @param[in] in input data.
 * @param[in] in_length input data length.
 * @return status of the operation.
 */
sa_status rsa_decrypt_pkcs1v15(
        void* out,
        size_t* out_length,
        const stored_key_t* stored_key,
        const void* in,
        size_t in_length);

/**
 * Decrypt using RSA and OAEP padding.
 *
 * @param[out] out output buffer.
 * @param[in,out] out_length output buffer length.
 * @param[in] stored_key RSA key.
 * @param[in] digest_algorithm the digest algorithm for OAEP padding.
 * @param[in] mgf1_digest_algorithm the digest algorithm for the MGF1 function.
 * @param[in] label the label for the OAEP padding. May be NULL.
 * @param[in] label_length the length of the label. Must be 0 if label is NULL.
 * @param[in] in input data.
 * @param[in] in_length input data length.
 * @return status of the operation.
 */
sa_status rsa_decrypt_oaep(
        void* out,
        size_t* out_length,
        const stored_key_t* stored_key,
        sa_digest_algorithm digest_algorithm,
        sa_digest_algorithm mgf1_digest_algorithm,
        const void* label,
        size_t label_length,
        const void* in,
        size_t in_length);

/**
 * Sign a message using RSA PKCS1v15 padding.
 *
 * @param[out] out output buffer.
 * @param[in,out] out_length output buffer length.
 * @param[in] digest_algorithm digest algorithm.
 * @param[in] stored_key RSA key.
 * @param[in] in input data.
 * @param[in] in_length input data length.
 * @param[in] precomputed_digest indicates if in contains the digest.
 * @return status of the operation.
 */
sa_status rsa_sign_pkcs1v15(
        void* out,
        size_t* out_length,
        sa_digest_algorithm digest_algorithm,
        const stored_key_t* stored_key,
        const void* in,
        size_t in_length,
        bool precomputed_digest);

/**
 * Sign a message using RSA PSS padding.
 *
 * @param[out] out output buffer.
 * @param[in,out] out_length output buffer length.
 * @param[in] digest_algorithm digest algorithm.
 * @param[in] mgf1_digest_algorithm digest algorithm for the MGF1 function.
 * @param[in] stored_key RSA key.
 * @param[in] salt_length salt length.
 * @param[in] in input data.
 * @param[in] in_length input data length.
 * @param[in] precomputed_digest indicates if in contains the digest.
 * @return status of the operation.
 */
sa_status rsa_sign_pss(
        void* out,
        size_t* out_length,
        sa_digest_algorithm digest_algorithm,
        const stored_key_t* stored_key,
        sa_digest_algorithm mgf1_digest_algorithm,
        size_t salt_length,
        const void* in,
        size_t in_length,
        bool precomputed_digest);

#ifdef __cplusplus
}
#endif

#endif // RSA_H
