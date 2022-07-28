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
 * @file ec.h
 *
 * This file contains the functions and structures implementing Elliptic Curve encryption and
 * signing operations.
 */

#ifndef EC_H
#define EC_H

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
 * Return the key size based on the curve.
 *
 * @param[in] curve Elliptic curve to use.
 * @return the key size.
 */
size_t ec_key_size_from_curve(sa_elliptic_curve curve);

/**
 * Validates an EC private key and returns its size
 * .
 * @param[in] curve the Elliptic curve.
 * @param[in] private the private key bytes.
 * @param[in] private_length the length of the private key.
 * @return the size of the private key or 0 if failed.
 */
size_t ec_validate_private(
        sa_elliptic_curve curve,
        const void* private,
        size_t private_length);

/**
 * Get public EC key in uncompressed [X|Y].
 *
 * @param[out] out public key.
 * @param[in/out] out_length public key length. Set to bytes written on completion.
 * @param[in] stored_key private key.
 * @return status of the operation.
 */
sa_status ec_get_public(
        void* out,
        size_t* out_length,
        const stored_key_t* stored_key);

/**
 * Verifies that the EC El Gamal cipher operation can be performed.
 *
 * @param cipher_mode the cipher mode.
 * @param stored_key the stored key to use in the cipher.
 * @return the status of the cipher operation.
 */
sa_status ec_verify_cipher(
        sa_cipher_mode cipher_mode,
        const stored_key_t* stored_key);

/**
 * Decrypt using EC in ElGamal mode.
 *
 * @param[out] out output buffer.
 * @param[in,out] out_length output buffer length.
 * @param[in] stored_key private key.
 * @param[in] in input buffer.
 * @param[in] in_length input buffer length.
 * @return
 */
sa_status ec_decrypt_elgamal(
        void* out,
        size_t* out_length,
        const stored_key_t* stored_key,
        const void* in,
        size_t in_length);

/**
 * Perform ECDH key exchange.
 *
 * @param[out] stored_key_shared_secret shared secret.
 * @param[in] rights rights for the shared secret.
 * @param[in] other_public other party's public key.
 * @param[in] other_public_length length of other party's public key.
 * @param[in] stored_key private key.
 * @return status of the operation
 */
sa_status ec_compute_ecdh_shared_secret(
        stored_key_t** stored_key_shared_secret,
        const sa_rights* rights,
        const void* other_public,
        size_t other_public_length,
        const stored_key_t* stored_key);

/**
 * Sign a message using ECDSA.
 *
 * @param[out] signature signature.
 * @param[in,out] signature_length signature length.
 * @param[in] digest_algorithm digest algorithm.
 * @param[in] stored_key private key.
 * @param[in] in message to sign.
 * @param[in] in_length length of message to sign.
 * @param[in] precomputed_digest indicates if in contains the digest.
 * @return status of the operation.
 */
sa_status ec_sign_ecdsa(
        void* signature,
        size_t* signature_length,
        sa_digest_algorithm digest_algorithm,
        const stored_key_t* stored_key,
        const void* in,
        size_t in_length,
        bool precomputed_digest);

/**
 * Sign a message using EDDSA.
 *
 * @param[out] signature signature.
 * @param[in,out] signature_length signature length.
 * @param[in] stored_key private key.
 * @param[in] in message to sign.
 * @param[in] in_length length of message to sign.
 * @return status of the operation.
 */
sa_status ec_sign_eddsa(
        void* signature,
        size_t* signature_length,
        const stored_key_t* stored_key,
        const void* in,
        size_t in_length);

/**
 * Generate an EC key.
 * @param[out] stored_key the generated EC key.
 * @param[in] rights the key rights.
 * @param[in] parameters the EC key parameters
 * @return status of the operation.
 */
sa_status ec_generate_key(
        stored_key_t** stored_key,
        const sa_rights* rights,
        sa_generate_parameters_ec* parameters);

#ifdef __cplusplus
}
#endif

#endif // EC_H
