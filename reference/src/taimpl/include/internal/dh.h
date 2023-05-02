/*
 * Copyright 2019-2023 Comcast Cable Communications Management, LLC
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
 * @file dh.h
 *
 * This file contains the functions and structures implementing Diffie-Hellman key exchange
 * protocol.
 */

#ifndef DH_H
#define DH_H

#include "stored_key.h"
#ifdef __cplusplus

#include <cstdbool>
#include <cstddef>
#include <cstdint>

extern "C" {
#else
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#endif

/**
 * Get public DH key.
 *
 * @param[out] out public key.
 * @param[in/out] out_length public key length. Set to bytes written on completion.
 * @param[in] stored_key private key.
 * @return status of the operation.
 */
sa_status dh_get_public(
        void* out,
        size_t* out_length,
        const stored_key_t* stored_key);

/**
 * Compute the DH shared secret.
 *
 * @param[out] stored_key_shared_secret shared secret
 * @param[in] rights the rights for the shared secret.
 * @param[in] other_public other party's public key
 * @param[in] other_public_length other party's public key length
 * @param[in] stored_key the stored private key
 * @return status of the operation
 */
sa_status dh_compute_shared_secret(
        stored_key_t** stored_key_shared_secret,
        const sa_rights* rights,
        const void* other_public,
        size_t other_public_length,
        const stored_key_t* stored_key);

/**
 * Generate the private/public key pair for the given DH parameters.
 *
 * @param[out] stored_key the generated key
 * @param[out] rights the rights for the key.
 * @param[in] p prime
 * @param[in] p_length the length of p
 * @param[in] g generator
 * @param[in] g_length the length of g
 * @return status of the operation
 */
sa_status dh_generate_key(
        stored_key_t** stored_key,
        const sa_rights* rights,
        const void* p,
        size_t p_length,
        const void* g,
        size_t g_length);

#ifdef __cplusplus
}
#endif

#endif // DH_H
