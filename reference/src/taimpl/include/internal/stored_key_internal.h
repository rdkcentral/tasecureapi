/**
 * Copyright 2020-2022 Comcast Cable Communications Management, LLC
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
 * @file stored_key.h
 *
 * This file contains the functions for internal stored_key operations.
 */

#ifndef STORED_KEY_INTERNAL_H
#define STORED_KEY_INTERNAL_H

#include "sa_types.h"
#include "stored_key.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Retrieves key bytes from a stored key.
 * @param stored_key the stored key.
 * @return the key bytes.
 */
const void* stored_key_get_key(const stored_key_t* stored_key);

/**
 * Retrieves the length from a stored key.
 * @param stored_key the stored key.
 * @return the key length.
 */
size_t stored_key_get_length(const stored_key_t* stored_key);

/**
 * Create a stored key.
 *
 * @param[out] stored_key created key.
 * @param[in] rights key rights for the created key.
 * @param[in] parent_rights parent key's key rights. Can be NULL.
 * @param[in] key_type key type.
 * @param[in] type_parameters additional data for the key type. If type is SA_KEY_TYPE_EC, this
 * value is used to indicate the sa_elliptic_curve.
 * @param[in] size key size in bytes. Number of secret key bytes for SA_KEY_TYPE_SYMMETRIC,
 * number of private key bytes for SA_KEY_TYPE_EC, modulus length for SA_KEY_TYPE_RSA, and
 * prime length for SA_KEY_TYPE_DH.
 * @param[in] in key payload.
 * @param[in] in_length key payload length.
 * @return the creation status.
 */
bool stored_key_create(
        stored_key_t** stored_key,
        const sa_rights* rights,
        const sa_rights* parent_rights,
        sa_key_type key_type,
        const sa_type_parameters* type_parameters,
        size_t size,
        const void* in,
        size_t in_length);

#ifdef __cplusplus
}
#endif

#endif // STORED_KEY_INTERNAL_H
