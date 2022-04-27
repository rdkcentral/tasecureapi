/**
 * Copyright 2020-2021 Comcast Cable Communications Management, LLC
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
 * This file contains the functions and structures for cstored key operations for use in SecApi TA.
 */

#ifndef STORED_KEY_H
#define STORED_KEY_H

#include "sa_types.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct stored_key_s stored_key_t;

/**
 * Retrieves the header from a stored key.
 * @param stored_key the stored key.
 * @return the key header.
 */
const sa_header* stored_key_get_header(const stored_key_t* stored_key);

/**
 * Import a stored key.
 *
 * @param[out] stored_key created key.
 * @param[in] rights key rights for the created key.
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
bool stored_key_import(
        stored_key_t** stored_key,
        const sa_rights* rights,
        sa_key_type key_type,
        uint8_t type_parameters,
        size_t size,
        const void* in,
        size_t in_length);

/**
 * Free key handle
 */
void stored_key_free(stored_key_t* stored_key);

#ifdef __cplusplus
}
#endif

#endif // STORED_KEY_H
