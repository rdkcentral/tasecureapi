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
 * @file key_type.h
 *
 * This file contains the functions and structures for validating key parameters for cryptographic
 * algorithms.
 */

#ifndef KEY_TYPE_H
#define KEY_TYPE_H

#include "sa_types.h"

#ifdef __cplusplus

#include <cstdbool>

extern "C" {
#else
#include <stdbool.h>
#endif

/**
 * Check whether an AES operation can be performed with a given key type and size combination.
 *
 * @param[in] key_type key type.
 * @param[in] size key size.
 * @return true if supported, false otherwise.
 */
bool key_type_supports_aes(
        sa_key_type key_type,
        size_t size);

/**
 * Check whether an HMAC operation can be performed with a given key type and size combination.
 *
 * @param[in] key_type key type.
 * @param[in] size key size.
 * @return true if supported, false otherwise.
 */
bool key_type_supports_hmac(
        sa_key_type key_type,
        size_t size);

/**
 * Check whether an RSA operation can be performed with a given key type and size combination
 *
 * @param[in] key_type key type.
 * @param[in] size key size.
 * @return true if supported, false otherwise.
 */
bool key_type_supports_rsa(
        sa_key_type key_type,
        size_t size);

/**
 * Check whether an ECP256 operation can be performed with a given key type and size combination.
 *
 * @param[in] key_type key type.
 * @param[in] curve elliptic curve.
 * @param[in] size key size.
 * @return true if supported, false otherwise.
 */
bool key_type_supports_ec(
        sa_key_type key_type,
        sa_elliptic_curve curve,
        size_t size);

/**
 * Check whether a DH operation can be performed with a given key type and size combination.
 *
 * @param[in] key_type key type.
 * @param[in] size key size.
 * @return true if supported, false otherwise.
 */
bool key_type_supports_dh(
        sa_key_type key_type,
        size_t size);

/**
 * Check whether the key type and size are supported for any algorithms in SecApi.
 *
 * @param[in] key_type key type.
 * @param[in] ec_curve elliptic curve parameter. Ignored if not an EC key.
 * @param[in] size key size.
 * @return true if supported, false otherwise.
 */
bool key_type_supports_any(
        sa_key_type key_type,
        uint8_t ec_curve,
        size_t size);

/**
 * Check whether an CHACHA20 operation can be performed with a given key type and size combination.
 *
 * @param[in] key_type key type.
 * @param[in] size key size.
 * @return true if supported, false otherwise.
 */
bool key_type_supports_chacha20(
        sa_key_type key_type,
        size_t size);

#ifdef __cplusplus
}
#endif

#endif // KEY_TYPE_H
