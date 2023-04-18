/*
 * Copyright 2020-2023 Comcast Cable Communications Management, LLC
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
 * @file netflix.h
 *
 * This file contains the functions and structures implementing Netflix key derivation algorithms.
 */

#ifndef NETFLIX_H
#define NETFLIX_H

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
 * Perform Netflix key derivation.
 * https://github.com/Netflix/msl/wiki/Pre-shared-Keys-or-Model-Group-Keys-Entity-Authentication
 *
 * @param[out] stored_key_wrap the wrap key result from the derivation.
 * @param[in] rights_wrap the rights for the wrap key.
 * @param[in] rights_parent the parent rights.
 * @param[in] stored_key_enc the enc key to use in the derivation.
 * @param[in] stored_key_hmac the mac key to use in the derivation.
 * @return the status of the operation.
 */
sa_status kdf_netflix_wrapping(
        stored_key_t** stored_key_wrap,
        const sa_rights* rights_wrap,
        const sa_rights* rights_parent,
        const stored_key_t* stored_key_enc,
        const stored_key_t* stored_key_hmac);

/**
 * Perform shared secret Netflix key derivation.
 * https://github.com/Netflix/msl/wiki/Authenticated-Diffie-Hellman-Key-Exchange
 *
 * @param[out] stored_key_enc the generated enc key.
 * @param[in] rights_enc the rights for the enc key.
 * @param[out] stored_key_hmac the generated hmac key.
 * @param[in] rights_hmac the rights for the hmac key.
 * @param[in] stored_key_in the key to use in the generation.
 * @param[in] stored_key_shared_secret the resulting shared secret.
 * @return the status of the operation.
 */
sa_status kdf_netflix_shared_secret(
        stored_key_t** stored_key_enc,
        const sa_rights* rights_enc,
        stored_key_t** stored_key_hmac,
        const sa_rights* rights_hmac,
        const stored_key_t* stored_key_in,
        const stored_key_t* stored_key_shared_secret);

#ifdef __cplusplus
}
#endif

#endif // NETFLIX_H
