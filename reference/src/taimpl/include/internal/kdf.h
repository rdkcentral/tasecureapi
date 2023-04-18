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
 * @file kdf.h
 *
 * This file contains the functions and structures implementing key derivation algorithms.
 */

#ifndef KDF_H
#define KDF_H

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
 * Derive a key using HKDF HMAC derivation.
 *
 * @param[out] stored_key_derived the derived key.
 * @param[in] rights rights for the derived key.
 * @param[in] parameters HKDF derivation parameters.
 * @param[in] stored_key_parent the parent key.
 * @return status of the operation
 */
sa_status kdf_hkdf_hmac(
        stored_key_t** stored_key_derived,
        const sa_rights* rights,
        sa_kdf_parameters_hkdf* parameters,
        const stored_key_t* stored_key_parent);

/**
 * Derive a key using Concat KDF derivation.
 *
 * @param[out] stored_key_derived the derived key.
 * @param[in] rights rights for the derived key.
 * @param[in] parameters concat derivation parameters.
 * @param[in] stored_key_parent the parent key.
 * @return status of the operation
 */
sa_status kdf_concat_kdf(
        stored_key_t** stored_key_derived,
        const sa_rights* rights,
        sa_kdf_parameters_concat* parameters,
        const stored_key_t* stored_key_parent);

/**
 * Derive a key using the ANSI X9.63 derivation.
 *
 * @param[out] stored_key_derived the derived key.
 * @param[in] rights rights for the derived key.
 * @param[in] parameters ANSI X9.63 derivation parameters.
 * @param[in] stored_key_parent the parent key.
 * @return status of the operation
 */
sa_status kdf_ansi_x963(
        stored_key_t** stored_key_derived,
        const sa_rights* rights,
        sa_kdf_parameters_ansi_x963* parameters,
        const stored_key_t* stored_key_parent);

/**
 * Derive a key using the NIST 800-108 KDF in counter mode.
 *
 * @param[out] stored_key_derived the derived key.
 * @param[in] rights rights for the derived key.
 * @param[in] parameters CMAC derivation parameters.
 * @param[in] stored_key_parent the parent key.
 * @return status of the operation
 */
sa_status kdf_ctr_cmac(
        stored_key_t** stored_key_derived,
        const sa_rights* rights,
        sa_kdf_parameters_cmac* parameters,
        const stored_key_t* stored_key_parent);

#ifdef __cplusplus
}
#endif

#endif // KDF_H
