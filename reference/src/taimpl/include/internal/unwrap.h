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
 * @file unwrap.h
 *
 * This file contains the functions and structures implementing AES unwrapping.
 */

#ifndef UNWRAP_H
#define UNWRAP_H

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
 * Unwrap data using AES ECB mode.
 *
 * @param[out] stored_key_unwrapped the stored unwrapped key.
 * @param[in] in ciphertext.
 * @param[in] in_length ciphertext length.
 * @param[in] rights the key rights.
 * @param[in] key_type the key type.
 * @param[in] type_parameters the key type parameters.
 * @param[in] cipher_algorithm cipher algorithm.
 * @param[in] stored_key_wrapping the unwrapping key.
 * @return status of the operation.
 */
sa_status unwrap_aes_ecb(
        stored_key_t** stored_key_unwrapped,
        const void* in,
        size_t in_length,
        const sa_rights* rights,
        sa_key_type key_type,
        void* type_parameters,
        sa_cipher_algorithm cipher_algorithm,
        const stored_key_t* stored_key_wrapping);

/**
 * Unwrap data using AES CBC mode.
 *
 * @param[out] stored_key_unwrapped the stored unwrapped key.
 * @param[in] in ciphertext.
 * @param[in] in_length ciphertext length.
 * @param[in] rights the key rights.
 * @param[in] key_type the key type.
 * @param[in] type_parameters the key type parameters.
 * @param[in] cipher_algorithm cipher algorithm.
 * @param[in] iv the 16 byte initialization vector.
 * @param[in] stored_key_wrapping the unwrapping key.
 * @return status of the operation.
 */
sa_status unwrap_aes_cbc(
        stored_key_t** stored_key_unwrapped,
        const void* in,
        size_t in_length,
        const sa_rights* rights,
        sa_key_type key_type,
        void* type_parameters,
        sa_cipher_algorithm cipher_algorithm,
        const void* iv,
        const stored_key_t* stored_key_wrapping);

/**
 * Unwrap data using AES CTR mode.
 *
 * @param[out] stored_key_unwrapped the stored unwrapped key.
 * @param[in] in ciphertext.
 * @param[in] in_length ciphertext length.
 * @param[in] rights the key rights.
 * @param[in] key_type the key type.
 * @param[in] type_parameters the key type parameters.
 * @param[in] ctr the 16 byte counter.
 * @param[in] stored_key_wrapping the unwrapping key.
 * @return status of the operation.
 */
sa_status unwrap_aes_ctr(
        stored_key_t** stored_key_unwrapped,
        const void* in,
        size_t in_length,
        const sa_rights* rights,
        sa_key_type key_type,
        void* type_parameters,
        const void* ctr,
        const stored_key_t* stored_key_wrapping);

/**
 * Unwrap data using AES GCM mode.
 *
 * @param[out] stored_key_unwrapped the stored unwrapped key.
 * @param[in] in ciphertext.
 * @param[in] in_length ciphertext length.
 * @param[in] rights the key rights.
 * @param[in] key_type the key type.
 * @param[in] type_parameters the key type parameters.
 * @param[in] algorithm_parameters the unwrap parameters.
 * @param[in] stored_key_wrapping the unwrapping key.
 * @return status of the operation.
 */
sa_status unwrap_aes_gcm(
        stored_key_t** stored_key_unwrapped,
        const void* in,
        size_t in_length,
        const sa_rights* rights,
        sa_key_type key_type,
        void* type_parameters,
        const sa_unwrap_parameters_aes_gcm* algorithm_parameters,
        const stored_key_t* stored_key_wrapping);

/**
 * Unwrap data using CHACHA20 mode.
 *
 * @param[out] stored_key_unwrapped the stored unwrapped key.
 * @param[in] in ciphertext.
 * @param[in] in_length ciphertext length.
 * @param[in] rights the key rights.
 * @param[in] key_type the key type.
 * @param[in] type_parameters the key type parameters.
 * @param[in] algorithm_parameters the unwrap parameters.
 * @param[in] stored_key_wrapping the unwrapping key.
 * @return status of the operation.
 */
sa_status unwrap_chacha20(
        stored_key_t** stored_key_unwrapped,
        const void* in,
        size_t in_length,
        const sa_rights* rights,
        sa_key_type key_type,
        void* type_parameters,
        const sa_unwrap_parameters_chacha20* algorithm_parameters,
        const stored_key_t* stored_key_wrapping);

/**
 * Unwrap data using CHACHA20 mode.
 *
 * @param[out] stored_key_unwrapped the stored unwrapped key.
 * @param[in] in ciphertext.
 * @param[in] in_length ciphertext length.
 * @param[in] rights the key rights.
 * @param[in] key_type the key type.
 * @param[in] type_parameters the key type parameters.
 * @param[in] algorithm_parameters the unwrap parameters.
 * @param[in] stored_key_wrapping the unwrapping key.
 * @return status of the operation.
 */
sa_status unwrap_chacha20_poly1305(
        stored_key_t** stored_key_unwrapped,
        const void* in,
        size_t in_length,
        const sa_rights* rights,
        sa_key_type key_type,
        void* type_parameters,
        const sa_unwrap_parameters_chacha20_poly1305* algorithm_parameters,
        const stored_key_t* stored_key_wrapping);

/**
 * Unwrap data using RSA.
 *
 * @param[out] stored_key_unwrapped the stored unwrapped key.
 * @param[in] in ciphertext.
 * @param[in] in_length ciphertext length.
 * @param[in] rights the key rights.
 * @param[in] cipher_algorithm the unwrap algorithm.
 * @param[in] algorithm_parameters the unwrap parameters.
 * @param[in] stored_key_wrapping the unwrapping key.
 * @return status of the operation.
 */
sa_status unwrap_rsa(
        stored_key_t** stored_key_unwrapped,
        const void* in,
        size_t in_length,
        const sa_rights* rights,
        sa_cipher_algorithm cipher_algorithm,
        void* algorithm_parameters,
        const stored_key_t* stored_key_wrapping);

/**
 * Unwrap data using EC.
 *
 * @param[out] stored_key_unwrapped the stored unwrapped key.
 * @param[in] in ciphertext.
 * @param[in] in_length ciphertext length.
 * @param[in] rights the key rights.
 * @param[in] algorithm_parameters the unwrap parameters.
 * @param[in] stored_key_wrapping the unwrapping key.
 * @return status of the operation.
 */
sa_status unwrap_ec(
        stored_key_t** stored_key_unwrapped,
        const void* in,
        size_t in_length,
        const sa_rights* rights,
        sa_unwrap_parameters_ec_elgamal* algorithm_parameters,
        const stored_key_t* stored_key_wrapping);

#ifdef __cplusplus
}
#endif

#endif // UNWRAP_H
