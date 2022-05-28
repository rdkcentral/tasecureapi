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
 * @file kdf.h
 *
 * This file contains the functions implementing internal hmac algorithms.
 */

#ifndef HMAC_INTERNAL_H
#define HMAC_INTERNAL_H

#include "sa_types.h"

#ifdef __cplusplus

#include <cstdbool>
#include <cstddef>

extern "C" {
#else
#include <stdbool.h>
#include <stddef.h>
#endif

/**
 * Compute the HMAC SHA value over inputs.
 *
 * @param[out] mac mac value.
 * @param[in,out] mac_length mac value length. Set to number of bytes written on exit.
 * @param[in] digest_algorithm digest algorithm.
 * @param[in] in1 first input data.
 * @param[in] in1_length first input data length.
 * @param[in] in2 second input data.
 * @param[in] in2_length second input data length.
 * @param[in] in3 third input data.
 * @param[in] in3_length third input data length.
 * @param[in] key key.
 * @param[in] key_length the key length.
 * @return status of the operation.
 */
bool hmac_internal(
        void* mac,
        size_t* mac_length,
        sa_digest_algorithm digest_algorithm,
        const void* in1,
        size_t in1_length,
        const void* in2,
        size_t in2_length,
        const void* in3,
        size_t in3_length,
        const void* key,
        size_t key_length);

#endif // HMAC_INTERNAL_H
