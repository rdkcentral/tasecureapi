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
 * @file digest.h
 *
 * This file contains the functions and structures implementing digest algorithms.
 */

#ifndef DIGEST_H
#define DIGEST_H

#include "sa_types.h"
#include "stored_key.h"
#include "digest_util_mbedtls.h"
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

#define DIGEST_MAX_LENGTH 64

/**
 * Compute a SHA digest value over inputs.
 *
 * @param[out] out output buffer for computed digest value.
 * @param[in,out] out_length output buffer length. Set to number of bytes written on exit.
 * @param[in] digest_algorithm the digest algorithm to use.
 * @param[in] in1 first input buffer.
 * @param[in] in1_length length of first input buffer.
 * @param[in] in2 second input buffer.
 * @param[in] in2_length length of second input buffer.
 * @param[in] in3 third input buffer.
 * @param[in] in3_length length of third input buffer.
 * @return status of the operation
 */
sa_status digest_sha(
        void* out,
        size_t* out_length,
        sa_digest_algorithm digest_algorithm,
        const void* in1,
        size_t in1_length,
        const void* in2,
        size_t in2_length,
        const void* in3,
        size_t in3_length);

/**
 * Computes a SHA digest over a key.
 *
 * @param[out] out output buffer for computed digest value.
 * @param[in,out] out_length output buffer length. Set to number of bytes written on exit.
 * @param[in] digest_algorithm the digest algorithm to use.
 * @param[in] stored_key the stored key over which to compute the digest.
 * @return status of the operation
 */
sa_status digest_key(
        void* out,
        size_t* out_length,
        sa_digest_algorithm digest_algorithm,
        const stored_key_t* stored_key);

#ifdef __cplusplus
}
#endif

#endif // DIGEST_H
