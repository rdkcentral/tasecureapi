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
 * @file rand.h
 *
 * This file contains the functions and structures implementing random number generation.
 * Implementors shall replace these functions with hardware based secure random number generator.
 */

#ifndef RAND_H
#define RAND_H

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
 * Fill output buffer with random numbers using hardware random number generator.
 *
 * @param[out] out output buffer
 * @param[in] out_length output buffer length
 * @return true if the call succeeded, false otherwise.
 */
bool rand_bytes(
        void* out,
        size_t out_length);

/**
 * Get the global CTR-DRBG context for mbedTLS operations.
 * This is needed for mbedTLS functions that require an RNG callback.
 *
 * @return Pointer to the global mbedtls_ctr_drbg_context, or NULL if not initialized
 */
void* rand_get_drbg_context(void);

#ifdef __cplusplus
}
#endif

#endif // RAND_H
