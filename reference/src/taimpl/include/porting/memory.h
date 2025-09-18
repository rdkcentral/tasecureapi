/*
 * Copyright 2019-2025 Comcast Cable Communications Management, LLC
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
 * @file memory.h
 *
 * This file contains functions for heap memory allocation and de-allocation as well as secure
 * versions of the memcmp and memset functions.
 */

#ifndef MEMORY_H
#define MEMORY_H

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
 * Allocate memory from a secure heap. If no such heap exists for a given platform, allocate
 * using memory_internal_alloc. Secure heap is preferred to general heap for storage of key material.
 *
 * @param[in] size size in bytes to allocate.
 * @return pointer to allocated buffer. NULL if the allocation failed.
 */
void* memory_secure_alloc(size_t size);

/**
 * Reallocates memory from a secure heap. If secure heap does not exist for a given platform,
 * use internal heap. This function is semantically same as the standard library realloc.
 *
 * @param[in] buffer buffer to reallocate.
 * @param[in] new_size new size of the buffer.
 * @return see standard library realloc.
 */
void* memory_secure_realloc(
        void* buffer,
        size_t new_size);

/**
 * Release memory back to the secure heap. If no such heap exists for a given platform, release
 * using memory_internal_free. This operation is a NOOP if the buffer is NULL.
 *
 * @param[in] buffer pointer to the buffer to release.
 */
void memory_secure_free(void* buffer);

/**
 * Allocate memory from a general purpose heap.
 *
 * @param[in] size size in bytes to allocate.
 * @return pointer to allocated buffer. NULL if the allocation failed.
 */
void* memory_internal_alloc(size_t size);

/**
 * Reallocates memory from an internal heap. This function is semantically same as the standard
 * library realloc.
 *
 * @param[in] buffer buffer to reallocate.
 * @param[in] new_size new size of the buffer.
 * @return see standard library realloc.
 */
void* memory_internal_realloc(
        void* buffer,
        size_t new_size);

/**
 * Release memory back to the general purpose heap. This operation is a NOOP if the buffer is NULL.
 *
 * @param[in] buffer buffer to release
 */
void memory_internal_free(void* buffer);

/**
 * Constant time memory compare function with same semantics as the standard memcmp.
 *
 * @param[in] in1 first input buffer.
 * @param[in] in2 second input buffer.
 * @param[in] length number of bytes to compare.
 * @return 0 if the buffers are the same.
 */
int memory_memcmp_constant(
        const void* in1,
        const void* in2,
        size_t length);

/**
 * Un-optimizable memory clear function with same semantics as the standard memset.
 *
 * @param[out] destination destination buffer.
 * @param[in] value value to fill the output buffer with.
 * @param[in] size number of bytes to set.
 * @return destination pointer.
 */
void* memory_memset_unoptimizable(
        void* destination,
        uint8_t value,
        size_t size);

#ifndef DISABLE_SVP
/**
 * Checks if all of the bytes between memory_location and memory_location+size are in SVP memory.
 *
 * @param destination the starting memory location.
 * @param size the number of bytes to check.
 * @return true if all bytes are within SVP memory. false if not.
 */
bool memory_is_valid_svp(
        void* memory_location,
        size_t size);
#endif // DISABLE_SVP

/**
 * Checks if all of the bytes between memory_location and memory_location+size are in non-SVP memory.
 *
 * @param destination the starting memory location.
 * @param size the number of bytes to check.
 * @return true if all bytes are within non-SVP memory. false if not.
 */
bool memory_is_valid_clear(
        void* memory_location,
        size_t size);

#ifdef __cplusplus
}
#endif

#endif // MEMORY_H
