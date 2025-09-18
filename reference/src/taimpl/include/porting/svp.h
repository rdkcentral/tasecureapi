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
 * @file svp.h
 *
 * This file contains the functions and structures implementing validation of and writing to secure
 * video pipeline buffers. Implementors shall replace this functionality with platform dependent
 * functionality.
 */
#ifndef SVP_H
#define SVP_H
#include "sa_types.h"

#ifdef __cplusplus

#include <cstdbool>
#include <cstddef>

extern "C" {
#else
#include <stdbool.h>
#include <stddef.h>
#include <stored_key.h>
#endif

typedef struct svp_buffer_s svp_buffer_t;

#ifndef DISABLE_SVP
/**
 * Creates a protected SVP buffer from a previously allocated SVP memory region and its size.
 *
 * @param[out] svp_buffer the SVP buffer that was allocated.
 * @param[in] svp_memory the previously allocated SVP memory region.
 * @param[in] size the size of the previously allocated SVP region.
 * @return true if successful.
 */
bool svp_create_buffer(
        svp_buffer_t** svp_buffer,
        void* svp_memory,
        size_t size);

/**
 * Releases a protected SVP buffer and returns the SVP memory region and its size.
 *
 * @param[out] svp_memory a reference to the SVP memory region.
 * @param[out] size the size of the SVP memory region.
 * @param[in] svp_buffer the SVP buffer to release.
 * @return true if successful.
 */
bool svp_release_buffer(
        void** svp_memory,
        size_t* size,
        svp_buffer_t* svp_buffer);

/**
 * Write the specified data into a protected SVP buffer
 *
 * @param[out] out_svp_buffer the buffer into which the data should be written.
 * @param[in] in the buffer from which to copy the data.
 * @param[in] in_length the length of the input data.
 * @param[in] offsets the offsets to write.
 * @param[in] offsets_length the number of offsets to write.
 * @return true if successful.
 */
bool svp_write(
        svp_buffer_t* out_svp_buffer,
        const void* in,
        size_t in_length,
        sa_svp_offset* offsets,
        size_t offsets_length);

/**
 * Copy the specified data from one protected SVP buffer to another
 *
 * @param[out] out_svp_buffer the buffer into which the data should be written.
 * @param[in] in_svp_buffer the buffer from which to copy the data.
 * @param[in] offsets the offsets to write.
 * @param[in] offsets_length the number of offsets to write.
 * @return true if successful.
 */
bool svp_copy(
        svp_buffer_t* out_svp_buffer,
        const svp_buffer_t* in_svp_buffer,
        sa_svp_offset* offsets,
        size_t offsets_length);

/**
 * Perform a key check by decrypting input data with an AES ECB into restricted memory and comparing with reference
 * value. This operation allows validation of keys that cannot decrypt into non-SVP buffers.
 *
 * @param in_bytes the bytes to decrypt.
 * @param bytes_to_process the number of bytes to decrypt.
 * @param expected the expected result.
 * @param stored_key the key to use in the decryption.
 * @return true if the decrypted bytes match the expected bytes.
 */
#endif // DISABLE_SVP
bool svp_key_check(
        uint8_t* in_bytes,
        size_t bytes_to_process,
        const void* expected,
        stored_key_t* stored_key);

/**
 * Computes a digest over the protected SVP buffer.
 *
 * @param[out] out the location to olace the digest.
 * @param[inout] out_length the length of the digest location and the number of bytes written.
 * @param[in] digest_algorithm the digest algorithm to use.
 * @param[in] svp_buffer_t* the SVP buffer to digest.
 * @param[in] offset the offset into SVP at which to start.
 * @param[in] length the number of bytes in the SVP buffer to include in the digest.
 * @return the digest of the SBP buffer.
 */
#ifndef DISABLE_SVP
bool svp_digest(
        void* out,
        size_t* out_length,
        sa_digest_algorithm digest_algorithm,
        const svp_buffer_t* svp_buffer,
        size_t offset,
        size_t length);

/**
 * Get the protected SVP memory location.
 *
 * @param[in] svp_buffer svp.
 * @return the SVP buffer.
 */
void* svp_get_svp_memory(const svp_buffer_t* svp_buffer);

/**
 * Get the protected SVP memory size.
 *
 * @param[in] svp_buffer svp.
 * @return the buffer length.
 */
size_t svp_get_size(const svp_buffer_t* svp_buffer);
#endif // DISABLE_SVP
#ifdef __cplusplus
}
#endif

#endif // SVP_H
