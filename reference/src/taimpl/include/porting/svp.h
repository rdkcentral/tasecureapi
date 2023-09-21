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
 * @file svp.h
 *
 * This file contains the functions and structures implementing validation of and writing to secure
 * video pipeline buffers. Implementors shall replace this functionality with platform dependent
 * functionality.
 */

#ifndef SVP_H
#define SVP_H

#include "sa_types.h"
#include "stored_key.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Identifies if SVP is supported.
 *
 * @return SA_STATUS_OK if supported. SA_STATUS_OPERATION_NOT_SUPPORTED if not supported.
 */
sa_status svp_supported();

/**
 * Write the specified data into a protected SVP buffer
 *
 * @param[out] out the SVP memory into which the data should be written.
 * @param[in] in the buffer from which to copy the data.
 * @param[in] in_length the length of the input data.
 * @param[in] offsets the offsets to write.
 * @param[in] offsets_length the number of offsets to write.
 * @return true if successful.
 */
bool svp_write(
        void* out,
        const void* in,
        size_t in_length,
        sa_svp_offset* offsets,
        size_t offsets_length);

/**
 * Copy the specified data from one protected SVP buffer to another
 *
 * @param[out] out the SVP memory into which the data should be written.
 * @param[in] in the SVP memory from which to copy the data.
 * @param[in] offsets the offsets to write.
 * @param[in] offsets_length the number of offsets to write.
 * @return true if successful.
 */
bool svp_copy(
        void* out,
        const void* in,
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
 * @param[in] svp_memory* the SVP memory to digest.
 * @param[in] offset the offset into SVP at which to start.
 * @param[in] length the number of bytes in the SVP buffer to include in the digest.
 * @return the digest of the SBP buffer.
 */
bool svp_digest(
        void* out,
        size_t* out_length,
        sa_digest_algorithm digest_algorithm,
        const void* svp_memory,
        size_t offset,
        size_t length);

#ifdef __cplusplus
}
#endif

#endif // SVP_H
