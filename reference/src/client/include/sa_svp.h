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

/**
 * @file sa_svp.h
 *
 * This file contains the function declarations for the "svp" module of the SecAPI. "svp"
 * module contains functions for performing cryptographic operations in Secure Video Pipeline
 * protected memory region.
 */

#ifndef SA_SVP_H
#define SA_SVP_H

#include "sa_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Determine if SVP is supported by this implementation.
 *
 * @return Operation status. Possible values are:
 * + SA_STATUS_OK - Operation succeeded. SVP is available on this platform.
 * + SA_STATUS_OPERATION_NOT_SUPPORTED - Implementation does not support the specified operation.
 * SVP is not available on this platform.
 * + SA_STATUS_SELF_TEST - Implementation self-test has failed.
 * + SA_STATUS_INTERNAL_ERROR - An unexpected error has occurred.
 */
sa_status sa_svp_supported();

/**
 * Allocate an SVP memory block. The output of this function must be compatible with RDK SVP functions.
 *
 * @param[out] svp_memory pointer to the SVP memory region.
 * @param[in] size Size of the restricted SVP memory region in bytes.
 * @return Operation status. Possible values are:
 * + SA_STATUS_OK - Operation succeeded.
 * + SA_STATUS_NULL_PARAMETER - svp_memory is NULL.
 * + SA_STATUS_OPERATION_NOT_SUPPORTED - Implementation does not support the specified operation.
 * + SA_STATUS_SELF_TEST - Implementation self-test has failed.
 * + SA_STATUS_INTERNAL_ERROR - An unexpected error has occurred.
 */
sa_status sa_svp_memory_alloc(
        void** svp_memory,
        size_t size);

/**
 * Free an SVP memory block. The input of this function must be compatible with RDK SVP functions.
 *
 * @param[in] svp_memory pointer to the SVP memory region.
 * @return Operation status. Possible values are:
 * + SA_STATUS_OK - Operation succeeded.
 * + SA_STATUS_NULL_PARAMETER - svp_memory is NULL.
 * + SA_STATUS_OPERATION_NOT_SUPPORTED - Implementation does not support the specified operation.
 * + SA_STATUS_SELF_TEST - Implementation self-test has failed.
 * + SA_STATUS_INTERNAL_ERROR - An unexpected error has occurred.
 */
sa_status sa_svp_memory_free(void* svp_memory);

/**
 * Write a block of data into an SVP memory region. The input of this function must be compatible with RDK SVP
 * functions.
 *
 * @param[in] out Destination SVP memory.
 * @param[in] in Source data to write.
 * @param[in] in_length The length of the source data.
 * @param[in] offsets a list of offsets into the source and destination of the block to copy and the length of the
 * block.
 * @param[in] offsets_length Number of offset blocks to copy.
 * @return Operation status. Possible values are:
 * + SA_STATUS_OK - Operation succeeded.
 * + SA_STATUS_NULL_PARAMETER - out, out_offset, or in is NULL.
 * + SA_STATUS_INVALID_PARAMETER - Writing past the end of the SVP memory region detected.
 * + SA_STATUS_INVALID_SVP_MEMORY - memory is not fully contained withing SVP memory region.
 * + SA_STATUS_OPERATION_NOT_SUPPORTED - Implementation does not support the specified operation.
 * + SA_STATUS_SELF_TEST - Implementation self-test has failed.
 * + SA_STATUS_INTERNAL_ERROR - An unexpected error has occurred.
 */
sa_status sa_svp_write(
        void* out,
        const void* in,
        size_t in_length,
        sa_svp_offset* offsets,
        size_t offsets_length);

/**
 * Copy a block of data from one secure memory region to another. Destination memory region is validated to be wholly
 * contained within the restricted SVP memory region. Destination range is validated to be wholly contained within the
 * destination SVP memory region. Input range is validated to be wholly contained within the input SVP memory region.
 * The inputs of this function must be compatible with RDK SVP functions.
 *
 * @param[in] out Destination SVP memory.
 * @param[in] in Source data to copy.
 * @param[in] offsets a list of offsets into the source and destination of the block to copy and the length of the
 * block.
 * @param[in] offsets_length Number of offset blocks to copy.
 * @return Operation status. Possible values are:
 * + SA_STATUS_OK - Operation succeeded.
 * + SA_STATUS_NULL_PARAMETER - out, out_offset or in is NULL.
 * + SA_STATUS_INVALID_PARAMETER - Reading or writing past the end of the SVP memory region detected.
 * + SA_STATUS_INVALID_SVP_MEMORY - SVP memory region is not fully contained withing SVP memory region.
 * + SA_STATUS_OPERATION_NOT_SUPPORTED - Implementation does not support the specified operation.
 * + SA_STATUS_SELF_TEST - Implementation self-test has failed.
 * + SA_STATUS_INTERNAL_ERROR - An unexpected error has occurred.
 */
sa_status sa_svp_copy(
        void* out,
        void* in,
        sa_svp_offset* offsets,
        size_t offsets_length);

/**
 * Perform a key check by decrypting input data with an AES ECB into restricted memory and comparing with reference
 * value. This operation allows validation of keys that cannot decrypt into non-SVP buffers.
 *
 * @param[in] key Cipher key.
 * @param[in] in Input data.
 * @param[in] bytes_to_process The number of bytes to process. Has to be equal to 16.
 * @param[in] expected Expected result.
 * @param[in] expected_length Expected result length in bytes. Has to be equal to 16.
 * @return Operation status. Possible values are:
 * + SA_STATUS_OK - Operation succeeded. Key check passed.
 * + SA_STATUS_NULL_PARAMETER - in or expected is NULL.
 * + SA_STATUS_INVALID_PARAMETER - in.context.clear/svp.length or expected length are not 16.
 * + SA_STATUS_OPERATION_NOT_ALLOWED - Key usage requirements are not met for the specified
 * operation.
 * + SA_STATUS_OPERATION_NOT_SUPPORTED - Implementation does not support the specified operation.
 * + SA_STATUS_SELF_TEST - Implementation self-test has failed.
 * + SA_STATUS_VERIFICATION_FAILED - Computed value does not match the expected one.
 * + SA_STATUS_INTERNAL_ERROR - An unexpected error has occurred.
 */
sa_status sa_svp_key_check(
        sa_key key,
        sa_buffer* in,
        size_t bytes_to_process,
        const void* expected,
        size_t expected_length);

/**
 * Perform an SVP memory region check by digesting the data in the SVP memory region at the offset and length and
 * comparing it with the input hash. This function can only be called from another TA. Calls from the REE will return
 * SA_STATUS_OPERATION_NOT_SUPPORTED.
 *
 * @param[in] svp_memory SVP memory region to hash.
 * @param[in] offset Offset at which to begin the hash.
 * @param[in] length Length of the data to hash.
 * @param[in] digest_algorithm Digest algorithm to use.
 * @param[in] hash Hash to compare against.
 * @param[in] hash_length Length of the hash.
 * @return Operation status. Possible values are:
 * + SA_STATUS_OK - Operation succeeded. Key check passed.
 * + SA_STATUS_NULL_PARAMETER - hash is NULL.
 * + SA_STATUS_INVALID_PARAMETER - offset or length is outside the SVP memory region range.
 * + SA_STATUS_OPERATION_NOT_SUPPORTED - Implementation does not support the specified operation.
 * + SA_STATUS_INVALID_SVP_MEMORY - invalid SVP memory region.
 * + SA_STATUS_SELF_TEST - Implementation self-test has failed.
 * + SA_STATUS_VERIFICATION_FAILED - Computed value does not match the expected one.
 * + SA_STATUS_INTERNAL_ERROR - An unexpected error has occurred.
 */
sa_status sa_svp_check(
        void* svp_memory,
        size_t offset,
        size_t length,
        sa_digest_algorithm digest_algorithm,
        const void* hash,
        size_t hash_length);

#ifdef __cplusplus
}
#endif

#endif /* SA_SVP_H */
