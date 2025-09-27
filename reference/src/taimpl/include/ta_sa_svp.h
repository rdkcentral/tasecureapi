/*
 * Copyright 2020-2025 Comcast Cable Communications Management, LLC
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
 * @file ta_sa_svp.h
 *
 * This file contains the TA implementation of "svp" module functions. Please refer to
 * sa_svp.h file for method and parameter documentation.
 */

#ifndef TA_SA_SVP_H
#define TA_SA_SVP_H

#include "ta_sa_types.h"

#ifdef __cplusplus

#include <cstddef>

extern "C" {
#else
#include <stddef.h>
#endif

/**
 * Determine if SVP is supported by this implementation.
 *
 * @param[in] client_slot the client slot ID.
 * @param[in] caller_uuid the UUID of the caller.
 * @return Operation status. Possible values are:
 * + SA_STATUS_OK - Operation succeeded. SVP is available on this platform.
 * + SA_STATUS_OPERATION_NOT_SUPPORTED - Implementation does not support the specified operation.
 * SVP is not available on this platform.
 * + SA_STATUS_SELF_TEST - Implementation self-test has failed.
 * + SA_STATUS_INTERNAL_ERROR - An unexpected error has occurred.
 */
sa_status ta_sa_svp_supported(
        ta_client client_slot,
        const sa_uuid* caller_uuid);

#ifndef DISABLE_SVP
/**
 * Create an SVP buffer handle. Buffer passed in is validated to be wholly contained within the
 * restricted SVP memory region. SecAPI does not provide functionality for allocating and
 * deallocating the secure region buffers.
 *
 * @param[out] svp_buffer SVP buffer handle.
 * @param[in] buffer Restricted SVP region buffer.
 * @param[in] size Size of the restricted SVP region buffer in bytes.
 * @param[in] client the client slot ID.
 * @param[in] caller_uuid the UUID of the caller.
 * @return Operation status. Possible values are:
 * + SA_STATUS_OK - Operation succeeded.
 * + SA_STATUS_NO_AVAILABLE_RESOURCE_SLOT - No available SVP slots.
 * + SA_STATUS_NULL_PARAMETER - SVP_buffer or buffer is NULL.
 * + SA_STATUS_INVALID_SVP_BUFFER - SVP buffer is not fully contained withing SVP memory region.
 * + SA_STATUS_OPERATION_NOT_SUPPORTED - Implementation does not support the specified operation.
 * + SA_STATUS_SELF_TEST - Implementation self-test has failed.
 * + SA_STATUS_INTERNAL_ERROR - An unexpected error has occurred.
 */
sa_status ta_sa_svp_buffer_create(
        sa_svp_buffer* svp_buffer,
        void* buffer,
        size_t size,
        ta_client client,
        const sa_uuid* caller_uuid);

/**
 * Release the SVP buffer handle. This call does not delete the SVP memory region buffer associated with it.
 *
 * @param[out] out a reference to the SVP memory region.
 * @param[out] out_length the length of the SVP memory region.
 * @param[in] svp_buffer SVP buffer handle.
 * @param[in] client_slot the client slot ID.
 * @param[in] caller_uuid the UUID of the caller.
 * @return Operation status. Possible values are:
 * + SA_STATUS_OK - Operation succeeded.
 * + SA_STATUS_NULL_PARAMETER - svp_buffer is NULL.
 * + SA_STATUS_OPERATION_NOT_SUPPORTED - Implementation does not support the specified operation.
 * + SA_STATUS_SELF_TEST - Implementation self-test has failed.
 * + SA_STATUS_INTERNAL_ERROR - An unexpected error has occurred.
 */
sa_status ta_sa_svp_buffer_release(
        void** out,
        size_t* out_length,
        sa_svp_buffer svp_buffer,
        ta_client client_slot,
        const sa_uuid* caller_uuid);

/**
 * Write a block of data into an SVP buffer.
 *
 * @param[in] out Destination SVP buffer.
 * @param[in] in Source data to write.
 * @param[in] in_length The length of the source data.
 * @param[in] offsets a list of offsets into the source and destination of the block to copy and the length of the
 * block.
 * @param[in] offset_length Number of offset blocks to copy.
 * @param[in] client_slot the client slot ID.
 * @param[in] caller_uuid the UUID of the caller.
 * @return Operation status. Possible values are:
 * + SA_STATUS_OK - Operation succeeded.
 * + SA_STATUS_NULL_PARAMETER - out, out_offset, or in is NULL.
 * + SA_STATUS_INVALID_PARAMETER - Writing past the end of the SVP buffer detected.
 * + SA_STATUS_INVALID_SVP_BUFFER - SVP buffer is not fully contained withing SVP memory region.
 * + SA_STATUS_OPERATION_NOT_SUPPORTED - Implementation does not support the specified operation.
 * + SA_STATUS_SELF_TEST - Implementation self-test has failed.
 * + SA_STATUS_INTERNAL_ERROR - An unexpected error has occurred.
 */
sa_status ta_sa_svp_buffer_write(
        sa_svp_buffer out,
        const void* in,
        size_t in_length,
        sa_svp_offset* offsets,
        size_t offsets_length,
        ta_client client_slot,
        const sa_uuid* caller_uuid);

/**
 * Copy a block of data from one secure buffer to another. Destination buffer is validated to be wholly contained within
 * the restricted SVP memory region. Destination range is validated to be wholly contained within the destination SVP
 * buffer. Input range is validated to be wholly contained within the input SVP buffer.
 *
 * @param[in] out Destination SVP buffer.
 * @param[in] in Source data to write.
 * @param[in] offsets a list of offsets into the source and destination of the block to copy and the length of the
 * block.
 * @param[in] offset_length Number of offset blocks to copy.
 * @param[in] client_slot the client slot ID.
 * @param[in] caller_uuid the UUID of the caller.
 * @return Operation status. Possible values are:
 * + SA_STATUS_OK - Operation succeeded.
 * + SA_STATUS_NULL_PARAMETER - out, out_offset or in is NULL.
 * + SA_STATUS_INVALID_PARAMETER - Reading or writing past the end of the SVP buffer detected.
 * + SA_STATUS_INVALID_SVP_BUFFER - SVP buffer is not fully contained withing SVP memory region.
 * + SA_STATUS_OPERATION_NOT_SUPPORTED - Implementation does not support the specified operation.
 * + SA_STATUS_SELF_TEST - Implementation self-test has failed.
 * + SA_STATUS_INTERNAL_ERROR - An unexpected error has occurred.
 */
sa_status ta_sa_svp_buffer_copy(
        sa_svp_buffer out,
        sa_svp_buffer in,
        sa_svp_offset* offsets,
        size_t offsets_length,
        ta_client client_slot,
        const sa_uuid* caller_uuid);
#endif // DISABLE_SVP
/**
 * Perform a key check by decrypting input data with an AES ECB into restricted memory and comparing with reference
 * value. This operation allows validation of keys that cannot decrypt into non-SVP buffers.
 *
 * @param[in] key Cipher key.
 * @param[in] in Input data.
 * @param[in] in_buffer_type the type of the in buffer.
 * @param[in] expected Expected result.
 * @param[in] expected_length Expected result length in bytes. Has to be equal to 16.
 * @param[in] client_slot the client slot ID.
 * @param[in] caller_uuid the UUID of the caller.
 * @return Operation status. Possible values are:
 * + SA_STATUS_OK - Operation succeeded. Key check passed.
 * + SA_STATUS_NULL_PARAMETER - key, in, or expected is NULL.
 * + SA_STATUS_INVALID_PARAMETER - in_length or expected length are not 16.
 * + SA_STATUS_OPERATION_NOT_ALLOWED - Key usage requirements are not met for the specified
 * operation.
 * + SA_STATUS_OPERATION_NOT_SUPPORTED - Implementation does not support the specified operation.
 * + SA_STATUS_SELF_TEST - Implementation self-test has failed.
 * + SA_STATUS_VERIFICATION_FAILED - Computed value does not match the expected one.
 * + SA_STATUS_INTERNAL_ERROR - An unexpected error has occurred.
 */
sa_status ta_sa_svp_key_check(
        sa_key key,
        sa_buffer* in,
        size_t bytes_to_process,
        const void* expected,
        size_t expected_length,
        ta_client client_slot,
        const sa_uuid* caller_uuid);
#ifndef DISABLE_SVP
/**
 * Perform a buffer check by digesting the data in the buffer at the offset and length and comparing it with the input
 * hash.
 *
 * @param[in] svp_buffer the buffer to hash.
 * @param[in] offset the offset at which to begin the hash.
 * @param[in] length the length of the data to hash.
 * @param[in] digest_algorithm the digest algorithm to use.
 * @param[in] hash the hash to compare against.
 * @param[in] hash_length the length of the hash.
 * @param[in] client_slot the client slot ID.
 * @param[in] caller_uuid the UUID of the caller.
 * @return Operation status. Possible values are:
 * + SA_STATUS_OK - Operation succeeded. Key check passed.
 * + SA_STATUS_NULL_PARAMETER - hash is NULL.
 * + SA_STATUS_INVALID_PARAMETER - offset or length is outside the buffer range.
 * + SA_STATUS_OPERATION_NOT_SUPPORTED - Implementation does not support the specified operation.
 * + SA_STATUS_INVALID_SVP_BUFFER - invalid SVP buffer.
 * + SA_STATUS_SELF_TEST - Implementation self-test has failed.
 * + SA_STATUS_VERIFICATION_FAILED - Computed value does not match the expected one.
 * + SA_STATUS_INTERNAL_ERROR - An unexpected error has occurred.
 */
sa_status ta_sa_svp_buffer_check(
        sa_svp_buffer svp_buffer,
        size_t offset,
        size_t length,
        sa_digest_algorithm digest_algorithm,
        const void* hash,
        size_t hash_length,
        ta_client client_slot,
        const sa_uuid* caller_uuid);

#endif // DISABLE_SVP
#ifdef __cplusplus
}
#endif

#endif // TA_SA_SVP_H


