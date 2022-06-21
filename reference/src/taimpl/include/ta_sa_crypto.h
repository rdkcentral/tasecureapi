/**
 * Copyright 2020-2022 Comcast Cable Communications Management, LLC
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
 * @file ta_sa_crypto.h
 *
 * This file contains the TA implementation of "crypto" module functions. Please refer to
 * sa_crypto.h file for method and parameter documentation.
 */

#ifndef TA_SA_CRYPTO_H
#define TA_SA_CRYPTO_H

#include "sa_types.h"
#include "ta_sa_types.h"

#ifdef __cplusplus

#include <cstdbool>
#include <cstddef>

extern "C" {
#else
#include <stdbool.h>
#include <stddef.h>
#endif

/**
 * Fill a memory buffer with random data.
 *
 * @param[out] out Destination buffer.
 * @param[in] length Number of bytes to write.
 * @param[in] client_slot the client slot ID.
 * @param[in] caller_uuid the UUID of the caller.
 * @return Operation status. Possible values are:
 * + SA_STATUS_OK - Operation succeeded.
 * + SA_STATUS_NULL_PARAMETER - out is NULL.
 * + SA_STATUS_OPERATION_NOT_SUPPORTED - Implementation does not support the specified operation.
 * + SA_STATUS_SELF_TEST - Implementation self-test has failed.
 * + SA_STATUS_INTERNAL_ERROR - An unexpected error has occurred.
 */
sa_status ta_sa_crypto_random(
        void* out,
        size_t length,
        ta_client client_slot,
        const sa_uuid* caller_uuid);

/**
 * Initialize the cipher context.
 *
 * @param[out] context Cipher context.
 * @param[in] cipher_algorithm Cipher algorithm.
 * @param[in] cipher_mode Cipher mode.
 * @param[in] key Cipher key.
 * @param[in] parameters Algorithm specific parameters. Use sa_cipher_parameters_aes_cbc with
 * SA_CIPHER_ALGORITHM_AES_CBC and SA_CIPHER_ALGORITHM_AES_CBC_PKCS7, sa_cipher_parameters_aes_ctr
 * with SA_CIPHER_ALGORITHM_AES_CTR, and sa_cipher_parameters_aes_gcm with
 * SA_CIPHER_ALGORITHM_AES_GCM.
 * @param[in] client_slot the client slot ID.
 * @param[in] caller_uuid the UUID of the caller.
 * @return Operation status. Possible values are:
 * + SA_STATUS_OK - Operation succeeded.
 * + SA_STATUS_NO_AVAILABLE_RESOURCE_SLOT - No available cipher slots.
 * + SA_STATUS_BAD_KEY_TYPE - Key is not of correct type for specified algorithm.
 * + SA_STATUS_NULL_PARAMETER - context, key, or parameters (if required) is NULL.
 * + SA_STATUS_BAD_PARAMETER
 *   + Invalid algorithm specified.
 *   + Invalid mode specified.
 *   + Invalid algorithm specific parameter value encountered.
 * + SA_STATUS_OPERATION_NOT_ALLOWED - Key usage requirements are not met for the specified
 * operation.
 * + SA_STATUS_OPERATION_NOT_SUPPORTED - Implementation does not support the specified operation.
 * + SA_STATUS_SELF_TEST - Implementation self-test has failed.
 * + SA_STATUS_INTERNAL_ERROR - An unexpected error has occurred.
 */
sa_status ta_sa_crypto_cipher_init(
        sa_crypto_cipher_context* context,
        sa_cipher_algorithm cipher_algorithm,
        sa_cipher_mode cipher_mode,
        sa_key key,
        void* parameters,
        ta_client client_slot,
        const sa_uuid* caller_uuid);

/**
 * Set the initialization vector or counter on a cipher context. This is an optimization that
 * allows the update of the IV or counter parameter without complete re-initialization of the cipher
 * context.
 *
 * @param[in] context Cipher context.
 * @param[in] iv Initialization vector.
 * @param[in] iv_length Initialization vector length in bytes. Has to be 16.
 * @param[in] client_slot the client slot ID.
 * @param[in] caller_uuid the UUID of the caller.
 * @return Operation status. Possible values are:
 * + SA_STATUS_OK - Operation succeeded.
 * + SA_STATUS_NULL_PARAMETER - iv is NULL.
 * + SA_STATUS_BAD_PARAMETER
 *   + iv_length is different than 16.
 *   + Context has been initialized with a cipher that does not require an IV.
 * + SA_STATUS_OPERATION_NOT_SUPPORTED - Implementation does not support the specified operation.
 * + SA_STATUS_SELF_TEST - Implementation self-test has failed.
 * + SA_STATUS_INTERNAL_ERROR - An unexpected error has occurred.
 */
sa_status ta_sa_crypto_cipher_update_iv(
        sa_crypto_cipher_context context,
        const void* iv,
        size_t iv_length,
        ta_client client_slot,
        const sa_uuid* caller_uuid);

/**
 * Process a data chunk with the cipher.
 *
 * @param[out] out output buffer. out can be set to NULL to obtain the required size. svp.offset or clear.offset will
 * be set to offset at which the written data ends on function return. If the key rights require SVP, then
 * out.buffer_type must be SA_BUFFER_TYPE_SVP. If out.buffer_type is SA_BUFFER_TYPE_SVP, then the key_type must be AES.
 * @param[in] context Cipher context.
 * @param[in] in input buffer. svp.offset or clear.offset will be set to offset at which the read data ends on function
 * return. If the out.buffer_type is SA_BUFFER_TYPE_CLEAR, then in.buffer_type must also be SA_BUFFER_TYPE_CLEAR.
 * @param[in,out] bytes_to_process number of bytes in the input buffer to process. Returns the number of bytes
 * returned in out. If out is NULL, the required out buffer size will be returned here.
 * @param[in] client_slot the client slot ID.
 * @param[in] caller_uuid the UUID of the caller.
 * @return Operation status. Possible values are:
 * + SA_STATUS_OK - Operation succeeded.
 * + SA_STATUS_NULL_PARAMETER - caller_uuid, in, or bytes_to_process is NULL.
 * + SA_STATUS_BAD_PARAMETER
 *   + out is not NULL and out.context.svp/clear.length is not large enough to hold the result.
 *   + in.context.svp/clear.length is not valid for specified cipher, mode, and/or key.
 *   + Context has already processed last data chunk.
 *   + out.buffer_type or in.buffer_type is not allowed.
 *   + if out.buffer_type does not match the key usage requirements or if in.buffer_type is svp when out.buffer_type is
 *   clear.
 * + SA_STATUS_OPERATION_NOT_ALLOWED - Key usage requirements are not met for the specified
 * operation.
 * + SA_STATUS_OPERATION_NOT_SUPPORTED - Implementation does not support the specified operation.
 * + SA_STATUS_SELF_TEST - Implementation self-test has failed.
 * + SA_STATUS_INTERNAL_ERROR - An unexpected error has occurred.
 */
sa_status ta_sa_crypto_cipher_process(
        sa_buffer* out,
        sa_crypto_cipher_context context,
        sa_buffer* in,
        size_t* bytes_to_process,
        ta_client client_slot,
        const sa_uuid* caller_uuid);

/**
 * Process last data chunk with a cipher. Adds padding on encryption for padded cipher
 * algorithms. Checks padding on decryption for padded cipher algorithms. Creates
 * and/or checks the tag for authenticated encryption ciphers.
 *
 * @param[out] out output buffer. out can be set to NULL to obtain the required size. svp.offset or clear.offset will
 * be set to offset at which the written data ends on function return. If the key rights require SVP, then
 * out.buffer_type must be SA_BUFFER_TYPE_SVP. If out.buffer_type is SA_BUFFER_TYPE_SVP, then the key_type must be AES.
 * @param[in] context Cipher context.
 * @param[in] in input buffer. svp.offset or clear.offset will be set to offset at which the read data ends on function
 * return. If the out.buffer_type is SA_BUFFER_TYPE_CLEAR, then in.buffer_type must also be SA_BUFFER_TYPE_CLEAR.
 * @param[in] parameters Algorithm specific cipher end parameters. Use
 * sa_cipher_end_parameters_aes_gcm with SA_CIPHER_ALGORITHM_AES_GCM.
 * @param[in,out] bytes_to_process number of bytes in the input buffer to process. Returns the number of bytes
 * returned in out. If out is NULL, the required out buffer size will be returned here.
 * @param[in] client_slot the client slot ID.
 * @param[in] caller_uuid the UUID of the caller.
 * @return Operation status. Possible values are:
 * + SA_STATUS_OK - Operation succeeded.
 * + SA_STATUS_NULL_PARAMETER - caller_uuid, in, or bytes_to_process is NULL.
 * + SA_STATUS_BAD_PARAMETER
 *   + out is not NULL and out.context.svp/clear.length is not large enough to hold the result.
 *   + in.context.svp/clear.length is not valid for specified cipher, mode, and/or key.
 *   + Context has already processed last data chunk.
 *   + out.buffer_type or in.buffer_type is not allowed.
 *   + if out.buffer_type does not match the key usage requirements or if in.buffer_type is svp when out.buffer_type is
 *   clear.
 * + SA_STATUS_OPERATION_NOT_ALLOWED - Key usage requirements are not met for the specified
 * operation.
 * + SA_STATUS_OPERATION_NOT_SUPPORTED - Implementation does not support the specified operation.
 * + SA_STATUS_SELF_TEST - Implementation self-test has failed.
 * + SA_STATUS_VERIFICATION_FAILED
 *   + Bad padding value has been encountered.
 *   + Tag verification has failed.
 * + SA_STATUS_INTERNAL_ERROR - An unexpected error has occurred.
 */
sa_status ta_sa_crypto_cipher_process_last(
        sa_buffer* out,
        sa_crypto_cipher_context context,
        sa_buffer* in,
        size_t* bytes_to_process,
        void* parameters,
        ta_client client_slot,
        const sa_uuid* caller_uuid);

/**
 * Release the cipher context.
 *
 * @param[in] context Cipher context.
 * @param[in] client_slot the client slot ID.
 * @param[in] caller_uuid the UUID of the caller.
 * @return Operation status. Possible values are:
 * + SA_STATUS_OK - Operation succeeded.
 * + SA_STATUS_NULL_PARAMETER - context is NULL.
 * + SA_STATUS_OPERATION_NOT_SUPPORTED - Implementation does not support the specified operation.
 * + SA_STATUS_SELF_TEST - Implementation self-test has failed.
 * + SA_STATUS_INTERNAL_ERROR - An unexpected error has occurred.
 */
sa_status ta_sa_crypto_cipher_release(
        sa_crypto_cipher_context context,
        ta_client client_slot,
        const sa_uuid* caller_uuid);

/**
 * Initialize the Message Authentication Code context.
 *
 * @param[out] context MAC context.
 * @param[in] mac_algorithm MAC algorithm.
 * @param[in] key MAC key.
 * @param[in] parameters Algorithm specific MAC parameters. Use sa_mac_parameters_hmac with
 * @param[in] client_slot the client slot ID.
 * @param[in] caller_uuid the UUID of the caller.
 * SA_MAC_ALGORITHM_HMAC.
 * @return Operation status. Possible values are:
 * + SA_STATUS_OK - Operation succeeded.
 * + SA_STATUS_NO_AVAILABLE_RESOURCE_SLOT - No available MAC slots.
 * + SA_STATUS_BAD_KEY_TYPE - Key type is not valid for the specified operation.
 * + SA_STATUS_NULL_PARAMETER - context, key, or parameters (if required) is NULL.
 * + SA_STATUS_BAD_PARAMETER
 *   + Invalid algorithm value encountered.
 *   + Invalid algorithm specific parameter value encountered.
 * + SA_STATUS_OPERATION_NOT_ALLOWED - Key usage requirements are not met for the specified
 * operation.
 * + SA_STATUS_OPERATION_NOT_SUPPORTED - Implementation does not support the specified operation.
 * + SA_STATUS_SELF_TEST - Implementation self-test has failed.
 * + SA_STATUS_INTERNAL_ERROR - An unexpected error has occurred.
 */
sa_status ta_sa_crypto_mac_init(
        sa_crypto_mac_context* context,
        sa_mac_algorithm mac_algorithm,
        sa_key key,
        void* parameters,
        ta_client client_slot,
        const sa_uuid* caller_uuid);

/**
 * Process a chunk of data with the MAC context.
 *
 * @param[in] context MAC context.
 * @param[in] in Input data.
 * @param[in] in_length Input data length.
 * @param[in] client_slot the client slot ID.
 * @param[in] caller_uuid the UUID of the caller.
 * @return Operation status. Possible values are:
 * + SA_STATUS_OK - Operation succeeded.
 * + SA_STATUS_NULL_PARAMETER - context or in is NULL.
 * + SA_STATUS_BAD_PARAMETER - MAC value has already been generated on the context.
 * + SA_STATUS_OPERATION_NOT_SUPPORTED - Implementation does not support the specified operation.
 * + SA_STATUS_SELF_TEST - Implementation self-test has failed.
 * + SA_STATUS_INTERNAL_ERROR - An unexpected error has occurred.
 */
sa_status ta_sa_crypto_mac_process(
        sa_crypto_mac_context context,
        const void* in,
        size_t in_length,
        ta_client client_slot,
        const sa_uuid* caller_uuid);

/**
 * Process a key with the MAC context.
 *
 * @param[in] context MAC context.
 * @param[in] key the key to process.
 * @param[in] client_slot the client slot ID.
 * @param[in] caller_uuid the UUID of the caller.
 * @return Operation status. Possible values are:
 * + SA_STATUS_OK - Operation succeeded.
 * + SA_STATUS_NULL_PARAMETER - context or in is NULL.
 * + SA_STATUS_BAD_PARAMETER - MAC value has already been generated on the context.
 * + SA_STATUS_OPERATION_NOT_SUPPORTED - Implementation does not support the specified operation.
 * + SA_STATUS_SELF_TEST - Implementation self-test has failed.
 * + SA_STATUS_INTERNAL_ERROR - An unexpected error has occurred.
 */
sa_status ta_sa_crypto_mac_process_key(
        sa_crypto_mac_context context,
        sa_key key,
        ta_client client_slot,
        const sa_uuid* caller_uuid);

/**
 * Compute the MAC value.
 *
 * @param[out] out Output buffer. Can be set to NULL to obtain the required length.
 * @param[in,out] out_length Output buffer length in bytes.
 * @param[in] context MAC context.
 * @param[in] client_slot the client slot ID.
 * @param[in] caller_uuid the UUID of the caller.
 * @return Operation status. Possible values are:
 * + SA_STATUS_OK - Operation succeeded.
 * + SA_STATUS_NULL_PARAMETER - out_length or context is NULL.
 * + SA_STATUS_BAD_PARAMETER
 *   + out is not NULL and *out_length value is too small to hold the result.
 *   + MAC value has already been generated on the context.
 * + SA_STATUS_OPERATION_NOT_SUPPORTED - Implementation does not support the specified operation.
 * + SA_STATUS_SELF_TEST - Implementation self-test has failed.
 * + SA_STATUS_INTERNAL_ERROR - An unexpected error has occurred.
 */
sa_status ta_sa_crypto_mac_compute(
        void* out,
        size_t* out_length,
        sa_crypto_mac_context context,
        ta_client client_slot,
        const sa_uuid* caller_uuid);

/**
 * Release the MAC context.
 *
 * @param[in] context MAC context.
 * @param[in] client_slot the client slot ID.
 * @param[in] caller_uuid the UUID of the caller.
 * @return Operation status. Possible values are:
 * + SA_STATUS_OK - Operation succeeded.
 * + SA_STATUS_OPERATION_NOT_SUPPORTED - Implementation does not support the specified operation.
 * + SA_STATUS_SELF_TEST - Implementation self-test has failed.
 * + SA_STATUS_INTERNAL_ERROR - An unexpected error has occurred.
 */
sa_status ta_sa_crypto_mac_release(
        sa_crypto_mac_context context,
        ta_client client_slot,
        const sa_uuid* caller_uuid);

/**
 * Sign the input data.
 *
 * @param[out] out Output buffer. Can be set to NULL to obtain the required length.
 * @param[in,out] out_length Output buffer length. Set to required length.
 * @param[in] signature_algorithm Signing algorithm.
 * @param[in] key Signing key.
 * @param[in] in Input data to sign.
 * @param[in] in_length Input data length.
 * @param[in] parameters Algorithm specific parameters. Use sa_sign_parameters_rsa_pss with
 * @param[in] client_slot the client slot ID.
 * @param[in] caller_uuid the UUID of the caller.
 * SA_SIGNATURE_ALGORITHM_RSA_PSS.
 * @return Operation status. Possible values are:
 * + SA_STATUS_OK - Operation succeeded.
 * + SA_STATUS_BAD_KEY_TYPE - Key type is not valid for the specified operation.
 * + SA_STATUS_NULL_PARAMETER - out_length, key, or parameters (if required) is NULL.
 * + SA_STATUS_BAD_PARAMETER
 *   + out is not NULL and *out_length is too small to hold the result.
 *   + Invalid algorithm specified.
 *   + Invalid digest specified.
 *   + Invalid algorithm specific parameter value encountered.
 * + SA_STATUS_OPERATION_NOT_ALLOWED - Key usage requirements are not met for the specified
 * operation.
 * + SA_STATUS_OPERATION_NOT_SUPPORTED - Implementation does not support the specified operation.
 * + SA_STATUS_SELF_TEST - Implementation self-test has failed.
 * + SA_STATUS_INTERNAL_ERROR - An unexpected error has occurred.
 */
sa_status ta_sa_crypto_sign(
        void* out,
        size_t* out_length,
        sa_signature_algorithm signature_algorithm,
        sa_key key,
        const void* in,
        size_t in_length,
        const void* parameters,
        ta_client client_slot,
        const sa_uuid* caller_uuid);

#ifdef __cplusplus
}
#endif

#endif // TA_SA_CRYPTO_H
