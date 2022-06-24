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
 * @file ta_sa_key.h
 *
 * This file contains the TA implementation of "key" module functions. Please refer to
 * sa_key.h file for method and parameter documentation.
 */

#ifndef TA_SA_KEY_H
#define TA_SA_KEY_H

#include "sa_types.h"

#ifdef __cplusplus

#include <cstddef>

extern "C" {
#else
#include <stddef.h>
#endif

/**
 * Generate a key.
 *
 * @param[out] key Generated key.
 * @param[in] rights Key rights for the newly created key.
 * @param[in] key_type Type of key to create.
 * @param[in] parameters Key type specific parameters for key generation. Use
 * sa_generate_parameters_symmetric with SA_KEY_TYPE_SYMMETRIC, sa_generate_parameters_rsa with
 * SA_KEY_TYPE_RSA, sa_generate_parameters_ec with SA_KEY_TYPE_EC, sa_generate_parameters_dh with
 * SA_KEY_TYPE_DH.
 * @param[in] client_slot the client slot ID.
 * @param[in] caller_uuid the UUID of the caller.
 * @return Operation status. Possible values are:
 * + SA_STATUS_OK - Operation succeeded.
 * + SA_STATUS_NO_AVAILABLE_RESOURCE_SLOT - There are no available key slots.
 * + SA_STATUS_NULL_PARAMETER - key, rights, or parameters (if required) is NULL.
 * + SA_STATUS_INVALID_PARAMETER
 *   + Invalid key type specified.
 *   + Invalid type specific parameter value encountered.
 * + SA_STATUS_OPERATION_NOT_SUPPORTED - Implementation does not support the specified operation.
 * + SA_STATUS_SELF_TEST - Implementation self-test has failed.
 * + SA_STATUS_INTERNAL_ERROR - An unexpected error has occurred.
 */
sa_status ta_sa_key_generate(
        sa_key* key,
        const sa_rights* rights,
        sa_key_type key_type,
        void* parameters,
        ta_client client_slot,
        const sa_uuid* caller_uuid);

/**
 * Export (rewrap) the key for persistence. Key rights are cryptographically bound to the key
 * material. Key material is encrypted using a device unique rewrap key. The exported key has an
 * integrity envelope that will be checked on key import. Encryption and integrity keys used to
 * protect the exported key container are derived from device root key using a 3-stage key ladder
 * that is not exposed to the users of the SecAPI.
 *
 * @param[out] out Output buffer. If NULL, size required to export key is returned.
 * @param[in,out] out_length Size of output buffer in bytes. Set to number of bytes written on
 * function return.
 * @param[in] mixin Input for the 3rd derivation stage of encryption and mac key used to protect the
 * exported key container. Defaults to all zeros if NULL.
 * @param[in] mixin_length Mixin length in bytes. Has to be equal to 16.
 * @param[in] key Key to export.
 * @param[in] client_slot the client slot ID.
 * @param[in] caller_uuid the UUID of the caller.
 * @return Operation status. Possible values are:
 * + SA_STATUS_OK - Operation succeeded.
 * + SA_STATUS_NULL_PARAMETER - out_length or key is NULL.
 * + SA_STATUS_INVALID_PARAMETER
 *   + out is not NULL and *out_length is smaller than required for exported key container.
 *   + mixin is not NULL and mixin_length is not 16.
 * + SA_STATUS_OPERATION_NOT_ALLOWED - Key usage requirements are not met for the specified
 * operation.
 * + SA_STATUS_OPERATION_NOT_SUPPORTED - Implementation does not support the specified operation.
 * + SA_STATUS_SELF_TEST - Implementation self-test has failed.
 * + SA_STATUS_INTERNAL_ERROR - An unexpected error has occurred.
 */
sa_status ta_sa_key_export(
        void* out,
        size_t* out_length,
        const void* mixin,
        size_t mixin_length,
        sa_key key,
        ta_client client_slot,
        const sa_uuid* caller_uuid);

/**
 * Import a key.
 *
 * @param[out] key Imported key handle.
 * @param[in] key_format Key format.
 * @param[in] in Input data.
 * @param[in] in_length Size of input data in bytes.
 * @param[in] parameters Format specific import parameters. Use sa_import_parameters_symmetric with
 * SA_KEY_FORMAT_SYMMETRIC_BYTES, sa_import_parameters_ec_private_bytes with
 * SA_KEY_FORMAT_EC_PRIVATE_BYTES, sa_import_parameters_rsa_private_key_info with
 * SA_KEY_FORMAT_RSA_PRIVATE_KEY_INFO, sa_import_parameters_exported with SA_KEY_FORMAT_EXPORTED,
 * sa_import_parameters_typej with SA_KEY_FORMAT_TYPEJ.
 * @param[in] client_slot the client slot ID.
 * @param[in] caller_uuid the UUID of the caller.
 * @return Operation status. Possible values are:
 * + SA_STATUS_OK - Operation succeeded.
 * + SA_STATUS_NO_AVAILABLE_RESOURCE_SLOT - There are no available key slots.
 * + SA_STATUS_INVALID_KEY_FORMAT - Input data failed the format validation.
 * + SA_STATUS_NULL_PARAMETER - key, in, or parameters (if required) is NULL.
 * + SA_STATUS_INVALID_PARAMETER
 *   + Invalid format value.
 *   + Invalid format specific parameter value encountered.
 * + SA_STATUS_OPERATION_NOT_SUPPORTED - Implementation does not support the specified operation.
 * + SA_STATUS_SELF_TEST - Implementation self-test has failed.
 * + SA_STATUS_VERIFICATION_FAILED - Signature verification has failed.
 * + SA_STATUS_INTERNAL_ERROR - An unexpected error has occurred.
 */
sa_status ta_sa_key_import(
        sa_key* key,
        sa_key_format key_format,
        const void* in,
        size_t in_length,
        void* parameters,
        ta_client client_slot,
        const sa_uuid* caller_uuid);

/**
 * Unwrap the key.
 *
 * @param[out] key Unwrapped key handle.
 * @param[in] rights Key rights to associate with the unwrapped key.
 * @param[in] key_type Type of the wrapped key.
 * @param[in] type_parameters Additional key type specific parameters. Use
 * sa_unwrap_type_parameters_ec with SA_KEY_TYPE_EC.
 * @param[in] cipher_algorithm Wrapping algorithm.
 * @param[in] algorithm_parameters Additional algorithm specific parameters. Use
 * sa_unwrap_parameters_aes_cbc with SA_CIPHER_ALGORITHM_AES_CBC and
 * SA_CIPHER_ALGORITHM_AES_CBC_PKCS7, sa_unwrap_parameters_aes_ctr with SA_CIPHER_ALGORITHM_AES_CTR,
 * sa_unwrap_parameters_aes_gcm with SA_CIPHER_ALGORITHM_AES_GCM, sa_unwrap_parameters_ec_elgamal
 * with SA_CIPHER_ALGORITHM_EC_ELGAMAL.
 * @param[in] wrapping_key Wrapping key.
 * @param[in] in Wrapped key ciphertext.
 * @param[in] in_length Wrapped key ciphertext length.
 * @param[in] client_slot the client slot ID.
 * @param[in] caller_uuid the UUID of the caller.
 * @return Operation status. Possible values are:
 * + SA_STATUS_OK - Operation succeeded.
 * + SA_STATUS_NO_AVAILABLE_RESOURCE_SLOT - There are no available key slots.
 * + SA_STATUS_INVALID_KEY_FORMAT - Input data failed the format validation.
 * + SA_STATUS_INVALID_KEY_TYPE - Wrapping key type is not valid for the specified algorithm.
 * + SA_STATUS_NULL_PARAMETER - key, rights, type_parameters (if required), algorithm_parameters (if
 * required), wrapping_key, or in is NULL.
 * + SA_STATUS_INVALID_PARAMETER
 *   + in_length is not valid for specified algorithm.
 *   + Invalid type value.
 *   + Invalid type specific parameter encountered.
 *   + Invalid algorithm.
 *   + Invalid algorithm specific parameter value encountered.
 * + SA_STATUS_OPERATION_NOT_ALLOWED - Wrapping key usage requirements are not met for the specified
 * operation.
 * + SA_STATUS_OPERATION_NOT_SUPPORTED - Implementation does not support the specified operation.
 * + SA_STATUS_SELF_TEST - Implementation self-test has failed.
 * + SA_STATUS_VERIFICATION_FAILED
 *   + Invalid padding value has been encountered.
 *   + Tag verification has failed.
 * + SA_STATUS_INTERNAL_ERROR - An unexpected error has occurred.
 */
sa_status ta_sa_key_unwrap(
        sa_key* key,
        const sa_rights* rights,
        sa_key_type key_type,
        void* type_parameters,
        sa_cipher_algorithm cipher_algorithm,
        void* algorithm_parameters,
        sa_key wrapping_key,
        const void* in,
        size_t in_length,
        ta_client client_slot,
        const sa_uuid* caller_uuid);

/**
 * Obtain the public component of an asymmetric key.
 *
 * @param[out] out Output buffer. If NULL, size required for public key is returned.
 * @param[in,out] out_length Size of the output buffer in bytes. Set to public key length on
 * function exit.
 * @param[in] key Private key handle.
 * @param[in] client_slot the client slot ID.
 * @param[in] caller_uuid the UUID of the caller.
 * @return Operation status. Possible values are:
 * + SA_STATUS_OK - Operation succeeded.
 * + SA_STATUS_INVALID_KEY_TYPE - Key type is not valid for the specified operation.
 * + SA_STATUS_NULL_PARAMETER - out_length or key is NULL.
 * + SA_STATUS_INVALID_PARAMETER - out is not NULL and *out_length is too small to store the public key.
 * + SA_STATUS_OPERATION_NOT_SUPPORTED - Implementation does not support the specified operation.
 * + SA_STATUS_SELF_TEST - Implementation self-test has failed.
 * + SA_STATUS_INTERNAL_ERROR - An unexpected error has occurred.
 */
sa_status ta_sa_key_get_public(
        void* out,
        size_t* out_length,
        sa_key key,
        ta_client client_slot,
        const sa_uuid* caller_uuid);

/**
 * Derive a symmetric key using the specified KDF.
 *
 * @param[out] key Derived key.
 * @param[in] rights Key rights to associate with the derived key.
 * @param[in] kdf_algorithm KDF algorithm.
 * @param[in] parameters Algorithm specific parameters. Use sa_kdf_parameters_root_key_ladder with
 * SA_KDF_ALGORITHM_ROOT_KEY_LADDER, sa_kdf_parameters_hkdf with SA_KDF_ALGORITHM_HKDF,
 * sa_kdf_parameters_concat with SA_KDF_ALGORITHM_CONCAT, sa_kdf_parameters_ansi_x963 with
 * SA_KDF_ALGORITHM_ANSI_X963, sa_kdf_parameters_cmac with SA_KDF_ALGORITHM_CMAC,
 * sa_kdf_parameters_netflix with SA_KDF_ALGORITHM_NETFLIX.
 * @param[in] client_slot the client slot ID.
 * @param[in] caller_uuid the UUID of the caller.
 * @return Operation status. Possible values are:
 * + SA_STATUS_OK - Operation succeeded.
 * + SA_STATUS_NO_AVAILABLE_RESOURCE_SLOT - There are no available key slots.
 * + SA_STATUS_INVALID_KEY_TYPE - Key type is not valid for the specified operation.
 * + SA_STATUS_NULL_PARAMETER - key, rights, or parameters is NULL.
 * + SA_STATUS_INVALID_PARAMETER
 *   + Invalid algorithm value.
 *   + Invalid algorithm specific parameter value encountered.
 * + SA_STATUS_OPERATION_NOT_ALLOWED - Key usage requirements are not met for the specified
 * operation.
 * + SA_STATUS_OPERATION_NOT_SUPPORTED - Implementation does not support the specified operation.
 * + SA_STATUS_SELF_TEST - Implementation self-test has failed.
 * + SA_STATUS_INTERNAL_ERROR - An unexpected error has occurred.
 */
sa_status ta_sa_key_derive(
        sa_key* key,
        const sa_rights* rights,
        sa_kdf_algorithm kdf_algorithm,
        void* parameters,
        ta_client client_slot,
        const sa_uuid* caller_uuid);

/**
 * Compute a shared secret using specified key exchange algorithm.
 *
 * @param[out] key Shared secret key.
 * @param[in] rights Key rights to associate with the shared secret key.
 * @param[in] key_exchange_algorithm Key exchange algorithm.
 * @param[in] private_key Private key.
 * @param[in] other_public Public component of other party in network order.
 * @param[in] other_public_length Length of the public component of the other party in bytes.
 * @param[in] parameters Additional algorithm specific parameters. Use
 * sa_key_exchange_parameters_netflix_authenticated_dh with
 * SA_KEY_EXCHANGE_ALGORITHM_NETFLIX_AUTHENTICATED_DH.
 * @param[in] client_slot the client slot ID.
 * @param[in] caller_uuid the UUID of the caller.
 * @return Operation status. Possible values are:
 * + SA_STATUS_OK - Operation succeeded.
 * + SA_STATUS_NO_AVAILABLE_RESOURCE_SLOT - There are no available key slots.
 * + SA_STATUS_INVALID_KEY_TYPE - Private key type is not valid for the specified operation.
 * + SA_STATUS_NULL_PARAMETER - key, rights, private_key, other_public, or parameters is NULL.
 * + SA_STATUS_INVALID_PARAMETER
 *   + Invalid algorithm value.
 *   + Invalid algorithm specific parameter value encountered.
 *   + other_public_length is not valid for specified algorithm and key.
 * + SA_STATUS_OPERATION_NOT_ALLOWED - Private key usage requirements are not met for the specified
 * operation.
 * + SA_STATUS_OPERATION_NOT_SUPPORTED - Implementation does not support the specified operation.
 * + SA_STATUS_SELF_TEST - Implementation self-test has failed.
 * + SA_STATUS_INTERNAL_ERROR - An unexpected error has occurred.
 */
sa_status ta_sa_key_exchange(
        sa_key* key,
        const sa_rights* rights,
        sa_key_exchange_algorithm key_exchange_algorithm,
        sa_key private_key,
        const void* other_public,
        size_t other_public_length,
        void* parameters,
        ta_client client_slot,
        const sa_uuid* caller_uuid);

/**
 * Release a key. Any existing cipher, MAC, or SVP contexts can still be used until they are
 * released.
 *
 * @param[in] key Key to release
 * @param[in] client_slot the client slot ID.
 * @param[in] caller_uuid the UUID of the caller.
 * @return Operation status. Possible values are:
 * + SA_STATUS_OK - Operation succeeded.
 * + SA_STATUS_INVALID_PARAMETER - key handle is invalid.
 * + SA_STATUS_OPERATION_NOT_SUPPORTED - Implementation does not support the specified operation.
 * + SA_STATUS_SELF_TEST - Implementation self-test has failed.
 * + SA_STATUS_INTERNAL_ERROR - An unexpected error has occurred.
 */
sa_status ta_sa_key_release(
        sa_key key,
        ta_client client_slot,
        const sa_uuid* caller_uuid);

/**
 * Obtain the key header.
 *
 * @param[out] header Key header.
 * @param[in] key Key handle.
 * @param[in] client_slot the client slot ID.
 * @param[in] caller_uuid the UUID of the caller.
 * + SA_STATUS_OK - Operation succeeded.
 * + SA_STATUS_NULL_PARAMETER - header is null.
 * + SA_STATUS_INVALID_PARAMETER - key handle is invalid.
 * + SA_STATUS_OPERATION_NOT_SUPPORTED - Implementation does not support the specified operation.
 * + SA_STATUS_SELF_TEST - Implementation self-test has failed.
 * + SA_STATUS_INTERNAL_ERROR - An unexpected error has occurred.
 */
sa_status ta_sa_key_header(
        sa_header* header,
        sa_key key,
        ta_client client_slot,
        const sa_uuid* caller_uuid);

/**
 * Returns the digest of a key using the specified digest algorithm.
 *
 * @param[out] out Output buffer. Can be set to NULL to obtain the required length.
 * @param[in,out] out_length Output buffer length in bytes.
 * @param[in] key the key to digest.
 * @param[in] digest_algorithm the digest algorithm to use.
 * @param[in] client_slot the client slot ID.
 * @param[in] caller_uuid the UUID of the caller.
 * @return Operation status. Possible values are:
 * + SA_STATUS_OK - Operation succeeded.
 * + SA_STATUS_NULL_PARAMETER - out_length or context is NULL.
 * + SA_STATUS_INVALID_PARAMETER
 *   + out is not NULL and *out_length value is too small to hold the result.
 * + SA_STATUS_OPERATION_NOT_SUPPORTED - Implementation does not support the specified operation.
 * + SA_STATUS_SELF_TEST - Implementation self-test has failed.
 * + SA_STATUS_INTERNAL_ERROR - An unexpected error has occurred.
 */
sa_status ta_sa_key_digest(
        void* out,
        size_t* out_length,
        sa_key key,
        sa_digest_algorithm digest_algorithm,
        ta_client client_slot,
        const sa_uuid* caller_uuid);

#ifdef __cplusplus
}
#endif

#endif // TA_SA_KEY_H
