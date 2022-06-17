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
 * @file cipher_store.h
 *
 * This file contains the functions and structures implementing storage for cipher contexts.
 * The context object is stored and retrieved using the value indicating the slot at which it
 * is stored. This mechanism allows applications to reference cipher context objects stored in a TA
 * without having explicit pointers to them.
 */

#ifndef CIPHER_STORE_H
#define CIPHER_STORE_H

#include "object_store.h"
#include "sa_types.h"
#include "symmetric.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cipher_s cipher_t;

typedef object_store_t cipher_store_t;

/**
 * Get the cipher algorithm.
 *
 * @param[in] cipher cipher.
 * @return cipher algorithm.
 */
sa_cipher_algorithm cipher_get_algorithm(const cipher_t* cipher);

/**
 * Get the cipher mode.
 *
 * @param[in] cipher cipher.
 * @return cipher mode.
 */
sa_cipher_mode cipher_get_mode(const cipher_t* cipher);

/**
 * Get the symmetric context.
 *
 * @param[in] cipher cipher.
 * @return AES context.
 */
const symmetric_context_t* cipher_get_symmetric_context(const cipher_t* cipher);

/**
 * Get the stored key.
 *
 * @param[in] cipher cipher.
 * @return the stored key.
 */
const stored_key_t* cipher_get_stored_key(const cipher_t* cipher);

/**
 * Get the key size.
 *
 * @param[in] cipher cipher.
 * @return key size.
 */
size_t cipher_get_key_size(const cipher_t* cipher);

/**
 * Get the key rights.
 *
 * @param[in] cipher cipher.
 * @return key rights.
 */
const sa_rights* cipher_get_key_rights(const cipher_t* cipher);

/**
 * Sets the OAEP parameters on the cipher context.
 *
 * @param[in] cipher the cipher context.
 * @param[in] digest_algorithm the digest algorithm of the OAEP padding.
 * @param[in] mgf1_digest_algorithm the digest algorithm fo the MGF1 function.
 * @param[in] label the label for the OAEP padding. May be NULL.
 * @param[in] label_length the length of the label. Must be0 if label is NULL.
 * @return SA_STATUS_OK if success.
 */
sa_status cipher_set_oaep_parameters(
        cipher_t* cipher,
        sa_digest_algorithm digest_algorithm,
        sa_digest_algorithm mgf1_digest_algorithm,
        void* label,
        size_t label_length);

/**
 * Gets the OAEP parameters on the cipher context.
 *
 * @param[in] cipher the cipher context.
 * @param[out] digest_algorithm the digest algorithm of the OAEP padding.
 * @param[out] mgf1_digest_algorithm the digest algorithm fo the MGF1 function.
 * @param[out] label the label for the OAEP padding. May be NULL.
 * @param[out] label_length the length of the label. Must be0 if label is NULL.
 * @return SA_STATUS_OK if success.
 */
sa_status cipher_get_oaep_parameters(
        const cipher_t* cipher,
        sa_digest_algorithm* digest_algorithm,
        sa_digest_algorithm* mgf1_digest_algorithm,
        const void** label,
        size_t* label_length);

/**
 * Create and initialize a new cipher store.
 *
 * @param[in] size number of cipher slots in the store.
 * @return store instance.
 */
cipher_store_t* cipher_store_init(size_t size);

/**
 * Release a store. If any ciphers are still contained in it, they will be released.
 *
 * @param[in] store store instance.
 */
void cipher_store_shutdown(cipher_store_t* store);

/**
 * Add a symmetric cipher to the store.
 *
 * @param[out] context slot at which the cipher was stored.
 * @param[in] store store.
 * @param[in] cipher_algorithm cipher algorithm.
 * @param[in] cipher_mode cipher mode.
 * @param[in] symmetric_context the symmetric context.
 * @param[in] stored_key the key. The cipher store will manage the key and it does not need to be freed.
 * @param[in] caller_uuid caller UUID.
 * @return status of the operation.
 */
sa_status cipher_store_add_symmetric_context(
        sa_crypto_cipher_context* context,
        cipher_store_t* store,
        sa_cipher_algorithm cipher_algorithm,
        sa_cipher_mode cipher_mode,
        symmetric_context_t* symmetric_context,
        stored_key_t* stored_key,
        const sa_uuid* caller_uuid);

/**
 * Add an asymmetric cipher to the store.
 *
 * @param[out] context slot at which the cipher was stored.
 * @param[in] store store.
 * @param[in] cipher_algorithm cipher algorithm.
 * @param[in] cipher_mode cipher mode.
 * @param[in] stored_key the key. The cipher store will manage the key and it does not need to be freed.
 * @param[in] caller_uuid caller UUID.
 * @return status of the operation.
 */
sa_status cipher_store_add_asymmetric_key(
        sa_crypto_cipher_context* context,
        cipher_store_t* store,
        sa_cipher_algorithm cipher_algorithm,
        sa_cipher_mode cipher_mode,
        stored_key_t* stored_key,
        const sa_uuid* caller_uuid);

/**
 * Remove a cipher from the store.
 *
 * @param[in] store store.
 * @param[in] context slot of the cipher to remove.
 * @param[in] caller_uuid caller UUID.
 * @return status of the operation.
 */
sa_status cipher_store_remove(
        cipher_store_t* store,
        sa_crypto_cipher_context context,
        const sa_uuid* caller_uuid);

/**
 * Obtain the cipher at the specified index and increment the reference count. All other attempts to
 * acquire the same cipher will block until the cipher is released. Cipher with reference
 * count greater then 0 is guaranteed not to be deleted.
 *
 * @param[out] cipher output cipher pointer.
 * @param[in] store store.
 * @param[in] context slot.
 * @param[in] caller_uuid caller UUID.
 * @return status of the operation.
 */
sa_status cipher_store_acquire_exclusive(
        cipher_t** cipher,
        cipher_store_t* store,
        sa_crypto_cipher_context context,
        const sa_uuid* caller_uuid);

/**
 * Release the cipher at the specified slot and decrement the reference count.
 *
 * @param[in] store store
 * @param[in] context slot
 * @param[in] cipher cipher to release
 * @param[in] caller_uuid caller UUID
 * @return status of the operation
 */
sa_status cipher_store_release_exclusive(
        cipher_store_t* store,
        sa_crypto_cipher_context context,
        cipher_t* cipher,
        const sa_uuid* caller_uuid);

#ifdef __cplusplus
}
#endif

#endif // CIPHER_STORE_H
