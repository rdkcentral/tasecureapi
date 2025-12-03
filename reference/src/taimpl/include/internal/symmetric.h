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
 * @file symmetric.h
 *
 * This file contains the functions and structures implementing symmetric key and cipher operations.
 */

#ifndef SYMMETRIC_H
#define SYMMETRIC_H

#include "stored_key.h"

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

typedef struct symmetric_context_s symmetric_context_t;

/**
 * Generate a symmetric key.
 * @param[out] stored_key_generated the generated AES key.
 * @param[in] rights the key rights.
 * @param[in] parameters the AES key parameters
 * @return the status of the operation.
 */
sa_status symmetric_generate_key(
        stored_key_t** stored_key_generated,
        const sa_rights* rights,
        sa_generate_parameters_symmetric* parameters);

/**
 * Verifies that the symmetric cipher operation can be performed.
 *
 * @param cipher_algorithm the cipher algorithm.
 * @param cipher_mode the cipher mode.
 * @param stored_key the stored key to use in the cipher.
 * @return the status of the cipher operation.
 */
sa_status symmetric_verify_cipher(
        sa_cipher_algorithm cipher_algorithm,
        sa_cipher_mode cipher_mode,
        const stored_key_t* stored_key);

/**
 * Create an AES ECB encryption context.
 *
 * @param[in] stored_key cipher key.
 * @param[in] padded true if using PKCS7 padding.
 * @return created AES context. NULL if the operation failed.
 */
symmetric_context_t* symmetric_create_aes_ecb_encrypt_context(
        const stored_key_t* stored_key,
        bool padded);

/**
 * Create an AES CBC encryption context.
 *
 * @param[in] stored_key cipher key.
 * @param[in] iv initialization vector.
 * @param[in] iv_length initialization vector length. Has to be 16 bytes.
 * @param[in] padded true if using PKCS7 padding.
 * @return created AES context. NULL if the operation failed.
 */
symmetric_context_t* symmetric_create_aes_cbc_encrypt_context(
        const stored_key_t* stored_key,
        const void* iv,
        size_t iv_length,
        bool padded);

/**
 * Create an AES CTR encryption context.
 *
 * @param[in] stored_key cipher key.
 * @param[in] counter counter.
 * @param[in] counter_length counter length. Has to be 16 bytes.
 * @return created AES context. NULL if the operation failed.
 */
symmetric_context_t* symmetric_create_aes_ctr_encrypt_context(
        const stored_key_t* stored_key,
        const void* counter,
        size_t counter_length);

/**
 * Create an AES GCM encryption context.
 *
 * @param[in] stored_key cipher key.
 * @param[in] iv initialization vector.
 * @param[in] iv_length initialization vector length. Has to be 12 bytes.
 * @param[in] aad additional authenticated data.
 * @param[in] aad_length additional authenticated data length.
 * @return created AES context. NULL if the operation failed.
 */
symmetric_context_t* symmetric_create_aes_gcm_encrypt_context(
        const stored_key_t* stored_key,
        const void* iv,
        size_t iv_length,
        const void* aad,
        size_t aad_length);

/**
 * Create an CHACHA20 encryption context.
 *
 * @param[in] stored_key cipher key.
 * @param[in] nonce nonce.
 * @param[in] nonce_length nonce length. Has to be 12 bytes.
 * @param[in] counter counter.
 * @param[in] counter_length counter length. Has to be 4 bytes.
 * @return created CHACHA20 context. NULL if the operation failed.
 */
symmetric_context_t* symmetric_create_chacha20_encrypt_context(
        const stored_key_t* stored_key,
        const void* nonce,
        size_t nonce_length,
        const void* counter,
        size_t counter_length);

/**
 * Create an CHACHA20-POLY1305 encryption context.
 *
 * @param[in] stored_key cipher key.
 * @param[in] nonce nonce.
 * @param[in] nonce_length nonce length. Has to be 12 bytes.
 * @param[in] aad additional authenticated data.
 * @param[in] aad_length additional authenticated data length.
 * @return created CHACHA20 context. NULL if the operation failed.
 */
symmetric_context_t* symmetric_create_chacha20_poly1305_encrypt_context(
        const stored_key_t* stored_key,
        const void* nonce,
        size_t nonce_length,
        const void* aad,
        size_t aad_length);

/**
 * Create an AES ECB decrypt context.
 *
 * @param[in] stored_key cipher key.
 * @param[in] padded true if using PKCS7 padding.
 * @return created AES context. NULL if the operation failed.
 */
symmetric_context_t* symmetric_create_aes_ecb_decrypt_context(
        const stored_key_t* stored_key,
        bool padded);

/**
 * Create an AES CBC decrypt context.
 *
 * @param[in] stored_key cipher key.
 * @param[in] iv initialization vector.
 * @param[in] iv_length initialization vector length. Has to be 16 bytes.
 * @param[in] padded true if using PKCS7 padding.
 * @return created AES context. NULL if the operation failed.
 */
symmetric_context_t* symmetric_create_aes_cbc_decrypt_context(
        const stored_key_t* stored_key,
        const void* iv,
        size_t iv_length,
        bool padded);

/**
 * Create an AES CTR decrypt context.
 *
 * @param[in] stored_key cipher key.
 * @param[in] counter counter.
 * @param[in] counter_length counter length. Has to be 16 bytes.
 * @return created AES context. NULL if the operation failed.
 */
symmetric_context_t* symmetric_create_aes_ctr_decrypt_context(
        const stored_key_t* stored_key,
        const void* counter,
        size_t counter_length);

/**
 * Create an AES GCM decrypt context.
 *
 * @param[in] stored_key cipher key.
 * @param[in] iv initialization vector.
 * @param[in] iv_length initialization vector length. Has to be 12 bytes.
 * @param[in] aad additional authenticated data.
 * @param[in] aad_length additional authenticated data length.
 * @return created AES context. NULL if the operation failed.
 */
symmetric_context_t* symmetric_create_aes_gcm_decrypt_context(
        const stored_key_t* stored_key,
        const void* iv,
        size_t iv_length,
        const void* aad,
        size_t aad_length);

/**
 * Create an CHACHA20 encryption context.
 *
 * @param[in] stored_key cipher key.
 * @param[in] nonce nonce.
 * @param[in] nonce_length nonce length. Has to be 12 bytes.
 * @param[in] counter counter.
 * @param[in] counter_length counter length. Has to be 4 bytes.
 * @return created CHACHA20 context. NULL if the operation failed.
 */
symmetric_context_t* symmetric_create_chacha20_decrypt_context(
        const stored_key_t* stored_key,
        const void* nonce,
        size_t nonce_length,
        const void* counter,
        size_t counter_length);

/**
 * Create an CHACHA20-POLY1305 encryption context.
 *
 * @param[in] stored_key cipher key.
 * @param[in] nonce nonce.
 * @param[in] nonce_length nonce length. Has to be 12 bytes.
 * @param[in] aad additional authenticated data.
 * @param[in] aad_length additional authenticated data length.
 * @return created CHACHA20 context. NULL if the operation failed.
 */
symmetric_context_t* symmetric_create_chacha20_poly1305_decrypt_context(
        const stored_key_t* stored_key,
        const void* nonce,
        size_t nonce_length,
        const void* aad,
        size_t aad_length);

/**
 * Encrypt a block of input data.
 *
 * @param[in] context AES context.
 * @param[out] out output buffer.
 * @param[in,out] out_length output buffer length. Set to bytes written on return.
 * @param[in] in input buffer.
 * @param[in] in_length input buffer length. Had to be a multiple of 16.
 * @return status of the operation.
 */
sa_status symmetric_context_encrypt(
        symmetric_context_t* context,
        void* out,
        size_t* out_length,
        const void* in,
        size_t in_length);

/**
 * Encrypt last chunk of input data mode. Can only be called on CTR and GCM contexts.
 *
 * @param[in] context symmetric context.
 * @param[out] out output buffer.
 * @param[in,out] out_length output buffer length. Set to bytes written on return.
 * @param[in] in input buffer.
 * @param[in] in_length input buffer length. Had to be less then or equal to 16.
 * @return status of the operation.
 */
sa_status symmetric_context_encrypt_last(
        symmetric_context_t* context,
        void* out,
        size_t* out_length,
        const void* in,
        size_t in_length);

/**
 * Decrypt input data.
 *
 * @param[in] context AES context.
 * @param[out] out output buffer.
 * @param[in,out] out_length output buffer length. Set to bytes written on return.
 * @param[in] in input buffer.
 * @param[in] in_length input buffer length. Had to be a multiple of 16.
 * @return status of the operation.
 */
sa_status symmetric_context_decrypt(
        symmetric_context_t* context,
        void* out,
        size_t* out_length,
        const void* in,
        size_t in_length);

/**
 * Decrypt last chunk of input data mode. Can only be called on CTR and GCM contexts.
 *
 * @param[in] context symmetric context.
 * @param[out] out output buffer.
 * @param[in,out] out_length output buffer length. Set to bytes written on return.
 * @param[in] in input buffer.
 * @param[in] in_length input buffer length. Had to be less then or equal to  16.
 * @return status of the operation.
 */
sa_status symmetric_context_decrypt_last(
        symmetric_context_t* context,
        void* out,
        size_t* out_length,
        const void* in,
        size_t in_length);

/**
 * Set the AES context IV to a new value.
 *
 * @param[in] context AES context.
 * @param[in] iv initialization vector.
 * @param[in] iv_length initialization vector length.
 * @return status of the operation.
 */
sa_status symmetric_context_set_iv(
        const symmetric_context_t* context,
        const void* iv,
        size_t iv_length);

/**
 * Reinitializes the symmetric cipher context for a new sample. This performs a full reset
 * including reset+setkey+set_iv to allow processing multiple samples with the same IV.
 * Only applicable for AES-CTR mode.
 *
 * @param[in] context symmetric context.
 * @param[in] stored_key the stored key to use for reinitialization.
 * @param[in] iv initialization vector.
 * @param[in] iv_length initialization vector length.
 * @return status of the operation.
 */
sa_status symmetric_context_reinit_for_sample(
        const symmetric_context_t* context,
        const stored_key_t* stored_key,
        const void* iv,
        size_t iv_length);

/**
 * Gets the authentication tag after the process_last call. Can only be called on AES GCM & ChaCha20-Poly1305 context.
 *
 * @param[in] context AES context.
 * @param[out] tag authentication tag.
 * @param[in] tag_length authentication tag length. Has to be less then or equal to 16.
 */
sa_status symmetric_context_get_tag(
        const symmetric_context_t* context,
        void* tag,
        size_t tag_length);

/**
 * Sets the authentication tag before the process_last call. Can only be called on AES GCM & ChaCha20-Poly1305 context.
 *
 * @param[in] context AES context.
 * @param[in] tag authentication tag.
 * @param[in] tag_length authentication tag length. Has to be less then or equal to 16.
 * @return status of the operation.
 */
sa_status symmetric_context_set_tag(
        symmetric_context_t* context,
        const void* tag,
        size_t tag_length);

/**
 * Free the AES context. Operation is a NOOP if context is NULL.
 *
 * @param[in] context AES context.
 */
void symmetric_context_free(symmetric_context_t* context);

#ifdef __cplusplus
}
#endif

#endif // SYMMETRIC_H
