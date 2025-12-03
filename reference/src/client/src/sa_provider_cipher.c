/*
 * Copyright 2023 Comcast Cable Communications Management, LLC
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

/*
 * Some code in this file is based off OpenSSL which is:
 * Copyright 2019-2021 The OpenSSL Project Authors
 * Licensed under the Apache License, Version 2.0
 */

#include "sa_provider_internal.h"
#if OPENSSL_VERSION_NUMBER >= 0x30000000
#include "common.h"
#include "log.h"
#include "sa_rights.h"
#include <memory.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#define MAX_AEAD_BUFFER_SIZE 65536  // 64KB buffer for AEAD data

typedef struct {
    sa_provider_context* provider_context;
    sa_cipher_algorithm cipher_algorithm;
    sa_cipher_mode mode;
    size_t key_size;
    size_t block_size;
    size_t iv_length;
    sa_key key;
    sa_crypto_cipher_context cipher_context;
    uint8_t iv[AES_BLOCK_SIZE];
    bool padded;
    bool aead;
    uint8_t tag[AES_BLOCK_SIZE];
    size_t tag_length;
    bool delete_key;
    uint8_t remaining_block[AES_BLOCK_SIZE];
    size_t remaining_block_length;
    uint8_t* aead_buffer;  // Buffer for AEAD data (dynamically allocated)
    size_t aead_buffer_length;  // Current amount of data in AEAD buffer
    size_t aead_processed_length;  // Amount of AEAD data already processed by TA
} sa_provider_cipher_context;

ossl_unused static OSSL_FUNC_cipher_newctx_fn cipher_aes_ecb_128_newctx;
ossl_unused static OSSL_FUNC_cipher_newctx_fn cipher_aes_ecb_256_newctx;
ossl_unused static OSSL_FUNC_cipher_newctx_fn cipher_aes_cbc_128_newctx;
ossl_unused static OSSL_FUNC_cipher_newctx_fn cipher_aes_cbc_256_newctx;
ossl_unused static OSSL_FUNC_cipher_newctx_fn cipher_aes_ctr_128_newctx;
ossl_unused static OSSL_FUNC_cipher_newctx_fn cipher_aes_ctr_256_newctx;
ossl_unused static OSSL_FUNC_cipher_newctx_fn cipher_aes_gcm_128_newctx;
ossl_unused static OSSL_FUNC_cipher_newctx_fn cipher_aes_gcm_256_newctx;
ossl_unused static OSSL_FUNC_cipher_newctx_fn cipher_chacha20_none_256_newctx;
ossl_unused static OSSL_FUNC_cipher_newctx_fn cipher_chacha20_poly1305_256_newctx;
ossl_unused static OSSL_FUNC_cipher_freectx_fn cipher_freectx;
ossl_unused static OSSL_FUNC_cipher_encrypt_init_fn cipher_encrypt_init;
ossl_unused static OSSL_FUNC_cipher_decrypt_init_fn cipher_decrypt_init;
ossl_unused static OSSL_FUNC_cipher_update_fn cipher_update;
ossl_unused static OSSL_FUNC_cipher_final_fn cipher_final;
ossl_unused static OSSL_FUNC_cipher_cipher_fn cipher_cipher;
ossl_unused static OSSL_FUNC_cipher_get_params_fn cipher_aes_ecb_128_get_params;
ossl_unused static OSSL_FUNC_cipher_get_params_fn cipher_aes_ecb_256_get_params;
ossl_unused static OSSL_FUNC_cipher_get_params_fn cipher_aes_cbc_128_get_params;
ossl_unused static OSSL_FUNC_cipher_get_params_fn cipher_aes_cbc_256_get_params;
ossl_unused static OSSL_FUNC_cipher_get_params_fn cipher_aes_ctr_128_get_params;
ossl_unused static OSSL_FUNC_cipher_get_params_fn cipher_aes_ctr_256_get_params;
ossl_unused static OSSL_FUNC_cipher_get_params_fn cipher_aes_gcm_128_get_params;
ossl_unused static OSSL_FUNC_cipher_get_params_fn cipher_aes_gcm_256_get_params;
ossl_unused static OSSL_FUNC_cipher_get_params_fn cipher_chacha20_none_256_get_params;
ossl_unused static OSSL_FUNC_cipher_get_params_fn cipher_chacha20_poly1305_256_get_params;
ossl_unused static OSSL_FUNC_cipher_get_ctx_params_fn cipher_get_ctx_params;
ossl_unused static OSSL_FUNC_cipher_set_ctx_params_fn cipher_set_ctx_params;
ossl_unused static OSSL_FUNC_cipher_gettable_params_fn cipher_gettable_params;
ossl_unused static OSSL_FUNC_cipher_settable_ctx_params_fn cipher_settable_ctx_params;
ossl_unused static OSSL_FUNC_cipher_gettable_ctx_params_fn cipher_gettable_ctx_params;

static void* cipher_newctx(
        sa_cipher_algorithm cipher_algorithm,
        size_t key_size,
        size_t block_size,
        size_t iv_length,
        bool aead,
        void* provctx) {

    if (provctx == NULL) {
        ERROR("NULL provctx");
        return NULL;
    }

    sa_provider_cipher_context* cipher_context = NULL;
    sa_provider_context* provider_context = provctx;
    cipher_context = OPENSSL_zalloc(sizeof(sa_provider_cipher_context));
    if (cipher_context == NULL) {
        ERROR("OPENSSL_zalloc failed");
        return NULL;
    }

    cipher_context->provider_context = provider_context;
    cipher_context->cipher_algorithm = cipher_algorithm;
    cipher_context->key_size = key_size;
    cipher_context->block_size = block_size;
    cipher_context->iv_length = iv_length;
    cipher_context->aead = aead;
    cipher_context->key = INVALID_HANDLE;
    cipher_context->cipher_context = INVALID_HANDLE;
    cipher_context->padded =
            cipher_context->cipher_algorithm == SA_CIPHER_ALGORITHM_AES_CBC_PKCS7 ||
            cipher_context->cipher_algorithm == SA_CIPHER_ALGORITHM_AES_ECB_PKCS7;
    cipher_context->tag_length = 0;
    cipher_context->aead_buffer = NULL;
    cipher_context->aead_buffer_length = 0;
    cipher_context->aead_processed_length = 0;
    
    // Allocate AEAD buffer if this is an AEAD cipher
    if (aead) {
        cipher_context->aead_buffer = OPENSSL_malloc(MAX_AEAD_BUFFER_SIZE);
        if (cipher_context->aead_buffer == NULL) {
            ERROR("OPENSSL_malloc failed for AEAD buffer");
            OPENSSL_free(cipher_context);
            return NULL;
        }
    }
    
    return cipher_context;
}

static void cipher_freectx(void* cctx) {
    if (cctx == NULL)
        return;

    sa_provider_cipher_context* cipher_context = cctx;
    if (cipher_context->cipher_context != INVALID_HANDLE)
        sa_crypto_cipher_release(cipher_context->cipher_context);

    if (cipher_context->delete_key && cipher_context->key != INVALID_HANDLE)
        sa_key_release(cipher_context->key);
    
    if (cipher_context->aead_buffer != NULL)
        OPENSSL_free(cipher_context->aead_buffer);

    cipher_context->key = INVALID_HANDLE;
    cipher_context->cipher_context = INVALID_HANDLE;
    OPENSSL_free(cipher_context);
}

static int cipher_init(
        void* cctx,
        const unsigned char* key,
        size_t keylen,
        const unsigned char* iv,
        size_t ivlen,
        const OSSL_PARAM params[],
        sa_cipher_mode mode) {

    if (cctx == NULL) {
        ERROR("NULL cctx");
        return 0;
    }

    int result = 0;
    sa_provider_cipher_context* cipher_context = cctx;
    do {
        cipher_context->mode = mode;
        if (cipher_context->cipher_context != INVALID_HANDLE) {
            sa_crypto_cipher_release(cipher_context->cipher_context);
            cipher_context->cipher_context = INVALID_HANDLE;
        }

        if (iv != NULL) {
            if (ivlen > AES_BLOCK_SIZE) {
                ERROR("Invalid IV length");
                break;
            }

            memcpy(cipher_context->iv, iv, ivlen);
        }

        if (key != NULL) {
            if (cipher_context->key != INVALID_HANDLE)
                sa_key_release(cipher_context->key);

            sa_rights rights;
            sa_rights_set_allow_all(&rights);
            sa_import_parameters_symmetric parameters_symmetric = {&rights};
            if (sa_key_import(&cipher_context->key, SA_KEY_FORMAT_SYMMETRIC_BYTES, key, keylen,
                        &parameters_symmetric) != SA_STATUS_OK) {
                ERROR("sa_key_import failed");
                break;
            }

            sa_header header;
            if (sa_key_header(&header, cipher_context->key) != SA_STATUS_OK) {
                ERROR("sa_key_header failed");
                break;
            }

            if (cipher_context->key_size != header.size) {
                ERROR("Key size mismtach for algorithm");
                break;
            }

            cipher_context->delete_key = true;
        }

        if (cipher_set_ctx_params(cctx, params) != 1) {
            ERROR("cipher_set_ctx_params failed");
            break;
        }

        result = 1;
    } while (false);

    return result;
}

static int cipher_encrypt_init(
        void* cctx,
        const unsigned char* key,
        size_t keylen,
        const unsigned char* iv,
        size_t ivlen,
        const OSSL_PARAM params[]) {

    return cipher_init(cctx, key, keylen, iv, ivlen, params, SA_CIPHER_MODE_ENCRYPT);
}

static int cipher_decrypt_init(void* cctx,
        const unsigned char* key,
        size_t keylen,
        const unsigned char* iv,
        size_t ivlen,
        const OSSL_PARAM params[]) {

    return cipher_init(cctx, key, keylen, iv, ivlen, params, SA_CIPHER_MODE_DECRYPT);
}

static int cipher_update(
        void* cctx,
        unsigned char* out,
        size_t* outl,
        size_t outsize,
        const unsigned char* in,
        size_t inl) {
    return cipher_cipher(cctx, out, outl, outsize, in, inl);
}

static int cipher_final(
        void* cctx,
        unsigned char* out,
        size_t* outl,
        size_t outsize) {
    return cipher_cipher(cctx, out, outl, outsize, NULL, 0);
}

static int cipher_cipher(
        void* cctx,
        unsigned char* out, //NOLINT
        size_t* outl,
        size_t outsize,
        const unsigned char* in,
        size_t inl) {

    if (cctx == NULL) {
        ERROR("NULL cctx");
        return 0;
    }

    if (outl == NULL) {
        ERROR("NULL outl");
        return 0;
    }

    int result = 0;
    sa_provider_cipher_context* cipher_context = cctx;
    do {
        if (cipher_context->key == INVALID_HANDLE) {
            ERROR("cipher_context->key is invalid");
            break;
        }

        if (cipher_context->cipher_context == INVALID_HANDLE) {
            /*
             * AEAD cipher initialization can behave poorly if passed a NULL pointer
             * for AAD even when the length is zero. Defensively use the address of
             * a local zero byte when AAD is empty (out != NULL) so the pointer is
             * non-NULL while the length remains 0.
             */
            uint8_t aad_zero = 0;
            void* aad = NULL;
            size_t aad_length;
            if (out == NULL) {
                aad = (void*) in;
                aad_length = inl;
            } else {
                aad = &aad_zero;
                aad_length = 0;
            }

            sa_cipher_parameters_aes_cbc parameters_aes_cbc;
            sa_cipher_parameters_aes_ctr parameters_aes_ctr;
            sa_cipher_parameters_chacha20 parameters_chacha20;
            sa_cipher_parameters_aes_gcm parameters_aes_gcm;
            sa_cipher_parameters_chacha20_poly1305 parameters_chacha20_poly1305;
            void* parameters;
            switch (cipher_context->cipher_algorithm) {
                case SA_CIPHER_ALGORITHM_AES_ECB:
                case SA_CIPHER_ALGORITHM_AES_ECB_PKCS7:
                    parameters = NULL;
                    break;

                case SA_CIPHER_ALGORITHM_AES_CBC:
                case SA_CIPHER_ALGORITHM_AES_CBC_PKCS7:
                    parameters_aes_cbc.iv = cipher_context->iv;
                    parameters_aes_cbc.iv_length = cipher_context->iv_length;
                    parameters = &parameters_aes_cbc;
                    break;

                case SA_CIPHER_ALGORITHM_AES_CTR:
                    parameters_aes_ctr.ctr = cipher_context->iv;
                    parameters_aes_ctr.ctr_length = cipher_context->iv_length;
                    parameters = &parameters_aes_ctr;
                    break;

                case SA_CIPHER_ALGORITHM_CHACHA20:
                    parameters_chacha20.counter = cipher_context->iv;
                    parameters_chacha20.counter_length = CHACHA20_COUNTER_LENGTH;
                    parameters_chacha20.nonce = cipher_context->iv + CHACHA20_COUNTER_LENGTH;
                    parameters_chacha20.nonce_length = CHACHA20_NONCE_LENGTH;
                    parameters = &parameters_chacha20;
                    break;

                case SA_CIPHER_ALGORITHM_AES_GCM:
                    parameters_aes_gcm.iv = cipher_context->iv;
                    parameters_aes_gcm.iv_length = cipher_context->iv_length;
                    parameters_aes_gcm.aad = aad;
                    parameters_aes_gcm.aad_length = aad_length;
                    parameters = &parameters_aes_gcm;
                    break;

                case SA_CIPHER_ALGORITHM_CHACHA20_POLY1305:
                    parameters_chacha20_poly1305.nonce = cipher_context->iv;
                    parameters_chacha20_poly1305.nonce_length = cipher_context->iv_length;
                    parameters_chacha20_poly1305.aad = aad;
                    parameters_chacha20_poly1305.aad_length = aad_length;
                    parameters = &parameters_chacha20_poly1305;
                    break;

                default:
                    continue; // NOLINT
            }

            sa_status status = sa_crypto_cipher_init(&cipher_context->cipher_context, cipher_context->cipher_algorithm,
                    cipher_context->mode, cipher_context->key, parameters);
            if (status != SA_STATUS_OK) {
                ERROR("sa_crypto_cipher_init failed %d", status);
                break;
            }
        }

        size_t total_processed = 0;
        if (out != NULL) {
            sa_status status = SA_STATUS_OK;
            size_t bytes_to_process = 0;

            if (in != NULL) {
                // Process an update call.
                sa_buffer out_buffer = {SA_BUFFER_TYPE_CLEAR, {.clear = {out, outsize, 0}}};
                sa_buffer in_buffer;
                in_buffer.buffer_type = SA_BUFFER_TYPE_CLEAR;

                // mbedTLS 2.16.10 GCM multi-part fix applied: directly pass data through
                // The fix in mbedTLS gcm.c now properly handles partial blocks across multiple update calls
                in_buffer.context.clear.buffer = (void*) in;
                in_buffer.context.clear.length = inl;
                in_buffer.context.clear.offset = 0;
                bytes_to_process = inl;

                if (cipher_context->aead) {
                    // For AEAD modes, pass data directly to mbedTLS (now supports multi-part with partial blocks)
                    status = sa_crypto_cipher_process(&out_buffer, cipher_context->cipher_context,
                            &in_buffer, &bytes_to_process);
                    if (status != SA_STATUS_OK) {
                        ERROR("sa_crypto_cipher_process returned %d", status);
                        break;
                    }
                    *outl = bytes_to_process;
                    total_processed = bytes_to_process;
                } else {
                    // For block cipher modes (ECB, CBC), buffer partial blocks
                    size_t total_length = cipher_context->remaining_block_length + inl;
                    size_t position = 0;
                // If inl is not a multiple of block size, store the leftover data in remaining_block. Then, the
                // next time this function is called, start with the remaining data and add data from in to it. Then
                // process the remainder of in.
                while (total_length >= cipher_context->block_size) {
                    if (cipher_context->remaining_block_length > 0) {
                        // Start with remaining_block and add in to it.
                        memcpy(cipher_context->remaining_block + cipher_context->remaining_block_length, in + position,
                                cipher_context->block_size - cipher_context->remaining_block_length);
                        position += cipher_context->block_size - cipher_context->remaining_block_length;
                        cipher_context->remaining_block_length = 0;

                        in_buffer.context.clear.buffer = cipher_context->remaining_block;
                        in_buffer.context.clear.length = AES_BLOCK_SIZE;
                        in_buffer.context.clear.offset = 0;
                        bytes_to_process = AES_BLOCK_SIZE;
                    } else {
                        // Process data from in.
                        in_buffer.context.clear.buffer = (void*) in;
                        in_buffer.context.clear.length = inl;
                        in_buffer.context.clear.offset = position;
                        bytes_to_process = ((inl - position) / cipher_context->block_size) * cipher_context->block_size;
                        position += bytes_to_process;
                    }

                    if (bytes_to_process % cipher_context->block_size == 0) {
                        total_length -= bytes_to_process;
                        status = sa_crypto_cipher_process(&out_buffer, cipher_context->cipher_context,
                                &in_buffer, &bytes_to_process);
                        total_processed += bytes_to_process;
                    }
                }

                    // Store any leftover data in remaining_block for processing on the next call to update.
                    if (position < inl) {
                        cipher_context->remaining_block_length = inl - position;
                        memcpy(cipher_context->remaining_block, in + position,
                                cipher_context->remaining_block_length);
                    }
                } // end of else (block cipher modes)
            } else if (cipher_context->cipher_algorithm != SA_CIPHER_ALGORITHM_AES_CBC &&
                       cipher_context->cipher_algorithm != SA_CIPHER_ALGORITHM_AES_ECB) {
                // Process a final call.
                sa_buffer out_buffer = {SA_BUFFER_TYPE_CLEAR, {.clear = {out, outsize, 0}}};
                sa_buffer in_buffer;
                
                // For AEAD modes, finalize and get the tag
                // mbedTLS multi-part fix handles all partial blocks internally, so no buffered data here
                if (cipher_context->aead) {
                    // Now finalize and get the tag
                    sa_cipher_end_parameters_aes_gcm end_parameters;
                    end_parameters.tag = cipher_context->tag;
                    end_parameters.tag_length = cipher_context->tag_length > 0 ? cipher_context->tag_length : MAX_GCM_TAG_LENGTH;
                    
                    // Call process_last with empty buffer just to finalize
                    uint8_t dummy_in = 0;
                    uint8_t dummy_out[16];
                    sa_buffer empty_out_buffer = {SA_BUFFER_TYPE_CLEAR, {.clear = {dummy_out, sizeof(dummy_out), 0}}};
                    sa_buffer empty_in_buffer = {SA_BUFFER_TYPE_CLEAR, {.clear = {&dummy_in, 0, 0}}};
                    size_t last_bytes = 0;
                    
                    status = sa_crypto_cipher_process_last(&empty_out_buffer, cipher_context->cipher_context, &empty_in_buffer,
                            &last_bytes, &end_parameters);
                    if (status != SA_STATUS_OK) {
                        ERROR("sa_crypto_cipher_process_last returned %d", status);
                        break;
                    }
                    
                    if (status == SA_STATUS_OK) {
                        fprintf(stderr, "sa_provider: GCM tag (len=%zu): ", end_parameters.tag_length);
                        for (size_t dbg_i = 0; dbg_i < end_parameters.tag_length; dbg_i++) 
                            fprintf(stderr, "%02x", cipher_context->tag[dbg_i]);
                        fprintf(stderr, "\n");
                    }
                } else {
                    // For non-AEAD modes, process remaining block
                    in_buffer.buffer_type = SA_BUFFER_TYPE_CLEAR;
                    in_buffer.context.clear.buffer = cipher_context->remaining_block;
                    in_buffer.context.clear.length = cipher_context->remaining_block_length;
                    in_buffer.context.clear.offset = 0;
                    bytes_to_process = cipher_context->remaining_block_length;

                    void* parameters = NULL;
                    status = sa_crypto_cipher_process_last(&out_buffer, cipher_context->cipher_context, &in_buffer,
                            &bytes_to_process, parameters);
                    total_processed += bytes_to_process;
                }
            } else if (cipher_context->remaining_block_length > 0) {
                // This is a SA_CIPHER_ALGORITHM_AES_CBC or SA_CIPHER_ALGORITHM_AES_ECB cipher, and it didn't end on a
                // block_size boundary. This is an error.
                ERROR("SA_CIPHER_ALGORITHM_AES_CBC or SA_CIPHER_ALGORITHM_AES_ECB didn't end on a block boundary");
                *outl = 0;
                break;
            }

            if (status == SA_STATUS_OK) {
                *outl = total_processed;
            } else {
                ERROR("cipher_do_cipher failed");
                *outl = 0;
                break;
            }
        } else {
            *outl = 0;
        }

        result = 1;
    } while (false);

    return result;
}

static int cipher_get_params(
        int mode,
        size_t key_length,
        size_t block_length,
        size_t iv_length,
        bool aead,
        OSSL_PARAM params[]) {

    if (params == NULL) {
        ERROR("NULL params");
        return 0;
    }

    OSSL_PARAM* param;

    param = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE);
    if (param != NULL && !OSSL_PARAM_set_uint(param, mode)) {
        ERROR("OSSL_PARAM_set_uint failed");
        return 0;
    }

    param = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (param != NULL && !OSSL_PARAM_set_size_t(param, key_length)) {
        ERROR("OSSL_PARAM_set_size_t failed");
        return 0;
    }

    param = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (param != NULL && !OSSL_PARAM_set_size_t(param, iv_length)) {
        ERROR("OSSL_PARAM_set_size_t failed");
        return 0;
    }

    param = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
    if (param != NULL && !OSSL_PARAM_set_size_t(param, block_length)) {
        ERROR("OSSL_PARAM_set_size_t failed");
        return 0;
    }

    param = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD);
    if (param != NULL && !OSSL_PARAM_set_int(param, aead)) {
        ERROR("OSSL_PARAM_set_int failed");
        return 0;
    }

    param = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_CUSTOM_IV);
    if (param != NULL && !OSSL_PARAM_set_int(param, 0)) {
        ERROR("OSSL_PARAM_set_int failed");
        return 0;
    }

    param = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_CTS);
    if (param != NULL && !OSSL_PARAM_set_int(param, 0)) {
        ERROR("OSSL_PARAM_set_int failed");
        return 0;
    }

    param = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK);
    if (param != NULL && !OSSL_PARAM_set_int(param, 0)) {
        ERROR("OSSL_PARAM_set_int failed");
        return 0;
    }

    param = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_HAS_RAND_KEY);
    if (param != NULL && !OSSL_PARAM_set_int(param, 0)) {
        ERROR("OSSL_PARAM_set_int failed");
        return 0;
    }

    return 1;
}

static const OSSL_PARAM* cipher_gettable_params(ossl_unused void* provctx) {
    static const OSSL_PARAM params[] = {
            OSSL_PARAM_uint(OSSL_CIPHER_PARAM_MODE, NULL),
            OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
            OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
            OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
            OSSL_PARAM_int(OSSL_CIPHER_PARAM_AEAD, NULL),
            OSSL_PARAM_int(OSSL_CIPHER_PARAM_CUSTOM_IV, NULL),
            OSSL_PARAM_int(OSSL_CIPHER_PARAM_CTS, NULL),
            OSSL_PARAM_int(OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK, NULL),
            OSSL_PARAM_int(OSSL_CIPHER_PARAM_HAS_RAND_KEY, NULL),
            OSSL_PARAM_END};

    return params;
}

static int cipher_get_ctx_params(
        void* cctx,
        OSSL_PARAM params[]) {

    if (cctx == NULL) {
        ERROR("NULL cctx");
        return 0;
    }

    if (params == NULL) {
        ERROR("NULL params");
        return 0;
    }

    sa_provider_cipher_context* cipher_context = cctx;
    OSSL_PARAM* param = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_PADDING);
    if (param != NULL && !OSSL_PARAM_set_uint(param, cipher_context->padded)) {
        ERROR("OSSL_PARAM_set_uint failed");
        return 0;
    }

    param = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (param != NULL && !OSSL_PARAM_set_size_t(param, cipher_context->key_size)) {
        ERROR("OSSL_PARAM_set_size_t failed");
        return 0;
    }

    param = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if (param != NULL && !OSSL_PARAM_set_octet_string(param, cipher_context->tag, AES_BLOCK_SIZE)) {
        ERROR("OSSL_PARAM_set_octet_string failed");
        return 0;
    }

    param = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (param != NULL && !OSSL_PARAM_set_size_t(param, cipher_context->iv_length)) {
        ERROR("OSSL_PARAM_set_size_t failed");
        return 0;
    }

    param = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
    if (param != NULL && !OSSL_PARAM_set_octet_string(param, cipher_context->iv,
                                 cipher_context->iv_length)) {
        ERROR("OSSL_PARAM_set_octet_string failed");
        return 0;
    }

    param = OSSL_PARAM_locate(params, OSSL_PARAM_SA_KEY);
    if (param != NULL && !OSSL_PARAM_set_ulong(param, cipher_context->key)) {
        ERROR("OSSL_PARAM_set_uint64 failed");
        return 0;
    }

    param = OSSL_PARAM_locate(params, OSSL_PARAM_SA_KEY_DELETE);
    if (param != NULL && !OSSL_PARAM_set_int(param, cipher_context->delete_key)) {
        ERROR("OSSL_PARAM_set_int failed");
        return 0;
    }

    return 1;
}

static int cipher_set_ctx_params(void* cctx,
        const OSSL_PARAM params[]) {

    if (cctx == NULL) {
        ERROR("NULL cctx");
        return 0;
    }

    if (params == NULL)
        return 1;

    sa_provider_cipher_context* cipher_context = cctx;
    const OSSL_PARAM* param = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_PADDING);
    if (param != NULL) {
        unsigned int padded;
        if (!OSSL_PARAM_get_uint(param, &padded)) {
            ERROR("OSSL_PARAM_get_uint failed");
            return 0;
        }

        cipher_context->padded = padded;
        if (padded) {
            if (cipher_context->cipher_algorithm == SA_CIPHER_ALGORITHM_AES_ECB)
                cipher_context->cipher_algorithm = SA_CIPHER_ALGORITHM_AES_ECB_PKCS7;
            else if (cipher_context->cipher_algorithm == SA_CIPHER_ALGORITHM_AES_CBC)
                cipher_context->cipher_algorithm = SA_CIPHER_ALGORITHM_AES_CBC_PKCS7;
        } else {
            if (cipher_context->cipher_algorithm == SA_CIPHER_ALGORITHM_AES_ECB_PKCS7)
                cipher_context->cipher_algorithm = SA_CIPHER_ALGORITHM_AES_ECB;
            else if (cipher_context->cipher_algorithm == SA_CIPHER_ALGORITHM_AES_CBC_PKCS7)
                cipher_context->cipher_algorithm = SA_CIPHER_ALGORITHM_AES_CBC;
        }
    }

    param = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if (param != NULL) {
        size_t length;
        void* p_tag = cipher_context->tag;
        if (!OSSL_PARAM_get_octet_string(param, &p_tag, AES_BLOCK_SIZE, &length)) {
            ERROR("OSSL_PARAM_get_octet_string failed");
            return 0;
        }
        /* record actual tag length provided by caller */
        cipher_context->tag_length = length;
    }

    param = OSSL_PARAM_locate_const(params, OSSL_PARAM_SA_KEY);
    if (param != NULL) {
        uint64_t key;
        if (!OSSL_PARAM_get_uint64(param, &key)) {
            ERROR("OSSL_PARAM_get_uint64 failed");
            return 0;
        }

        sa_header header;
        if (sa_key_header(&header, key) != SA_STATUS_OK) {
            ERROR("sa_key_header failed");
            return 0;
        }

        if (cipher_context->key_size != header.size) {
            ERROR("Key size mismtach for algorithm");
            return 0;
        }

        if (cipher_context->key != INVALID_HANDLE)
            sa_key_release(cipher_context->key);

        cipher_context->key = key;
    }

    param = OSSL_PARAM_locate_const(params, OSSL_PARAM_SA_KEY_DELETE);
    if (param != NULL) {
        int delete_key;
        if (!OSSL_PARAM_get_int(param, &delete_key)) {
            ERROR("OSSL_PARAM_get_int failed");
            return 0;
        }

        cipher_context->delete_key = delete_key;
    }

    return 1;
}

static const OSSL_PARAM* cipher_gettable_ctx_params(
        ossl_unused void* cctx,
        ossl_unused void* provctx) {
    static const OSSL_PARAM params[] = {
            OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, NULL),
            OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
            OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
            OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
            OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, NULL, 0),
            OSSL_PARAM_uint64(OSSL_PARAM_SA_KEY, NULL),
            OSSL_PARAM_int(OSSL_PARAM_SA_KEY_DELETE, NULL),
            OSSL_PARAM_END};

    return params;
}

static const OSSL_PARAM* cipher_settable_ctx_params(
        ossl_unused void* cctx,
        ossl_unused void* provctx) {
    static const OSSL_PARAM params[] = {
            OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, NULL),
            OSSL_PARAM_uint(OSSL_CIPHER_PARAM_KEYLEN, NULL),
            OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
            OSSL_PARAM_uint64(OSSL_PARAM_SA_KEY, NULL),
            OSSL_PARAM_int(OSSL_PARAM_SA_KEY_DELETE, NULL),
            OSSL_PARAM_END};

    return params;
}

#define SA_PROVIDER_CIPHER_FUNCTIONS(algorithm, mode, size, sa_cipher, evp_ciph, iv_length, block_length, aead) \
    static void* cipher_##algorithm##_##mode##_##size##_newctx(void* provctx) { /* NOLINT */ \
        return cipher_newctx(sa_cipher, (size) / 8, block_length, iv_length, aead, provctx); \
    } \
\
    static int cipher_##algorithm##_##mode##_##size##_get_params(OSSL_PARAM params[]) { \
        return cipher_get_params(evp_ciph, (size) / 8, block_length, iv_length, aead, params); \
    } \
\
    static const OSSL_DISPATCH sa_provider_##algorithm##_##mode##_##size##_cipher_functions[] = { \
            {OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void)) cipher_##algorithm##_##mode##_##size##_newctx}, \
            {OSSL_FUNC_CIPHER_FREECTX, (void (*)(void)) cipher_freectx}, /* Disallow DUPCTX */ \
            {OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void)) cipher_encrypt_init}, \
            {OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void)) cipher_decrypt_init}, \
            {OSSL_FUNC_CIPHER_UPDATE, (void (*)(void)) cipher_update}, \
            {OSSL_FUNC_CIPHER_FINAL, (void (*)(void)) cipher_final}, \
            {OSSL_FUNC_CIPHER_CIPHER, (void (*)(void)) cipher_cipher}, \
            {OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void)) cipher_##algorithm##_##mode##_##size##_get_params}, \
            {OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (void (*)(void)) cipher_gettable_params}, \
            {OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (void (*)(void)) cipher_get_ctx_params}, \
            {OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (void (*)(void)) cipher_set_ctx_params}, \
            {OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, (void (*)(void)) cipher_gettable_ctx_params}, \
            {OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, (void (*)(void)) cipher_settable_ctx_params}, \
            {0, NULL}}
// clang-format off
SA_PROVIDER_CIPHER_FUNCTIONS(aes, ecb, 128, SA_CIPHER_ALGORITHM_AES_ECB_PKCS7, EVP_CIPH_ECB_MODE, AES_BLOCK_SIZE,
        AES_BLOCK_SIZE, false);
SA_PROVIDER_CIPHER_FUNCTIONS(aes, ecb, 256, SA_CIPHER_ALGORITHM_AES_ECB_PKCS7, EVP_CIPH_ECB_MODE, AES_BLOCK_SIZE,
        AES_BLOCK_SIZE, false);
SA_PROVIDER_CIPHER_FUNCTIONS(aes, cbc, 128, SA_CIPHER_ALGORITHM_AES_CBC_PKCS7, EVP_CIPH_CBC_MODE, AES_BLOCK_SIZE,
        AES_BLOCK_SIZE, false);
SA_PROVIDER_CIPHER_FUNCTIONS(aes, cbc, 256, SA_CIPHER_ALGORITHM_AES_CBC_PKCS7, EVP_CIPH_CBC_MODE, AES_BLOCK_SIZE,
        AES_BLOCK_SIZE, false);
SA_PROVIDER_CIPHER_FUNCTIONS(aes, ctr, 128, SA_CIPHER_ALGORITHM_AES_CTR, EVP_CIPH_CTR_MODE, AES_BLOCK_SIZE, 1, false);
SA_PROVIDER_CIPHER_FUNCTIONS(aes, ctr, 256, SA_CIPHER_ALGORITHM_AES_CTR, EVP_CIPH_CTR_MODE, AES_BLOCK_SIZE, 1, false);
SA_PROVIDER_CIPHER_FUNCTIONS(aes, gcm, 128, SA_CIPHER_ALGORITHM_AES_GCM, EVP_CIPH_GCM_MODE, GCM_IV_LENGTH, 1, true);
SA_PROVIDER_CIPHER_FUNCTIONS(aes, gcm, 256, SA_CIPHER_ALGORITHM_AES_GCM, EVP_CIPH_GCM_MODE, GCM_IV_LENGTH, 1, true);
SA_PROVIDER_CIPHER_FUNCTIONS(chacha20, none, 256, SA_CIPHER_ALGORITHM_CHACHA20, 0,
        CHACHA20_COUNTER_LENGTH + CHACHA20_NONCE_LENGTH, 1, false);
SA_PROVIDER_CIPHER_FUNCTIONS(chacha20, poly1305, 256, SA_CIPHER_ALGORITHM_CHACHA20_POLY1305, 0, CHACHA20_NONCE_LENGTH,
        1, true);
// clang-format on

ossl_unused const OSSL_ALGORITHM sa_provider_ciphers[] = {
        {"AES-128-ECB:2.16.840.1.101.3.4.1.1", "provider=secapi3",
                sa_provider_aes_ecb_128_cipher_functions, ""},
        {"AES-256-ECB:2.16.840.1.101.3.4.1.41", "provider=secapi3",
                sa_provider_aes_ecb_256_cipher_functions, ""},
        {"AES-128-CBC:AES128:2.16.840.1.101.3.4.1.2", "provider=secapi3",
                sa_provider_aes_cbc_128_cipher_functions, ""},
        {"AES-256-CBC:AES256:2.16.840.1.101.3.4.1.42", "provider=secapi3",
                sa_provider_aes_cbc_256_cipher_functions, ""},
        {"AES-128-CTR", "provider=secapi3",
                sa_provider_aes_ctr_128_cipher_functions, ""},
        {"AES-256-CTR", "provider=secapi3",
                sa_provider_aes_ctr_256_cipher_functions, ""},
        {"AES-128-GCM:id-aes128-GCM:2.16.840.1.101.3.4.1.6", "provider=secapi3",
                sa_provider_aes_gcm_128_cipher_functions, ""},
        {"AES-256-GCM:id-aes256-GCM:2.16.840.1.101.3.4.1.46", "provider=secapi3",
                sa_provider_aes_gcm_256_cipher_functions, ""},
        {"ChaCha20", "provider=secapi3",
                sa_provider_chacha20_none_256_cipher_functions, ""},
        {"ChaCha20-Poly1305", "provider=secapi3",
                sa_provider_chacha20_poly1305_256_cipher_functions, ""},
        {NULL, NULL, NULL, NULL}};

#endif
