/**
 * Copyright 2022 Comcast Cable Communications Management, LLC
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

#include "common.h"
#include "log.h"
#include "sa.h"
#include "sa_engine_internal.h"
#include <openssl/engine.h>
#include <threads.h>
#if OPENSSL_VERSION_NUMBER < 0x30000000
#include <memory.h>
#endif

// These do not follow the convention of all upper case to make the DECLARE_CIPHER macro work properly.
#define BLOCK_SIZE_aes_cbc 16
#define BLOCK_SIZE_aes_ecb 16
#define BLOCK_SIZE_aes_ctr 1
#define BLOCK_SIZE_aes_gcm 1
#define BLOCK_SIZE_chacha20_chacha20 1
#define BLOCK_SIZE_chacha20_poly1305 1
#define IV_LEN_aes_cbc 16
#define IV_LEN_aes_ecb 0
#define IV_LEN_aes_ctr 16
#define IV_LEN_aes_gcm 12
#define IV_LEN_chacha20_chacha20 16
#define IV_LEN_chacha20_poly1305 12
#define NID_chacha20_256_chacha20 NID_chacha20
#define NID_chacha20_256_poly1305 NID_chacha20_poly1305

#if OPENSSL_VERSION_NUMBER >= 0x10100000

#define DECLARE_CIPHER(algorithm, keysize, mode, cipher_flags) \
    static EVP_CIPHER* cipher_##algorithm##_##keysize##_##mode = NULL; \
    static const EVP_CIPHER* get_cipher_##algorithm##_##keysize##_##mode() { \
        if (mtx_lock(&engine_mutex) != 0) { \
            ERROR("mtx_lock failed"); \
            return NULL; \
        } \
        if (cipher_##algorithm##_##keysize##_##mode == NULL) { \
            cipher_##algorithm##_##keysize##_##mode = EVP_CIPHER_meth_new(NID_##algorithm##_##keysize##_##mode, \
                    BLOCK_SIZE_##algorithm##_##mode, SYM_##keysize##_KEY_SIZE); \
            if (cipher_##algorithm##_##keysize##_##mode == NULL || \
                    !EVP_CIPHER_meth_set_iv_length(cipher_##algorithm##_##keysize##_##mode, \
                            IV_LEN_##algorithm##_##mode) || \
                    !EVP_CIPHER_meth_set_flags(cipher_##algorithm##_##keysize##_##mode, (cipher_flags)) || \
                    !EVP_CIPHER_meth_set_init(cipher_##algorithm##_##keysize##_##mode, cipher_init) || \
                    !EVP_CIPHER_meth_set_do_cipher(cipher_##algorithm##_##keysize##_##mode, cipher_do_cipher) || \
                    !EVP_CIPHER_meth_set_ctrl(cipher_##algorithm##_##keysize##_##mode, cipher_ctrl) || \
                    !EVP_CIPHER_meth_set_cleanup(cipher_##algorithm##_##keysize##_##mode, cipher_cleanup)) { \
                EVP_CIPHER_meth_free(cipher_##algorithm##_##keysize##_##mode); \
                cipher_##algorithm##_##keysize##_##mode = NULL; \
            } \
        } \
        mtx_unlock(&engine_mutex); \
        return cipher_##algorithm##_##keysize##_##mode; \
    }

#else

#define EVP_CIPHER_meth_free OPENSSL_free
#define DECLARE_CIPHER(algorithm, keysize, mode, cipher_flags) \
    static EVP_CIPHER* cipher_##algorithm##_##keysize##_##mode = NULL; \
    static const EVP_CIPHER* get_cipher_##algorithm##_##keysize##_##mode() { \
        if (mtx_lock(&engine_mutex) != 0) { \
            ERROR("mtx_lock failed"); \
            return NULL; \
        } \
        if (cipher_##algorithm##_##keysize##_##mode == NULL) { \
            cipher_##algorithm##_##keysize##_##mode = OPENSSL_malloc(sizeof(EVP_CIPHER)); \
            cipher_##algorithm##_##keysize##_##mode->nid = NID_##algorithm##_##keysize##_##mode; \
            cipher_##algorithm##_##keysize##_##mode->block_size = BLOCK_SIZE_##algorithm##_##mode; \
            cipher_##algorithm##_##keysize##_##mode->key_len = SYM_##keysize##_KEY_SIZE; \
            cipher_##algorithm##_##keysize##_##mode->iv_len = IV_LEN_##algorithm##_##mode; \
            cipher_##algorithm##_##keysize##_##mode->flags = (cipher_flags); \
            cipher_##algorithm##_##keysize##_##mode->init = cipher_init; \
            cipher_##algorithm##_##keysize##_##mode->do_cipher = cipher_do_cipher; \
            cipher_##algorithm##_##keysize##_##mode->cleanup = cipher_cleanup; \
            cipher_##algorithm##_##keysize##_##mode->ctx_size = BLOCK_SIZE_##algorithm##_##mode * 2; \
            cipher_##algorithm##_##keysize##_##mode->set_asn1_parameters = NULL; \
            cipher_##algorithm##_##keysize##_##mode->get_asn1_parameters = NULL; \
            cipher_##algorithm##_##keysize##_##mode->ctrl = cipher_ctrl; \
            cipher_##algorithm##_##keysize##_##mode->app_data = NULL; \
        } \
        mtx_unlock(&engine_mutex); \
        return cipher_##algorithm##_##keysize##_##mode; \
    }

#endif

typedef struct {
    sa_key* key;
    const unsigned char* iv;
    sa_cipher_mode mode;
    sa_cipher_algorithm cipher_algorithm;
    bool padding;
    sa_crypto_cipher_context cipher_context;
    uint8_t tag[16];
} cipher_app_data;

static int cipher_nids[] = {
#if OPENSSL_VERSION_NUMBER >= 0x10100000
        NID_chacha20,
        NID_chacha20_poly1305,
#endif
        NID_aes_128_cbc,
        NID_aes_128_ecb,
        NID_aes_128_ctr,
        NID_aes_128_gcm,
        NID_aes_256_cbc,
        NID_aes_256_ecb,
        NID_aes_256_ctr,
        NID_aes_256_gcm};

static int cipher_nids_num = (sizeof(cipher_nids) / sizeof(cipher_nids[0]));

static sa_cipher_algorithm cipher_get_cipher_algorithm(int nid) {
    switch (nid) {
        case NID_aes_128_ecb:
        case NID_aes_256_ecb:
            return SA_CIPHER_ALGORITHM_AES_ECB;

        case NID_aes_128_cbc:
        case NID_aes_256_cbc:
            return SA_CIPHER_ALGORITHM_AES_CBC;

        case NID_aes_128_ctr:
        case NID_aes_256_ctr:
            return SA_CIPHER_ALGORITHM_AES_CTR;

        case NID_aes_128_gcm:
        case NID_aes_256_gcm:
            return SA_CIPHER_ALGORITHM_AES_GCM;

#if OPENSSL_VERSION_NUMBER >= 0x10100000
        case NID_chacha20:
            return SA_CIPHER_ALGORITHM_CHACHA20;

        case NID_chacha20_poly1305:
            return SA_CIPHER_ALGORITHM_CHACHA20_POLY1305;
#endif

        default:
            return UINT32_MAX;
    }
}

static int cipher_init(
        EVP_CIPHER_CTX* cipher_ctx,
        const unsigned char* key,
        const unsigned char* iv,
        int enc) {

    int result = 0;
    cipher_app_data* app_data = NULL;
    do {
        app_data = EVP_CIPHER_CTX_get_app_data(cipher_ctx);
        if (app_data == NULL) {
            app_data = malloc(sizeof(cipher_app_data));
            app_data->cipher_algorithm = cipher_get_cipher_algorithm(EVP_CIPHER_CTX_nid(cipher_ctx));
            app_data->padding = app_data->cipher_algorithm == SA_CIPHER_ALGORITHM_AES_CBC ||
                                app_data->cipher_algorithm == SA_CIPHER_ALGORITHM_AES_ECB;
            app_data->cipher_context = UINT32_MAX;
            app_data->mode = enc ? SA_CIPHER_MODE_ENCRYPT : SA_CIPHER_MODE_DECRYPT;
            app_data->key = NULL;
            app_data->iv = NULL;
            EVP_CIPHER_CTX_set_app_data(cipher_ctx, app_data);
        }

        if (key != NULL) {
            app_data->key = (sa_key*) key;
            sa_header header;
            sa_status status = sa_key_header(&header, *app_data->key);
            if (status != SA_STATUS_OK) {
                ERROR("sa_key_header failed %d", status);
                break;
            }

            int key_length = EVP_CIPHER_CTX_key_length(cipher_ctx);
            if (key_length != header.size) {
                ERROR("Key size mismtach for algorithm");
                break;
            }
        }

        if (iv != NULL) {
            app_data->iv = iv;
        }

        result = 1;
    } while (false);

    return result;
}

static int cipher_do_cipher(
        EVP_CIPHER_CTX* cipher_ctx,
        unsigned char* out, // NOLINT
        const unsigned char* in,
        size_t in_length) {

    int result = -1;
    do {
        cipher_app_data* app_data = EVP_CIPHER_CTX_get_app_data(cipher_ctx);
        if (app_data == NULL || app_data->key == NULL) {
            ERROR("NULL app_data");
            break;
        }

        if (app_data->cipher_context == UINT32_MAX) {
            void* aad = NULL;
            size_t aad_length;
            if (out == NULL) {
                aad = (void*) in;
                aad_length = in_length;
            } else {
                aad_length = 0;
            }

            int iv_length = EVP_CIPHER_CTX_iv_length(cipher_ctx);
            sa_cipher_parameters_aes_cbc parameters_aes_cbc;
            sa_cipher_parameters_aes_ctr parameters_aes_ctr;
            sa_cipher_parameters_chacha20 parameters_chacha20;
            sa_cipher_parameters_aes_gcm parameters_aes_gcm;
            sa_cipher_parameters_chacha20_poly1305 parameters_chacha20_poly1305;
            void* parameters;
            switch (app_data->cipher_algorithm) {
                case SA_CIPHER_ALGORITHM_AES_ECB:
                    parameters = NULL;
                    break;

                case SA_CIPHER_ALGORITHM_AES_CBC:
                    parameters_aes_cbc.iv = app_data->iv;
                    parameters_aes_cbc.iv_length = iv_length;
                    parameters = &parameters_aes_cbc;
                    break;

                case SA_CIPHER_ALGORITHM_AES_CTR:
                    parameters_aes_ctr.ctr = app_data->iv;
                    parameters_aes_ctr.ctr_length = iv_length;
                    parameters = &parameters_aes_ctr;
                    break;

                case SA_CIPHER_ALGORITHM_CHACHA20:
                    parameters_chacha20.counter = app_data->iv;
                    parameters_chacha20.counter_length = CHACHA20_COUNTER_LENGTH;
                    parameters_chacha20.nonce = app_data->iv + CHACHA20_COUNTER_LENGTH;
                    parameters_chacha20.nonce_length = CHACHA20_NONCE_LENGTH;
                    parameters = &parameters_chacha20;
                    break;

                case SA_CIPHER_ALGORITHM_AES_GCM:
                    parameters_aes_gcm.iv = app_data->iv;
                    parameters_aes_gcm.iv_length = iv_length;
                    parameters_aes_gcm.aad = aad;
                    parameters_aes_gcm.aad_length = aad_length;
                    parameters = &parameters_aes_gcm;
                    break;

                case SA_CIPHER_ALGORITHM_CHACHA20_POLY1305:
                    parameters_chacha20_poly1305.nonce = app_data->iv;
                    parameters_chacha20_poly1305.nonce_length = iv_length;
                    parameters_chacha20_poly1305.aad = aad;
                    parameters_chacha20_poly1305.aad_length = aad_length;
                    parameters = &parameters_chacha20_poly1305;
                    break;

                default:
                    continue; // NOLINT
            }

            sa_status status = sa_crypto_cipher_init(&app_data->cipher_context, app_data->cipher_algorithm,
                    app_data->mode, *app_data->key, parameters);
            if (status != SA_STATUS_OK) {
                ERROR("sa_crypto_cipher_init failed %d", status);
                break;
            }
        }

        if (out != NULL) {
            sa_status status = SA_STATUS_OK;
            size_t bytes_to_process = in_length;
            if (in != NULL) {
                sa_buffer out_buffer = {SA_BUFFER_TYPE_CLEAR, .context.clear = {out, in_length, 0}};
                sa_buffer in_buffer = {SA_BUFFER_TYPE_CLEAR, .context.clear = {(void*) in, in_length, 0}};

                status = sa_crypto_cipher_process(&out_buffer, app_data->cipher_context, &in_buffer,
                        &bytes_to_process);
            } else if (app_data->cipher_algorithm != SA_CIPHER_ALGORITHM_AES_CBC &&
                       app_data->cipher_algorithm != SA_CIPHER_ALGORITHM_AES_ECB &&
                       app_data->cipher_algorithm != SA_CIPHER_ALGORITHM_CHACHA20) {
                uint8_t temp;
                sa_buffer out_buffer = {SA_BUFFER_TYPE_CLEAR,
                        .context.clear = {out, EVP_CIPHER_CTX_block_size(cipher_ctx), 0}};
                sa_buffer in_buffer = {SA_BUFFER_TYPE_CLEAR, .context.clear = {&temp, 0, 0}};
                bytes_to_process = 0;

                sa_cipher_end_parameters_aes_gcm end_parameters = {app_data->tag, 16};
                status = sa_crypto_cipher_process_last(&out_buffer, app_data->cipher_context, &in_buffer,
                        &bytes_to_process, &end_parameters);
            }

            if (status == SA_STATUS_OK)
                result = (int) bytes_to_process;
            else
                ERROR("cipher_do_cipher");
        } else {
            result = 1;
        }
    } while (false);

    return result;
}

static int cipher_ctrl(
        EVP_CIPHER_CTX* cipher_ctx,
        int type,
        int arg,
        void* ptr) {

#if OPENSSL_VERSION_NUMBER >= 0x10100000
    if (type == EVP_CTRL_AEAD_GET_TAG) {
#else
    if (type == EVP_CTRL_GCM_GET_TAG) {
#endif
        if (ptr == NULL) {
            ERROR("NULL ptr");
            return 0;
        }

        if (arg > 16) {
            ERROR("Invalid arg");
            return 0;
        }

        cipher_app_data* app_data = EVP_CIPHER_CTX_get_app_data(cipher_ctx);
        if (app_data == NULL) {
            ERROR("NULL app_data");
            return 0;
        }

        memcpy(ptr, app_data->tag, arg);
        return 1;
    }

#if OPENSSL_VERSION_NUMBER >= 0x10100000
    if (type == EVP_CTRL_AEAD_SET_TAG) {
#else
    if (type == EVP_CTRL_GCM_SET_TAG) {
#endif
        if (ptr == NULL) {
            ERROR("NULL ptr");
            return 0;
        }

        if (arg > 16) {
            ERROR("Invalid arg");
            return 0;
        }

        cipher_app_data* app_data = EVP_CIPHER_CTX_get_app_data(cipher_ctx);
        if (app_data == NULL) {
            ERROR("NULL app_data");
            return 0;
        }

        memset(app_data->tag, 0, 16);
        memcpy(app_data->tag, ptr, arg);
        return 1;
    }

    return 0;
}

static int cipher_cleanup(EVP_CIPHER_CTX* cipher_ctx) {
    cipher_app_data* app_data = EVP_CIPHER_CTX_get_app_data(cipher_ctx);
    if (app_data != NULL) {
        if (app_data->cipher_context != UINT32_MAX)
            sa_crypto_cipher_release(app_data->cipher_context);

        free(app_data);
    }

    return 1;
}

DECLARE_CIPHER(aes, 128, ecb, EVP_CIPH_ECB_MODE | EVP_CIPH_ALWAYS_CALL_INIT)
DECLARE_CIPHER(aes, 256, ecb, EVP_CIPH_ECB_MODE | EVP_CIPH_ALWAYS_CALL_INIT)
DECLARE_CIPHER(aes, 128, cbc, EVP_CIPH_CBC_MODE | EVP_CIPH_ALWAYS_CALL_INIT)
DECLARE_CIPHER(aes, 256, cbc, EVP_CIPH_CBC_MODE | EVP_CIPH_ALWAYS_CALL_INIT)
DECLARE_CIPHER(aes, 128, ctr, EVP_CIPH_CTR_MODE | EVP_CIPH_ALWAYS_CALL_INIT)
DECLARE_CIPHER(aes, 256, ctr, EVP_CIPH_CTR_MODE | EVP_CIPH_ALWAYS_CALL_INIT)
DECLARE_CIPHER(aes, 128, gcm, EVP_CIPH_GCM_MODE | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CUSTOM_IV | EVP_CIPH_FLAG_CUSTOM_CIPHER)
DECLARE_CIPHER(aes, 256, gcm, EVP_CIPH_GCM_MODE | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CUSTOM_IV | EVP_CIPH_FLAG_CUSTOM_CIPHER)
#if OPENSSL_VERSION_NUMBER >= 0x10100000
DECLARE_CIPHER(chacha20, 256, chacha20, EVP_CIPH_ALWAYS_CALL_INIT)
DECLARE_CIPHER(chacha20, 256, poly1305, EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_FLAG_CUSTOM_CIPHER)
#endif

int sa_get_engine_ciphers(
        ENGINE* engine,
        const EVP_CIPHER** cipher,
        const int** nids,
        int nid) {

    if (!cipher) {
        if (nids == NULL)
            return 0;

        *nids = cipher_nids;
        return cipher_nids_num;
    }

    switch (nid) {
        case NID_aes_128_ecb:
            *cipher = get_cipher_aes_128_ecb();
            break;

        case NID_aes_256_ecb:
            *cipher = get_cipher_aes_256_ecb();
            break;

        case NID_aes_128_cbc:
            *cipher = get_cipher_aes_128_cbc();
            break;

        case NID_aes_256_cbc:
            *cipher = get_cipher_aes_256_cbc();
            break;

        case NID_aes_128_ctr:
            *cipher = get_cipher_aes_128_ctr();
            break;

        case NID_aes_256_ctr:
            *cipher = get_cipher_aes_256_ctr();
            break;

        case NID_aes_128_gcm:
            *cipher = get_cipher_aes_128_gcm();
            break;

        case NID_aes_256_gcm:
            *cipher = get_cipher_aes_256_gcm();
            break;

#if OPENSSL_VERSION_NUMBER >= 0x10100000
        case NID_chacha20:
            *cipher = get_cipher_chacha20_256_chacha20();
            break;

        case NID_chacha20_poly1305:
            *cipher = get_cipher_chacha20_256_poly1305();
            break;
#endif

        default:
            *cipher = NULL;
            return 0;
    }

    return 1;
}

void sa_free_engine_ciphers() {
    EVP_CIPHER_meth_free(cipher_aes_128_ecb);
    cipher_aes_128_ecb = NULL;

    EVP_CIPHER_meth_free(cipher_aes_256_ecb);
    cipher_aes_256_ecb = NULL;

    EVP_CIPHER_meth_free(cipher_aes_128_cbc);
    cipher_aes_128_cbc = NULL;

    EVP_CIPHER_meth_free(cipher_aes_256_cbc);
    cipher_aes_256_cbc = NULL;

    EVP_CIPHER_meth_free(cipher_aes_128_ctr);
    cipher_aes_128_ctr = NULL;

    EVP_CIPHER_meth_free(cipher_aes_256_ctr);
    cipher_aes_256_ctr = NULL;

    EVP_CIPHER_meth_free(cipher_aes_128_gcm);
    cipher_aes_128_gcm = NULL;

    EVP_CIPHER_meth_free(cipher_aes_256_gcm);
    cipher_aes_256_gcm = NULL;

#if OPENSSL_VERSION_NUMBER >= 0x10100000
    EVP_CIPHER_meth_free(cipher_chacha20_256_chacha20);
    cipher_chacha20_256_chacha20 = NULL;

    EVP_CIPHER_meth_free(cipher_chacha20_256_poly1305);
    cipher_chacha20_256_poly1305 = NULL;
#endif
}
