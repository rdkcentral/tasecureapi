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

#include "symmetric.h" // NOLINT
#include "common.h"
#include "log.h"
#include "pad.h"
#include "porting/memory.h"
#include "porting/rand.h"
#include "sa_types.h"
#include "stored_key_internal.h"
#include "pkcs12_mbedtls.h"
#include <memory.h>


struct symmetric_context_s {
    sa_cipher_algorithm cipher_algorithm;
    sa_cipher_mode cipher_mode;
    union {
        mbedtls_cipher_context_t cipher_ctx;      // For AES-CBC, AES-CTR
        mbedtls_aes_context aes_ctx;              // For AES-ECB (direct API)
        mbedtls_gcm_context gcm_ctx;              // For AES-GCM
        mbedtls_chacha20_context chacha20_ctx;    // For ChaCha20
        mbedtls_chachapoly_context chachapoly_ctx;// For ChaCha20-Poly1305
    } ctx;
    bool is_gcm;
    bool is_chacha;         // true for ChaCha20
    bool is_chachapoly;     // true for ChaCha20-Poly1305
    uint8_t gcm_tag[MAX_GCM_TAG_LENGTH];        // Store GCM tag for verification during decrypt
    size_t gcm_tag_length;
    uint8_t chachapoly_tag[CHACHA20_TAG_LENGTH]; // Store ChaCha20-Poly1305 tag for verification
    size_t chachapoly_tag_length;
};

sa_status symmetric_generate_key(
        stored_key_t** stored_key_generated,
        const sa_rights* rights,
        sa_generate_parameters_symmetric* parameters) {

    if (stored_key_generated == NULL) {
        ERROR("NULL stored_key_generated");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (rights == NULL) {
        ERROR("NULL rights");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (parameters == NULL) {
        ERROR("NULL parameters");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status = SA_STATUS_INTERNAL_ERROR;
    uint8_t* generated = NULL;
    do {
        generated = memory_secure_alloc(parameters->key_length);
        if (generated == NULL) {
            ERROR("memory_secure_alloc failed");
            break;
        }

        if (!rand_bytes(generated, parameters->key_length)) {
            ERROR("rand_bytes failed");
            break;
        }

        sa_type_parameters type_parameters;
        memory_memset_unoptimizable(&type_parameters, 0, sizeof(sa_type_parameters));
        status = stored_key_create(stored_key_generated, rights, NULL, SA_KEY_TYPE_SYMMETRIC, &type_parameters,
                parameters->key_length, generated, parameters->key_length);
        if (status != SA_STATUS_OK) {
            ERROR("stored_key_create failed");
            break;
        }
    } while (false);

    if (generated != NULL) {
        memory_memset_unoptimizable(generated, 0, parameters->key_length);
        memory_secure_free(generated);
    }

    return status;
}

sa_status symmetric_verify_cipher(
        sa_cipher_algorithm cipher_algorithm,
        sa_cipher_mode cipher_mode,
        const stored_key_t* stored_key) {

    DEBUG("stored_key %p", stored_key);
    if (cipher_algorithm != SA_CIPHER_ALGORITHM_AES_ECB &&
            cipher_algorithm != SA_CIPHER_ALGORITHM_AES_ECB_PKCS7 &&
            cipher_algorithm != SA_CIPHER_ALGORITHM_AES_CBC &&
            cipher_algorithm != SA_CIPHER_ALGORITHM_AES_CBC_PKCS7 &&
            cipher_algorithm != SA_CIPHER_ALGORITHM_AES_CTR &&
            cipher_algorithm != SA_CIPHER_ALGORITHM_AES_GCM &&
            cipher_algorithm != SA_CIPHER_ALGORITHM_RSA_PKCS1V15 &&
            cipher_algorithm != SA_CIPHER_ALGORITHM_RSA_OAEP &&
            cipher_algorithm != SA_CIPHER_ALGORITHM_EC_ELGAMAL &&
            cipher_algorithm != SA_CIPHER_ALGORITHM_CHACHA20 &&
            cipher_algorithm != SA_CIPHER_ALGORITHM_CHACHA20_POLY1305) {
        ERROR("Invalid cipher_algorithm");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (cipher_mode != SA_CIPHER_MODE_DECRYPT &&
            cipher_mode != SA_CIPHER_MODE_ENCRYPT) {
        ERROR("Invalid cipher_mode");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (cipher_algorithm == SA_CIPHER_ALGORITHM_CHACHA20 || cipher_algorithm == SA_CIPHER_ALGORITHM_CHACHA20_POLY1305) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        return SA_STATUS_OPERATION_NOT_SUPPORTED;
#else
        return SA_STATUS_OK;
#endif
    }

    return SA_STATUS_OK;
}

symmetric_context_t* symmetric_create_aes_ecb_encrypt_context(
        const stored_key_t* stored_key,
        bool padded) {

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return NULL;
    }

    const void* key = stored_key_get_key(stored_key);
    if (key == NULL) {
        ERROR("stored_key_get_key failed");
        return NULL;
    }

    size_t key_length = stored_key_get_length(stored_key);
    if (key_length != SYM_128_KEY_SIZE && key_length != SYM_256_KEY_SIZE) {
        ERROR("Invalid key_length");
        return NULL;
    }

    bool status = false;
    symmetric_context_t* context = NULL;
    do {
        context = memory_internal_alloc(sizeof(symmetric_context_t));
        if (context == NULL) {
            ERROR("memory_internal_alloc failed");
            break;
        }

        memory_memset_unoptimizable(context, 0, sizeof(symmetric_context_t));
        context->cipher_algorithm = padded ? SA_CIPHER_ALGORITHM_AES_ECB_PKCS7 : SA_CIPHER_ALGORITHM_AES_ECB;
        context->cipher_mode = SA_CIPHER_MODE_ENCRYPT;
        context->is_gcm = false;
        context->is_chacha = false;

        // Use direct AES API for ECB mode (doesn't support padding in cipher API)
        mbedtls_aes_init(&context->ctx.aes_ctx);

        int ret = mbedtls_aes_setkey_enc(&context->ctx.aes_ctx, key, key_length * 8);
        if (ret != 0) {
            ERROR("mbedtls_aes_setkey_enc failed: -0x%04x", -ret);
            break;
        }

        status = true;
    } while (false);

    if (!status) {
        symmetric_context_free(context);
        context = NULL;
    }

    return context;
}

symmetric_context_t* symmetric_create_aes_cbc_encrypt_context(
        const stored_key_t* stored_key,
        const void* iv,
        size_t iv_length,
        bool padded) {

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return NULL;
    }

    const void* key = stored_key_get_key(stored_key);
    if (key == NULL) {
        ERROR("stored_key_get_key failed");
        return NULL;
    }

    size_t key_length = stored_key_get_length(stored_key);
    if (key_length != SYM_128_KEY_SIZE && key_length != SYM_256_KEY_SIZE) {
        ERROR("Invalid key_length");
        return NULL;
    }

    if (iv == NULL) {
        ERROR("NULL iv");
        return NULL;
    }

    if (iv_length != AES_BLOCK_SIZE) {
        ERROR("Invalid iv_length");
        return NULL;
    }

    bool status = false;
    symmetric_context_t* context = NULL;
    do {
        context = memory_internal_alloc(sizeof(symmetric_context_t));
        if (context == NULL) {
            ERROR("memory_internal_alloc failed");
            break;
        }

        memory_memset_unoptimizable(context, 0, sizeof(symmetric_context_t));
        context->cipher_algorithm = padded ? SA_CIPHER_ALGORITHM_AES_CBC_PKCS7 : SA_CIPHER_ALGORITHM_AES_CBC;
        context->cipher_mode = SA_CIPHER_MODE_ENCRYPT;
        context->is_gcm = false;
        context->is_chacha = false;

        mbedtls_cipher_init(&context->ctx.cipher_ctx);

        // Select cipher type based on key length
        mbedtls_cipher_type_t cipher_type = (key_length == SYM_128_KEY_SIZE) ?
            MBEDTLS_CIPHER_AES_128_CBC : MBEDTLS_CIPHER_AES_256_CBC;

        const mbedtls_cipher_info_t* cipher_info = mbedtls_cipher_info_from_type(cipher_type);
        if (cipher_info == NULL) {
            ERROR("mbedtls_cipher_info_from_type failed");
            break;
        }

        int ret = mbedtls_cipher_setup(&context->ctx.cipher_ctx, cipher_info);
        if (ret != 0) {
            ERROR("mbedtls_cipher_setup failed: -0x%04x", -ret);
            break;
        }

        ret = mbedtls_cipher_setkey(&context->ctx.cipher_ctx, key, key_length * 8, MBEDTLS_ENCRYPT);
        if (ret != 0) {
            ERROR("mbedtls_cipher_setkey failed: -0x%04x", -ret);
            break;
        }

        // Set padding mode
        mbedtls_cipher_padding_t padding = padded ? MBEDTLS_PADDING_PKCS7 : MBEDTLS_PADDING_NONE;
        ret = mbedtls_cipher_set_padding_mode(&context->ctx.cipher_ctx, padding);
        if (ret != 0) {
            ERROR("mbedtls_cipher_set_padding_mode failed: -0x%04x", -ret);
            break;
        }

        // Set IV for CBC mode
        ret = mbedtls_cipher_set_iv(&context->ctx.cipher_ctx, iv, iv_length);
        if (ret != 0) {
            ERROR("mbedtls_cipher_set_iv failed: -0x%04x", -ret);
            break;
        }

        status = true;
    } while (false);

    if (!status) {
        symmetric_context_free(context);
        context = NULL;
    }

    return context;
}

symmetric_context_t* symmetric_create_aes_ctr_encrypt_context(
        const stored_key_t* stored_key,
        const void* counter,
        size_t counter_length) {

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return NULL;
    }

    const void* key = stored_key_get_key(stored_key);
    if (key == NULL) {
        ERROR("stored_key_get_key failed");
        return NULL;
    }

    size_t key_length = stored_key_get_length(stored_key);
    if (key_length != SYM_128_KEY_SIZE && key_length != SYM_256_KEY_SIZE) {
        ERROR("Invalid key_length");
        return NULL;
    }

    if (counter == NULL) {
        ERROR("NULL counter");
        return NULL;
    }

    if (counter_length != AES_BLOCK_SIZE) {
        ERROR("Invalid counter_length");
        return NULL;
    }

    bool status = false;
    symmetric_context_t* context = NULL;
    do {
        context = memory_internal_alloc(sizeof(symmetric_context_t));
        if (context == NULL) {
            ERROR("memory_internal_alloc failed");
            break;
        }

        memory_memset_unoptimizable(context, 0, sizeof(symmetric_context_t));
        context->cipher_algorithm = SA_CIPHER_ALGORITHM_AES_CTR;
        context->cipher_mode = SA_CIPHER_MODE_ENCRYPT;
        context->is_gcm = false;
        context->is_chacha = false;

        mbedtls_cipher_init(&context->ctx.cipher_ctx);

        // Select cipher type based on key length
        mbedtls_cipher_type_t cipher_type = (key_length == SYM_128_KEY_SIZE) ?
            MBEDTLS_CIPHER_AES_128_CTR : MBEDTLS_CIPHER_AES_256_CTR;

        const mbedtls_cipher_info_t* cipher_info = mbedtls_cipher_info_from_type(cipher_type);
        if (cipher_info == NULL) {
            ERROR("mbedtls_cipher_info_from_type failed");
            break;
        }

        int ret = mbedtls_cipher_setup(&context->ctx.cipher_ctx, cipher_info);
        if (ret != 0) {
            ERROR("mbedtls_cipher_setup failed: -0x%04x", -ret);
            break;
        }

        ret = mbedtls_cipher_setkey(&context->ctx.cipher_ctx, key, key_length * 8, MBEDTLS_ENCRYPT);
        if (ret != 0) {
            ERROR("mbedtls_cipher_setkey failed: -0x%04x", -ret);
            break;
        }

        // Set counter/IV for CTR mode
        ret = mbedtls_cipher_set_iv(&context->ctx.cipher_ctx, counter, counter_length);
        if (ret != 0) {
            ERROR("mbedtls_cipher_set_iv failed: -0x%04x", -ret);
            break;
        }

        // CTR mode is a stream cipher - no padding needed

        status = true;
    } while (false);

    if (!status) {
        symmetric_context_free(context);
        context = NULL;
    }

    return context;
}

symmetric_context_t* symmetric_create_aes_gcm_encrypt_context(
        const stored_key_t* stored_key,
        const void* iv,
        size_t iv_length,
        const void* aad,
        size_t aad_length) {

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return NULL;
    }

    const void* key = stored_key_get_key(stored_key);
    if (key == NULL) {
        ERROR("stored_key_get_key failed");
        return NULL;
    }

    size_t key_length = stored_key_get_length(stored_key);
    if (key_length != SYM_128_KEY_SIZE && key_length != SYM_256_KEY_SIZE) {
        ERROR("Invalid key_length");
        return NULL;
    }

    if (iv == NULL) {
        ERROR("NULL iv");
        return NULL;
    }

    if (iv_length != GCM_IV_LENGTH) {
        ERROR("Invalid iv_length");
        return NULL;
    }

    if (aad == NULL && aad_length > 0) {
        ERROR("NULL aad_length");
        return NULL;
    }

    bool status = false;
    symmetric_context_t* context = NULL;
    do {
        context = memory_internal_alloc(sizeof(symmetric_context_t));
        if (context == NULL) {
            ERROR("memory_internal_alloc failed");
            break;
        }

        memory_memset_unoptimizable(context, 0, sizeof(symmetric_context_t));
        context->cipher_algorithm = SA_CIPHER_ALGORITHM_AES_GCM;
        context->cipher_mode = SA_CIPHER_MODE_ENCRYPT;
        context->is_gcm = true;
        context->is_chacha = false;

        mbedtls_gcm_init(&context->ctx.gcm_ctx);

        // Set up GCM with key
        mbedtls_cipher_id_t cipher_id = MBEDTLS_CIPHER_ID_AES;
        int ret = mbedtls_gcm_setkey(&context->ctx.gcm_ctx, cipher_id, key, key_length * 8);
        if (ret != 0) {
            ERROR("mbedtls_gcm_setkey failed: -0x%04x", -ret);
            break;
        }

        // Start GCM encryption with IV (mbedTLS 3.x API)
        ret = mbedtls_gcm_starts(&context->ctx.gcm_ctx, MBEDTLS_GCM_ENCRYPT,
                                  iv, iv_length);
        if (ret != 0) {
            ERROR("mbedtls_gcm_starts failed: -0x%04x", -ret);
            break;
        }

        // Update AAD if present
        if (aad_length > 0) {
            ret = mbedtls_gcm_update_ad(&context->ctx.gcm_ctx, aad, aad_length);
            if (ret != 0) {
                ERROR("mbedtls_gcm_update_ad failed: -0x%04x", -ret);
                break;
            }
        }

        status = true;
    } while (false);

    if (!status) {
        symmetric_context_free(context);
        context = NULL;
    }

    return context;
}

symmetric_context_t* symmetric_create_chacha20_encrypt_context(
        const stored_key_t* stored_key,
        const void* nonce,
        size_t nonce_length,
        const void* counter,
        size_t counter_length) {

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    return NULL;
#else
    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return NULL;
    }

    const void* key = stored_key_get_key(stored_key);
    if (key == NULL) {
        ERROR("stored_key_get_key failed");
        return NULL;
    }

    size_t key_length = stored_key_get_length(stored_key);
    if (key_length != SYM_256_KEY_SIZE) {
        ERROR("Invalid key_length");
        return NULL;
    }

    if (counter == NULL) {
        ERROR("NULL counter");
        return NULL;
    }

    if (counter_length != CHACHA20_COUNTER_LENGTH) {
        ERROR("Invalid counter_length");
        return NULL;
    }

    if (nonce == NULL) {
        ERROR("NULL nonce");
        return NULL;
    }

    if (nonce_length != CHACHA20_NONCE_LENGTH) {
        ERROR("Invalid nonce_length");
        return NULL;
    }

    bool status = false;
    symmetric_context_t* context = NULL;
    do {
        context = memory_internal_alloc(sizeof(symmetric_context_t));
        if (context == NULL) {
            ERROR("memory_internal_alloc failed");
            break;
        }

        context->cipher_algorithm = SA_CIPHER_ALGORITHM_CHACHA20;
        context->cipher_mode = SA_CIPHER_MODE_ENCRYPT;
        context->is_gcm = false;
        context->is_chacha = true;
        context->is_chachapoly = false;

        // Initialize ChaCha20 context
        mbedtls_chacha20_init(&context->ctx.chacha20_ctx);

        // Set the 256-bit key
        int ret = mbedtls_chacha20_setkey(&context->ctx.chacha20_ctx, key);
        if (ret != 0) {
            ERROR("mbedtls_chacha20_setkey failed: -0x%04x", -ret);
            break;
        }

        // Extract 32-bit counter from counter buffer (4 bytes)
        uint32_t initial_counter;
        memcpy(&initial_counter, counter, sizeof(uint32_t));

        // Start ChaCha20 with the nonce (12 bytes) and counter
        ret = mbedtls_chacha20_starts(&context->ctx.chacha20_ctx, nonce, initial_counter);
        if (ret != 0) {
            ERROR("mbedtls_chacha20_starts failed: -0x%04x", -ret);
            break;
        }

        status = true;
    } while (false);

    if (!status) {
        symmetric_context_free(context);
        context = NULL;
    }

    return context;
#endif
}

symmetric_context_t* symmetric_create_chacha20_poly1305_encrypt_context(
        const stored_key_t* stored_key,
        const void* nonce,
        size_t nonce_length,
        const void* aad,
        size_t aad_length) {

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    return NULL;
#else
    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return NULL;
    }

    const void* key = stored_key_get_key(stored_key);
    if (key == NULL) {
        ERROR("stored_key_get_key failed");
        return NULL;
    }

    size_t key_length = stored_key_get_length(stored_key);
    if (key_length != SYM_256_KEY_SIZE) {
        ERROR("Invalid key_length");
        return NULL;
    }

    if (nonce == NULL) {
        ERROR("NULL nonce");
        return NULL;
    }

    if (nonce_length != CHACHA20_NONCE_LENGTH) {
        ERROR("Invalid nonce_length");
        return NULL;
    }

    if (aad == NULL && aad_length > 0) {
        ERROR("NULL aad_length");
        return NULL;
    }

    bool status = false;
    symmetric_context_t* context = NULL;
    do {
        context = memory_internal_alloc(sizeof(symmetric_context_t));
        if (context == NULL) {
            ERROR("memory_internal_alloc failed");
            break;
        }

        context->cipher_algorithm = SA_CIPHER_ALGORITHM_CHACHA20_POLY1305;
        context->cipher_mode = SA_CIPHER_MODE_ENCRYPT;
        context->is_gcm = false;
        context->is_chacha = false;
        context->is_chachapoly = true;

        // Initialize ChaCha20-Poly1305 context
        mbedtls_chachapoly_init(&context->ctx.chachapoly_ctx);

        // Set the 256-bit key
        int ret = mbedtls_chachapoly_setkey(&context->ctx.chachapoly_ctx, key);
        if (ret != 0) {
            ERROR("mbedtls_chachapoly_setkey failed: -0x%04x", -ret);
            break;
        }

        // Start encryption with nonce (12 bytes for ChaCha20-Poly1305)
        ret = mbedtls_chachapoly_starts(&context->ctx.chachapoly_ctx, nonce, MBEDTLS_CHACHAPOLY_ENCRYPT);
        if (ret != 0) {
            ERROR("mbedtls_chachapoly_starts failed: -0x%04x", -ret);
            break;
        }

        // Set AAD (Additional Authenticated Data) if present
        if (aad != NULL && aad_length > 0) {
            ret = mbedtls_chachapoly_update_aad(&context->ctx.chachapoly_ctx, aad, aad_length);
            if (ret != 0) {
                ERROR("mbedtls_chachapoly_update_aad failed: -0x%04x", -ret);
                break;
            }
        }

        status = true;
    } while (false);

    if (!status) {
        symmetric_context_free(context);
        context = NULL;
    }

    return context;
#endif
}

symmetric_context_t* symmetric_create_aes_ecb_decrypt_context(
        const stored_key_t* stored_key,
        bool padded) {
    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return NULL;
    }

    const void* key = stored_key_get_key(stored_key);
    if (key == NULL) {
        ERROR("stored_key_get_key failed");
        return NULL;
    }

    size_t key_length = stored_key_get_length(stored_key);
    if (key_length != SYM_128_KEY_SIZE && key_length != SYM_256_KEY_SIZE) {
        ERROR("Invalid key_length");
        return NULL;
    }

    bool status = false;
    symmetric_context_t* context = NULL;
    do {
        context = memory_internal_alloc(sizeof(symmetric_context_t));
        if (context == NULL) {
            ERROR("memory_internal_alloc failed");
            break;
        }

        memory_memset_unoptimizable(context, 0, sizeof(symmetric_context_t));
        context->cipher_algorithm = padded ? SA_CIPHER_ALGORITHM_AES_ECB_PKCS7 : SA_CIPHER_ALGORITHM_AES_ECB;
        context->cipher_mode = SA_CIPHER_MODE_DECRYPT;
        context->is_gcm = false;
        context->is_chacha = false;

        // Use direct AES API for ECB mode (doesn't support padding in cipher API)
        mbedtls_aes_init(&context->ctx.aes_ctx);

        int ret = mbedtls_aes_setkey_dec(&context->ctx.aes_ctx, key, key_length * 8);
        if (ret != 0) {
            ERROR("mbedtls_aes_setkey_dec failed: -0x%04x", -ret);
            break;
        }

        status = true;
    } while (false);

    if (!status) {
        symmetric_context_free(context);
        context = NULL;
    }

    return context;
}

symmetric_context_t* symmetric_create_aes_cbc_decrypt_context(
        const stored_key_t* stored_key,
        const void* iv,
        size_t iv_length,
        bool padded) {

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return NULL;
    }

    const void* key = stored_key_get_key(stored_key);
    if (key == NULL) {
        ERROR("stored_key_get_key failed");
        return NULL;
    }

    size_t key_length = stored_key_get_length(stored_key);
    if (key_length != SYM_128_KEY_SIZE && key_length != SYM_256_KEY_SIZE) {
        ERROR("Invalid key_length");
        return NULL;
    }

    if (iv == NULL) {
        ERROR("NULL iv");
        return NULL;
    }

    if (iv_length != AES_BLOCK_SIZE) {
        ERROR("Invalid iv_length");
        return NULL;
    }

    bool status = false;
    symmetric_context_t* context = NULL;
    do {
        context = memory_internal_alloc(sizeof(symmetric_context_t));
        if (context == NULL) {
            ERROR("memory_internal_alloc failed");
            break;
        }

        memory_memset_unoptimizable(context, 0, sizeof(symmetric_context_t));
        context->cipher_algorithm = padded ? SA_CIPHER_ALGORITHM_AES_CBC_PKCS7 : SA_CIPHER_ALGORITHM_AES_CBC;
        context->cipher_mode = SA_CIPHER_MODE_DECRYPT;
        context->is_gcm = false;
        context->is_chacha = false;

        mbedtls_cipher_init(&context->ctx.cipher_ctx);

        // Select cipher type based on key length
        mbedtls_cipher_type_t cipher_type = (key_length == SYM_128_KEY_SIZE) ?
            MBEDTLS_CIPHER_AES_128_CBC : MBEDTLS_CIPHER_AES_256_CBC;

        const mbedtls_cipher_info_t* cipher_info = mbedtls_cipher_info_from_type(cipher_type);
        if (cipher_info == NULL) {
            ERROR("mbedtls_cipher_info_from_type failed");
            break;
        }

        int ret = mbedtls_cipher_setup(&context->ctx.cipher_ctx, cipher_info);
        if (ret != 0) {
            ERROR("mbedtls_cipher_setup failed: -0x%04x", -ret);
            break;
        }

        ret = mbedtls_cipher_setkey(&context->ctx.cipher_ctx, key, key_length * 8, MBEDTLS_DECRYPT);
        if (ret != 0) {
            ERROR("mbedtls_cipher_setkey failed: -0x%04x", -ret);
            break;
        }

        // Set padding mode
        mbedtls_cipher_padding_t padding = padded ? MBEDTLS_PADDING_PKCS7 : MBEDTLS_PADDING_NONE;
        ret = mbedtls_cipher_set_padding_mode(&context->ctx.cipher_ctx, padding);
        if (ret != 0) {
            ERROR("mbedtls_cipher_set_padding_mode failed: -0x%04x", -ret);
            break;
        }

        // Set IV for CBC mode
        ret = mbedtls_cipher_set_iv(&context->ctx.cipher_ctx, iv, iv_length);
        if (ret != 0) {
            ERROR("mbedtls_cipher_set_iv failed: -0x%04x", -ret);
            break;
        }

        status = true;
    } while (false);

    if (!status) {
        symmetric_context_free(context);
        context = NULL;
    }

    return context;
}

symmetric_context_t* symmetric_create_aes_ctr_decrypt_context(
        const stored_key_t* stored_key,
        const void* counter,
        size_t counter_length) {

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return NULL;
    }

    const void* key = stored_key_get_key(stored_key);
    if (key == NULL) {
        ERROR("stored_key_get_key failed");
        return NULL;
    }

    size_t key_length = stored_key_get_length(stored_key);
    if (key_length != SYM_128_KEY_SIZE && key_length != SYM_256_KEY_SIZE) {
        ERROR("Invalid key_length");
        return NULL;
    }

    if (counter == NULL) {
        ERROR("NULL counter");
        return NULL;
    }

    if (counter_length != AES_BLOCK_SIZE) {
        ERROR("Invalid counter_length");
        return NULL;
    }

    bool status = false;
    symmetric_context_t* context = NULL;
    do {
        context = memory_internal_alloc(sizeof(symmetric_context_t));
        if (context == NULL) {
            ERROR("memory_internal_alloc failed");
            break;
        }

        memory_memset_unoptimizable(context, 0, sizeof(symmetric_context_t));
        context->cipher_algorithm = SA_CIPHER_ALGORITHM_AES_CTR;
        context->cipher_mode = SA_CIPHER_MODE_DECRYPT;
        context->is_gcm = false;
        context->is_chacha = false;

        mbedtls_cipher_init(&context->ctx.cipher_ctx);

        // Select cipher type based on key length
        mbedtls_cipher_type_t cipher_type = (key_length == SYM_128_KEY_SIZE) ?
            MBEDTLS_CIPHER_AES_128_CTR : MBEDTLS_CIPHER_AES_256_CTR;

        const mbedtls_cipher_info_t* cipher_info = mbedtls_cipher_info_from_type(cipher_type);
        if (cipher_info == NULL) {
            ERROR("mbedtls_cipher_info_from_type failed");
            break;
        }

        int ret = mbedtls_cipher_setup(&context->ctx.cipher_ctx, cipher_info);
        if (ret != 0) {
            ERROR("mbedtls_cipher_setup failed: -0x%04x", -ret);
            break;
        }

        ret = mbedtls_cipher_setkey(&context->ctx.cipher_ctx, key, key_length * 8, MBEDTLS_DECRYPT);
        if (ret != 0) {
            ERROR("mbedtls_cipher_setkey failed: -0x%04x", -ret);
            break;
        }

        // Set counter/IV for CTR mode
        ret = mbedtls_cipher_set_iv(&context->ctx.cipher_ctx, counter, counter_length);
        if (ret != 0) {
            ERROR("mbedtls_cipher_set_iv failed: -0x%04x", -ret);
            break;
        }

        status = true;
    } while (false);

    if (!status) {
        symmetric_context_free(context);
        context = NULL;
    }

    return context;
}

symmetric_context_t* symmetric_create_aes_gcm_decrypt_context(
        const stored_key_t* stored_key,
        const void* iv,
        size_t iv_length,
        const void* aad,
        size_t aad_length) {

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return NULL;
    }

    const void* key = stored_key_get_key(stored_key);
    if (key == NULL) {
        ERROR("stored_key_get_key failed");
        return NULL;
    }

    size_t key_length = stored_key_get_length(stored_key);
    if (key_length != SYM_128_KEY_SIZE && key_length != SYM_256_KEY_SIZE) {
        ERROR("Invalid key_length");
        return NULL;
    }

    if (iv == NULL) {
        ERROR("NULL iv");
        return NULL;
    }

    if (iv_length != GCM_IV_LENGTH) {
        ERROR("Invalid iv_length");
        return NULL;
    }

    if (aad == NULL && aad_length > 0) {
        ERROR("NULL aad");
        return NULL;
    }

    bool status = false;
    symmetric_context_t* context = NULL;
    do {
        context = memory_internal_alloc(sizeof(symmetric_context_t));
        if (context == NULL) {
            ERROR("memory_internal_alloc failed");
            break;
        }

        memory_memset_unoptimizable(context, 0, sizeof(symmetric_context_t));
        context->cipher_algorithm = SA_CIPHER_ALGORITHM_AES_GCM;
        context->cipher_mode = SA_CIPHER_MODE_DECRYPT;
        context->is_gcm = true;
        context->is_chacha = false;

        mbedtls_gcm_init(&context->ctx.gcm_ctx);

        // Set up GCM with key
        mbedtls_cipher_id_t cipher_id = MBEDTLS_CIPHER_ID_AES;
        int ret = mbedtls_gcm_setkey(&context->ctx.gcm_ctx, cipher_id, key, key_length * 8);
        if (ret != 0) {
            ERROR("mbedtls_gcm_setkey failed: -0x%04x", -ret);
            break;
        }

        // Start GCM decryption with IV (mbedTLS 3.x API)
        ret = mbedtls_gcm_starts(&context->ctx.gcm_ctx, MBEDTLS_GCM_DECRYPT,
                                  iv, iv_length);
        if (ret != 0) {
            ERROR("mbedtls_gcm_starts failed: -0x%04x", -ret);
            break;
        }

        // Update AAD if present
        if (aad_length > 0) {
            ret = mbedtls_gcm_update_ad(&context->ctx.gcm_ctx, aad, aad_length);
            if (ret != 0) {
                ERROR("mbedtls_gcm_update_ad failed: -0x%04x", -ret);
                break;
            }
        }

        status = true;
    } while (false);

    if (!status) {
        symmetric_context_free(context);
        context = NULL;
    }

    return context;
}

symmetric_context_t* symmetric_create_chacha20_decrypt_context(
        const stored_key_t* stored_key,
        const void* nonce,
        size_t nonce_length,
        const void* counter,
        size_t counter_length) {

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    return NULL;
#else
    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return NULL;
    }

    const void* key = stored_key_get_key(stored_key);
    if (key == NULL) {
        ERROR("stored_key_get_key failed");
        return NULL;
    }

    size_t key_length = stored_key_get_length(stored_key);
    if (key_length != SYM_256_KEY_SIZE) {
        ERROR("Invalid key_length");
        return NULL;
    }

    if (counter == NULL) {
        ERROR("NULL counter");
        return NULL;
    }

    if (counter_length != CHACHA20_COUNTER_LENGTH) {
        ERROR("Invalid counter_length");
        return NULL;
    }

    if (nonce == NULL) {
        ERROR("NULL nonce");
        return NULL;
    }

    if (nonce_length != CHACHA20_NONCE_LENGTH) {
        ERROR("Invalid nonce_length");
        return NULL;
    }

    bool status = false;
    symmetric_context_t* context = NULL;
    do {
        context = memory_internal_alloc(sizeof(symmetric_context_t));
        if (context == NULL) {
            ERROR("memory_internal_alloc failed");
            break;
        }

        context->cipher_algorithm = SA_CIPHER_ALGORITHM_CHACHA20;
        context->cipher_mode = SA_CIPHER_MODE_DECRYPT;
        context->is_gcm = false;
        context->is_chacha = true;
        context->is_chachapoly = false;

        // Initialize ChaCha20 context
        mbedtls_chacha20_init(&context->ctx.chacha20_ctx);

        // Set the 256-bit key
        int ret = mbedtls_chacha20_setkey(&context->ctx.chacha20_ctx, key);
        if (ret != 0) {
            ERROR("mbedtls_chacha20_setkey failed: -0x%04x", -ret);
            break;
        }

        // Extract 32-bit counter from counter buffer (4 bytes)
        uint32_t initial_counter;
        memcpy(&initial_counter, counter, sizeof(uint32_t));

        // Start ChaCha20 with the nonce (12 bytes) and counter
        // Note: ChaCha20 is a stream cipher, same operation for encrypt/decrypt
        ret = mbedtls_chacha20_starts(&context->ctx.chacha20_ctx, nonce, initial_counter);
        if (ret != 0) {
            ERROR("mbedtls_chacha20_starts failed: -0x%04x", -ret);
            break;
        }

        status = true;
    } while (false);

    if (!status) {
        symmetric_context_free(context);
        context = NULL;
    }

    return context;
#endif
}

symmetric_context_t* symmetric_create_chacha20_poly1305_decrypt_context(
        const stored_key_t* stored_key,
        const void* nonce,
        size_t nonce_length,
        const void* aad,
        size_t aad_length) {

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    return NULL;
#else
    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return NULL;
    }

    const void* key = stored_key_get_key(stored_key);
    if (key == NULL) {
        ERROR("stored_key_get_key failed");
        return NULL;
    }

    size_t key_length = stored_key_get_length(stored_key);
    if (key_length != SYM_256_KEY_SIZE) {
        ERROR("Invalid key_length");
        return NULL;
    }

    if (nonce == NULL) {
        ERROR("NULL nonce");
        return NULL;
    }

    if (nonce_length != CHACHA20_NONCE_LENGTH) {
        ERROR("Invalid nonce_length");
        return NULL;
    }

    if (aad == NULL && aad_length > 0) {
        ERROR("NULL aad");
        return NULL;
    }

    bool status = false;
    symmetric_context_t* context = NULL;
    do {
        context = memory_internal_alloc(sizeof(symmetric_context_t));
        if (context == NULL) {
            ERROR("memory_internal_alloc failed");
            break;
        }

        context->cipher_algorithm = SA_CIPHER_ALGORITHM_CHACHA20_POLY1305;
        context->cipher_mode = SA_CIPHER_MODE_DECRYPT;
        context->is_gcm = false;
        context->is_chacha = false;
        context->is_chachapoly = true;

        // Initialize ChaCha20-Poly1305 context
        mbedtls_chachapoly_init(&context->ctx.chachapoly_ctx);

        // Set the 256-bit key
        int ret = mbedtls_chachapoly_setkey(&context->ctx.chachapoly_ctx, key);
        if (ret != 0) {
            ERROR("mbedtls_chachapoly_setkey failed: -0x%04x", -ret);
            break;
        }

        // Start decryption with nonce (12 bytes for ChaCha20-Poly1305)
        ret = mbedtls_chachapoly_starts(&context->ctx.chachapoly_ctx, nonce, MBEDTLS_CHACHAPOLY_DECRYPT);
        if (ret != 0) {
            ERROR("mbedtls_chachapoly_starts failed: -0x%04x", -ret);
            break;
        }

        // Set AAD (Additional Authenticated Data) if present
        if (aad != NULL && aad_length > 0) {
            ret = mbedtls_chachapoly_update_aad(&context->ctx.chachapoly_ctx, aad, aad_length);
            if (ret != 0) {
                ERROR("mbedtls_chachapoly_update_aad failed: -0x%04x", -ret);
                break;
            }
        }

        status = true;
    } while (false);

    if (!status) {
        symmetric_context_free(context);
        context = NULL;
    }

    return context;
#endif
}

sa_status symmetric_context_encrypt(
        symmetric_context_t* context,
        void* out,
        size_t* out_length,
        const void* in,
        size_t in_length) {

    if (context == NULL) {
        ERROR("NULL context");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (context->cipher_mode != SA_CIPHER_MODE_ENCRYPT) {
        ERROR("Invalid cipher mode");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (out == NULL) {
        ERROR("NULL out");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (in == NULL) {
        ERROR("NULL in");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (context->cipher_algorithm != SA_CIPHER_ALGORITHM_AES_CTR &&
            context->cipher_algorithm != SA_CIPHER_ALGORITHM_AES_GCM &&
            context->cipher_algorithm != SA_CIPHER_ALGORITHM_CHACHA20 &&
            context->cipher_algorithm != SA_CIPHER_ALGORITHM_CHACHA20_POLY1305) {
        if (in_length % AES_BLOCK_SIZE != 0) {
            ERROR("Invalid in_length");
            return SA_STATUS_INVALID_PARAMETER;
        }
    }

    if (context->is_chachapoly) {
        // ChaCha20-Poly1305 uses mbedTLS chachapoly update
        int ret = mbedtls_chachapoly_update(&context->ctx.chachapoly_ctx, in_length, in, out);
        if (ret != 0) {
            ERROR("mbedtls_chachapoly_update failed: -0x%04x", -ret);
            return SA_STATUS_INTERNAL_ERROR;
        }
        *out_length = in_length;  // ChaCha20-Poly1305 is a stream cipher, output size = input size
    } else if (context->is_chacha) {
        // ChaCha20 uses mbedTLS chacha20 update
        int ret = mbedtls_chacha20_update(&context->ctx.chacha20_ctx, in_length, in, out);
        if (ret != 0) {
            ERROR("mbedtls_chacha20_update failed: -0x%04x", -ret);
            return SA_STATUS_INTERNAL_ERROR;
        }
        *out_length = in_length;  // ChaCha20 is a stream cipher, output size = input size
    } else if (context->is_gcm) {
        // AES-GCM uses mbedTLS GCM update (mbedTLS 3.x API)
        size_t olen;
        int ret = mbedtls_gcm_update(&context->ctx.gcm_ctx, in, in_length, out, in_length, &olen);
        if (ret != 0) {
            ERROR("mbedtls_gcm_update failed: -0x%04x", -ret);
            return SA_STATUS_INTERNAL_ERROR;
        }
        *out_length = olen;  // Use actual output length from mbedTLS
    } else if (context->cipher_algorithm == SA_CIPHER_ALGORITHM_AES_ECB ||
               context->cipher_algorithm == SA_CIPHER_ALGORITHM_AES_ECB_PKCS7) {
        // AES-ECB uses direct AES API - process block by block
        *out_length = 0;
        for (size_t i = 0; i < in_length; i += AES_BLOCK_SIZE) {
            int ret = mbedtls_aes_crypt_ecb(&context->ctx.aes_ctx, MBEDTLS_AES_ENCRYPT,
                                             (const unsigned char*)in + i,
                                             (unsigned char*)out + i);
            if (ret != 0) {
                ERROR("mbedtls_aes_crypt_ecb failed: -0x%04x", -ret);
                return SA_STATUS_INTERNAL_ERROR;
            }
            *out_length += AES_BLOCK_SIZE;
        }
    } else {
        // AES-CBC/CTR uses mbedTLS cipher update
        int ret = mbedtls_cipher_update(&context->ctx.cipher_ctx, in, in_length, out, out_length);
        if (ret != 0) {
            ERROR("mbedtls_cipher_update failed: -0x%04x", -ret);
            return SA_STATUS_INTERNAL_ERROR;
        }
    }

    return SA_STATUS_OK;
}

sa_status symmetric_context_encrypt_last(
        symmetric_context_t* context,
        void* out,
        size_t* out_length,
        const void* in,
        size_t in_length) {

    if (context == NULL) {
        ERROR("NULL context");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (context->cipher_mode != SA_CIPHER_MODE_ENCRYPT) {
        ERROR("Invalid cipher mode");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (context->cipher_algorithm == SA_CIPHER_ALGORITHM_AES_ECB ||
            context->cipher_algorithm == SA_CIPHER_ALGORITHM_AES_CBC) {
        ERROR("Invalid cipher algorithm");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (out_length == NULL) {
        ERROR("NULL out_length");
        return SA_STATUS_NULL_PARAMETER;
    }

    if ((context->cipher_algorithm == SA_CIPHER_ALGORITHM_AES_ECB_PKCS7 ||
                context->cipher_algorithm == SA_CIPHER_ALGORITHM_AES_CBC_PKCS7) &&
            in_length > AES_BLOCK_SIZE) {
        ERROR("Invalid in_length");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (out == NULL) {
        *out_length = PADDED_SIZE(in_length);
        return SA_STATUS_OK;
    }

    if (in == NULL) {
        ERROR("NULL in");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (context->is_chachapoly) {
        // ChaCha20-Poly1305 uses mbedTLS chachapoly finish to get the tag
        // First, process any remaining data
        int ret;
        if (in_length > 0) {
            ret = mbedtls_chachapoly_update(&context->ctx.chachapoly_ctx, in_length, in, out);
            if (ret != 0) {
                ERROR("mbedtls_chachapoly_update failed: -0x%04x", -ret);
                return SA_STATUS_INTERNAL_ERROR;
            }
        }

        // Finalize and get the authentication tag
        ret = mbedtls_chachapoly_finish(&context->ctx.chachapoly_ctx, context->chachapoly_tag);
        if (ret != 0) {
            ERROR("mbedtls_chachapoly_finish failed: -0x%04x", -ret);
            return SA_STATUS_INTERNAL_ERROR;
        }

        context->chachapoly_tag_length = CHACHA20_TAG_LENGTH;
        *out_length = in_length;
    } else if (context->is_chacha) {
        // ChaCha20 (without Poly1305) - just process the remaining data
        if (in_length > 0) {
            int ret = mbedtls_chacha20_update(&context->ctx.chacha20_ctx, in_length, in, out);
            if (ret != 0) {
                ERROR("mbedtls_chacha20_update failed: -0x%04x", -ret);
                return SA_STATUS_INTERNAL_ERROR;
            }
        }
        *out_length = in_length;
    } else if (context->is_gcm) {
        // AES-GCM doesn't use "last" - just finish
        *out_length = 0;
    } else if (context->cipher_algorithm == SA_CIPHER_ALGORITHM_AES_ECB_PKCS7) {
        // AES-ECB with PKCS7 padding - manual padding with direct AES API
        unsigned char padded_block[AES_BLOCK_SIZE];

        // Copy input to padded block
        if (in_length > 0) {
            memcpy(padded_block, in, in_length);
        }

        // Add PKCS7 padding
        unsigned char padding_value = AES_BLOCK_SIZE - in_length;
        for (size_t i = in_length; i < AES_BLOCK_SIZE; i++) {
            padded_block[i] = padding_value;
        }

        // Encrypt the padded block
        int ret = mbedtls_aes_crypt_ecb(&context->ctx.aes_ctx, MBEDTLS_AES_ENCRYPT,
                                         padded_block, (unsigned char*)out);
        if (ret != 0) {
            ERROR("mbedtls_aes_crypt_ecb failed: -0x%04x", -ret);
            return SA_STATUS_INTERNAL_ERROR;
        }

        *out_length = AES_BLOCK_SIZE;
    } else {
        // AES-CBC with PKCS7 padding - use mbedTLS cipher finish
        size_t update_length = 0;
        int ret = mbedtls_cipher_update(&context->ctx.cipher_ctx, in, in_length, out, &update_length);
        if (ret != 0) {
            ERROR("mbedtls_cipher_update failed: -0x%04x", -ret);
            return SA_STATUS_INTERNAL_ERROR;
        }

        size_t final_length = 0;
        ret = mbedtls_cipher_finish(&context->ctx.cipher_ctx, out + update_length, &final_length);
        if (ret != 0) {
            ERROR("mbedtls_cipher_finish failed: -0x%04x", -ret);
            return SA_STATUS_INTERNAL_ERROR;
        }

        *out_length = update_length + final_length;
    }

    return SA_STATUS_OK;
}

sa_status symmetric_context_decrypt(
        symmetric_context_t* context,
        void* out,
        size_t* out_length,
        const void* in,
        size_t in_length) {

    if (context == NULL) {
        ERROR("NULL context");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (context->cipher_mode != SA_CIPHER_MODE_DECRYPT) {
        ERROR("Invalid cipher mode");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (out == NULL) {
        ERROR("NULL out");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (in == NULL) {
        ERROR("NULL in");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (context->cipher_algorithm != SA_CIPHER_ALGORITHM_AES_CTR &&
            context->cipher_algorithm != SA_CIPHER_ALGORITHM_AES_GCM &&
            context->cipher_algorithm != SA_CIPHER_ALGORITHM_CHACHA20 &&
            context->cipher_algorithm != SA_CIPHER_ALGORITHM_CHACHA20_POLY1305) {
        if (in_length % AES_BLOCK_SIZE != 0) {
            ERROR("Invalid in_length");
            return SA_STATUS_INVALID_PARAMETER;
        }
    }

    if (context->is_chachapoly) {
        // ChaCha20-Poly1305 uses mbedTLS chachapoly update
        int ret = mbedtls_chachapoly_update(&context->ctx.chachapoly_ctx, in_length, in, out);
        if (ret != 0) {
            ERROR("mbedtls_chachapoly_update failed: -0x%04x", -ret);
            return SA_STATUS_INTERNAL_ERROR;
        }
        *out_length = in_length;  // ChaCha20-Poly1305 is a stream cipher, output size = input size
    } else if (context->is_chacha) {
        // ChaCha20 uses mbedTLS chacha20 update
        int ret = mbedtls_chacha20_update(&context->ctx.chacha20_ctx, in_length, in, out);
        if (ret != 0) {
            ERROR("mbedtls_chacha20_update failed: -0x%04x", -ret);
            return SA_STATUS_INTERNAL_ERROR;
        }
        *out_length = in_length;  // ChaCha20 is a stream cipher, output size = input size
    } else if (context->is_gcm) {
        // AES-GCM uses mbedTLS GCM update (mbedTLS 3.x API)
        size_t olen;
        int ret = mbedtls_gcm_update(&context->ctx.gcm_ctx, in, in_length, out, in_length, &olen);
        if (ret != 0) {
            ERROR("mbedtls_gcm_update failed: -0x%04x", -ret);
            return SA_STATUS_INTERNAL_ERROR;
        }
        *out_length = olen;  // Use actual output length from mbedTLS
    } else if (context->cipher_algorithm == SA_CIPHER_ALGORITHM_AES_ECB ||
               context->cipher_algorithm == SA_CIPHER_ALGORITHM_AES_ECB_PKCS7) {
        // AES-ECB uses direct AES API - process block by block
        *out_length = 0;
        for (size_t i = 0; i < in_length; i += AES_BLOCK_SIZE) {
            int ret = mbedtls_aes_crypt_ecb(&context->ctx.aes_ctx, MBEDTLS_AES_DECRYPT,
                                             (const unsigned char*)in + i,
                                             (unsigned char*)out + i);
            if (ret != 0) {
                ERROR("mbedtls_aes_crypt_ecb failed: -0x%04x", -ret);
                return SA_STATUS_INTERNAL_ERROR;
            }
            *out_length += AES_BLOCK_SIZE;
        }
    } else {
        // AES-CBC/CTR uses mbedTLS cipher update
        int ret = mbedtls_cipher_update(&context->ctx.cipher_ctx, in, in_length, out, out_length);
        if (ret != 0) {
            ERROR("mbedtls_cipher_update failed: -0x%04x", -ret);
            return SA_STATUS_INTERNAL_ERROR;
        }
    }

    return SA_STATUS_OK;
}

sa_status symmetric_context_decrypt_last(
        symmetric_context_t* context,
        void* out,
        size_t* out_length,
        const void* in,
        size_t in_length) {

    if (context == NULL) {
        ERROR("NULL context");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (context->cipher_mode != SA_CIPHER_MODE_DECRYPT) {
        ERROR("Invalid cipher mode");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (context->cipher_algorithm == SA_CIPHER_ALGORITHM_AES_ECB ||
            context->cipher_algorithm == SA_CIPHER_ALGORITHM_AES_CBC) {
        ERROR("Invalid cipher algorithm");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (out_length == NULL) {
        ERROR("NULL out_length");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (context->cipher_algorithm != SA_CIPHER_ALGORITHM_CHACHA20_POLY1305 && in_length > AES_BLOCK_SIZE) {
        ERROR("Invalid in_length");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (out == NULL) {
        *out_length = in_length;
        return SA_STATUS_OK;
    }

    if (in == NULL) {
        ERROR("NULL in");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (context->is_chachapoly) {
        // ChaCha20-Poly1305 uses mbedTLS chachapoly finish with tag verification
        // First, process any remaining data
        if (in_length > 0) {
            int ret = mbedtls_chachapoly_update(&context->ctx.chachapoly_ctx, in_length, in, out);
            if (ret != 0) {
                ERROR("mbedtls_chachapoly_update failed: -0x%04x", -ret);
                return SA_STATUS_INTERNAL_ERROR;
            }
        }

        // Finalize and verify the authentication tag
        unsigned char computed_tag[CHACHA20_TAG_LENGTH];
        int ret = mbedtls_chachapoly_finish(&context->ctx.chachapoly_ctx, computed_tag);
        if (ret != 0) {
            ERROR("mbedtls_chachapoly_finish failed: -0x%04x", -ret);
            return SA_STATUS_INTERNAL_ERROR;
        }

        // Verify the tag matches what was set
        if (memcmp(computed_tag, context->chachapoly_tag, context->chachapoly_tag_length) != 0) {
            ERROR("ChaCha20-Poly1305 tag verification failed");
            return SA_STATUS_VERIFICATION_FAILED;
        }

        *out_length = in_length;
    } else if (context->is_chacha) {
        // ChaCha20 (without Poly1305) - just process the remaining data
        if (in_length > 0) {
            int ret = mbedtls_chacha20_update(&context->ctx.chacha20_ctx, in_length, in, out);
            if (ret != 0) {
                ERROR("mbedtls_chacha20_update failed: -0x%04x", -ret);
                return SA_STATUS_INTERNAL_ERROR;
            }
        }
        *out_length = in_length;
    } else if (context->is_gcm) {
        // AES-GCM - finish decryption with tag verification (mbedTLS 3.x API)
        // First process any remaining input data
        size_t olen = 0;
        if (in != NULL && in_length > 0) {
            int ret = mbedtls_gcm_update(&context->ctx.gcm_ctx, in, in_length, out, in_length, &olen);
            if (ret != 0) {
                ERROR("mbedtls_gcm_update failed: -0x%04x", -ret);
                return SA_STATUS_INTERNAL_ERROR;
            }
            *out_length = olen;
        } else {
            *out_length = 0;
        }

        // Now finish and verify the tag (mbedTLS 3.x API)
        unsigned char computed_tag[16];  // GCM tag max size
        size_t olen2;
        int ret = mbedtls_gcm_finish(&context->ctx.gcm_ctx, NULL, 0, &olen2, computed_tag, context->gcm_tag_length);
        if (ret != 0) {
            ERROR("mbedtls_gcm_finish failed: -0x%04x", -ret);
            return SA_STATUS_INTERNAL_ERROR;
        }

        // Verify the tag
        if (memcmp(computed_tag, context->gcm_tag, context->gcm_tag_length) != 0) {
            ERROR("GCM tag verification failed");
            return SA_STATUS_VERIFICATION_FAILED;
        }

        *out_length = in_length;
    } else if (context->cipher_algorithm == SA_CIPHER_ALGORITHM_AES_ECB_PKCS7) {
        // AES-ECB with PKCS7 padding - decrypt and remove padding manually
        if (in_length != AES_BLOCK_SIZE) {
            ERROR("Invalid in_length for ECB PKCS7");
            return SA_STATUS_INVALID_PARAMETER;
        }

        unsigned char decrypted_block[AES_BLOCK_SIZE];
        int ret = mbedtls_aes_crypt_ecb(&context->ctx.aes_ctx, MBEDTLS_AES_DECRYPT,
                                         (const unsigned char*)in, decrypted_block);
        if (ret != 0) {
            ERROR("mbedtls_aes_crypt_ecb failed: -0x%04x", -ret);
            return SA_STATUS_INTERNAL_ERROR;
        }

        // Verify and remove PKCS7 padding
        unsigned char padding_value = decrypted_block[AES_BLOCK_SIZE - 1];
        if (padding_value == 0 || padding_value > AES_BLOCK_SIZE) {
            ERROR("Invalid PKCS7 padding value");
            return SA_STATUS_VERIFICATION_FAILED;
        }

        // Verify all padding bytes are correct
        for (size_t i = AES_BLOCK_SIZE - padding_value; i < AES_BLOCK_SIZE; i++) {
            if (decrypted_block[i] != padding_value) {
                ERROR("Invalid PKCS7 padding");
                return SA_STATUS_VERIFICATION_FAILED;
            }
        }

        // Copy unpadded data to output
        size_t unpadded_length = AES_BLOCK_SIZE - padding_value;
        memcpy(out, decrypted_block, unpadded_length);
        *out_length = unpadded_length;
    } else {
        // AES-CBC with PKCS7 padding - use mbedTLS cipher finish
        size_t update_length = 0;
        int ret = mbedtls_cipher_update(&context->ctx.cipher_ctx, in, in_length, out, &update_length);
        if (ret != 0) {
            ERROR("mbedtls_cipher_update failed: -0x%04x", -ret);
            return SA_STATUS_INTERNAL_ERROR;
        }

        size_t final_length = 0;
        ret = mbedtls_cipher_finish(&context->ctx.cipher_ctx, out + update_length, &final_length);
        if (ret != 0) {
            ERROR("mbedtls_cipher_finish failed: -0x%04x", -ret);
            return SA_STATUS_INTERNAL_ERROR;
        }

        *out_length = update_length + final_length;
    }

    return SA_STATUS_OK;
}

sa_status symmetric_context_set_iv(
        const symmetric_context_t* context,
        const void* iv,
        size_t iv_length) {

    if (context == NULL) {
        ERROR("NULL context");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (iv == NULL) {
        ERROR("NULL iv");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (context->cipher_algorithm == SA_CIPHER_ALGORITHM_AES_CBC ||
            context->cipher_algorithm == SA_CIPHER_ALGORITHM_AES_CBC_PKCS7 ||
            context->cipher_algorithm == SA_CIPHER_ALGORITHM_AES_CTR) {
        if (iv_length != AES_BLOCK_SIZE) {
            ERROR("Invalid iv_length");
            return SA_STATUS_INVALID_PARAMETER;
        }

        // AES-CBC/CTR uses mbedTLS cipher API - set IV
        // Note: Cast away const since mbedTLS API requires non-const, but operation is logically const from caller perspective
        symmetric_context_t* mutable_context = (symmetric_context_t*)context;
        int ret = mbedtls_cipher_set_iv(&mutable_context->ctx.cipher_ctx, iv, iv_length);
        if (ret != 0) {
            ERROR("mbedtls_cipher_set_iv failed: -0x%04x", -ret);
            return SA_STATUS_INTERNAL_ERROR;
        }
    } else {
        ERROR("Invalid cipher algorithm");
        return SA_STATUS_INVALID_PARAMETER;
    }

    return SA_STATUS_OK;
}

sa_status symmetric_context_get_tag(
        const symmetric_context_t* context,
        void* tag,
        size_t tag_length) {

    if (context == NULL) {
        ERROR("NULL context");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (context->cipher_algorithm != SA_CIPHER_ALGORITHM_AES_GCM &&
            context->cipher_algorithm != SA_CIPHER_ALGORITHM_CHACHA20_POLY1305) {
        ERROR("Invalid cipher algorithm");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (context->cipher_mode != SA_CIPHER_MODE_ENCRYPT) {
        ERROR("Invalid cipher mode");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (tag == NULL) {
        ERROR("NULL tag");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (context->cipher_algorithm == SA_CIPHER_ALGORITHM_AES_GCM && tag_length > MAX_GCM_TAG_LENGTH) {
        ERROR("Invalid tag_length");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (context->cipher_algorithm == SA_CIPHER_ALGORITHM_CHACHA20_POLY1305 && tag_length != CHACHA20_TAG_LENGTH) {
        ERROR("Invalid tag_length");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (context->cipher_algorithm == SA_CIPHER_ALGORITHM_AES_GCM) {
        // AES-GCM uses mbedTLS - get tag via mbedtls_gcm_finish (mbedTLS 3.x API)
        // Note: Cast away const since mbedTLS API requires non-const, but operation is logically const from caller perspective
        uint8_t local_tag[16];  // GCM tag max size
        symmetric_context_t* mutable_context = (symmetric_context_t*)context;
        size_t olen;
        int ret = mbedtls_gcm_finish(&mutable_context->ctx.gcm_ctx, NULL, 0, &olen, local_tag, tag_length);
        if (ret != 0) {
            ERROR("mbedtls_gcm_finish failed: -0x%04x", -ret);
            return SA_STATUS_INTERNAL_ERROR;
        }

        memcpy(tag, local_tag, tag_length);
    } else {
        // ChaCha20-Poly1305 uses mbedTLS - tag was generated in encrypt_last
        if (context->chachapoly_tag_length != tag_length) {
            ERROR("Tag length mismatch");
            return SA_STATUS_INVALID_PARAMETER;
        }

        memcpy(tag, context->chachapoly_tag, tag_length);
    }

    return SA_STATUS_OK;
}

sa_status symmetric_context_set_tag(
        symmetric_context_t* context,
        const void* tag,
        size_t tag_length) {

    if (context == NULL) {
        ERROR("NULL context");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (context->cipher_algorithm != SA_CIPHER_ALGORITHM_AES_GCM &&
            context->cipher_algorithm != SA_CIPHER_ALGORITHM_CHACHA20_POLY1305) {
        ERROR("Invalid cipher algorithm");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (context->cipher_mode != SA_CIPHER_MODE_DECRYPT) {
        ERROR("Invalid cipher mode");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (tag == NULL) {
        ERROR("NULL tag");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (context->cipher_algorithm == SA_CIPHER_ALGORITHM_AES_GCM && tag_length > MAX_GCM_TAG_LENGTH) {
        ERROR("Invalid tag_length");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (context->cipher_algorithm == SA_CIPHER_ALGORITHM_CHACHA20_POLY1305 && tag_length != CHACHA20_TAG_LENGTH) {
        ERROR("Invalid tag_length");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (context->cipher_algorithm == SA_CIPHER_ALGORITHM_AES_GCM) {
        // AES-GCM uses mbedTLS - store tag for verification in finish()
        memcpy(context->gcm_tag, tag, tag_length);
        context->gcm_tag_length = tag_length;
    } else {
        // ChaCha20-Poly1305 uses mbedTLS - store tag for verification in decrypt_last
        memcpy(context->chachapoly_tag, tag, tag_length);
        context->chachapoly_tag_length = tag_length;
    }

    return SA_STATUS_OK;
}

void symmetric_context_free(symmetric_context_t* context) {
    if (context == NULL) {
        return;
    }

    if (context->is_chachapoly) {
        // ChaCha20-Poly1305 uses mbedTLS chachapoly context
        mbedtls_chachapoly_free(&context->ctx.chachapoly_ctx);
    } else if (context->is_chacha) {
        // ChaCha20 uses mbedTLS chacha20 context
        mbedtls_chacha20_free(&context->ctx.chacha20_ctx);
    } else if (context->is_gcm) {
        // AES-GCM uses mbedTLS GCM context
        mbedtls_gcm_free(&context->ctx.gcm_ctx);
    } else if (context->cipher_algorithm == SA_CIPHER_ALGORITHM_AES_ECB ||
               context->cipher_algorithm == SA_CIPHER_ALGORITHM_AES_ECB_PKCS7) {
        // AES-ECB uses direct AES context
        mbedtls_aes_free(&context->ctx.aes_ctx);
    } else {
        // AES-CBC/CTR uses mbedTLS cipher context
        mbedtls_cipher_free(&context->ctx.cipher_ctx);
    }

    memory_internal_free(context);
}
