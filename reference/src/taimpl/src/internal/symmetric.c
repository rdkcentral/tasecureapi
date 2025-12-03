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
#define MBEDTLS_ALLOW_PRIVATE_ACCESS 1
#include "mbedtls_header.h"
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
    /* Store IV and AAD for single-shot GCM operations (if used) */
    uint8_t gcm_iv[16];
    size_t gcm_iv_length;
    uint8_t* gcm_aad;
    size_t gcm_aad_length;
    uint8_t chachapoly_tag[CHACHA20_TAG_LENGTH]; // Store ChaCha20-Poly1305 tag for verification
    size_t chachapoly_tag_length;
    // For PKCS7 decryption: buffer the last block during process() calls
    uint8_t pkcs7_buffer[AES_BLOCK_SIZE];
    size_t pkcs7_buffer_length;
    bool gcm_first_update_logged; // log the first GCM update only once
    uint8_t gcm_buffer[16];       // Buffer for GCM partial blocks
    size_t gcm_buffer_length;
};

// Helper: log up to 64 bytes as hex using DEBUG macro
static void log_hex_debug(const char* label, const void* data, size_t len) {
    if (data == NULL || len == 0) {
        ERROR("%s: <empty>", label);
        return;
    }

    const uint8_t* bytes = (const uint8_t*) data;
    size_t cap = (len > 64) ? 64 : len; // limit output
    char buf[3 * 64 + 1];
    size_t pos = 0;
    for (size_t i = 0; i < cap; i++) {
        int written = snprintf(&buf[pos], sizeof(buf) - pos, "%02x", bytes[i]);
        if (written < 0) break;
        pos += (size_t) written;
    }
    buf[pos] = '\0';
    DEBUG("%s: %s%s", label, buf, (len > cap) ? "..." : "");
}

/* Compute initial GCM counter J0 for 12-byte IV: J0 = IV || 0x00000001 (big-endian) */
static void compute_gcm_j0(const uint8_t iv[12], uint8_t j0[16]) {
    // Copy IV (12 bytes)
    memcpy(j0, iv, 12);
    // Append 0x00000001 in big-endian
    j0[12] = 0x00;
    j0[13] = 0x00;
    j0[14] = 0x00;
    j0[15] = 0x01;
}

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

    // ChaCha20 and ChaCha20-Poly1305 are supported with mbedTLS
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
    context->gcm_first_update_logged = false;
        context->gcm_buffer_length = 0;
        memset(context->gcm_buffer, 0, 16);

        mbedtls_gcm_init(&context->ctx.gcm_ctx);

        // Set up GCM with key
        mbedtls_cipher_id_t cipher_id = MBEDTLS_CIPHER_ID_AES;
        int ret = mbedtls_gcm_setkey(&context->ctx.gcm_ctx, cipher_id, key, key_length * 8);
        if (ret != 0) {
            ERROR("mbedtls_gcm_setkey failed: -0x%04x", -ret);
            break;
        }

        // Store IV and AAD for potential single-shot GCM operations
        if (iv_length <= sizeof(context->gcm_iv)) {
            memcpy(context->gcm_iv, iv, iv_length);
            context->gcm_iv_length = iv_length;
        } else {
            ERROR("IV length too large to store");
            break;
        }
        if (aad != NULL && aad_length > 0) {
            context->gcm_aad = memory_internal_alloc(aad_length);
            if (context->gcm_aad == NULL) {
                ERROR("memory_internal_alloc failed");
                break;
            }
            memcpy(context->gcm_aad, aad, aad_length);
            context->gcm_aad_length = aad_length;
        } else {
            context->gcm_aad = NULL;
            context->gcm_aad_length = 0;
        }

        // Start GCM encryption with IV and AAD (mbedTLS 2.16.10 API takes 6 params)
        {
            int r = mbedtls_gcm_starts(&context->ctx.gcm_ctx, MBEDTLS_GCM_ENCRYPT,
                                      (const unsigned char*)iv, iv_length,
                                      (const unsigned char*)aad, aad_length);
            if (r != 0) {
                ERROR("mbedtls_gcm_starts failed: -0x%04x", -r);
                break;
            }
        }

        // Log IV and AAD for debugging (limited length)
        DEBUG("GCM encrypt starts: iv_length=%zu aad_length=%zu", iv_length, aad_length);
        log_hex_debug("GCM IV", iv, iv_length);
        if (aad != NULL && aad_length > 0) log_hex_debug("GCM AAD", aad, aad_length);
        // Compute and log initial counter (J0) for 12-byte IV
        if (iv_length == 12) {
            uint8_t j0[16];
            compute_gcm_j0((const uint8_t*) iv, j0);
            log_hex_debug("GCM J0", j0, sizeof(j0));
            /* Diagnostic: compute AES-ECB encryptions of J0 and J0+1 using mbedTLS AES API */
            {
                /* Also derive ECTR by using a temporary cipher context (public API) to avoid
                 * accessing internal mbedtls_gcm_context fields directly. This mirrors what
                 * mbedtls_gcm would do: AES-ECB encrypt the counter block to produce the
                 * ECTR (keystream) block. */
                uint8_t ectr[16];
                size_t olen = 0;
                mbedtls_cipher_context_t tmp_cipher;
                mbedtls_cipher_init(&tmp_cipher);
                do {
                    mbedtls_cipher_type_t cipher_type = (key_length == SYM_128_KEY_SIZE) ?
                        MBEDTLS_CIPHER_AES_128_ECB : MBEDTLS_CIPHER_AES_256_ECB;
                    const mbedtls_cipher_info_t* cipher_info = mbedtls_cipher_info_from_type(cipher_type);
                    if (cipher_info == NULL) {
                        ERROR("mbedtls_cipher_info_from_type failed for diagnostic ECTR");
                        break;
                    }
                    int r = mbedtls_cipher_setup(&tmp_cipher, cipher_info);
                    if (r != 0) {
                        ERROR("mbedtls_cipher_setup failed for diagnostic ECTR: -0x%04x", -r);
                        break;
                    }
                    r = mbedtls_cipher_setkey(&tmp_cipher, key, key_length * 8, MBEDTLS_ENCRYPT);
                    if (r != 0) {
                        ERROR("mbedtls_cipher_setkey failed for diagnostic ECTR: -0x%04x", -r);
                        break;
                    }
                    /* ECB mode: encrypt the single 16-byte J0 block to derive ECTR(J0) */
                    int r2 = mbedtls_cipher_update(&tmp_cipher, j0, 16, ectr, &olen);
                    if (r2 == 0 && olen == 16) {
                        log_hex_debug("GCM TA ECTR(J0) via cipher API", ectr, olen);
                    } else if (r2 != 0) {
                        ERROR("mbedtls_cipher_update failed for diagnostic ECTR: -0x%04x", -r2);
                    }
                } while (false);
                mbedtls_cipher_free(&tmp_cipher);

                uint8_t j0_inc[16];
                memcpy(j0_inc, j0, 16);
                for (int i = 15; i >= 12; i--) { if (++j0_inc[i] != 0) break; }
                uint8_t e_j0[16];
                uint8_t e_j0_inc[16];
                mbedtls_aes_context aes_ctx;
                mbedtls_aes_init(&aes_ctx);
                int ret2 = mbedtls_aes_setkey_enc(&aes_ctx, key, key_length * 8);
                if (ret2 == 0) {
                    ret2 = mbedtls_aes_crypt_ecb(&aes_ctx, MBEDTLS_AES_ENCRYPT, j0, e_j0);
                    if (ret2 == 0) log_hex_debug("GCM TA E(K,J0)", e_j0, sizeof(e_j0));
                    ret2 = mbedtls_aes_crypt_ecb(&aes_ctx, MBEDTLS_AES_ENCRYPT, j0_inc, e_j0_inc);
                    if (ret2 == 0) log_hex_debug("GCM TA E(K,J0+1)", e_j0_inc, sizeof(e_j0_inc));
                    /* Also compute J0+2 and J0+3 for deeper diagnostics */
                    uint8_t j0_inc2[16];
                    uint8_t j0_inc3[16];
                    /* j0_inc is J0+1; compute J0+2 and J0+3 correctly */
                    memcpy(j0_inc2, j0_inc, 16);
                    for (int i = 15; i >= 12; i--) { if (++j0_inc2[i] != 0) break; }
                    /* derive J0+3 from J0+2 to avoid duplicating the same value */
                    memcpy(j0_inc3, j0_inc2, 16);
                    for (int i = 15; i >= 12; i--) { if (++j0_inc3[i] != 0) break; }
                    uint8_t e_j0_inc2[16];
                    uint8_t e_j0_inc3[16];
                    ret2 = mbedtls_aes_crypt_ecb(&aes_ctx, MBEDTLS_AES_ENCRYPT, j0_inc2, e_j0_inc2);
                    if (ret2 == 0) log_hex_debug("GCM TA E(K,J0+2)", e_j0_inc2, sizeof(e_j0_inc2));
                    ret2 = mbedtls_aes_crypt_ecb(&aes_ctx, MBEDTLS_AES_ENCRYPT, j0_inc3, e_j0_inc3);
                    if (ret2 == 0) log_hex_debug("GCM TA E(K,J0+3)", e_j0_inc3, sizeof(e_j0_inc3));
                    /* Also log H = E(K, 0^128) used in GHASH/tag computation */
                    uint8_t zero_block[16] = {0};
                    uint8_t h_block[16];
                    ret2 = mbedtls_aes_crypt_ecb(&aes_ctx, MBEDTLS_AES_ENCRYPT, zero_block, h_block);
                    if (ret2 == 0) log_hex_debug("GCM TA H (E(K,0))", h_block, 16);
                } else {
                    ERROR("mbedtls_aes_setkey_enc failed for diagnostic AES-ECB: -0x%04x", -ret2);
                }
                mbedtls_aes_free(&aes_ctx);
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
}

symmetric_context_t* symmetric_create_chacha20_poly1305_encrypt_context(
        const stored_key_t* stored_key,
        const void* nonce,
        size_t nonce_length,
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
        context->gcm_buffer_length = 0;
        memset(context->gcm_buffer, 0, 16);

        mbedtls_gcm_init(&context->ctx.gcm_ctx);

        // Set up GCM with key
        mbedtls_cipher_id_t cipher_id = MBEDTLS_CIPHER_ID_AES;
        int ret = mbedtls_gcm_setkey(&context->ctx.gcm_ctx, cipher_id, key, key_length * 8);
        if (ret != 0) {
            ERROR("mbedtls_gcm_setkey failed: -0x%04x", -ret);
            break;
        }

        /* Mirror encrypt path: store IV and AAD for potential single-shot/incremental
         * operations and initialize internal GCM state immediately so GHASH and
         * counter values are consistent across provider and verifier. */
        context->gcm_first_update_logged = false;

        // Store IV and AAD for potential single-shot GCM operations
        if (iv_length <= sizeof(context->gcm_iv)) {
            memcpy(context->gcm_iv, iv, iv_length);
            context->gcm_iv_length = iv_length;
        } else {
            ERROR("IV length too large to store");
            break;
        }
        if (aad != NULL && aad_length > 0) {
            context->gcm_aad = memory_internal_alloc(aad_length);
            if (context->gcm_aad == NULL) {
                ERROR("memory_internal_alloc failed");
                break;
            }
            memcpy(context->gcm_aad, aad, aad_length);
            context->gcm_aad_length = aad_length;
        } else {
            context->gcm_aad = NULL;
            context->gcm_aad_length = 0;
        }

        // Start GCM decryption with IV and AAD (mbedTLS 2.16.10 API takes 6 params)
        {
            int r = mbedtls_gcm_starts(&context->ctx.gcm_ctx, MBEDTLS_GCM_DECRYPT,
                                      context->gcm_iv, context->gcm_iv_length,
                                      context->gcm_aad, context->gcm_aad_length);
            if (r != 0) {
                ERROR("mbedtls_gcm_starts failed: -0x%04x", -r);
                break;
            }
        }

        status = true;
    } while (false);

    if (!status) {
        symmetric_context_free(context);
        context = NULL;
    }

    DEBUG("symmetric_create_aes_gcm_decrypt_context: Returning context. gcm_iv_length=%zu", context->gcm_iv_length);
    return context;
}

symmetric_context_t* symmetric_create_chacha20_decrypt_context(
        const stored_key_t* stored_key,
        const void* nonce,
        size_t nonce_length,
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
}

symmetric_context_t* symmetric_create_chacha20_poly1305_decrypt_context(
        const stored_key_t* stored_key,
        const void* nonce,
        size_t nonce_length,
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

    if (out_length != NULL) {
        *out_length = 0;
    }

    if (context->is_chachapoly) {
        int ret = mbedtls_chachapoly_update(&context->ctx.chachapoly_ctx, in_length, in, out);
        if (ret != 0) {
            ERROR("mbedtls_chachapoly_update failed: -0x%04x", -ret);
            return SA_STATUS_INTERNAL_ERROR;
        }
        *out_length = in_length;
    } else if (context->is_chacha) {
        int ret = mbedtls_chacha20_update(&context->ctx.chacha20_ctx, in_length, in, out);
        if (ret != 0) {
            ERROR("mbedtls_chacha20_update failed: -0x%04x", -ret);
            return SA_STATUS_INTERNAL_ERROR;
        }
        *out_length = in_length;
    } else if (context->is_gcm) {
        if (!context->gcm_first_update_logged) {
            DEBUG("GCM encrypt update: %zu bytes", in_length);
            log_hex_debug("GCM encrypt in", in, in_length > 48 ? 48 : in_length);
            context->gcm_first_update_logged = true;
        }
        int ret = mbedtls_gcm_update(&context->ctx.gcm_ctx, in_length, in, out);
        if (ret != 0) {
            ERROR("mbedtls_gcm_update failed: -0x%04x", -ret);
            return SA_STATUS_INTERNAL_ERROR;
        }
        if (in_length > 0) {
             log_hex_debug("GCM encrypt out", out, in_length > 48 ? 48 : in_length);
        }
        *out_length = in_length;
    } else if (context->cipher_algorithm == SA_CIPHER_ALGORITHM_AES_ECB_PKCS7) {
        // Buffer input data for ECB PKCS7 to avoid padding intermediate blocks.
        // We only process full blocks here.
        *out_length = 0;
        
        size_t processed = 0;
        while (processed < in_length) {
            size_t space = 16 - context->gcm_buffer_length;
            size_t chunk = (in_length - processed < space) ? (in_length - processed) : space;
            
            memcpy(context->gcm_buffer + context->gcm_buffer_length, (const uint8_t*)in + processed, chunk);
            context->gcm_buffer_length += chunk;
            processed += chunk;
            
            if (context->gcm_buffer_length == 16) {
                // Encrypt full block without padding
                int ret = mbedtls_aes_crypt_ecb(&context->ctx.aes_ctx, MBEDTLS_AES_ENCRYPT, context->gcm_buffer, (uint8_t*)out + *out_length);
                if (ret != 0) {
                    ERROR("mbedtls update failed: -0x%04x", -ret);
                    return SA_STATUS_INTERNAL_ERROR;
                }
                *out_length += 16;
                context->gcm_buffer_length = 0;
            }
        }
    } else if (context->cipher_algorithm == SA_CIPHER_ALGORITHM_AES_ECB) {
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
        // AES-GCM doesn't need explicit last processing
        *out_length = 0;
    } else if (context->cipher_algorithm == SA_CIPHER_ALGORITHM_AES_ECB_PKCS7) {
        // AES-ECB with PKCS7 padding - handle remaining buffered data and padding
        *out_length = 0;
        
        // Combine buffered data (if any) with input data (if any)
        unsigned char padded_block[AES_BLOCK_SIZE];
        size_t total_data = context->gcm_buffer_length + in_length;
        
        if (total_data > AES_BLOCK_SIZE) {
            ERROR("Too much data for PKCS7 encrypt_last: buffered=%zu, input=%zu", 
                  context->gcm_buffer_length, in_length);
            return SA_STATUS_INVALID_PARAMETER;
        }
        
        // Copy buffered data first
        if (context->gcm_buffer_length > 0) {
            memcpy(padded_block, context->gcm_buffer, context->gcm_buffer_length);
        }
        
        // Then copy input data
        if (in_length > 0) {
            memcpy(padded_block + context->gcm_buffer_length, in, in_length);
        }
        
        // Add PKCS7 padding
        unsigned char padding_value = AES_BLOCK_SIZE - total_data;
        for (size_t i = total_data; i < AES_BLOCK_SIZE; i++) {
            padded_block[i] = padding_value;
        }
        
        // Encrypt the padded block
        int ret = mbedtls_aes_crypt_ecb(&context->ctx.aes_ctx, MBEDTLS_AES_ENCRYPT,
                                         padded_block, (unsigned char*)out + *out_length);
        if (ret != 0) {
            ERROR("mbedtls_aes_crypt_ecb failed: -0x%04x", -ret);
            return SA_STATUS_INTERNAL_ERROR;
        }
        
        *out_length += AES_BLOCK_SIZE;
        context->gcm_buffer_length = 0;
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

    if (out_length == NULL) {
        ERROR("NULL out_length");
        return SA_STATUS_NULL_PARAMETER;
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

    if (out_length != NULL) {
        *out_length = 0;
    }

    if (context->is_chachapoly) {
        int ret = mbedtls_chachapoly_update(&context->ctx.chachapoly_ctx, in_length, in, out);
        if (ret != 0) {
            ERROR("mbedtls_chachapoly_update failed: -0x%04x", -ret);
            return SA_STATUS_INTERNAL_ERROR;
        }
        *out_length = in_length;
    } else if (context->is_chacha) {
        int ret = mbedtls_chacha20_update(&context->ctx.chacha20_ctx, in_length, in, out);
        if (ret != 0) {
            ERROR("mbedtls_chacha20_update failed: -0x%04x", -ret);
            return SA_STATUS_INTERNAL_ERROR;
        }
        *out_length = in_length;
    } else if (context->is_gcm) {
        if (!context->gcm_first_update_logged) {
            DEBUG("GCM decrypt update: %zu bytes", in_length);
            log_hex_debug("GCM decrypt in", in, in_length > 48 ? 48 : in_length);
            context->gcm_first_update_logged = true;
        }
        int ret = mbedtls_gcm_update(&context->ctx.gcm_ctx, in_length, in, out);
        if (ret != 0) {
            ERROR("mbedtls_gcm_update failed: -0x%04x", -ret);
            return SA_STATUS_INTERNAL_ERROR;
        }
        if (in_length > 0) {
            log_hex_debug("GCM decrypt out", out, in_length > 48 ? 48 : in_length);
        }
        *out_length = in_length;
    } else if (context->cipher_algorithm == SA_CIPHER_ALGORITHM_AES_ECB_PKCS7) {
        // PKCS7 decryption: Decrypt blocks but ALWAYS buffer the last 16 bytes.
        // This ensures that if the last block is padding, it's available for decrypt_last.
        // If it's not padding (because more data is coming), it will be decrypted in the next call.
        
        *out_length = 0;
        size_t processed = 0;
        while (processed < in_length) {
            // If buffer is full and we have more data, decrypt the buffer
            if (context->gcm_buffer_length == AES_BLOCK_SIZE) {
                int ret = mbedtls_aes_crypt_ecb(&context->ctx.aes_ctx, MBEDTLS_AES_DECRYPT,
                                                 context->gcm_buffer, (unsigned char*)out + *out_length);
                if (ret != 0) {
                    ERROR("mbedtls_aes_crypt_ecb failed: -0x%04x", -ret);
                    return SA_STATUS_INTERNAL_ERROR;
                }
                *out_length += AES_BLOCK_SIZE;
                context->gcm_buffer_length = 0;
            }

            // Fill buffer with new data
            size_t space = AES_BLOCK_SIZE - context->gcm_buffer_length;
            size_t chunk = (in_length - processed < space) ? (in_length - processed) : space;
            
            memcpy(context->gcm_buffer + context->gcm_buffer_length, (const unsigned char*)in + processed, chunk);
            context->gcm_buffer_length += chunk;
            processed += chunk;
        }
    } else if (context->cipher_algorithm == SA_CIPHER_ALGORITHM_AES_ECB) {
        // AES-ECB uses direct AES API - process block by block
        *out_length = 0;
        

        // Non-PKCS7: decrypt all blocks normally
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
        // printf("DEBUG: AES-CTR/CBC decrypt. Algo: %d, In: %zu\n", context->cipher_algorithm, in_length);
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
        // AES-GCM - decrypt any remaining data, then finish and verify the tag
        *out_length = 0;

        // First, decrypt any remaining data
        if (in_length > 0) {
            int ret = mbedtls_gcm_update(&context->ctx.gcm_ctx, in_length, in, out);
            if (ret != 0) {
                ERROR("mbedtls_gcm_update failed: -0x%04x", -ret);
                return SA_STATUS_INTERNAL_ERROR;
            }
            *out_length = in_length;
        }

        // Now finish and verify the tag
        unsigned char computed_tag[16];  // GCM tag max size
        int ret = mbedtls_gcm_finish(&context->ctx.gcm_ctx, computed_tag, context->gcm_tag_length);
        if (ret != 0) {
            ERROR("mbedtls_gcm_finish failed: %d", ret);
            return SA_STATUS_INTERNAL_ERROR;
        }

        /* Diagnostic: print the computed tag seen by the TA immediately after finish */
        DEBUG("ta: mbedtls_gcm_finish computed_tag (len=%zu): ", context->gcm_tag_length);
        for (size_t dbg_i = 0; dbg_i < (size_t)context->gcm_tag_length && dbg_i < 16; dbg_i++) {
            DEBUG("%02x", computed_tag[dbg_i]);
        }

        // Verify the tag
        if (memcmp(computed_tag, context->gcm_tag, context->gcm_tag_length) != 0) {
            ERROR("GCM tag verification failed");
            // Log computed and expected tags (limited length) using DEBUG
            char comp_buf[3 * 16 + 1] = {0};
            char exp_buf[3 * 16 + 1] = {0};
            size_t posc = 0;
            size_t pose = 0;
            for (size_t i = 0; i < context->gcm_tag_length && i < 16; i++) {
                posc += (size_t) snprintf(&comp_buf[posc], sizeof(comp_buf) - posc, "%02x", computed_tag[i]);
                pose += (size_t) snprintf(&exp_buf[pose], sizeof(exp_buf) - pose, "%02x", context->gcm_tag[i]);
            }
            ERROR("ta: computed tag: %s", comp_buf);
            ERROR("ta: expected tag: %s", exp_buf);
            return SA_STATUS_VERIFICATION_FAILED;
        }

        log_hex_debug("GCM decrypt out", out, *out_length > 48 ? 48 : *out_length);
    } else if (context->cipher_algorithm == SA_CIPHER_ALGORITHM_AES_ECB_PKCS7) {
        // AES-ECB with PKCS7 padding - decrypt the final padding block and remove padding
        *out_length = 0;
        unsigned char final_block[AES_BLOCK_SIZE];
        bool have_final_block = false;
        
        // 1. Process buffered data
        if (context->gcm_buffer_length > 0) {
            if (context->gcm_buffer_length != AES_BLOCK_SIZE) {
                ERROR("Invalid buffered length for PKCS7 decrypt_last: %zu", context->gcm_buffer_length);
                return SA_STATUS_INTERNAL_ERROR;
            }
            
            if (in_length > 0) {
                // Buffer is NOT the last block, decrypt and output it
                int ret = mbedtls_aes_crypt_ecb(&context->ctx.aes_ctx, MBEDTLS_AES_DECRYPT,
                                                 context->gcm_buffer, (unsigned char*)out + *out_length);
                if (ret != 0) {
                    ERROR("mbedtls_aes_crypt_ecb failed: -0x%04x", -ret);
                    return SA_STATUS_INTERNAL_ERROR;
                }
                *out_length += AES_BLOCK_SIZE;
            } else {
                // Buffer IS the last block
                int ret = mbedtls_aes_crypt_ecb(&context->ctx.aes_ctx, MBEDTLS_AES_DECRYPT,
                                                 context->gcm_buffer, final_block);
                if (ret != 0) {
                    ERROR("mbedtls_aes_crypt_ecb failed: -0x%04x", -ret);
                    return SA_STATUS_INTERNAL_ERROR;
                }
                have_final_block = true;
            }
            context->gcm_buffer_length = 0;
        }
        
        // 2. Process input data
        if (in_length > 0) {
            if (in_length != AES_BLOCK_SIZE) {
                ERROR("Invalid in_length for PKCS7 decrypt_last: expected %d, got %zu", 
                      AES_BLOCK_SIZE, in_length);
                return SA_STATUS_INVALID_PARAMETER;
            }
            
            // This MUST be the last block
            int ret = mbedtls_aes_crypt_ecb(&context->ctx.aes_ctx, MBEDTLS_AES_DECRYPT,
                                             (const unsigned char*)in, final_block);
            if (ret != 0) {
                ERROR("mbedtls_aes_crypt_ecb failed: -0x%04x", -ret);
                return SA_STATUS_INTERNAL_ERROR;
            }
            have_final_block = true;
        }
        
        if (!have_final_block) {
            ERROR("No data to decrypt in decrypt_last");
            return SA_STATUS_INVALID_PARAMETER;
        }
        
        // Validate and remove PKCS7 padding from final block
        unsigned char padding_value = final_block[AES_BLOCK_SIZE - 1];
        if (padding_value == 0 || padding_value > AES_BLOCK_SIZE) {
            ERROR("Invalid PKCS7 padding value: %d", padding_value);
            return SA_STATUS_VERIFICATION_FAILED;
        }
        
        // Verify all padding bytes match
        for (size_t i = AES_BLOCK_SIZE - padding_value; i < AES_BLOCK_SIZE; i++) {
            if (final_block[i] != padding_value) {
                ERROR("Invalid PKCS7 padding at position %zu: expected 0x%02x, got 0x%02x",
                      i, padding_value, final_block[i]);
                return SA_STATUS_VERIFICATION_FAILED;
            }
        }
        
        // Output the unpadded data
        size_t unpadded_length = AES_BLOCK_SIZE - padding_value;
        memcpy((unsigned char*)out + *out_length, final_block, unpadded_length);
        *out_length += unpadded_length;
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

#include <stdio.h>

// ... (existing includes)

// ... (existing code)

sa_status symmetric_context_reinit_for_sample(
        const symmetric_context_t* context,
        const stored_key_t* stored_key,
        const void* iv,
        size_t iv_length) {

    if (context == NULL) {
        ERROR("NULL context");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return SA_STATUS_NULL_PARAMETER;
    }

    // Only applicable for CTR mode
    if (context->cipher_algorithm != SA_CIPHER_ALGORITHM_AES_CTR) {
        // For other modes, just set IV
        return symmetric_context_set_iv(context, iv, iv_length);
    }

    // Get the key
    const void* key = stored_key_get_key(stored_key);
    if (key == NULL) {
        ERROR("stored_key_get_key failed");
        return SA_STATUS_NULL_PARAMETER;
    }

    size_t key_length = stored_key_get_length(stored_key);

    // Cast away const for modification
    symmetric_context_t* mutable_context = (symmetric_context_t*)context;
    
    // For CTR mode, we need to completely reinitialize the cipher context
    // because mbedTLS doesn't properly reset internal buffers with just reset+setkey
    
    // Get the cipher info for re-setup
    const mbedtls_cipher_info_t* cipher_info = mbedtls_cipher_info_from_type(
        mbedtls_cipher_get_type(&mutable_context->ctx.cipher_ctx));
    
    if (cipher_info == NULL) {
        ERROR("mbedtls_cipher_info_from_type failed");
        return SA_STATUS_INTERNAL_ERROR;
    }
    
    // Free the existing context
    mbedtls_cipher_free(&mutable_context->ctx.cipher_ctx);
    
    // Re-initialize
    mbedtls_cipher_init(&mutable_context->ctx.cipher_ctx);
    
    // Re-setup with the cipher info
    int ret = mbedtls_cipher_setup(&mutable_context->ctx.cipher_ctx, cipher_info);
    if (ret != 0) {
        ERROR("mbedtls_cipher_setup failed: -0x%04x", -ret);
        return SA_STATUS_INTERNAL_ERROR;
    }
    
    // Set the key
    mbedtls_operation_t operation = MBEDTLS_DECRYPT;
    ret = mbedtls_cipher_setkey(&mutable_context->ctx.cipher_ctx, key, key_length * 8, operation);
    if (ret != 0) {
        ERROR("mbedtls_cipher_setkey failed: -0x%04x", -ret);
        return SA_STATUS_INTERNAL_ERROR;
    }

    // Reset the cipher to clear any internal buffers/state - must be AFTER setkey, BEFORE set_iv
    ret = mbedtls_cipher_reset(&mutable_context->ctx.cipher_ctx);
    if (ret != 0) {
        ERROR("mbedtls_cipher_reset failed: -0x%04x", -ret);
        return SA_STATUS_INTERNAL_ERROR;
    }

    // Set the IV
    ret = mbedtls_cipher_set_iv(&mutable_context->ctx.cipher_ctx, iv, iv_length);
    if (ret != 0) {
        ERROR("mbedtls_cipher_set_iv failed: -0x%04x", -ret);
        return SA_STATUS_INTERNAL_ERROR;
    }

    return SA_STATUS_OK;
}

sa_status symmetric_context_get_tag(
        const symmetric_context_t* context,
        void* tag,
        size_t tag_length) {

    int ret = -1;
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
        /* If a tag was already generated (e.g. by single-shot encrypt), use it. */
        if (context->gcm_tag_length > 0 && context->cipher_mode == SA_CIPHER_MODE_ENCRYPT) {
            if (tag_length > context->gcm_tag_length) {
                ERROR("Invalid tag_length");
                return SA_STATUS_INVALID_PARAMETER;
            }
            memcpy(tag, context->gcm_tag, tag_length);
            return SA_STATUS_OK;
        }

        /* mbedTLS API requires a non-const context pointer; cast away const for the call */
        symmetric_context_t* mutable_context = (symmetric_context_t*) context;
        ret = mbedtls_gcm_finish(&mutable_context->ctx.gcm_ctx, (unsigned char*)tag, tag_length);
        if (ret != 0) {
            ERROR("mbedtls_gcm_finish failed");
            return SA_STATUS_INTERNAL_ERROR;
        }
    } else if (context->is_chachapoly) {
        /* ChaCha20-Poly1305: Use the tag that was already computed in encrypt_last()
         * DO NOT call mbedtls_chachapoly_finish() again - it was already called! */
        if (context->chachapoly_tag_length != tag_length) {
            ERROR("Invalid tag_length: expected %zu, got %zu", 
                  context->chachapoly_tag_length, tag_length);
            return SA_STATUS_INVALID_PARAMETER;
        }
        
        /* Simply copy the cached tag */
        memcpy(tag, context->chachapoly_tag, tag_length);
        return SA_STATUS_OK;
    } else {
        /* Generic cipher API (should not be used for ChaCha20-Poly1305 in mbedtls 2.x) */
        symmetric_context_t* mutable_context = (symmetric_context_t*) context;
        if (mbedtls_cipher_write_tag(&mutable_context->ctx.cipher_ctx, tag, tag_length) != 0) {
            ERROR("mbedtls_cipher_write_tag failed");
            return SA_STATUS_INTERNAL_ERROR;
        }
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
        if (tag_length > MAX_GCM_TAG_LENGTH) {
             ERROR("Invalid tag_length");
             return SA_STATUS_INVALID_PARAMETER;
        }
        DEBUG("symmetric_context_set_tag: Setting tag len=%zu", tag_length);
        log_hex_debug("Expected Tag", tag, tag_length);
        memcpy(context->gcm_tag, tag, tag_length);
        context->gcm_tag_length = tag_length;
    } else if (context->cipher_algorithm == SA_CIPHER_ALGORITHM_CHACHA20_POLY1305) {
        // For ChaCha20-Poly1305, cache the tag for verification in decrypt_last()
        DEBUG("symmetric_context_set_tag: Caching ChaCha20-Poly1305 tag len=%zu", tag_length);
        log_hex_debug("Expected Tag", tag, tag_length);
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
