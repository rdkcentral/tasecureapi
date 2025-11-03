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

#include "porting/otp.h" // NOLINT
#include "common.h"
#include "hmac_internal.h"
#include "log.h"
#include "pkcs12_mbedtls.h"
#include "porting/memory.h"
#include "porting/otp_internal.h"
#include "stored_key_internal.h"
#include <ctype.h>

#define MAX_DEVICE_NAME_LENGTH 16

static uint64_t device_id;

static uint64_t convert_str_to_int(
        const char* str,
        size_t str_length) {
    static const char lookup[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    uint64_t value = 0;
    if (str_length > MAX_DEVICE_NAME_LENGTH) {
        ERROR("Invalid str length");
        return 0;
    }

    for (size_t i = 0; i < str_length; i++) {
        bool found = false;
        for (size_t j = 0; !found && j < sizeof(lookup); j++) {
            if (tolower(str[i]) == lookup[j]) {
                value = (value << 4) + j;
                found = true;
            }
        }

        if (!found) {
            ERROR("Invalid str value");
            return 0;
        }
    }

    return value;
}

// mbedTLS implementation
static bool get_root_key(
        void* root_key,
        size_t* root_key_length) {
    static size_t key_length = 0;
    static uint8_t key[SYM_128_KEY_SIZE];

    if (root_key_length == NULL) {
        ERROR("NULL root_key_length");
        return false;
    }

    if (root_key == NULL) {
        ERROR("NULL root_key");
        return false;
    }

    if (key_length == 0) {
        char device_name[MAX_DEVICE_NAME_LENGTH];
        size_t device_name_length = MAX_DEVICE_NAME_LENGTH;
        device_name[0] = '\0';

        // Get keystore path and password from environment or use defaults
        const char* keystore_path = getenv("ROOT_KEYSTORE");
        const char* keystore_password = getenv("ROOT_KEYSTORE_PASSWORD");

        if (keystore_path == NULL) {
            keystore_path = "root_keystore.p12";
        }

        if (keystore_password == NULL) {
            keystore_password = DEFAULT_ROOT_KEYSTORE_PASSWORD;
        }

        // Call mbedTLS PKCS#12 parser
        key_length = SYM_128_KEY_SIZE;
        if (!load_pkcs12_secret_key_mbedtls(key, &key_length,
                                           device_name, &device_name_length)) {
            ERROR("load_pkcs12_secret_key_mbedtls failed");
            return false;
        }

        device_id = convert_str_to_int(device_name, device_name_length);
        if (device_id == 0) {
            ERROR("Invalid device ID in keystore");
            return false;
        }
    }

    if (*root_key_length < key_length) {
        ERROR("root key too short");
        return false;
    }

    memcpy(root_key, key, key_length);
    *root_key_length = key_length;
    return true;
}

// mbedTLS implementation
static bool get_common_root_key(
        void* common_root_key,
        size_t* common_root_key_length) {
    static size_t key_length = 0;
    static uint8_t key[SYM_128_KEY_SIZE];

    if (common_root_key_length == NULL) {
        ERROR("NULL common_root_key_length");
        return false;
    }

    if (common_root_key == NULL) {
        ERROR("NULL common_root_key");
        return false;
    }

    if (key_length == 0) {
        char name[MAX_NAME_SIZE];
        size_t name_length = MAX_NAME_SIZE;
        strcpy(name, COMMON_ROOT_NAME);

        // Get keystore path and password from environment or use defaults
        const char* keystore_path = getenv("ROOT_KEYSTORE");
        const char* keystore_password = getenv("ROOT_KEYSTORE_PASSWORD");

        if (keystore_path == NULL) {
            keystore_path = "root_keystore.p12";
        }

        if (keystore_password == NULL) {
            keystore_password = "password";
        }

        // Call mbedTLS PKCS#12 parser with specific key name
        key_length = SYM_128_KEY_SIZE;
        if (!load_pkcs12_secret_key_mbedtls(key, &key_length,
                                           name, &name_length)) {
            ERROR("load_pkcs12_secret_key_mbedtls failed");
            return false;
        }
    }

    if (*common_root_key_length < key_length) {
        ERROR("root key too short");
        return false;
    }

    memcpy(common_root_key, key, key_length);
    *common_root_key_length = key_length;
    return true;
}

static sa_status wrap_aes_cbc(
        void* out,
        const void* in,
        size_t in_length,
        const void* iv,
        const void* key,
        size_t key_length) {

    if (out == NULL) {
        ERROR("NULL out");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (in == NULL) {
        ERROR("NULL in");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (in_length % AES_BLOCK_SIZE) {
        ERROR("Invalid in_length");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (iv == NULL) {
        ERROR("NULL iv");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (key == NULL) {
        ERROR("NULL key");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (key_length != SYM_128_KEY_SIZE && key_length != SYM_256_KEY_SIZE) {
        ERROR("Invalid key_length");
        return SA_STATUS_INVALID_PARAMETER;
    }

    sa_status status = SA_STATUS_INTERNAL_ERROR;
    mbedtls_cipher_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    mbedtls_cipher_init(&ctx);

    do {
        // Select cipher type based on key length
        mbedtls_cipher_type_t cipher_type = (key_length == SYM_128_KEY_SIZE) ?
            MBEDTLS_CIPHER_AES_128_CBC : MBEDTLS_CIPHER_AES_256_CBC;

        const mbedtls_cipher_info_t* cipher_info = mbedtls_cipher_info_from_type(cipher_type);
        if (cipher_info == NULL) {
            ERROR("mbedtls_cipher_info_from_type failed");
            break;
        }

        int ret = mbedtls_cipher_setup(&ctx, cipher_info);
        if (ret != 0) {
            ERROR("mbedtls_cipher_setup failed: -0x%04x", -ret);
            break;
        }

        ret = mbedtls_cipher_setkey(&ctx, key, key_length * 8, MBEDTLS_ENCRYPT);
        if (ret != 0) {
            ERROR("mbedtls_cipher_setkey failed: -0x%04x", -ret);
            break;
        }

        // Turn off padding
        ret = mbedtls_cipher_set_padding_mode(&ctx, MBEDTLS_PADDING_NONE);
        if (ret != 0) {
            ERROR("mbedtls_cipher_set_padding_mode failed: -0x%04x", -ret);
            break;
        }

        size_t out_len = 0;
        ret = mbedtls_cipher_crypt(&ctx, iv, AES_BLOCK_SIZE, in, in_length, out, &out_len);
        if (ret != 0) {
            ERROR("mbedtls_cipher_crypt failed: -0x%04x", -ret);
            break;
        }

        if (out_len != in_length) {
            ERROR("Output length mismatch: expected %zu, got %zu", in_length, out_len);
            break;
        }

        status = SA_STATUS_OK;
    } while (false);

    mbedtls_cipher_free(&ctx);

    return status;
}

/**
 * This function simulates the 3 stage HW key ladder rooted in the OTP key. None of the
 * intermediate keys in the key ladder (root, stage 1 result, stage 2 result) shall be readable or
 * usable by any SW components. Stage 3 result shall be usable only by SecApi TA and not by any
 * other TEE or REE applications.
 */
static sa_status otp_hw_key_ladder(
        void* derived,
        sa_root_key_type root_key_type,
        const void* c1,
        const void* c2,
        const void* c3) {

    if (derived == NULL) {
        ERROR("NULL derived");
        return false;
    }

    if (c1 == NULL) {
        ERROR("NULL c1");
        return false;
    }

    if (c2 == NULL) {
        ERROR("NULL c2");
        return false;
    }

    if (c3 == NULL) {
        ERROR("NULL c3");
        return false;
    }

    sa_status status = SA_STATUS_INTERNAL_ERROR;
    uint8_t* k1 = NULL;
    size_t k1_length = SYM_128_KEY_SIZE;
    uint8_t* k2 = NULL;
    size_t k2_length = SYM_128_KEY_SIZE;
    uint8_t root_key[SYM_256_KEY_SIZE];
    do {
        size_t root_key_length = SYM_256_KEY_SIZE;
        if (root_key_type == UNIQUE) {
            if (!get_root_key(root_key, &root_key_length)) {
                ERROR("get_root_key failed");
                break;
            }
        } else if (root_key_type == COMMON) {
            if (!get_common_root_key(root_key, &root_key_length)) {
                ERROR("get_common_root_key failed");
                break;
            }
        } else {
            ERROR("unknown root key type");
            status = SA_STATUS_INVALID_PARAMETER;
            break;
        }

        k1 = memory_secure_alloc(k1_length);
        if (k1 == NULL) {
            ERROR("memory_secure_alloc failed");
            break;
        }

        k2 = memory_secure_alloc(k2_length);
        if (k2 == NULL) {
            ERROR("memory_secure_alloc failed");
            break;
        }

        status = unwrap_aes_ecb_internal(k1, c1, AES_BLOCK_SIZE, root_key, root_key_length);
        if (status != SA_STATUS_OK) {
            ERROR("unwrap_aes_ecb_internal failed");
            break;
        }

        status = unwrap_aes_ecb_internal(k2, c2, AES_BLOCK_SIZE, k1, k1_length);
        if (status != SA_STATUS_OK) {
            ERROR("unwrap_aes_ecb_internal failed");
            break;
        }

        status = unwrap_aes_ecb_internal(derived, c3, AES_BLOCK_SIZE, k2, k2_length);
        if (status != SA_STATUS_OK) {
            ERROR("unwrap_aes_ecb_internal failed");
            break;
        }

        status = SA_STATUS_OK;
    } while (false);

    memory_memset_unoptimizable(root_key, 0, SYM_256_KEY_SIZE);
    if (k1 != NULL) {
        memory_memset_unoptimizable(k1, 0, k1_length);
        memory_secure_free(k1);
    }

    if (k2 != NULL) {
        memory_memset_unoptimizable(k2, 0, k2_length);
        memory_secure_free(k2);
    }

    return status;
}

sa_status unwrap_aes_ecb_internal(
        void* out,
        const void* in,
        size_t in_length,
        const void* key,
        size_t key_length) {

    if (out == NULL) {
        ERROR("NULL out");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (in == NULL) {
        ERROR("NULL in");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (in_length % AES_BLOCK_SIZE) {
        ERROR("Invalid in_length");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (key == NULL) {
        ERROR("NULL key");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (key_length != SYM_128_KEY_SIZE && key_length != SYM_256_KEY_SIZE) {
        ERROR("Invalid key_length");
        return SA_STATUS_INVALID_PARAMETER;
    }

    sa_status status = SA_STATUS_INTERNAL_ERROR;
    mbedtls_aes_context aes_ctx;
    mbedtls_aes_init(&aes_ctx);

    do {
        // Set decryption key
        int ret = mbedtls_aes_setkey_dec(&aes_ctx, key, key_length * 8);
        if (ret != 0) {
            ERROR("mbedtls_aes_setkey_dec failed: -0x%04x", -ret);
            break;
        }

        // Process data in 16-byte blocks (ECB mode)
        for (size_t i = 0; i < in_length; i += AES_BLOCK_SIZE) {
            ret = mbedtls_aes_crypt_ecb(&aes_ctx, MBEDTLS_AES_DECRYPT,
                                        in + i, out + i);
            if (ret != 0) {
                ERROR("mbedtls_aes_crypt_ecb failed at block %zu: -0x%04x", i / AES_BLOCK_SIZE, -ret);
                break;
            }
        }

        if (ret != 0) {
            break;
        }

        status = SA_STATUS_OK;
    } while (false);

    mbedtls_aes_free(&aes_ctx);

    return status;
}

sa_status unwrap_aes_cbc_internal(
        void* out,
        const void* in,
        size_t in_length,
        const void* iv,
        const void* key,
        size_t key_length) {

    if (out == NULL) {
        ERROR("NULL out");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (in == NULL) {
        ERROR("NULL in");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (in_length % AES_BLOCK_SIZE) {
        ERROR("Invalid in_length");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (iv == NULL) {
        ERROR("NULL iv");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (key == NULL) {
        ERROR("NULL key");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (key_length != SYM_128_KEY_SIZE && key_length != SYM_256_KEY_SIZE) {
        ERROR("Invalid key_length");
        return SA_STATUS_INVALID_PARAMETER;
    }

    sa_status status = SA_STATUS_INTERNAL_ERROR;
    mbedtls_cipher_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    mbedtls_cipher_init(&ctx);

    do {
        // Select cipher type based on key length
        mbedtls_cipher_type_t cipher_type = (key_length == SYM_128_KEY_SIZE) ?
            MBEDTLS_CIPHER_AES_128_CBC : MBEDTLS_CIPHER_AES_256_CBC;

        const mbedtls_cipher_info_t* cipher_info = mbedtls_cipher_info_from_type(cipher_type);
        if (cipher_info == NULL) {
            ERROR("mbedtls_cipher_info_from_type failed");
            break;
        }

        int ret = mbedtls_cipher_setup(&ctx, cipher_info);
        if (ret != 0) {
            ERROR("mbedtls_cipher_setup failed: -0x%04x", -ret);
            break;
        }

        ret = mbedtls_cipher_setkey(&ctx, key, key_length * 8, MBEDTLS_DECRYPT);
        if (ret != 0) {
            ERROR("mbedtls_cipher_setkey failed: -0x%04x", -ret);
            break;
        }

        // Turn off padding
        ret = mbedtls_cipher_set_padding_mode(&ctx, MBEDTLS_PADDING_NONE);
        if (ret != 0) {
            ERROR("mbedtls_cipher_set_padding_mode failed: -0x%04x", -ret);
            break;
        }

        size_t out_len = 0;
        ret = mbedtls_cipher_crypt(&ctx, iv, AES_BLOCK_SIZE, in, in_length, out, &out_len);
        if (ret != 0) {
            ERROR("mbedtls_cipher_crypt failed: -0x%04x", -ret);
            break;
        }

        if (out_len != in_length) {
            ERROR("Output length mismatch: expected %zu, got %zu", in_length, out_len);
            break;
        }

        status = SA_STATUS_OK;
    } while (false);

    mbedtls_cipher_free(&ctx);

    return status;
}

sa_status unwrap_aes_gcm_internal(
        void* out,
        const void* in,
        size_t in_length,
        const void* iv,
        size_t iv_length,
        const void* aad,
        size_t aad_length,
        const void* tag,
        size_t tag_length,
        const void* key,
        size_t key_length) {

    if (out == NULL) {
        ERROR("NULL out");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (in == NULL) {
        ERROR("NULL in");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (iv == NULL) {
        ERROR("NULL iv");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (iv_length != GCM_IV_LENGTH) {
        ERROR("Invalid iv_length");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (aad == NULL && aad_length > 0) {
        ERROR("NULL aad");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (tag == NULL) {
        ERROR("NULL tag");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (tag_length > AES_BLOCK_SIZE) {
        ERROR("Invalid tag_length");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (key == NULL) {
        ERROR("NULL key");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (key_length != SYM_128_KEY_SIZE && key_length != SYM_256_KEY_SIZE) {
        ERROR("Invalid key_length");
        return SA_STATUS_INVALID_PARAMETER;
    }

    sa_status status = SA_STATUS_INTERNAL_ERROR;
    mbedtls_gcm_context ctx;
    memset(&ctx, 0, sizeof(ctx));
    mbedtls_gcm_init(&ctx);

    do {
        // Select cipher ID based on key length
        mbedtls_cipher_id_t cipher_id = (key_length == SYM_128_KEY_SIZE) ?
            MBEDTLS_CIPHER_ID_AES : MBEDTLS_CIPHER_ID_AES;

        int ret = mbedtls_gcm_setkey(&ctx, cipher_id, key, key_length * 8);
        if (ret != 0) {
            ERROR("mbedtls_gcm_setkey failed: -0x%04x", -ret);
            break;
        }

        ret = mbedtls_gcm_auth_decrypt(&ctx, in_length, iv, iv_length,
                                       aad, aad_length, tag, tag_length,
                                       in, out);
        if (ret != 0) {
            ERROR("mbedtls_gcm_auth_decrypt failed: -0x%04x", -ret);
            break;
        }

        status = SA_STATUS_OK;
    } while (false);

    mbedtls_gcm_free(&ctx);

    return status;
}

sa_status otp_device_id(uint64_t* id) {
    if (id == NULL) {
        ERROR("NULL id");
        return SA_STATUS_NULL_PARAMETER;
    }

    // If not initialized yet, attempt to set the device id and ignore the result.
    uint8_t root_key[SYM_256_KEY_SIZE];
    size_t root_key_length = SYM_256_KEY_SIZE;
    if (device_id == 0)
        get_root_key(root_key, &root_key_length);

    *id = device_id;
    return SA_STATUS_OK;
}

sa_status otp_root_key_ladder(
        stored_key_t** stored_key_derived,
        const sa_rights* rights,
        sa_root_key_type root_key_type,
        const void* c1,
        const void* c2,
        const void* c3,
        const void* c4) {

    if (stored_key_derived == NULL) {
        ERROR("NULL stored_key_derived");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (rights == NULL) {
        ERROR("NULL rights");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (c1 == NULL) {
        ERROR("NULL c1");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (c2 == NULL) {
        ERROR("NULL c2");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (c3 == NULL) {
        ERROR("NULL c3");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (c4 == NULL) {
        ERROR("NULL c4");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status = SA_STATUS_INTERNAL_ERROR;
    uint8_t* k3 = NULL;
    size_t k3_length = SYM_128_KEY_SIZE;
    uint8_t* derived = NULL;
    size_t derived_length = AES_BLOCK_SIZE;
    do {
        derived = memory_secure_alloc(derived_length);
        if (derived == NULL) {
            ERROR("memory_secure_alloc failed");
            break;
        }

        k3 = memory_secure_alloc(k3_length);
        if (k3 == NULL) {
            ERROR("memory_secure_alloc failed");
            break;
        }

        status = otp_hw_key_ladder(k3, root_key_type, c1, c2, c3);
        if (status != SA_STATUS_OK) {
            ERROR("otp_hw_key_ladder failed");
            break;
        }

        status = unwrap_aes_ecb_internal(derived, c4, AES_BLOCK_SIZE, k3, k3_length);
        if (status != SA_STATUS_OK) {
            ERROR("unwrap_aes_ecb_internal failed");
            break;
        }

        sa_type_parameters type_parameters;
        memory_memset_unoptimizable(&type_parameters, 0, sizeof(sa_type_parameters));
        status = stored_key_create(stored_key_derived, rights, NULL, SA_KEY_TYPE_SYMMETRIC, &type_parameters,
                derived_length, derived, derived_length);
        if (status != SA_STATUS_OK) {
            ERROR("stored_key_create failed");
            break;
        }

        status = SA_STATUS_OK;
    } while (false);

    if (k3 != NULL) {
        memory_memset_unoptimizable(k3, 0, k3_length);
        memory_secure_free(k3);
    }

    if (derived != NULL) {
        memory_memset_unoptimizable(derived, 0, derived_length);
        memory_secure_free(derived);
    }

    return status;
}

sa_status otp_wrap_aes_cbc(
        void* wrapped,
        const key_ladder_inputs_t* key_ladder_inputs,
        const void* in,
        size_t in_length,
        const void* iv) {

    if (wrapped == NULL) {
        ERROR("NULL wrapped");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (key_ladder_inputs == NULL) {
        ERROR("NULL key_ladder_inputs");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (in == NULL) {
        ERROR("NULL in");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (in_length % AES_BLOCK_SIZE) {
        ERROR("Invalid in_length");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (iv == NULL) {
        ERROR("NULL iv");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status = SA_STATUS_INTERNAL_ERROR;
    uint8_t* wrapping_key = NULL;
    size_t wrapping_key_length = SYM_128_KEY_SIZE;
    do {
        wrapping_key = memory_secure_alloc(wrapping_key_length);
        if (wrapping_key == NULL) {
            ERROR("memory_secure_alloc failed");
            break;
        }

        // derive wrapping key
        status = otp_hw_key_ladder(wrapping_key, UNIQUE, key_ladder_inputs->c1, key_ladder_inputs->c2,
                key_ladder_inputs->c3);
        if (status != SA_STATUS_OK) {
            ERROR("otp_hw_key_ladder failed");
            break;
        }

        status = wrap_aes_cbc(wrapped, in, in_length, iv, wrapping_key, wrapping_key_length);
        if (status != SA_STATUS_OK) {
            ERROR("wrap_aes_cbc failed");
            break;
        }

        status = SA_STATUS_OK;
    } while (false);

    if (wrapping_key != NULL) {
        memory_memset_unoptimizable(wrapping_key, 0, wrapping_key_length);
        memory_secure_free(wrapping_key);
    }

    return status;
}

sa_status otp_unwrap_aes_cbc(
        void* out,
        const key_ladder_inputs_t* key_ladder_inputs,
        const void* wrapped,
        size_t wrapped_length,
        const void* iv) {

    if (out == NULL) {
        ERROR("NULL out");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (key_ladder_inputs == NULL) {
        ERROR("NULL key_ladder_inputs");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (wrapped == NULL) {
        ERROR("NULL wrapped");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (wrapped_length % AES_BLOCK_SIZE) {
        ERROR("Invalid wrapped_length");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (iv == NULL) {
        ERROR("NULL iv");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status = SA_STATUS_INTERNAL_ERROR;
    uint8_t* wrapping_key = NULL;
    size_t wrapping_key_length = SYM_128_KEY_SIZE;
    do {
        wrapping_key = memory_secure_alloc(wrapping_key_length);
        if (wrapping_key == NULL) {
            ERROR("memory_secure_alloc failed");
            break;
        }

        // derive wrapping key
        status = otp_hw_key_ladder(wrapping_key, UNIQUE, key_ladder_inputs->c1, key_ladder_inputs->c2,
                key_ladder_inputs->c3);
        if (status != SA_STATUS_OK) {
            ERROR("otp_hw_key_ladder failed");
            break;
        }

        status = unwrap_aes_cbc_internal(out, wrapped, wrapped_length, iv, wrapping_key, wrapping_key_length);
        if (status != SA_STATUS_OK) {
            ERROR("unwrap_aes_cbc_internal failed");
            break;
        }

        status = SA_STATUS_OK;
    } while (false);

    if (wrapping_key != NULL) {
        memory_memset_unoptimizable(wrapping_key, 0, wrapping_key_length);
        memory_secure_free(wrapping_key);
    }

    return status;
}

sa_status otp_unwrap_aes_gcm(
        void* out,
        const key_ladder_inputs_t* key_ladder_inputs,
        sa_root_key_type root_key_type,
        const void* wrapped,
        size_t wrapped_length,
        const void* iv,
        size_t iv_length,
        const void* aad,
        size_t aad_length,
        const void* tag,
        size_t tag_length) {

    if (out == NULL) {
        ERROR("NULL out");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (key_ladder_inputs == NULL) {
        ERROR("NULL key_ladder_inputs");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (wrapped == NULL) {
        ERROR("NULL wrapped");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (iv == NULL) {
        ERROR("NULL iv");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (aad == NULL) {
        ERROR("NULL aad");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (tag == NULL) {
        ERROR("NULL tag");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status = SA_STATUS_INTERNAL_ERROR;
    uint8_t* wrapping_key = NULL;
    size_t wrapping_key_length = SYM_128_KEY_SIZE;
    do {
        wrapping_key = memory_secure_alloc(wrapping_key_length);
        if (wrapping_key == NULL) {
            ERROR("memory_secure_alloc failed");
            break;
        }

        // derive wrapping key
        status = otp_hw_key_ladder(wrapping_key, root_key_type, key_ladder_inputs->c1, key_ladder_inputs->c2,
                key_ladder_inputs->c3);
        if (status != SA_STATUS_OK) {
            ERROR("otp_hw_key_ladder failed");
            break;
        }

        status = unwrap_aes_gcm_internal(out, wrapped, wrapped_length, iv, iv_length, aad, aad_length, tag, tag_length,
                wrapping_key, wrapping_key_length);
        if (status != SA_STATUS_OK) {
            ERROR("unwrap_aes_gcm_internal failed");
            break;
        }

        status = SA_STATUS_OK;
    } while (false);

    if (wrapping_key != NULL) {
        memory_memset_unoptimizable(wrapping_key, 0, wrapping_key_length);
        memory_secure_free(wrapping_key);
    }

    return status;
}

sa_status otp_hmac_sha256(
        void* mac,
        const key_ladder_inputs_t* key_ladder_inputs,
        const void* in1,
        size_t in1_length,
        const void* in2,
        size_t in2_length,
        const void* in3,
        size_t in3_length) {

    if (mac == NULL) {
        ERROR("NULL mac");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (key_ladder_inputs == NULL) {
        ERROR("NULL key_ladder_inputs");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (in1 == NULL && in1_length > 0) {
        ERROR("NULL in1");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (in2 == NULL && in2_length > 0) {
        ERROR("NULL in2");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (in3 == NULL && in3_length > 0) {
        ERROR("NULL in3");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status = SA_STATUS_INTERNAL_ERROR;
    uint8_t* hmac_key = NULL;
    size_t hmac_key_length = SYM_128_KEY_SIZE;
    do {
        hmac_key = memory_secure_alloc(hmac_key_length);
        if (hmac_key == NULL) {
            ERROR("memory_secure_alloc failed");
            break;
        }

        // derive integrity key
        status = otp_hw_key_ladder(hmac_key, UNIQUE, key_ladder_inputs->c1, key_ladder_inputs->c2,
                key_ladder_inputs->c3);
        if (status != SA_STATUS_OK) {
            ERROR("otp_hw_key_ladder failed");
            break;
        }

        size_t mac_length = SHA256_DIGEST_LENGTH;
        status = hmac_internal(mac, &mac_length, SA_DIGEST_ALGORITHM_SHA256, in1, in1_length, in2, in2_length, in3,
                in3_length, hmac_key, hmac_key_length);
        if (status != SA_STATUS_OK) {
            ERROR("hmac_internal failed");
            break;
        }

        status = SA_STATUS_OK;
    } while (false);

    if (hmac_key != NULL) {
        memory_memset_unoptimizable(hmac_key, 0, hmac_key_length);
        memory_secure_free(hmac_key);
    }

    return status;
}
