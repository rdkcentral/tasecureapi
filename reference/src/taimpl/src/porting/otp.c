/**
 * Copyright 2020-2021 Comcast Cable Communications Management, LLC
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
#include "porting/memory.h"
#include "porting/otp_internal.h"
#include "stored_key_internal.h"
#include <openssl/evp.h>

static struct {
    /**
     * Root key for the 3-stage HW key ladder. This key is device unique and serialized by the
     * SOC manufacturer. Replace any reference to this variable in SecApi TA with actual HW key
     * ladder operations.
     */
    const uint8_t root_key[SYM_128_KEY_SIZE];

    /**
     * Device ID for the SOC part. This id is device unique and serialized by the SOC manufacturer.
     */
    const uint64_t device_id;
} global_otp = {
        .root_key = {
                0xe7, 0x9b, 0x03, 0x18, 0x85, 0x1b, 0x9d, 0xbd,
                0xd7, 0x17, 0x18, 0xf9, 0xec, 0x72, 0xf0, 0x3d},
        .device_id = 0xfffffffffffffffeULL,
};

static bool wrap_aes_cbc(
        void* out,
        const void* in,
        size_t in_length,
        const void* iv,
        const void* key,
        size_t key_length) {

    if (out == NULL) {
        ERROR("NULL out");
        return false;
    }

    if (in == NULL) {
        ERROR("NULL in");
        return false;
    }

    if (in_length % AES_BLOCK_SIZE) {
        ERROR("Bad in_length");
        return false;
    }

    if (iv == NULL) {
        ERROR("NULL iv");
        return false;
    }

    if (key == NULL) {
        ERROR("NULL key");
        return false;
    }

    if (key_length != SYM_128_KEY_SIZE && key_length != SYM_256_KEY_SIZE) {
        ERROR("Bad key_length");
        return false;
    }

    bool status = false;
    EVP_CIPHER_CTX* context = NULL;

    do {
        context = EVP_CIPHER_CTX_new();
        if (context == NULL) {
            ERROR("EVP_CIPHER_CTX_new failed");
            break;
        }

        const EVP_CIPHER* cipher = NULL;
        if (key_length == SYM_128_KEY_SIZE)
            cipher = EVP_aes_128_cbc();
        else
            cipher = EVP_aes_256_cbc();

        if (cipher == NULL) {
            ERROR("EVP_aes_???_cbc failed");
            break;
        }

        if (EVP_EncryptInit_ex(context, cipher, NULL, key, (const unsigned char*) iv) != 1) {
            ERROR("EVP_EncryptInit_ex failed");
            break;
        }

        // turn off padding
        if (EVP_CIPHER_CTX_set_padding(context, 0) != 1) {
            ERROR("EVP_CIPHER_CTX_set_padding failed");
            break;
        }

        int out_length = (int) in_length;
        if (EVP_EncryptUpdate(context, out, &out_length, in, (int) in_length) != 1) {
            ERROR("EVP_EncryptUpdate failed");
            break;
        }

        status = true;
    } while (false);

    EVP_CIPHER_CTX_free(context);

    return status;
}

/**
 * This function simulates the 3 stage HW key ladder rooted in the OTP key. None of the
 * intermediate keys in the key ladder (root, stage 1 result, stage 2 result) shall be readable or
 * usable by any SW components. Stage 3 result shall be usable only by SecApi TA and not by any
 * other TEE or REE applications.
 */
static bool otp_hw_key_ladder(
        void* derived,
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

    bool status = false;
    uint8_t* k1 = NULL;
    size_t k1_length = SYM_128_KEY_SIZE;
    uint8_t* k2 = NULL;
    size_t k2_length = SYM_128_KEY_SIZE;

    do {
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

        if (!unwrap_aes_ecb_internal(k1, c1, AES_BLOCK_SIZE, global_otp.root_key, sizeof(global_otp.root_key))) {
            ERROR("unwrap_aes_ecb_internal failed");
            break;
        }

        if (!unwrap_aes_ecb_internal(k2, c2, AES_BLOCK_SIZE, k1, k1_length)) {
            ERROR("unwrap_aes_ecb_internal failed");
            break;
        }

        if (!unwrap_aes_ecb_internal(derived, c3, AES_BLOCK_SIZE, k2, k2_length)) {
            ERROR("unwrap_aes_ecb_internal failed");
            break;
        }

        status = true;
    } while (false);

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

bool unwrap_aes_ecb_internal(
        void* out,
        const void* in,
        size_t in_length,
        const void* key,
        size_t key_length) {

    if (out == NULL) {
        ERROR("NULL out");
        return false;
    }

    if (in == NULL) {
        ERROR("NULL in");
        return false;
    }

    if (in_length % AES_BLOCK_SIZE) {
        ERROR("Bad in_length");
        return false;
    }

    if (key == NULL) {
        ERROR("NULL key");
        return false;
    }

    if (key_length != SYM_128_KEY_SIZE && key_length != SYM_256_KEY_SIZE) {
        ERROR("Bad key_length");
        return false;
    }

    bool status = false;
    EVP_CIPHER_CTX* context = NULL;

    do {
        context = EVP_CIPHER_CTX_new();
        if (context == NULL) {
            ERROR("EVP_CIPHER_CTX_new failed");
            break;
        }

        const EVP_CIPHER* cipher = NULL;
        if (key_length == SYM_128_KEY_SIZE)
            cipher = EVP_aes_128_ecb();
        else
            cipher = EVP_aes_256_ecb();

        if (cipher == NULL) {
            ERROR("EVP_aes_???_ebc failed");
            break;
        }

        if (EVP_DecryptInit_ex(context, cipher, NULL, (const unsigned char*) key, NULL) != 1) {
            ERROR("EVP_DecryptInit_ex failed");
            break;
        }

        // turn off padding
        if (EVP_CIPHER_CTX_set_padding(context, 0) != 1) {
            ERROR("EVP_CIPHER_CTX_set_padding failed");
            break;
        }

        int out_length = (int) in_length;
        if (EVP_DecryptUpdate(context, out, &out_length, in, (int) in_length) != 1) {
            ERROR("EVP_DecryptUpdate failed");
            break;
        }

        status = true;
    } while (false);

    EVP_CIPHER_CTX_free(context);

    return status;
}

bool unwrap_aes_cbc_internal(
        void* out,
        const void* in,
        size_t in_length,
        const void* iv,
        const void* key,
        size_t key_length) {

    if (out == NULL) {
        ERROR("NULL out");
        return false;
    }

    if (in == NULL) {
        ERROR("NULL in");
        return false;
    }

    if (in_length % AES_BLOCK_SIZE) {
        ERROR("Bad in_length");
        return false;
    }

    if (iv == NULL) {
        ERROR("NULL iv");
        return false;
    }

    if (key == NULL) {
        ERROR("NULL key");
        return false;
    }

    if (key_length != SYM_128_KEY_SIZE && key_length != SYM_256_KEY_SIZE) {
        ERROR("Bad key_length");
        return false;
    }

    bool status = false;
    EVP_CIPHER_CTX* context = NULL;

    do {
        context = EVP_CIPHER_CTX_new();
        if (context == NULL) {
            ERROR("EVP_CIPHER_CTX_new failed");
            break;
        }

        const EVP_CIPHER* cipher = NULL;
        if (key_length == SYM_128_KEY_SIZE)
            cipher = EVP_aes_128_cbc();
        else // key_length == SYM_256_KEY_SIZE
            cipher = EVP_aes_256_cbc();

        if (cipher == NULL) {
            ERROR("EVP_aes_???_cbc failed");
            break;
        }

        if (EVP_DecryptInit_ex(context, cipher, NULL, (const unsigned char*) key,
                    (const unsigned char*) iv) != 1) {
            ERROR("EVP_DecryptInit_ex failed");
            break;
        }

        // turn off padding
        if (EVP_CIPHER_CTX_set_padding(context, 0) != 1) {
            ERROR("EVP_CIPHER_CTX_set_padding failed");
            break;
        }

        int out_length = (int) in_length;
        if (EVP_DecryptUpdate(context, out, &out_length, in, (int) in_length) != 1) {
            ERROR("EVP_DecryptUpdate failed");
            break;
        }

        status = true;
    } while (false);

    EVP_CIPHER_CTX_free(context);

    return status;
}

bool unwrap_aes_gcm_internal(
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
        return false;
    }

    if (in == NULL) {
        ERROR("NULL in");
        return false;
    }

    if (iv == NULL) {
        ERROR("NULL iv");
        return false;
    }

    if (iv_length != GCM_IV_LENGTH) {
        ERROR("Bad iv_length");
        return false;
    }

    if (aad == NULL && aad_length > 0) {
        ERROR("NULL aad");
        return false;
    }

    if (tag == NULL) {
        ERROR("NULL tag");
        return false;
    }

    if (tag_length > AES_BLOCK_SIZE) {
        ERROR("Bad tag_length");
        return false;
    }

    if (key == NULL) {
        ERROR("NULL key");
        return false;
    }

    if (key_length != SYM_128_KEY_SIZE && key_length != SYM_256_KEY_SIZE) {
        ERROR("Bad key_length");
        return false;
    }

    bool status = false;
    EVP_CIPHER_CTX* context = NULL;

    do {
        context = EVP_CIPHER_CTX_new();
        if (context == NULL) {
            ERROR("EVP_CIPHER_CTX_new failed");
            break;
        }

        const EVP_CIPHER* cipher = NULL;
        if (key_length == SYM_128_KEY_SIZE)
            cipher = EVP_aes_128_gcm();
        else // key_length == SYM_256_KEY_SIZE
            cipher = EVP_aes_256_gcm();

        if (cipher == NULL) {
            ERROR("EVP_aes_???_gcm failed");
            break;
        }

        // init cipher
        if (EVP_DecryptInit_ex(context, cipher, NULL, NULL, NULL) != 1) {
            ERROR("EVP_DecryptInit_ex failed");
            break;
        }

        // set iv length
        if (EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, (int) iv_length, NULL) != 1) {
            ERROR("EVP_CIPHER_CTX_ctrl failed");
            break;
        }

        // init key and iv
        if (EVP_DecryptInit_ex(context, cipher, NULL, key, iv) != 1) {
            ERROR("EVP_DecryptInit_ex failed");
            break;
        }

        // turn off padding
        if (EVP_CIPHER_CTX_set_padding(context, 0) != 1) {
            ERROR("EVP_CIPHER_CTX_set_padding failed");
            break;
        }

        // set aad
        int out_length = (int) in_length;
        if (EVP_DecryptUpdate(context, NULL, &out_length, aad, (int) aad_length) != 1) {
            ERROR("EVP_DecryptUpdate failed");
            break;
        }

        if (EVP_DecryptUpdate(context, out, &out_length, in, (int) in_length) != 1) {
            ERROR("EVP_DecryptUpdate failed");
            break;
        }

        // check tag
        if (EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_TAG, (int) tag_length, (void*) tag) != 1) {
            ERROR("EVP_CIPHER_CTX_ctrl failed");
            break;
        }

        int length = 0;
        if (EVP_DecryptFinal_ex(context, NULL, &length) != 1) {
            ERROR("EVP_DecryptFinal_ex failed");
            break;
        }

        status = true;
    } while (false);

    if (context) {
        EVP_CIPHER_CTX_free(context);
        context = NULL;
    }

    return status;
}

bool otp_device_id(uint64_t* id) {
    if (id == NULL) {
        ERROR("NULL id");
        return false;
    }

    *id = global_otp.device_id;
    return true;
}

bool otp_root_key_ladder(
        stored_key_t** stored_key_derived,
        const sa_rights* rights,
        const void* c1,
        const void* c2,
        const void* c3,
        const void* c4) {

    if (stored_key_derived == NULL) {
        ERROR("NULL stored_key_derived");
        return false;
    }

    if (rights == NULL) {
        ERROR("NULL rights");
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

    if (c4 == NULL) {
        ERROR("NULL c4");
        return false;
    }

    bool status = false;
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

        if (!otp_hw_key_ladder(k3, c1, c2, c3)) {
            ERROR("otp_hw_key_ladder failed");
            break;
        }

        if (!unwrap_aes_ecb_internal(derived, c4, AES_BLOCK_SIZE, k3, k3_length)) {
            ERROR("unwrap_aes_ecb_internal failed");
            break;
        }

        sa_type_parameters type_parameters;
        memory_memset_unoptimizable(&type_parameters, 0, sizeof(sa_type_parameters));
        status = stored_key_create(stored_key_derived, rights, NULL, SA_KEY_TYPE_SYMMETRIC, &type_parameters,
                derived_length, derived, derived_length);
        if (!status) {
            ERROR("stored_key_create failed");
            break;
        }
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

bool otp_wrap_aes_cbc(
        void* wrapped,
        const key_ladder_inputs_t* key_ladder_inputs,
        const void* in,
        size_t in_length,
        const void* iv) {

    if (wrapped == NULL) {
        ERROR("NULL wrapped");
        return false;
    }

    if (key_ladder_inputs == NULL) {
        ERROR("NULL key_ladder_inputs");
        return false;
    }

    if (in == NULL) {
        ERROR("NULL in");
        return false;
    }

    if (in_length % AES_BLOCK_SIZE) {
        ERROR("Bad in_length");
        return false;
    }

    if (iv == NULL) {
        ERROR("NULL iv");
        return false;
    }

    bool status = false;
    uint8_t* wrapping_key = NULL;
    size_t wrapping_key_length = SYM_128_KEY_SIZE;
    do {
        wrapping_key = memory_secure_alloc(wrapping_key_length);
        if (wrapping_key == NULL) {
            ERROR("memory_secure_alloc failed");
            break;
        }

        // derive wrapping key
        if (!otp_hw_key_ladder(wrapping_key, key_ladder_inputs->c1, key_ladder_inputs->c2, key_ladder_inputs->c3)) {
            ERROR("otp_hw_key_ladder failed");
            break;
        }

        if (!wrap_aes_cbc(wrapped, in, in_length, iv, wrapping_key, wrapping_key_length)) {
            ERROR("wrap_aes_cbc failed");
            break;
        }

        status = true;
    } while (false);

    if (wrapping_key != NULL) {
        memory_memset_unoptimizable(wrapping_key, 0, wrapping_key_length);
        memory_secure_free(wrapping_key);
    }

    return status;
}

bool otp_unwrap_aes_cbc(
        void* out,
        const key_ladder_inputs_t* key_ladder_inputs,
        const void* wrapped,
        size_t wrapped_length,
        const void* iv) {

    if (out == NULL) {
        ERROR("NULL out");
        return false;
    }

    if (key_ladder_inputs == NULL) {
        ERROR("NULL key_ladder_inputs");
        return false;
    }

    if (wrapped == NULL) {
        ERROR("NULL wrapped");
        return false;
    }

    if (wrapped_length % AES_BLOCK_SIZE) {
        ERROR("Bad wrapped_length");
        return false;
    }

    if (iv == NULL) {
        ERROR("NULL iv");
        return false;
    }

    bool status = false;
    uint8_t* wrapping_key = NULL;
    size_t wrapping_key_length = SYM_128_KEY_SIZE;
    do {
        wrapping_key = memory_secure_alloc(wrapping_key_length);
        if (wrapping_key == NULL) {
            ERROR("memory_secure_alloc failed");
            break;
        }

        // derive wrapping key
        if (!otp_hw_key_ladder(wrapping_key, key_ladder_inputs->c1, key_ladder_inputs->c2, key_ladder_inputs->c3)) {
            ERROR("otp_hw_key_ladder failed");
            break;
        }

        if (!unwrap_aes_cbc_internal(out, wrapped, wrapped_length, iv, wrapping_key, wrapping_key_length)) {
            ERROR("unwrap_aes_cbc_internal failed");
            break;
        }

        status = true;
    } while (false);

    if (wrapping_key != NULL) {
        memory_memset_unoptimizable(wrapping_key, 0, wrapping_key_length);
        memory_secure_free(wrapping_key);
    }

    return status;
}

bool otp_unwrap_aes_gcm(
        void* out,
        const key_ladder_inputs_t* key_ladder_inputs,
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
        return false;
    }

    if (key_ladder_inputs == NULL) {
        ERROR("NULL key_ladder_inputs");
        return false;
    }

    if (wrapped == NULL) {
        ERROR("NULL wrapped");
        return false;
    }

    if (iv == NULL) {
        ERROR("NULL iv");
        return false;
    }

    if (aad == NULL) {
        ERROR("NULL aad");
        return false;
    }

    if (tag == NULL) {
        ERROR("NULL tag");
        return false;
    }

    bool status = false;
    uint8_t* wrapping_key = NULL;
    size_t wrapping_key_length = SYM_128_KEY_SIZE;
    do {
        wrapping_key = memory_secure_alloc(wrapping_key_length);
        if (wrapping_key == NULL) {
            ERROR("memory_secure_alloc failed");
            break;
        }

        // derive wrapping key
        if (!otp_hw_key_ladder(wrapping_key, key_ladder_inputs->c1, key_ladder_inputs->c2, key_ladder_inputs->c3)) {
            ERROR("otp_hw_key_ladder failed");
            break;
        }

        if (!unwrap_aes_gcm_internal(out, wrapped, wrapped_length, iv, iv_length, aad, aad_length, tag, tag_length,
                    wrapping_key, wrapping_key_length)) {
            ERROR("unwrap_aes_gcm_internal failed");
            break;
        }

        status = true;
    } while (false);

    if (wrapping_key != NULL) {
        memory_memset_unoptimizable(wrapping_key, 0, wrapping_key_length);
        memory_secure_free(wrapping_key);
    }

    return status;
}

bool otp_hmac_sha256(
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
        return false;
    }

    if (key_ladder_inputs == NULL) {
        ERROR("NULL key_ladder_inputs");
        return false;
    }

    if (in1 == NULL && in1_length > 0) {
        ERROR("NULL in1");
        return false;
    }

    if (in2 == NULL && in2_length > 0) {
        ERROR("NULL in2");
        return false;
    }

    if (in3 == NULL && in3_length > 0) {
        ERROR("NULL in3");
        return false;
    }

    bool status = false;
    uint8_t* hmac_key = NULL;
    size_t hmac_key_length = SYM_128_KEY_SIZE;

    do {
        hmac_key = memory_secure_alloc(hmac_key_length);
        if (hmac_key == NULL) {
            ERROR("memory_secure_alloc failed");
            break;
        }

        // derive integrity key
        if (!otp_hw_key_ladder(hmac_key, key_ladder_inputs->c1, key_ladder_inputs->c2, key_ladder_inputs->c3)) {
            ERROR("otp_hw_key_ladder failed");
            break;
        }

        size_t mac_length = SHA256_DIGEST_LENGTH;
        if (!hmac_internal(mac, &mac_length, SA_DIGEST_ALGORITHM_SHA256, in1, in1_length, in2, in2_length, in3,
                    in3_length, hmac_key, hmac_key_length)) {
            ERROR("hmac_internal failed");
            break;
        }

        status = true;
    } while (false);

    if (hmac_key != NULL) {
        memory_memset_unoptimizable(hmac_key, 0, hmac_key_length);
        memory_secure_free(hmac_key);
    }

    return status;
}
