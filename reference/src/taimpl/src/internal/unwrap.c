/**
 * Copyright 2019-2022 Comcast Cable Communications Management, LLC
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

#include "unwrap.h" // NOLINT
#include "common.h"
#include "ec.h"
#include "log.h"
#include "pad.h"
#include "porting/memory.h"
#include "porting/otp_internal.h"
#include "rsa.h"
#include "stored_key_internal.h"
#include <openssl/evp.h>
#if OPENSSL_VERSION_NUMBER >= 0x10100000
#include <memory.h>
#endif

static sa_status import_key(
        stored_key_t** stored_key_unwrapped,
        const sa_rights* rights,
        const sa_rights* wrapping_key_rights,
        sa_key_type key_type,
        void* parameters,
        const void* in,
        size_t in_length) {

    if (rights == NULL) {
        ERROR("NULL rights");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (wrapping_key_rights == NULL) {
        ERROR("NULL wrapping_key_rights");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (key_type != SA_KEY_TYPE_EC && key_type != SA_KEY_TYPE_SYMMETRIC && key_type != SA_KEY_TYPE_RSA) {
        ERROR("Bad key_type");
        return SA_STATUS_BAD_PARAMETER;
    }

    if (key_type == SA_KEY_TYPE_EC && parameters == NULL) {
        ERROR("NULL parameters");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (in == NULL) {
        ERROR("NULL in");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status = SA_STATUS_INTERNAL_ERROR;
    do {
        sa_type_parameters type_parameters;
        memory_memset_unoptimizable(&type_parameters, 0, sizeof(sa_type_parameters));
        size_t key_size = in_length;
        if (key_type == SA_KEY_TYPE_EC) {
            sa_unwrap_type_parameters_ec* ec_parameters = (sa_unwrap_type_parameters_ec*) parameters;
            key_size = ec_validate_private(ec_parameters->curve, in, in_length);
            if (key_size == 0) {
                ERROR("ec_validate_private failed");
                break;
            }

            type_parameters.curve = ec_parameters->curve;
        } else if (key_type == SA_KEY_TYPE_RSA) { // key_type == SA_KEY_TYPE_RSA
            key_size = rsa_validate_private(in, in_length);
            if (key_size == 0) {
                ERROR("rsa_validate_private failed");
                break;
            }
        }

        if (!stored_key_create(stored_key_unwrapped, rights, wrapping_key_rights, key_type, &type_parameters,
                    key_size, in, in_length)) {
            ERROR("stored_key_create failed");
            break;
        }

        status = SA_STATUS_OK;
    } while (false);

    return status;
}

sa_status unwrap_aes_ecb(
        stored_key_t** stored_key_unwrapped,
        const void* in,
        size_t in_length,
        const sa_rights* rights,
        sa_key_type key_type,
        void* parameters,
        sa_cipher_algorithm cipher_algorithm,
        const stored_key_t* stored_key_wrapping) {

    if (stored_key_unwrapped == NULL) {
        ERROR("NULL stored_key_unwrapped");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (in == NULL) {
        ERROR("NULL in");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (rights == NULL) {
        ERROR("NULL rights");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (stored_key_wrapping == NULL) {
        ERROR("NULL stored_key_wrapping");
        return SA_STATUS_NULL_PARAMETER;
    }

    const void* key = stored_key_get_key(stored_key_wrapping);
    if (key == NULL) {
        ERROR("stored_key_get_key failed");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status;
    size_t key_length = stored_key_get_length(stored_key_wrapping);
    uint8_t* unwrapped_key = NULL;
    do {
        unwrapped_key = memory_secure_alloc(in_length);
        if (unwrapped_key == NULL) {
            ERROR("memory_secure_alloc failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        if (!unwrap_aes_ecb_internal(unwrapped_key, in, in_length, key, key_length)) {
            ERROR("unwrap_aes_ecb_internal failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        uint8_t pad_value = 0;
        if (cipher_algorithm == SA_CIPHER_ALGORITHM_AES_ECB_PKCS7) {
            if (!pad_check_pkcs7(&pad_value, unwrapped_key + in_length - AES_BLOCK_SIZE)) {
                ERROR("pad_check_pkcs7 failed");
                status = SA_STATUS_BAD_KEY_FORMAT;
                break;
            }
        }

        const sa_header* header = stored_key_get_header(stored_key_wrapping);
        if (header == NULL) {
            ERROR("stored_key_get_header failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        status = import_key(stored_key_unwrapped, rights, &header->rights, key_type, parameters, unwrapped_key,
                in_length - pad_value);
        if (status != SA_STATUS_OK) {
            ERROR("import_key failed");
            break;
        }
    } while (false);

    if (unwrapped_key != NULL) {
        memory_memset_unoptimizable(unwrapped_key, 0, in_length);
        memory_secure_free(unwrapped_key);
    }

    return status;
}

sa_status unwrap_aes_cbc(
        stored_key_t** stored_key_unwrapped,
        const void* in,
        size_t in_length,
        const sa_rights* rights,
        sa_key_type key_type,
        void* parameters,
        sa_cipher_algorithm cipher_algorithm,
        const void* iv,
        const stored_key_t* stored_key_wrapping) {

    if (stored_key_unwrapped == NULL) {
        ERROR("NULL stored_key_unwrapped");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (in == NULL) {
        ERROR("NULL in");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (rights == NULL) {
        ERROR("NULL rights");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (iv == NULL) {
        ERROR("NULL iv");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (stored_key_wrapping == NULL) {
        ERROR("NULL stored_key_wrapping");
        return SA_STATUS_NULL_PARAMETER;
    }

    const void* key = stored_key_get_key(stored_key_wrapping);
    if (key == NULL) {
        ERROR("stored_key_get_key failed");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status;
    size_t key_length = stored_key_get_length(stored_key_wrapping);
    uint8_t* unwrapped_key = NULL;
    do {
        unwrapped_key = memory_secure_alloc(in_length);
        if (unwrapped_key == NULL) {
            ERROR("memory_secure_alloc failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        if (!unwrap_aes_cbc_internal(unwrapped_key, in, in_length, iv, key, key_length)) {
            ERROR("unwrap_aes_ecb_internal failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        uint8_t pad_value = 0;
        if (cipher_algorithm == SA_CIPHER_ALGORITHM_AES_CBC_PKCS7) {
            if (!pad_check_pkcs7(&pad_value, unwrapped_key + in_length - AES_BLOCK_SIZE)) {
                ERROR("pad_check_pkcs7 failed");
                status = SA_STATUS_BAD_KEY_FORMAT;
                break;
            }
        }

        const sa_header* header = stored_key_get_header(stored_key_wrapping);
        if (header == NULL) {
            ERROR("stored_key_get_header failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        status = import_key(stored_key_unwrapped, rights, &header->rights, key_type, parameters, unwrapped_key,
                in_length - pad_value);
        if (status != SA_STATUS_OK) {
            ERROR("import_key failed");
            break;
        }
    } while (false);

    if (unwrapped_key != NULL) {
        memory_memset_unoptimizable(unwrapped_key, 0, in_length);
        memory_secure_free(unwrapped_key);
    }

    return status;
}

sa_status unwrap_aes_ctr(
        stored_key_t** stored_key_unwrapped,
        const void* in,
        size_t in_length,
        const sa_rights* rights,
        sa_key_type key_type,
        void* parameters,
        const void* ctr,
        const stored_key_t* stored_key_wrapping) {

    if (stored_key_unwrapped == NULL) {
        ERROR("NULL stored_key_unwrapped");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (in == NULL) {
        ERROR("NULL in");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (rights == NULL) {
        ERROR("NULL rights");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (ctr == NULL) {
        ERROR("NULL parameters");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (stored_key_wrapping == NULL) {
        ERROR("NULL stored_key_wrapping");
        return SA_STATUS_NULL_PARAMETER;
    }

    const void* key = stored_key_get_key(stored_key_wrapping);
    if (key == NULL) {
        ERROR("stored_key_get_key failed");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status;
    size_t key_length = stored_key_get_length(stored_key_wrapping);
    EVP_CIPHER_CTX* context = NULL;
    uint8_t* unwrapped_key = NULL;
    do {
        unwrapped_key = memory_secure_alloc(in_length);
        if (unwrapped_key == NULL) {
            ERROR("memory_secure_alloc failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        context = EVP_CIPHER_CTX_new();
        if (context == NULL) {
            ERROR("EVP_CIPHER_CTX_new failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        const EVP_CIPHER* cipher = NULL;
        if (key_length == SYM_128_KEY_SIZE)
            cipher = EVP_aes_128_ctr();
        else // key_length == SYM_256_KEY_SIZE
            cipher = EVP_aes_256_ctr();

        if (cipher == NULL) {
            ERROR("EVP_aes_???_ctr failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        if (EVP_DecryptInit_ex(context, cipher, NULL, key, ctr) != 1) {
            ERROR("EVP_DecryptInit_ex failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        // turn off padding
        if (EVP_CIPHER_CTX_set_padding(context, 0) != 1) {
            ERROR("EVP_CIPHER_CTX_set_padding failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        int out_length = (int) in_length;
        if (EVP_DecryptUpdate(context, unwrapped_key, &out_length, in, (int) in_length) != 1) {
            ERROR("EVP_DecryptUpdate failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        const sa_header* header = stored_key_get_header(stored_key_wrapping);
        if (header == NULL) {
            ERROR("stored_key_get_header failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        status = import_key(stored_key_unwrapped, rights, &header->rights, key_type, parameters, unwrapped_key,
                in_length);
        if (status != SA_STATUS_OK) {
            ERROR("import_key failed");
            break;
        }
    } while (false);

    if (unwrapped_key != NULL) {
        memory_memset_unoptimizable(unwrapped_key, 0, in_length);
        memory_secure_free(unwrapped_key);
    }

    EVP_CIPHER_CTX_free(context);
    return status;
}

sa_status unwrap_aes_gcm(
        stored_key_t** stored_key_unwrapped,
        const void* in,
        size_t in_length,
        const sa_rights* rights,
        sa_key_type key_type,
        void* parameters,
        const sa_unwrap_parameters_aes_gcm* algorithm_parameters,
        const stored_key_t* stored_key_wrapping) {

    if (stored_key_unwrapped == NULL) {
        ERROR("NULL stored_key_unwrapped");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (in == NULL) {
        ERROR("NULL in");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (rights == NULL) {
        ERROR("NULL rights");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (algorithm_parameters == NULL) {
        ERROR("NULL algorithm_parameters");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (stored_key_wrapping == NULL) {
        ERROR("NULL stored_key_wrapping");
        return SA_STATUS_NULL_PARAMETER;
    }

    const void* key = stored_key_get_key(stored_key_wrapping);
    if (key == NULL) {
        ERROR("stored_key_get_key failed");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status;
    size_t key_length = stored_key_get_length(stored_key_wrapping);
    uint8_t* unwrapped_key = NULL;
    do {
        unwrapped_key = memory_secure_alloc(in_length);
        if (unwrapped_key == NULL) {
            ERROR("memory_secure_alloc failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        if (!unwrap_aes_gcm_internal(unwrapped_key, in, in_length,
                    algorithm_parameters->iv, algorithm_parameters->iv_length,
                    algorithm_parameters->aad, algorithm_parameters->aad_length,
                    algorithm_parameters->tag, algorithm_parameters->tag_length,
                    key, key_length)) {
            ERROR("unwrap_aes_gcm_internal failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        const sa_header* header = stored_key_get_header(stored_key_wrapping);
        if (header == NULL) {
            ERROR("stored_key_get_header failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        status = import_key(stored_key_unwrapped, rights, &header->rights, key_type, parameters, unwrapped_key,
                in_length);
        if (status != SA_STATUS_OK) {
            ERROR("import_key failed");
            break;
        }
    } while (false);

    if (unwrapped_key != NULL) {
        memory_memset_unoptimizable(unwrapped_key, 0, in_length);
        memory_secure_free(unwrapped_key);
    }

    return status;
}

#if OPENSSL_VERSION_NUMBER >= 0x10100000
sa_status unwrap_chacha20(
        stored_key_t** stored_key_unwrapped,
        const void* in,
        size_t in_length,
        const sa_rights* rights,
        sa_key_type key_type,
        void* type_parameters,
        const sa_unwrap_parameters_chacha20* parameters,
        const stored_key_t* stored_key_wrapping) {

    if (stored_key_unwrapped == NULL) {
        ERROR("NULL stored_key_unwrapped");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (in == NULL) {
        ERROR("NULL in");
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

    if (stored_key_wrapping == NULL) {
        ERROR("NULL stored_key_wrapping");
        return SA_STATUS_NULL_PARAMETER;
    }

    const void* key = stored_key_get_key(stored_key_wrapping);
    if (key == NULL) {
        ERROR("stored_key_get_key failed");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status;
    EVP_CIPHER_CTX* context = NULL;
    uint8_t* unwrapped_key = NULL;
    do {
        unwrapped_key = memory_secure_alloc(in_length);
        if (unwrapped_key == NULL) {
            ERROR("memory_secure_alloc failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        context = EVP_CIPHER_CTX_new();
        if (context == NULL) {
            ERROR("EVP_CIPHER_CTX_new failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        const EVP_CIPHER* cipher = EVP_chacha20();
        if (cipher == NULL) {
            ERROR("EVP_chacha20 failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        uint8_t iv[CHACHA20_COUNTER_LENGTH + CHACHA20_NONCE_LENGTH];
        memcpy(iv, parameters->counter, parameters->counter_length);
        memcpy(iv + CHACHA20_COUNTER_LENGTH, parameters->nonce, parameters->nonce_length);
        if (EVP_DecryptInit_ex(context, cipher, NULL, key, iv) != 1) {
            ERROR("EVP_DecryptInit_ex failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        // turn off padding
        if (EVP_CIPHER_CTX_set_padding(context, 0) != 1) {
            ERROR("EVP_CIPHER_CTX_set_padding failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        int out_length = (int) in_length;
        if (EVP_DecryptUpdate(context, unwrapped_key, &out_length, in, (int) in_length) != 1) {
            ERROR("EVP_DecryptUpdate failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        const sa_header* header = stored_key_get_header(stored_key_wrapping);
        if (header == NULL) {
            ERROR("stored_key_get_header failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        status = import_key(stored_key_unwrapped, rights, &header->rights, key_type, type_parameters, unwrapped_key,
                in_length);
        if (status != SA_STATUS_OK) {
            ERROR("import_key failed");
            break;
        }
    } while (false);

    if (unwrapped_key != NULL) {
        memory_memset_unoptimizable(unwrapped_key, 0, in_length);
        memory_secure_free(unwrapped_key);
    }

    EVP_CIPHER_CTX_free(context);
    return status;
}

sa_status unwrap_chacha20_poly1305(
        stored_key_t** stored_key_unwrapped,
        const void* in,
        size_t in_length,
        const sa_rights* rights,
        sa_key_type key_type,
        void* type_parameters,
        const sa_unwrap_parameters_chacha20_poly1305* parameters,
        const stored_key_t* stored_key_wrapping) {

    if (stored_key_unwrapped == NULL) {
        ERROR("NULL stored_key_unwrapped");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (in == NULL) {
        ERROR("NULL in");
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

    if (stored_key_wrapping == NULL) {
        ERROR("NULL stored_key_wrapping");
        return SA_STATUS_NULL_PARAMETER;
    }

    const void* key = stored_key_get_key(stored_key_wrapping);
    if (key == NULL) {
        ERROR("stored_key_get_key failed");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status;
    EVP_CIPHER_CTX* context = NULL;
    uint8_t* unwrapped_key = NULL;
    do {
        unwrapped_key = memory_secure_alloc(in_length);
        if (unwrapped_key == NULL) {
            ERROR("memory_secure_alloc failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        context = EVP_CIPHER_CTX_new();
        if (context == NULL) {
            ERROR("EVP_CIPHER_CTX_new failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        const EVP_CIPHER* cipher = EVP_chacha20_poly1305();
        if (cipher == NULL) {
            ERROR("EVP_chacha20_poly1305 failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        if (EVP_DecryptInit_ex(context, cipher, NULL, NULL, NULL) != 1) {
            ERROR("EVP_DecryptInit_ex failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        // set nonce length
        if (EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_SET_IVLEN, (int) parameters->nonce_length, NULL) != 1) {
            ERROR("EVP_CIPHER_CTX_ctrl failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        // init key and nonce
        if (EVP_DecryptInit_ex(context, cipher, NULL, key, parameters->nonce) != 1) {
            ERROR("EVP_DecryptInit_ex failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        // turn off padding
        if (EVP_CIPHER_CTX_set_padding(context, 0) != 1) {
            ERROR("EVP_CIPHER_CTX_set_padding failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        // set aad
        if (parameters->aad != NULL) {
            int out_length = 0;
            if (EVP_DecryptUpdate(context, NULL, &out_length, parameters->aad, (int) parameters->aad_length) != 1) {
                ERROR("EVP_DecryptUpdate failed");
                status = SA_STATUS_INTERNAL_ERROR;
                break;
            }
        }

        int out_length = (int) in_length;
        if (EVP_DecryptUpdate(context, unwrapped_key, &out_length, in, (int) in_length) != 1) {
            ERROR("EVP_DecryptUpdate failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        // check tag
        if (EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_SET_TAG, (int) parameters->tag_length,
                    (void*) parameters->tag) != 1) {
            ERROR("EVP_CIPHER_CTX_ctrl failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        int length = 0;
        if (EVP_DecryptFinal_ex(context, NULL, &length) != 1) {
            ERROR("EVP_DecryptFinal_ex failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        const sa_header* header = stored_key_get_header(stored_key_wrapping);
        if (header == NULL) {
            ERROR("stored_key_get_header failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        status = import_key(stored_key_unwrapped, rights, &header->rights, key_type, type_parameters, unwrapped_key,
                in_length);
        if (status != SA_STATUS_OK) {
            ERROR("import_key failed");
            break;
        }
    } while (false);

    if (unwrapped_key != NULL) {
        memory_memset_unoptimizable(unwrapped_key, 0, in_length);
        memory_secure_free(unwrapped_key);
    }

    EVP_CIPHER_CTX_free(context);
    return status;
}
#endif

sa_status unwrap_rsa(
        stored_key_t** stored_key_unwrapped,
        const void* in,
        size_t in_length,
        const sa_rights* rights,
        sa_key_type key_type,
        sa_cipher_algorithm cipher_algorithm,
        void* parameters,
        const stored_key_t* stored_key_wrapping) {

    if (stored_key_unwrapped == NULL) {
        ERROR("NULL stored_key_unwrapped");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (in == NULL) {
        ERROR("NULL in");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (rights == NULL) {
        ERROR("NULL rights");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (stored_key_wrapping == NULL) {
        ERROR("NULL stored_key_wrapping");
        return SA_STATUS_NULL_PARAMETER;
    }

    const void* key = stored_key_get_key(stored_key_wrapping);
    if (key == NULL) {
        ERROR("stored_key_get_key failed");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status;
    uint8_t* unwrapped_key = NULL;
    do {
        unwrapped_key = memory_secure_alloc(in_length);
        if (unwrapped_key == NULL) {
            ERROR("memory_secure_alloc failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        size_t unwrapped_key_length = in_length;
        if (cipher_algorithm == SA_CIPHER_ALGORITHM_RSA_OAEP) {
            if (parameters == NULL) {
                ERROR("NULL parameters");
                status = SA_STATUS_BAD_PARAMETER;
                break;
            }

            sa_unwrap_parameters_rsa_oaep* oaep_parameters = (sa_unwrap_parameters_rsa_oaep*) parameters;
            if (oaep_parameters->label == NULL && oaep_parameters->label_length != 0) {
                ERROR("Invalid label_length");
                return SA_STATUS_BAD_PARAMETER;
            }

            if (!rsa_decrypt_oaep(unwrapped_key, &unwrapped_key_length, stored_key_wrapping,
                        oaep_parameters->digest_algorithm, oaep_parameters->mgf1_digest_algorithm,
                        oaep_parameters->label, oaep_parameters->label_length, in, in_length)) {
                ERROR("rsa_decrypt_oaep failed");
                status = SA_STATUS_INTERNAL_ERROR;
                break;
            }
        } else { // algorithm == SA_CIPHER_ALGORITHM_RSA_PKCS1V15
            if (!rsa_decrypt_pkcs1v15(unwrapped_key, &unwrapped_key_length, stored_key_wrapping, in, in_length)) {
                ERROR("rsa_decrypt_pkcs1v15 failed");
                status = SA_STATUS_INTERNAL_ERROR;
                break;
            }
        }

        const sa_header* header = stored_key_get_header(stored_key_wrapping);
        if (header == NULL) {
            ERROR("stored_key_get_header failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        status = import_key(stored_key_unwrapped, rights, &header->rights, SA_KEY_TYPE_SYMMETRIC, 0, unwrapped_key,
                unwrapped_key_length);
        if (status != SA_STATUS_OK) {
            ERROR("import_key failed");
            break;
        }
    } while (false);

    if (unwrapped_key != NULL) {
        memory_memset_unoptimizable(unwrapped_key, 0, in_length);
        memory_secure_free(unwrapped_key);
    }

    return status;
}

sa_status unwrap_ec(
        stored_key_t** stored_key_unwrapped,
        const void* in,
        size_t in_length,
        const sa_rights* rights,
        sa_key_type key_type,
        sa_unwrap_parameters_ec_elgamal* algorithm_parameters,
        const stored_key_t* stored_key_wrapping) {

    if (stored_key_unwrapped == NULL) {
        ERROR("NULL stored_key_unwrapped");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (in == NULL) {
        ERROR("NULL in");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (rights == NULL) {
        ERROR("NULL rights");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (stored_key_wrapping == NULL) {
        ERROR("NULL stored_key_wrapping");
        return SA_STATUS_NULL_PARAMETER;
    }

    const void* key = stored_key_get_key(stored_key_wrapping);
    if (key == NULL) {
        ERROR("stored_key_get_key failed");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status;
    uint8_t* unwrapped_key = NULL;
    size_t unwrapped_key_length;
    do {
        const sa_header* header = stored_key_get_header(stored_key_wrapping);
        if (header == NULL) {
            ERROR("stored_key_get_header failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        unwrapped_key_length = ec_key_size_from_curve(header->type_parameters.curve);
        if (unwrapped_key_length == 0) {
            ERROR("Unexpected ec curve encountered");
            status = SA_STATUS_OPERATION_NOT_SUPPORTED;
            break;
        }

        if (algorithm_parameters->key_length < SYM_128_KEY_SIZE) {
            ERROR("Bad key_length");
            status = SA_STATUS_BAD_PARAMETER;
            break;
        }

        if ((algorithm_parameters->offset + algorithm_parameters->key_length) > unwrapped_key_length) {
            ERROR("Bad offset and key_length combination");
            status = SA_STATUS_BAD_PARAMETER;
            break;
        }

        if (in_length != unwrapped_key_length * 4) {
            ERROR("Bad in_length");
            status = SA_STATUS_BAD_PARAMETER;
            break;
        }

        unwrapped_key = memory_secure_alloc(unwrapped_key_length);
        if (unwrapped_key == NULL) {
            ERROR("memory_secure_alloc failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        size_t written = unwrapped_key_length;
        status = ec_decrypt_elgamal(unwrapped_key, &written, stored_key_wrapping, in, in_length);
        if (status != SA_STATUS_OK) {
            ERROR("ecp256_dec_elgamal failed");
            break;
        }

        if (written != unwrapped_key_length) {
            ERROR("ecp256_dec_elgamal failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        status = import_key(stored_key_unwrapped, rights, &header->rights, SA_KEY_TYPE_SYMMETRIC, 0,
                unwrapped_key + algorithm_parameters->offset, algorithm_parameters->key_length);
        if (status != SA_STATUS_OK) {
            ERROR("import_key failed");
            break;
        }
    } while (false);

    if (unwrapped_key != NULL) {
        memory_memset_unoptimizable(unwrapped_key, 0, unwrapped_key_length);
        memory_secure_free(unwrapped_key);
    }

    return status;
}
