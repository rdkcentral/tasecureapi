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

#include "unwrap.h" // NOLINT
#include "common.h"
#include "ec.h"
#include "log.h"
#include "pad.h"
#include "porting/memory.h"
#include "porting/otp_internal.h"
#include "porting/overflow.h"
#include "rsa.h"
#include "stored_key_internal.h"
#include "mbedtls_header.h"
#include <memory.h>

static sa_status import_key(
        stored_key_t** stored_key_unwrapped,
        const sa_rights* rights,
        const sa_rights* wrapping_key_rights,
        sa_key_type key_type,
        void* algorithm_parameters,
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
        ERROR("Invalid key_type");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (key_type == SA_KEY_TYPE_EC && algorithm_parameters == NULL) {
        ERROR("NULL algorithm_parameters");
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
            sa_unwrap_type_parameters_ec* ec_parameters = (sa_unwrap_type_parameters_ec*) algorithm_parameters;
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

        status = stored_key_create(stored_key_unwrapped, rights, wrapping_key_rights, key_type, &type_parameters,
                key_size, in, in_length);
        if (status != SA_STATUS_OK) {
            ERROR("stored_key_create failed");
            break;
        }
    } while (false);

    return status;
}

sa_status unwrap_aes_ecb(
        stored_key_t** stored_key_unwrapped,
        const void* in,
        size_t in_length,
        const sa_rights* rights,
        sa_key_type key_type,
        void* type_parameters,
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

        status = unwrap_aes_ecb_internal(unwrapped_key, in, in_length, key, key_length);
        if (status != SA_STATUS_OK) {
            ERROR("unwrap_aes_ecb_internal failed");
            break;
        }

        uint8_t pad_value = 0;
        if (cipher_algorithm == SA_CIPHER_ALGORITHM_AES_ECB_PKCS7) {
            if (!pad_check_pkcs7(&pad_value, unwrapped_key + in_length - AES_BLOCK_SIZE)) {
                ERROR("pad_check_pkcs7 failed");
                status = SA_STATUS_INVALID_KEY_FORMAT;
                break;
            }
        }

        const sa_header* header = stored_key_get_header(stored_key_wrapping);
        if (header == NULL) {
            ERROR("stored_key_get_header failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        status = import_key(stored_key_unwrapped, rights, &header->rights, key_type, type_parameters, unwrapped_key,
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
        void* type_parameters,
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

        status = unwrap_aes_cbc_internal(unwrapped_key, in, in_length, iv, key, key_length);
        if (status != SA_STATUS_OK) {
            ERROR("unwrap_aes_cbc_internal failed");
            break;
        }

        uint8_t pad_value = 0;
        if (cipher_algorithm == SA_CIPHER_ALGORITHM_AES_CBC_PKCS7) {
            if (!pad_check_pkcs7(&pad_value, unwrapped_key + in_length - AES_BLOCK_SIZE)) {
                ERROR("pad_check_pkcs7 failed");
                status = SA_STATUS_INVALID_KEY_FORMAT;
                break;
            }
        }

        const sa_header* header = stored_key_get_header(stored_key_wrapping);
        if (header == NULL) {
            ERROR("stored_key_get_header failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        status = import_key(stored_key_unwrapped, rights, &header->rights, key_type, type_parameters, unwrapped_key,
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
        void* type_parameters,
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
    mbedtls_cipher_context_t context;
    mbedtls_cipher_init(&context);
    uint8_t* unwrapped_key = NULL;
    do {
        unwrapped_key = memory_secure_alloc(in_length);
        if (unwrapped_key == NULL) {
            ERROR("memory_secure_alloc failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        // Set up cipher based on key length
        const mbedtls_cipher_info_t* cipher_info = NULL;
        if (key_length == SYM_128_KEY_SIZE)
            cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_CTR);
        else // key_length == SYM_256_KEY_SIZE
            cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_CTR);

        if (cipher_info == NULL) {
            ERROR("mbedtls_cipher_info_from_type failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        if (mbedtls_cipher_setup(&context, cipher_info) != 0) {
            ERROR("mbedtls_cipher_setup failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        if (mbedtls_cipher_setkey(&context, key, (int) (key_length * 8), MBEDTLS_DECRYPT) != 0) {
            ERROR("mbedtls_cipher_setkey failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        // NOTE: CTR mode is a stream cipher - padding mode is not applicable and will fail if set
        // Do not call mbedtls_cipher_set_padding_mode for CTR mode

        size_t out_length = 0;
        if (mbedtls_cipher_crypt(&context, ctr, 16, in, in_length, unwrapped_key, &out_length) != 0) {
            ERROR("mbedtls_cipher_crypt failed");
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

    mbedtls_cipher_free(&context);
    return status;
}

sa_status unwrap_aes_gcm(
        stored_key_t** stored_key_unwrapped,
        const void* in,
        size_t in_length,
        const sa_rights* rights,
        sa_key_type key_type,
        void* type_parameters,
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

        status = unwrap_aes_gcm_internal(unwrapped_key, in, in_length,
                algorithm_parameters->iv, algorithm_parameters->iv_length,
                algorithm_parameters->aad, algorithm_parameters->aad_length,
                algorithm_parameters->tag, algorithm_parameters->tag_length,
                key, key_length);
        if (status != SA_STATUS_OK) {
            ERROR("unwrap_aes_gcm_internal failed");
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

    return status;
}

sa_status unwrap_chacha20(
        stored_key_t** stored_key_unwrapped,
        const void* in,
        size_t in_length,
        const sa_rights* rights,
        sa_key_type key_type,
        void* type_parameters,
        const sa_unwrap_parameters_chacha20* algorithm_parameters,
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
    mbedtls_chacha20_context context;
    mbedtls_chacha20_init(&context);
    uint8_t* unwrapped_key = NULL;
    do {
        unwrapped_key = memory_secure_alloc(in_length);
        if (unwrapped_key == NULL) {
            ERROR("memory_secure_alloc failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        // Set up the key
        if (mbedtls_chacha20_setkey(&context, key) != 0) {
            ERROR("mbedtls_chacha20_setkey failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        // Combine counter and nonce as required by ChaCha20
        uint32_t counter;
        memcpy(&counter, algorithm_parameters->counter, sizeof(counter));
        
        if (mbedtls_chacha20_starts(&context, algorithm_parameters->nonce, counter) != 0) {
            ERROR("mbedtls_chacha20_starts failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        if (mbedtls_chacha20_update(&context, in_length, in, unwrapped_key) != 0) {
            ERROR("mbedtls_chacha20_update failed");
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

    mbedtls_chacha20_free(&context);
    return status;
}

sa_status unwrap_chacha20_poly1305(
        stored_key_t** stored_key_unwrapped,
        const void* in,
        size_t in_length,
        const sa_rights* rights,
        sa_key_type key_type,
        void* type_parameters,
        const sa_unwrap_parameters_chacha20_poly1305* algorithm_parameters,
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
    mbedtls_chachapoly_context context;
    mbedtls_chachapoly_init(&context);
    uint8_t* unwrapped_key = NULL;
    do {
        unwrapped_key = memory_secure_alloc(in_length);
        if (unwrapped_key == NULL) {
            ERROR("memory_secure_alloc failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        // Set up the key
        if (mbedtls_chachapoly_setkey(&context, key) != 0) {
            ERROR("mbedtls_chachapoly_setkey failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        // Perform AEAD decryption with authentication
        if (mbedtls_chachapoly_auth_decrypt(&context,
                    in_length,
                    algorithm_parameters->nonce,
                    algorithm_parameters->aad,
                    algorithm_parameters->aad_length,
                    algorithm_parameters->tag,
                    in,
                    unwrapped_key) != 0) {
            ERROR("mbedtls_chachapoly_auth_decrypt failed");
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

    mbedtls_chachapoly_free(&context);
    return status;
}

sa_status unwrap_rsa(
        stored_key_t** stored_key_unwrapped,
        const void* in,
        size_t in_length,
        const sa_rights* rights,
        sa_cipher_algorithm cipher_algorithm,
        void* algorithm_parameters,
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
            if (algorithm_parameters == NULL) {
                ERROR("NULL algorithm_parameters");
                status = SA_STATUS_INVALID_PARAMETER;
                break;
            }

            sa_unwrap_parameters_rsa_oaep* oaep_parameters = (sa_unwrap_parameters_rsa_oaep*) algorithm_parameters;
            if (oaep_parameters->label == NULL && oaep_parameters->label_length != 0) {
                ERROR("Invalid label_length");
                return SA_STATUS_INVALID_PARAMETER;
            }

            status = rsa_decrypt_oaep(unwrapped_key, &unwrapped_key_length, stored_key_wrapping,
                    oaep_parameters->digest_algorithm, oaep_parameters->mgf1_digest_algorithm,
                    oaep_parameters->label, oaep_parameters->label_length, in, in_length);
            if (status != SA_STATUS_OK) {
                ERROR("rsa_decrypt_oaep failed");
                break;
            }
        } else { // algorithm == SA_CIPHER_ALGORITHM_RSA_PKCS1V15
            status = rsa_decrypt_pkcs1v15(unwrapped_key, &unwrapped_key_length, stored_key_wrapping, in, in_length);
            if (status != SA_STATUS_OK) {
                ERROR("rsa_decrypt_pkcs1v15 failed");
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
            ERROR("Invalid key_length");
            status = SA_STATUS_INVALID_PARAMETER;
            break;
        }

        unsigned long total_length;
        if (add_overflow(algorithm_parameters->offset, algorithm_parameters->key_length, &total_length)) {
            ERROR("Integer overflow");
            status = SA_STATUS_INVALID_PARAMETER;
            break;
        }

        if (total_length > unwrapped_key_length) {
            ERROR("Invalid offset and key_length combination");
            status = SA_STATUS_INVALID_PARAMETER;
            break;
        }

        // SEC1 standard format: Two uncompressed EC points (0x04 || X || Y each)
        // Expected: (1 + 2*key_size) + (1 + 2*key_size) = 2 + 4*key_size bytes
        size_t expected_length = 2 + unwrapped_key_length * 4;
        if (in_length != expected_length) {
            ERROR("Invalid in_length: expected %zu bytes (SEC1 format), received %zu bytes",
                    expected_length, in_length);
            status = SA_STATUS_INVALID_PARAMETER;
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
            ERROR("ec_decrypt_elgamal failed");
            break;
        }

        if (written != unwrapped_key_length) {
            ERROR("ec_decrypt_elgamal failed");
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
