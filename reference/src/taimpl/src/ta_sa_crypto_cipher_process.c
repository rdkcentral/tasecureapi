/*
 * Copyright 2020-2025 Comcast Cable Communications Management, LLC
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

#include "buffer.h"
#include "cipher_store.h"
#include "client_store.h"
#include "common.h"
#include "digest.h"
#include "ec.h"
#include "log.h"
#include "rights.h"
#include "rsa.h"
#include "ta_sa.h"

static size_t get_required_length(
        cipher_t* cipher,
        size_t bytes_to_process,
        bool apply_padding) {
    sa_cipher_algorithm cipher_algorithm = cipher_get_algorithm(cipher);

    switch (cipher_algorithm) {
        case SA_CIPHER_ALGORITHM_AES_CBC:
        case SA_CIPHER_ALGORITHM_AES_CTR:
        case SA_CIPHER_ALGORITHM_AES_ECB:
        case SA_CIPHER_ALGORITHM_AES_GCM:
        case SA_CIPHER_ALGORITHM_CHACHA20:
        case SA_CIPHER_ALGORITHM_CHACHA20_POLY1305:
            return bytes_to_process;

        case SA_CIPHER_ALGORITHM_AES_CBC_PKCS7:
        case SA_CIPHER_ALGORITHM_AES_ECB_PKCS7:
            return bytes_to_process + (apply_padding ? AES_BLOCK_SIZE : 0);

        case SA_CIPHER_ALGORITHM_RSA_PKCS1V15:
        case SA_CIPHER_ALGORITHM_RSA_OAEP:
        case SA_CIPHER_ALGORITHM_EC_ELGAMAL:
            return cipher_get_key_size(cipher);

        default:
            return 0;
    }
}

static sa_status ta_sa_crypto_cipher_process_symmetric(
        void* out,
        cipher_t* cipher,
        const void* in,
        size_t* bytes_to_process,
        const sa_uuid* caller_uuid) {

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (cipher == NULL) {
        ERROR("NULL cipher");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (bytes_to_process == NULL) {
        ERROR("NULL bytes_to_process");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_cipher_algorithm cipher_algorithm = cipher_get_algorithm(cipher);
    if ((cipher_algorithm == SA_CIPHER_ALGORITHM_AES_CBC || cipher_algorithm == SA_CIPHER_ALGORITHM_AES_CBC_PKCS7 ||
                cipher_algorithm == SA_CIPHER_ALGORITHM_AES_ECB ||
                cipher_algorithm == SA_CIPHER_ALGORITHM_AES_ECB_PKCS7) &&
            (*bytes_to_process % AES_BLOCK_SIZE != 0)) {
        ERROR("Invalid bytes_to_process");
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

    symmetric_context_t* symmetric_context = cipher_get_symmetric_context(cipher);
    if (symmetric_context == NULL) {
        ERROR("cipher_get_symmetric_context failed");
        return SA_STATUS_NULL_PARAMETER;
    }

    const sa_rights* rights = cipher_get_key_rights(cipher);
    if (rights == NULL) {
        ERROR("cipher_get_key_rights failed");
        return SA_STATUS_INTERNAL_ERROR;
    }

    sa_cipher_mode cipher_mode = cipher_get_mode(cipher);
    if (cipher_mode == SA_CIPHER_MODE_ENCRYPT) {
        if (!rights_allowed_encrypt(rights, SA_KEY_TYPE_SYMMETRIC)) {
            ERROR("rights_allowed_encrypt failed");
            return SA_STATUS_OPERATION_NOT_ALLOWED;
        }

        size_t length = *bytes_to_process;
        sa_status status = symmetric_context_encrypt(symmetric_context, out, &length, in, *bytes_to_process);
        if (status != SA_STATUS_OK) {
            ERROR("symmetric_context_encrypt failed");
            return status;
        }

        *bytes_to_process = length;
    } else if (cipher_mode == SA_CIPHER_MODE_DECRYPT) {
        if (!rights_allowed_decrypt(rights, SA_KEY_TYPE_SYMMETRIC)) {
            ERROR("rights_allowed_decrypt failed");
            return SA_STATUS_OPERATION_NOT_ALLOWED;
        }

        size_t length = *bytes_to_process;
        sa_status status = symmetric_context_decrypt(symmetric_context, out, &length, in, *bytes_to_process);
        if (status != SA_STATUS_OK) {
            ERROR("symmetric_context_decrypt failed");
            return status;
        }

        *bytes_to_process = length;
    } else {
        ERROR("Unknown mode encountered");
        return SA_STATUS_INTERNAL_ERROR;
    }

    return SA_STATUS_OK;
}

static sa_status ta_sa_crypto_cipher_process_rsa_pkcs1v15(
        void* out,
        size_t out_length,
        cipher_t* cipher,
        const void* in,
        size_t* bytes_to_process,
        const sa_uuid* caller_uuid) {

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (cipher == NULL) {
        ERROR("NULL cipher");
        return SA_STATUS_NULL_PARAMETER;
    }

    size_t key_size = cipher_get_key_size(cipher);
    if (key_size == 0) {
        ERROR("cipher_get_key_size failed");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (out == NULL) {
        ERROR("NULL out");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (*bytes_to_process != key_size) {
        ERROR("Invalid bytes_to_process");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (in == NULL) {
        ERROR("NULL in");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_cipher_mode cipher_mode = cipher_get_mode(cipher);
    if (cipher_mode != SA_CIPHER_MODE_DECRYPT) {
        ERROR("Invalid cipher mode");
        return SA_STATUS_INVALID_PARAMETER;
    }

    const sa_rights* rights = cipher_get_key_rights(cipher);
    if (rights == NULL) {
        ERROR("cipher_get_key_rights failed");
        return SA_STATUS_INTERNAL_ERROR;
    }

    if (!rights_allowed_decrypt(rights, SA_KEY_TYPE_RSA)) {
        ERROR("rights_allowed_decrypt failed");
        return SA_STATUS_OPERATION_NOT_ALLOWED;
    }

    const stored_key_t* stored_key = cipher_get_stored_key(cipher);
    if (stored_key == NULL) {
        ERROR("cipher_get_stored_key failed");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status = rsa_decrypt_pkcs1v15(out, &out_length, stored_key, in, *bytes_to_process);
    if (status != SA_STATUS_OK) {
        ERROR("rsa_decrypt_pkcs1v15 failed");
        return status;
    }

    *bytes_to_process = out_length;
    return status;
}
static sa_status ta_sa_crypto_cipher_process_rsa_oaep(
        void* out,
        size_t out_length,
        cipher_t* cipher,
        const void* in,
        size_t* bytes_to_process,
        const sa_uuid* caller_uuid) {

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (cipher == NULL) {
        ERROR("NULL cipher");
        return SA_STATUS_NULL_PARAMETER;
    }

    size_t key_size = cipher_get_key_size(cipher);
    if (key_size == 0) {
        ERROR("cipher_get_key_size failed");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (out == NULL) {
        ERROR("NULL out");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (*bytes_to_process != key_size) {
        ERROR("Invalid bytes_to_process");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (in == NULL) {
        ERROR("NULL in");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_cipher_mode cipher_mode = cipher_get_mode(cipher);
    if (cipher_mode != SA_CIPHER_MODE_DECRYPT) {
        ERROR("Invalid cipher mode");
        return SA_STATUS_INVALID_PARAMETER;
    }

    const sa_rights* rights = cipher_get_key_rights(cipher);
    if (rights == NULL) {
        ERROR("cipher_get_key_rights failed");
        return SA_STATUS_INTERNAL_ERROR;
    }

    if (!rights_allowed_decrypt(rights, SA_KEY_TYPE_RSA)) {
        ERROR("rights_allowed_decrypt failed");
        return SA_STATUS_OPERATION_NOT_ALLOWED;
    }

    const stored_key_t* stored_key = cipher_get_stored_key(cipher);
    if (stored_key == NULL) {
        ERROR("cipher_get_stored_key failed");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_digest_algorithm digest_algorithm;
    sa_digest_algorithm mgf1_digest_algorithm;
    const void* label;
    size_t label_length;
    if (cipher_get_oaep_parameters(cipher, &digest_algorithm, &mgf1_digest_algorithm, &label, &label_length) !=
            SA_STATUS_OK) {
        ERROR("cipher_get_oaep_parameters failed");
        return SA_STATUS_INTERNAL_ERROR;
    }

    sa_status status = rsa_decrypt_oaep(out, &out_length, stored_key, digest_algorithm, mgf1_digest_algorithm, label,
            label_length, in, *bytes_to_process);
    if (status != SA_STATUS_OK) {
        ERROR("rsa_decrypt_oaep failed");
        return status;
    }

    *bytes_to_process = out_length;
    return status;
}

static sa_status ta_sa_crypto_cipher_process_ec_elgamal(
        void* out,
        cipher_t* cipher,
        const void* in,
        size_t* bytes_to_process,
        const sa_uuid* caller_uuid) {

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (cipher == NULL) {
        ERROR("NULL cipher");
        return SA_STATUS_NULL_PARAMETER;
    }

    size_t key_size = cipher_get_key_size(cipher);
    if (key_size == 0) {
        ERROR("cipher_get_ec_key_size failed");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (out == NULL) {
        ERROR("NULL out");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (*bytes_to_process != key_size * 4) {
        ERROR("Invalid bytes_to_process");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (in == NULL) {
        ERROR("NULL in");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_cipher_mode cipher_mode = cipher_get_mode(cipher);
    if (cipher_mode != SA_CIPHER_MODE_DECRYPT) {
        ERROR("Invalid cipher mode");
        return SA_STATUS_INVALID_PARAMETER;
    }

    const sa_rights* rights = cipher_get_key_rights(cipher);
    if (rights == NULL) {
        ERROR("cipher_get_key_rights failed");
        return SA_STATUS_INTERNAL_ERROR;
    }

    if (!rights_allowed_decrypt(rights, SA_KEY_TYPE_EC)) {
        ERROR("rights_allowed_decrypt failed");
        return SA_STATUS_OPERATION_NOT_ALLOWED;
    }

    size_t out_length = *bytes_to_process;
    const stored_key_t* stored_key = cipher_get_stored_key(cipher);
    if (stored_key == NULL) {
        ERROR("cipher_get_stored_key failed");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (ec_decrypt_elgamal(out, &out_length, stored_key, in, *bytes_to_process) != SA_STATUS_OK) {
        ERROR("ec_decrypt_elgamal failed");
        return SA_STATUS_VERIFICATION_FAILED;
    }

    *bytes_to_process = out_length;
    return SA_STATUS_OK;
}

sa_status ta_sa_crypto_cipher_process(
        sa_buffer* out,
        sa_crypto_cipher_context context,
        sa_buffer* in,
        size_t* bytes_to_process,
        ta_client client_slot,
        const sa_uuid* caller_uuid) {

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (bytes_to_process == NULL) {
        ERROR("NULL bytes_to_process");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (in == NULL) {
        ERROR("NULL in");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status;
    client_store_t* client_store = client_store_global();
    client_t* client = NULL;
    cipher_store_t* cipher_store = NULL;
    cipher_t* cipher = NULL;
    svp_t* out_svp = NULL;
    svp_t* in_svp = NULL;
    do {
        status = client_store_acquire(&client, client_store, client_slot, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("client_store_acquire failed");
            break;
        }

        cipher_store = client_get_cipher_store(client);
        status = cipher_store_acquire_exclusive(&cipher, cipher_store, context, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("cipher_store_acquire_exclusive failed");
            status = SA_STATUS_INVALID_PARAMETER;
            break;
        }

        sa_cipher_mode cipher_mode = cipher_get_mode(cipher);
        size_t required_length = get_required_length(cipher, *bytes_to_process,
                !out && cipher_mode == SA_CIPHER_MODE_ENCRYPT);
        if (out == NULL) {
            *bytes_to_process = required_length;
            status = SA_STATUS_OK;
            break;
        }

        if (out->buffer_type != SA_BUFFER_TYPE_CLEAR && out->buffer_type != SA_BUFFER_TYPE_SVP) {
            ERROR("Invalid out buffer type");
            return SA_STATUS_INVALID_PARAMETER;
        }

        if (in->buffer_type != SA_BUFFER_TYPE_CLEAR && in->buffer_type != SA_BUFFER_TYPE_SVP) {
            ERROR("Invalid in buffer type");
            return SA_STATUS_INVALID_PARAMETER;
        }

        sa_cipher_algorithm cipher_algorithm = cipher_get_algorithm(cipher);
        if ((out->buffer_type == SA_BUFFER_TYPE_SVP || in->buffer_type == SA_BUFFER_TYPE_SVP) &&
                (cipher_algorithm == SA_CIPHER_ALGORITHM_AES_GCM ||
                        cipher_algorithm == SA_CIPHER_ALGORITHM_CHACHA20_POLY1305 ||
                        cipher_algorithm == SA_CIPHER_ALGORITHM_RSA_OAEP ||
                        cipher_algorithm == SA_CIPHER_ALGORITHM_RSA_PKCS1V15 ||
                        cipher_algorithm == SA_CIPHER_ALGORITHM_EC_ELGAMAL)) {
            ERROR("Invalid algorithm");
            status = SA_STATUS_OPERATION_NOT_ALLOWED;
            break;
        }

        if (out->buffer_type == SA_BUFFER_TYPE_CLEAR && in->buffer_type != out->buffer_type) {
            ERROR("buffer_type mismatch");
            status = SA_STATUS_INVALID_PARAMETER;
            break;
        }

        const sa_rights* rights = cipher_get_key_rights(cipher);
        if (rights == NULL) {
            ERROR("cipher_get_key_rights failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        if (out->buffer_type == SA_BUFFER_TYPE_CLEAR && !rights_allowed_clear(rights)) {
            ERROR("rights_allowed_clear failed");
            status = SA_STATUS_OPERATION_NOT_ALLOWED;
            break;
        }

        uint8_t* out_bytes = NULL;
        status = convert_buffer(&out_bytes, &out_svp, out, required_length, client, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("convert_buffer failed");
            break;
        }

        uint8_t* in_bytes = NULL;
        status = convert_buffer(&in_bytes, &in_svp, in, *bytes_to_process, client, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("convert_buffer failed");
            break;
        }

        size_t in_length = *bytes_to_process;
        if (cipher_algorithm == SA_CIPHER_ALGORITHM_AES_ECB ||
                cipher_algorithm == SA_CIPHER_ALGORITHM_AES_ECB_PKCS7 ||
                cipher_algorithm == SA_CIPHER_ALGORITHM_AES_CBC ||
                cipher_algorithm == SA_CIPHER_ALGORITHM_AES_CBC_PKCS7 ||
                cipher_algorithm == SA_CIPHER_ALGORITHM_AES_CTR ||
                cipher_algorithm == SA_CIPHER_ALGORITHM_AES_GCM ||
                cipher_algorithm == SA_CIPHER_ALGORITHM_CHACHA20 ||
                cipher_algorithm == SA_CIPHER_ALGORITHM_CHACHA20_POLY1305) {
            status = ta_sa_crypto_cipher_process_symmetric(out_bytes, cipher, in_bytes, bytes_to_process, caller_uuid);
            if (status != SA_STATUS_OK) {
                ERROR("ta_sa_crypto_cipher_process_aes failed");
                break;
            }
        } else if (cipher_algorithm == SA_CIPHER_ALGORITHM_RSA_PKCS1V15) {
            status = ta_sa_crypto_cipher_process_rsa_pkcs1v15(out_bytes, required_length, cipher, in_bytes,
                    bytes_to_process, caller_uuid);
            if (status != SA_STATUS_OK) {
                ERROR("ta_sa_crypto_cipher_process_rsa_pkcs1v15 failed");
                break;
            }
        } else if (cipher_algorithm == SA_CIPHER_ALGORITHM_RSA_OAEP) {
            status = ta_sa_crypto_cipher_process_rsa_oaep(out_bytes, required_length, cipher, in_bytes,
                    bytes_to_process, caller_uuid);
            if (status != SA_STATUS_OK) {
                ERROR("ta_sa_crypto_cipher_process_rsa_oaep failed");
                break;
            }
        } else if (cipher_algorithm == SA_CIPHER_ALGORITHM_EC_ELGAMAL) {
            status = ta_sa_crypto_cipher_process_ec_elgamal(out_bytes, cipher, in_bytes, bytes_to_process, caller_uuid);
            if (status != SA_STATUS_OK) {
                ERROR("ta_sa_crypto_cipher_process_ec_elgamal failed");
                break;
            }
        } else {
            ERROR("Unknown algorithm encountered");
            status = SA_STATUS_INVALID_PARAMETER;
            break;
        }

        if (out != NULL) {
            if (in->buffer_type == SA_BUFFER_TYPE_CLEAR) {
                in->context.clear.offset += in_length;
	    }
#ifndef DISABLE_SVP
	    else if ( in->buffer_type == SA_BUFFER_TYPE_SVP) {
                in->context.svp.offset += in_length;
	    }
#endif

            if (out->buffer_type == SA_BUFFER_TYPE_CLEAR) {
                out->context.clear.offset += *bytes_to_process;
	    }
#ifndef DISABLE_SVP
	    else if ( out->buffer_type == SA_BUFFER_TYPE_SVP) {
                //in->context.svp.offset += in_length;
                out->context.svp.offset += *bytes_to_process;
	    }
#endif
        }
    } while (false);

#ifndef DISABLE_SVP
    if (in_svp != NULL)
        svp_store_release_exclusive(client_get_svp_store(client), in->context.svp.buffer, in_svp, caller_uuid);

    if (out_svp != NULL)
        svp_store_release_exclusive(client_get_svp_store(client), out->context.svp.buffer, out_svp, caller_uuid);
#endif
    if (cipher != NULL)
        cipher_store_release_exclusive(cipher_store, context, cipher, caller_uuid);

    client_store_release(client_store, client_slot, client, caller_uuid);

    return status;
}
