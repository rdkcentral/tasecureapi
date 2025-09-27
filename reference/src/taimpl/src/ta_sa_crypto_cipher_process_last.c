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
#include "log.h"
#include "pad.h"
#include "rights.h"
#include "symmetric.h"
#include "ta_sa.h"

static size_t get_required_length(
        cipher_t* cipher,
        size_t bytes_to_process) {
    sa_cipher_algorithm cipher_algorithm = cipher_get_algorithm(cipher);

    switch (cipher_algorithm) {
        case SA_CIPHER_ALGORITHM_AES_CBC_PKCS7:
        case SA_CIPHER_ALGORITHM_AES_ECB_PKCS7:
            return PADDED_SIZE(bytes_to_process);

        case SA_CIPHER_ALGORITHM_AES_CTR:
        case SA_CIPHER_ALGORITHM_AES_GCM:
        case SA_CIPHER_ALGORITHM_CHACHA20:
        case SA_CIPHER_ALGORITHM_CHACHA20_POLY1305:
            return bytes_to_process;

        default:
            return 0;
    }
}

static sa_status ta_sa_crypto_cipher_process_last_aes_pkcs7(
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

    if (out == NULL) {
        *bytes_to_process = AES_BLOCK_SIZE;
        return SA_STATUS_OK;
    }

    if (in == NULL) {
        ERROR("NULL in");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (*bytes_to_process > AES_BLOCK_SIZE) {
        ERROR("Invalid bytes_to_process");
        return SA_STATUS_INVALID_PARAMETER;
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

    sa_status status = SA_STATUS_INTERNAL_ERROR;
    do {
        if (cipher_mode == SA_CIPHER_MODE_ENCRYPT) {
            if (!rights_allowed_encrypt(rights, SA_KEY_TYPE_SYMMETRIC)) {
                ERROR("rights_allowed_encrypt failed");
                status = SA_STATUS_OPERATION_NOT_ALLOWED;
                break;
            }

            status = symmetric_context_encrypt_last(symmetric_context, out, &out_length, in, *bytes_to_process);
            if (status != SA_STATUS_OK) {
                ERROR("symmetric_context_encrypt failed");
            }

            *bytes_to_process = out_length;
        } else if (cipher_mode == SA_CIPHER_MODE_DECRYPT) {
            if (*bytes_to_process % AES_BLOCK_SIZE != 0) {
                ERROR("Invalid bytes_to_process");
                status = SA_STATUS_INVALID_PARAMETER;
                break;
            }

            if (!rights_allowed_decrypt(rights, SA_KEY_TYPE_SYMMETRIC)) {
                ERROR("rights_allowed_decrypt failed");
                return SA_STATUS_OPERATION_NOT_ALLOWED;
            }

            status = symmetric_context_decrypt_last(symmetric_context, out, &out_length, in, *bytes_to_process);
            if (status != SA_STATUS_OK) {
                ERROR("symmetric_context_decrypt_last failed");
                return status;
            }

            *bytes_to_process = out_length;
        } else {
            ERROR("Unknown mode encountered");
        }
    } while (false);

    return status;
}

static sa_status ta_sa_crypto_cipher_process_last_aes_ctr(
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

        size_t out_length = *bytes_to_process;
        sa_status status = symmetric_context_encrypt_last(symmetric_context, out, &out_length, in, *bytes_to_process);
        if (status != SA_STATUS_OK) {
            ERROR("symmetric_context_encrypt_last failed");
            return status;
        }

        *bytes_to_process = out_length;
    } else if (cipher_mode == SA_CIPHER_MODE_DECRYPT) {
        if (!rights_allowed_decrypt(rights, SA_KEY_TYPE_SYMMETRIC)) {
            ERROR("rights_allowed_decrypt failed");
            return SA_STATUS_OPERATION_NOT_ALLOWED;
        }

        size_t out_length = *bytes_to_process;
        sa_status status = symmetric_context_decrypt_last(symmetric_context, out, &out_length, in, *bytes_to_process);
        if (status != SA_STATUS_OK) {
            ERROR("symmetric_context_decrypt_last failed");
            return status;
        }

        *bytes_to_process = out_length;
    } else {
        ERROR("Unknown mode encountered");
        return SA_STATUS_INTERNAL_ERROR;
    }

    return SA_STATUS_OK;
}

static sa_status ta_sa_crypto_cipher_process_last_chacha20(
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

        size_t out_length = *bytes_to_process;
        sa_status status = symmetric_context_encrypt_last(symmetric_context, out, &out_length, in, *bytes_to_process);
        if (status != SA_STATUS_OK) {
            ERROR("symmetric_context_encrypt_last failed");
            return status;
        }

        *bytes_to_process = out_length;
    } else if (cipher_mode == SA_CIPHER_MODE_DECRYPT) {
        if (!rights_allowed_decrypt(rights, SA_KEY_TYPE_SYMMETRIC)) {
            ERROR("rights_allowed_decrypt failed");
            return SA_STATUS_OPERATION_NOT_ALLOWED;
        }

        size_t out_length = *bytes_to_process;
        sa_status status = symmetric_context_decrypt_last(symmetric_context, out, &out_length, in, *bytes_to_process);
        if (status != SA_STATUS_OK) {
            ERROR("symmetric_context_decrypt_last failed");
            return status;
        }

        *bytes_to_process = out_length;
    } else {
        ERROR("Unknown mode encountered");
        return SA_STATUS_INTERNAL_ERROR;
    }

    return SA_STATUS_OK;
}

static sa_status ta_sa_crypto_cipher_process_last_aes_gcm(
        void* out,
        cipher_t* cipher,
        const void* in,
        size_t* bytes_to_process,
        sa_cipher_end_parameters_aes_gcm* parameters,
        const sa_uuid* caller_uuid) {

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (cipher == NULL) {
        ERROR("NULL cipher");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (*bytes_to_process > AES_BLOCK_SIZE) {
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

    if (parameters == NULL) {
        ERROR("NULL parameters");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (parameters->tag == NULL) {
        ERROR("NULL tag");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (parameters->tag_length > AES_BLOCK_SIZE) {
        ERROR("Invalid tag_length");
        return SA_STATUS_INVALID_PARAMETER;
    }

    sa_cipher_mode cipher_mode = cipher_get_mode(cipher);
    if (cipher_mode == SA_CIPHER_MODE_ENCRYPT) {
        if (!rights_allowed_encrypt(rights, SA_KEY_TYPE_SYMMETRIC)) {
            ERROR("rights_allowed_encrypt failed");
            return SA_STATUS_OPERATION_NOT_ALLOWED;
        }

        size_t out_length = *bytes_to_process;
        sa_status status = symmetric_context_encrypt_last(symmetric_context, out, &out_length, in, *bytes_to_process);
        if (status != SA_STATUS_OK) {
            ERROR("symmetric_context_encrypt_last failed");
            return status;
        }

        status = symmetric_context_get_tag(symmetric_context, parameters->tag, parameters->tag_length);
        if (status != SA_STATUS_OK) {
            ERROR("symmetric_context_get_tag failed");
            return status;
        }

        *bytes_to_process = out_length;
    } else if (cipher_mode == SA_CIPHER_MODE_DECRYPT) {
        if (!rights_allowed_decrypt(rights, SA_KEY_TYPE_SYMMETRIC)) {
            ERROR("rights_allowed_decrypt failed");
            return SA_STATUS_OPERATION_NOT_ALLOWED;
        }

        sa_status status = symmetric_context_set_tag(symmetric_context, parameters->tag, parameters->tag_length);
        if (status != SA_STATUS_OK) {
            ERROR("symmetric_context_check_tag failed");
            return status;
        }

        size_t out_length = *bytes_to_process;
        status = symmetric_context_decrypt_last(symmetric_context, out, &out_length, in, *bytes_to_process);
        if (status != SA_STATUS_OK) {
            ERROR("symmetric_context_decrypt_last failed");
            return status;
        }

        *bytes_to_process = out_length;
    } else {
        ERROR("Unknown mode encountered");
        return SA_STATUS_INTERNAL_ERROR;
    }

    return SA_STATUS_OK;
}

static sa_status ta_sa_crypto_cipher_process_last_chacha20_poly1305(
        void* out,
        cipher_t* cipher,
        const void* in,
        size_t* bytes_to_process,
        sa_cipher_end_parameters_chacha20_poly1305* parameters,
        const sa_uuid* caller_uuid) {

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (cipher == NULL) {
        ERROR("NULL cipher");
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

    if (parameters == NULL) {
        ERROR("NULL parameters");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (parameters->tag == NULL) {
        ERROR("NULL tag");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (parameters->tag_length != CHACHA20_TAG_LENGTH) {
        ERROR("Invalid tag_length");
        return SA_STATUS_INVALID_PARAMETER;
    }

    sa_cipher_mode cipher_mode = cipher_get_mode(cipher);
    if (cipher_mode == SA_CIPHER_MODE_ENCRYPT) {
        if (!rights_allowed_encrypt(rights, SA_KEY_TYPE_SYMMETRIC)) {
            ERROR("rights_allowed_encrypt failed");
            return SA_STATUS_OPERATION_NOT_ALLOWED;
        }

        size_t out_length = *bytes_to_process;
        sa_status status = symmetric_context_encrypt_last(symmetric_context, out, &out_length, in, *bytes_to_process);
        if (status != SA_STATUS_OK) {
            ERROR("symmetric_context_encrypt_last failed");
            return status;
        }

        status = symmetric_context_get_tag(symmetric_context, parameters->tag, parameters->tag_length);
        if (status != SA_STATUS_OK) {
            ERROR("symmetric_context_get_tag failed");
            return status;
        }

        *bytes_to_process = out_length;
    } else if (cipher_mode == SA_CIPHER_MODE_DECRYPT) {
        if (!rights_allowed_decrypt(rights, SA_KEY_TYPE_SYMMETRIC)) {
            ERROR("rights_allowed_decrypt failed");
            return SA_STATUS_OPERATION_NOT_ALLOWED;
        }

        sa_status status = symmetric_context_set_tag(symmetric_context, parameters->tag, parameters->tag_length);
        if (status != SA_STATUS_OK) {
            ERROR("symmetric_context_check_tag failed");
            return status;
        }

        size_t out_length = *bytes_to_process;
        status = symmetric_context_decrypt_last(symmetric_context, out, &out_length, in, *bytes_to_process);
        if (status != SA_STATUS_OK) {
            ERROR("symmetric_context_decrypt_last failed");
            return status;
        }

        *bytes_to_process = out_length;
    } else {
        ERROR("Unknown mode encountered");
        return SA_STATUS_INTERNAL_ERROR;
    }

    return SA_STATUS_OK;
}

sa_status ta_sa_crypto_cipher_process_last(
        sa_buffer* out,
        sa_crypto_cipher_context context,
        sa_buffer* in,
        size_t* bytes_to_process,
        void* parameters,
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
            break;
        }

        size_t required_length = get_required_length(cipher, *bytes_to_process);
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
        if (cipher_algorithm == SA_CIPHER_ALGORITHM_AES_ECB_PKCS7 ||
                cipher_algorithm == SA_CIPHER_ALGORITHM_AES_CBC_PKCS7) {
            status = ta_sa_crypto_cipher_process_last_aes_pkcs7(out_bytes, required_length, cipher, in_bytes,
                    bytes_to_process, caller_uuid);
            if (status != SA_STATUS_OK) {
                ERROR("ta_sa_crypto_cipher_process_last_aes_pkcs7 failed");
                break;
            }
        } else if (cipher_algorithm == SA_CIPHER_ALGORITHM_AES_CTR) {
            status = ta_sa_crypto_cipher_process_last_aes_ctr(out_bytes, cipher, in_bytes, bytes_to_process,
                    caller_uuid);
            if (status != SA_STATUS_OK) {
                ERROR("ta_sa_crypto_cipher_process_last_aes_ctr failed");
                break;
            }
        } else if (cipher_algorithm == SA_CIPHER_ALGORITHM_CHACHA20) {
            status = ta_sa_crypto_cipher_process_last_chacha20(out_bytes, cipher, in_bytes, bytes_to_process,
                    caller_uuid);
            if (status != SA_STATUS_OK) {
                ERROR("ta_sa_crypto_cipher_process_last_chacha20 failed");
                break;
            }
        } else if (cipher_algorithm == SA_CIPHER_ALGORITHM_AES_GCM) {
            status = ta_sa_crypto_cipher_process_last_aes_gcm(out_bytes, cipher, in_bytes, bytes_to_process,
                    (sa_cipher_end_parameters_aes_gcm*) parameters, caller_uuid);
            if (status != SA_STATUS_OK) {
                ERROR("ta_sa_crypto_cipher_process_last_aes_gcm failed");
                break;
            }
        } else if (cipher_algorithm == SA_CIPHER_ALGORITHM_CHACHA20_POLY1305) {
            status = ta_sa_crypto_cipher_process_last_chacha20_poly1305(out_bytes, cipher, in_bytes, bytes_to_process,
                    (sa_cipher_end_parameters_chacha20_poly1305*) parameters, caller_uuid);
            if (status != SA_STATUS_OK) {
                ERROR("ta_sa_crypto_cipher_process_last_aes_gcm failed");
                break;
            }
        } else {
            status = SA_STATUS_INVALID_PARAMETER;
            ERROR("Unknown algorithm encountered");
            break;
        }

        if (out != NULL) {
            if (in->buffer_type == SA_BUFFER_TYPE_CLEAR) {
                in->context.clear.offset += in_length;
	    }
#ifndef DISABLE_SVP
            else if (in->buffer_type == SA_BUFFER_TYPE_SVP)
            {
                in->context.svp.offset += in_length;
            }
#endif
            if (out->buffer_type == SA_BUFFER_TYPE_SVP) {
                out->context.clear.offset += *bytes_to_process;
	    }
#ifndef DISABLE_SVP
            else if (out->buffer_type == SA_BUFFER_TYPE_SVP)
	    {
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
