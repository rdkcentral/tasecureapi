/**
 * Copyright 2020-2022 Comcast Cable Communications Management, LLC
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

#include "cipher_store.h"
#include "client_store.h"
#include "common.h"
#include "ec.h"
#include "key_store.h"
#include "key_type.h"
#include "log.h"
#include "rights.h"
#include "rsa.h"
#include "ta_sa.h"

static sa_status ta_sa_crypto_cipher_init_aes_ecb(
        sa_crypto_cipher_context* context,
        sa_cipher_algorithm cipher_algorithm,
        sa_cipher_mode cipher_mode,
        stored_key_t* stored_key,
        client_t* client,
        const sa_uuid* caller_uuid) {

    if (context == NULL) {
        ERROR("NULL context");
        return SA_STATUS_NULL_PARAMETER;
    }
    *context = INVALID_HANDLE;

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return SA_STATUS_NULL_PARAMETER;
    }

    const sa_header* header = stored_key_get_header(stored_key);
    if (header == NULL) {
        ERROR("stored_key_get_header failed");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (!key_type_supports_aes(header->type, header->size)) {
        ERROR("key_type_supports_aes failed");
        return SA_STATUS_BAD_KEY_TYPE;
    }

    if (client == NULL) {
        ERROR("NULL client");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status;
    symmetric_context_t* symmetric_context = NULL;
    do {
        status = symmetric_verify_cipher(cipher_algorithm, cipher_mode, stored_key);
        if (status != SA_STATUS_OK) {
            ERROR("symmetric_verify_cipher failed");
            break;
        }

        if (cipher_mode == SA_CIPHER_MODE_ENCRYPT) {
            symmetric_context = symmetric_create_aes_ecb_encrypt_context(stored_key);
            if (symmetric_context == NULL) {
                ERROR("symmetric_create_aes_ecb_encrypt_context failed");
                status = SA_STATUS_INTERNAL_ERROR;
                break;
            }
        } else if (cipher_mode == SA_CIPHER_MODE_DECRYPT) {
            symmetric_context = symmetric_create_aes_ecb_decrypt_context(stored_key);
            if (symmetric_context == NULL) {
                ERROR("symmetric_create_aes_ecb_decrypt_context failed");
                status = SA_STATUS_INTERNAL_ERROR;
                break;
            }
        } else {
            ERROR("Unknown cipher mode encountered");
            status = SA_STATUS_BAD_PARAMETER;
            break;
        }

        cipher_store_t* cipher_store = client_get_cipher_store(client);
        status = cipher_store_add_symmetric_context(context, cipher_store, cipher_algorithm, cipher_mode,
                symmetric_context, stored_key, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("cipher_store_add_symmetric_context failed");
            break;
        }

        // symmetric_context and stored key are now owned by cipher store
        symmetric_context = NULL;
    } while (false);

    symmetric_context_free(symmetric_context);

    return status;
}

static sa_status ta_sa_crypto_cipher_init_aes_cbc(
        sa_crypto_cipher_context* context,
        sa_cipher_algorithm cipher_algorithm,
        sa_cipher_mode cipher_mode,
        stored_key_t* stored_key,
        sa_cipher_parameters_aes_cbc* parameters,
        client_t* client,
        const sa_uuid* caller_uuid) {

    if (context == NULL) {
        ERROR("NULL context");
        return SA_STATUS_NULL_PARAMETER;
    }
    *context = INVALID_HANDLE;

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return SA_STATUS_NULL_PARAMETER;
    }

    const sa_header* header = stored_key_get_header(stored_key);
    if (header == NULL) {
        ERROR("stored_key_get_header failed");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (!key_type_supports_aes(header->type, header->size)) {
        ERROR("key_type_supports_aes failed");
        return SA_STATUS_BAD_KEY_TYPE;
    }

    if (client == NULL) {
        ERROR("NULL client");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (parameters == NULL) {
        ERROR("NULL parameters");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (parameters->iv == NULL) {
        ERROR("NULL iv");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (parameters->iv_length != AES_BLOCK_SIZE) {
        ERROR("Bad iv_length");
        return SA_STATUS_BAD_PARAMETER;
    }

    sa_status status;
    symmetric_context_t* symmetric_context = NULL;
    do {
        status = symmetric_verify_cipher(cipher_algorithm, cipher_mode, stored_key);
        if (status != SA_STATUS_OK) {
            ERROR("symmetric_verify_cipher failed");
            break;
        }

        if (cipher_mode == SA_CIPHER_MODE_ENCRYPT) {
            symmetric_context = symmetric_create_aes_cbc_encrypt_context(stored_key, parameters->iv,
                    parameters->iv_length);
            if (symmetric_context == NULL) {
                ERROR("symmetric_create_aes_cbc_encrypt_context failed");
                status = SA_STATUS_INTERNAL_ERROR;
                break;
            }
        } else if (cipher_mode == SA_CIPHER_MODE_DECRYPT) {
            symmetric_context = symmetric_create_aes_cbc_decrypt_context(stored_key, parameters->iv,
                    parameters->iv_length);
            if (symmetric_context == NULL) {
                ERROR("symmetric_create_aes_cbc_decrypt_context failed");
                status = SA_STATUS_INTERNAL_ERROR;
                break;
            }
        } else {
            ERROR("Unknown cipher cipher_mode encountered");
            status = SA_STATUS_BAD_PARAMETER;
            break;
        }

        cipher_store_t* cipher_store = client_get_cipher_store(client);
        status = cipher_store_add_symmetric_context(context, cipher_store, cipher_algorithm, cipher_mode,
                symmetric_context, stored_key, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("cipher_store_add_symmetric_context failed");
            break;
        }

        // symmetric_context and stored key are now owned by cipher store
        symmetric_context = NULL;
    } while (false);

    symmetric_context_free(symmetric_context);

    return status;
}

static sa_status ta_sa_crypto_cipher_init_aes_ctr(
        sa_crypto_cipher_context* context,
        sa_cipher_mode cipher_mode,
        stored_key_t* stored_key,
        sa_cipher_parameters_aes_ctr* parameters,
        client_t* client,
        const sa_uuid* caller_uuid) {

    if (context == NULL) {
        ERROR("NULL context");
        return SA_STATUS_NULL_PARAMETER;
    }
    *context = INVALID_HANDLE;

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return SA_STATUS_NULL_PARAMETER;
    }

    const sa_header* header = stored_key_get_header(stored_key);
    if (header == NULL) {
        ERROR("stored_key_get_header failed");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (!key_type_supports_aes(header->type, header->size)) {
        ERROR("key_type_supports_aes failed");
        return SA_STATUS_BAD_KEY_TYPE;
    }

    if (client == NULL) {
        ERROR("NULL client");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (parameters == NULL) {
        ERROR("NULL parameters");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (parameters->ctr == NULL) {
        ERROR("NULL ctr");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (parameters->ctr_length != AES_BLOCK_SIZE) {
        ERROR("Bad ctr_length");
        return SA_STATUS_BAD_PARAMETER;
    }

    sa_status status;
    symmetric_context_t* symmetric_context = NULL;
    do {
        status = symmetric_verify_cipher(SA_CIPHER_ALGORITHM_AES_CTR, cipher_mode, stored_key);
        if (status != SA_STATUS_OK) {
            ERROR("symmetric_verify_cipher failed");
            break;
        }

        if (cipher_mode == SA_CIPHER_MODE_ENCRYPT) {
            symmetric_context = symmetric_create_aes_ctr_encrypt_context(stored_key, parameters->ctr,
                    parameters->ctr_length);
            if (symmetric_context == NULL) {
                ERROR("symmetric_create_aes_ctr_encrypt_context failed");
                status = SA_STATUS_INTERNAL_ERROR;
                break;
            }
        } else if (cipher_mode == SA_CIPHER_MODE_DECRYPT) {
            symmetric_context = symmetric_create_aes_ctr_decrypt_context(stored_key, parameters->ctr,
                    parameters->ctr_length);
            if (symmetric_context == NULL) {
                ERROR("symmetric_create_aes_ctr_decrypt_context failed");
                status = SA_STATUS_INTERNAL_ERROR;
                break;
            }
        } else {
            ERROR("Unknown cipher mode encountered");
            status = SA_STATUS_BAD_PARAMETER;
            break;
        }

        cipher_store_t* cipher_store = client_get_cipher_store(client);
        status = cipher_store_add_symmetric_context(context, cipher_store, SA_CIPHER_ALGORITHM_AES_CTR, cipher_mode,
                symmetric_context, stored_key, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("cipher_store_add_symmetric_context failed");
            break;
        }

        // symmetric_context and stored key are now owned by cipher store
        symmetric_context = NULL;
    } while (false);

    symmetric_context_free(symmetric_context);

    return status;
}

static sa_status ta_sa_crypto_cipher_init_aes_gcm(
        sa_crypto_cipher_context* context,
        sa_cipher_mode cipher_mode,
        stored_key_t* stored_key,
        sa_cipher_parameters_aes_gcm* parameters,
        client_t* client,
        const sa_uuid* caller_uuid) {

    if (context == NULL) {
        ERROR("NULL context");
        return SA_STATUS_NULL_PARAMETER;
    }
    *context = INVALID_HANDLE;

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return SA_STATUS_NULL_PARAMETER;
    }

    const sa_header* header = stored_key_get_header(stored_key);
    if (header == NULL) {
        ERROR("stored_key_get_header failed");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (!key_type_supports_aes(header->type, header->size)) {
        ERROR("key_type_supports_aes failed");
        return SA_STATUS_BAD_KEY_TYPE;
    }

    if (client == NULL) {
        ERROR("NULL client");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (parameters == NULL) {
        ERROR("NULL parameters");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (parameters->iv == NULL) {
        ERROR("NULL iv");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (parameters->iv_length != GCM_IV_LENGTH) {
        ERROR("Bad iv_length");
        return SA_STATUS_BAD_PARAMETER;
    }

    if (parameters->aad == NULL && parameters->aad_length > 0) {
        ERROR("NULL aad");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status;
    symmetric_context_t* symmetric_context = NULL;
    do {
        status = symmetric_verify_cipher(SA_CIPHER_ALGORITHM_AES_GCM, cipher_mode, stored_key);
        if (status != SA_STATUS_OK) {
            ERROR("symmetric_verify_cipher failed");
            break;
        }

        if (cipher_mode == SA_CIPHER_MODE_ENCRYPT) {
            symmetric_context = symmetric_create_aes_gcm_encrypt_context(stored_key, parameters->iv,
                    parameters->iv_length, parameters->aad, parameters->aad_length);
            if (symmetric_context == NULL) {
                ERROR("symmetric_create_aes_gcm_encrypt_context failed");
                status = SA_STATUS_INTERNAL_ERROR;
                break;
            }
        } else if (cipher_mode == SA_CIPHER_MODE_DECRYPT) {
            symmetric_context = symmetric_create_aes_gcm_decrypt_context(stored_key, parameters->iv,
                    parameters->iv_length, parameters->aad, parameters->aad_length);
            if (symmetric_context == NULL) {
                ERROR("symmetric_create_aes_gcm_decrypt_context failed");
                status = SA_STATUS_INTERNAL_ERROR;
                break;
            }
        } else {
            ERROR("Unknown cipher mode encountered");
            status = SA_STATUS_BAD_PARAMETER;
            break;
        }

        cipher_store_t* cipher_store = client_get_cipher_store(client);
        status = cipher_store_add_symmetric_context(context, cipher_store, SA_CIPHER_ALGORITHM_AES_GCM, cipher_mode,
                symmetric_context, stored_key, caller_uuid);
        if (*context == INVALID_HANDLE) {
            ERROR("cipher_store_add_symmetric_context failed");
            break;
        }

        // symmetric_context and stored key are now owned by cipher store
        symmetric_context = NULL;
        status = SA_STATUS_OK;
    } while (false);

    symmetric_context_free(symmetric_context);

    return status;
}

static sa_status ta_sa_crypto_cipher_init_chacha20(
        sa_crypto_cipher_context* context,
        sa_cipher_mode cipher_mode,
        stored_key_t* stored_key,
        sa_cipher_parameters_chacha20* parameters,
        client_t* client,
        const sa_uuid* caller_uuid) {

    if (context == NULL) {
        ERROR("NULL context");
        return SA_STATUS_NULL_PARAMETER;
    }
    *context = INVALID_HANDLE;

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return SA_STATUS_NULL_PARAMETER;
    }

    const sa_header* header = stored_key_get_header(stored_key);
    if (header == NULL) {
        ERROR("stored_key_get_header failed");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (!key_type_supports_chacha20(header->type, header->size)) {
        ERROR("key_type_supports_chacha20 failed");
        return SA_STATUS_BAD_KEY_TYPE;
    }

    if (client == NULL) {
        ERROR("NULL client");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (parameters == NULL) {
        ERROR("NULL parameters");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (parameters->nonce == NULL) {
        ERROR("NULL nonce");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (parameters->nonce_length != CHACHA20_NONCE_LENGTH) {
        ERROR("Bad nonce_length");
        return SA_STATUS_BAD_PARAMETER;
    }

    if (parameters->counter == NULL) {
        ERROR("NULL counter");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (parameters->counter_length != CHACHA20_COUNTER_LENGTH) {
        ERROR("Bad counter_length");
        return SA_STATUS_BAD_PARAMETER;
    }

    sa_status status;
    symmetric_context_t* symmetric_context = NULL;
    do {
        status = symmetric_verify_cipher(SA_CIPHER_ALGORITHM_CHACHA20, cipher_mode, stored_key);
        if (status != SA_STATUS_OK) {
            ERROR("symmetric_verify_cipher failed");
            break;
        }

        if (cipher_mode == SA_CIPHER_MODE_ENCRYPT) {
            symmetric_context = symmetric_create_chacha20_encrypt_context(stored_key, parameters->nonce,
                    parameters->nonce_length, parameters->counter, parameters->counter_length);
            if (symmetric_context == NULL) {
                ERROR("symmetric_create_chacha20_encrypt_context failed");
                status = SA_STATUS_INTERNAL_ERROR;
                break;
            }
        } else if (cipher_mode == SA_CIPHER_MODE_DECRYPT) {
            symmetric_context = symmetric_create_chacha20_decrypt_context(stored_key, parameters->nonce,
                    parameters->nonce_length, parameters->counter, parameters->counter_length);
            if (symmetric_context == NULL) {
                ERROR("symmetric_create_chacha20_decrypt_context failed");
                status = SA_STATUS_INTERNAL_ERROR;
                break;
            }
        } else {
            ERROR("Unknown cipher mode encountered");
            status = SA_STATUS_BAD_PARAMETER;
            break;
        }

        cipher_store_t* cipher_store = client_get_cipher_store(client);
        status = cipher_store_add_symmetric_context(context, cipher_store, SA_CIPHER_ALGORITHM_CHACHA20, cipher_mode,
                symmetric_context, stored_key, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("cipher_store_add_symmetric_context failed");
            break;
        }

        // symmetric_context and stored key are now owned by cipher store
        symmetric_context = NULL;
    } while (false);

    symmetric_context_free(symmetric_context);
    return status;
}

static sa_status ta_sa_crypto_cipher_init_chacha20_poly1305(
        sa_crypto_cipher_context* context,
        sa_cipher_mode cipher_mode,
        stored_key_t* stored_key,
        sa_cipher_parameters_chacha20_poly1305* parameters,
        client_t* client,
        const sa_uuid* caller_uuid) {
    if (context == NULL) {
        ERROR("NULL context");
        return SA_STATUS_NULL_PARAMETER;
    }
    *context = INVALID_HANDLE;

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return SA_STATUS_NULL_PARAMETER;
    }

    const sa_header* header = stored_key_get_header(stored_key);
    if (header == NULL) {
        ERROR("stored_key_get_header failed");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (!key_type_supports_chacha20(header->type, header->size)) {
        ERROR("key_type_supports_chacha20 failed");
        return SA_STATUS_BAD_KEY_TYPE;
    }

    if (client == NULL) {
        ERROR("NULL client");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (parameters == NULL) {
        ERROR("NULL parameters");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (parameters->nonce == NULL) {
        ERROR("NULL nonce");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (parameters->nonce_length != CHACHA20_NONCE_LENGTH) {
        ERROR("Bad nonce_length");
        return SA_STATUS_BAD_PARAMETER;
    }

    if (parameters->aad == NULL && parameters->aad_length > 0) {
        ERROR("NULL aad");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status;
    symmetric_context_t* symmetric_context = NULL;
    do {
        status = symmetric_verify_cipher(SA_CIPHER_ALGORITHM_CHACHA20_POLY1305, cipher_mode, stored_key);
        if (status != SA_STATUS_OK) {
            ERROR("symmetric_verify_cipher failed");
            break;
        }

        if (cipher_mode == SA_CIPHER_MODE_ENCRYPT) {
            symmetric_context = symmetric_create_chacha20_poly1305_encrypt_context(stored_key, parameters->nonce,
                    parameters->nonce_length, parameters->aad, parameters->aad_length);
            if (symmetric_context == NULL) {
                ERROR("symmetric_create_chacha20_poly1305_encrypt_context failed");
                status = SA_STATUS_INTERNAL_ERROR;
                break;
            }
        } else if (cipher_mode == SA_CIPHER_MODE_DECRYPT) {
            symmetric_context = symmetric_create_chacha20_poly1305_decrypt_context(stored_key, parameters->nonce,
                    parameters->nonce_length, parameters->aad, parameters->aad_length);
            if (symmetric_context == NULL) {
                ERROR("symmetric_create_chacha20_poly1305_decrypt_context failed");
                status = SA_STATUS_INTERNAL_ERROR;
                break;
            }
        } else {
            ERROR("Unknown cipher mode encountered");
            status = SA_STATUS_BAD_PARAMETER;
            break;
        }

        cipher_store_t* cipher_store = client_get_cipher_store(client);
        status = cipher_store_add_symmetric_context(context, cipher_store, SA_CIPHER_ALGORITHM_CHACHA20_POLY1305,
                cipher_mode,
                symmetric_context, stored_key, caller_uuid);
        if (*context == INVALID_HANDLE) {
            ERROR("cipher_store_add_symmetric_context failed");
            break;
        }

        // symmetric_context and stored key are now owned by cipher store
        symmetric_context = NULL;
        status = SA_STATUS_OK;
    } while (false);

    symmetric_context_free(symmetric_context);
    return status;
}

static sa_status ta_sa_crypto_cipher_init_rsa(
        sa_crypto_cipher_context* context,
        sa_cipher_algorithm cipher_algorithm,
        sa_cipher_mode cipher_mode,
        stored_key_t* stored_key,
        client_t* client,
        const sa_uuid* caller_uuid) {

    if (context == NULL) {
        ERROR("NULL context");
        return SA_STATUS_NULL_PARAMETER;
    }
    *context = INVALID_HANDLE;

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return SA_STATUS_NULL_PARAMETER;
    }

    const sa_header* header = stored_key_get_header(stored_key);
    if (header == NULL) {
        ERROR("stored_key_get_header failed");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (!key_type_supports_rsa(header->type, header->size)) {
        ERROR("key_type_supports_rsa failed");
        return SA_STATUS_BAD_KEY_TYPE;
    }

    if (client == NULL) {
        ERROR("NULL client");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (cipher_mode != SA_CIPHER_MODE_DECRYPT) {
        ERROR("Bad mode");
        return SA_STATUS_BAD_PARAMETER;
    }

    if (cipher_algorithm != SA_CIPHER_ALGORITHM_RSA_PKCS1V15 && cipher_algorithm != SA_CIPHER_ALGORITHM_RSA_OAEP) {
        ERROR("Bad algorithm");
        return SA_STATUS_BAD_PARAMETER;
    }

    sa_status status;
    do {
        status = rsa_verify_cipher(cipher_algorithm, cipher_mode, stored_key);
        if (status != SA_STATUS_OK) {
            ERROR("rsa_verify_cipher failed");
            break;
        }

        cipher_store_t* cipher_store = client_get_cipher_store(client);
        status = cipher_store_add_asymmetric_key(context, cipher_store, cipher_algorithm, cipher_mode, stored_key,
                caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("cipher_store_add_asymmetric_key failed");
            break;
        }
    } while (false);

    return status;
}

static sa_status ta_sa_crypto_cipher_init_ec(
        sa_crypto_cipher_context* context,
        sa_cipher_mode cipher_mode,
        stored_key_t* stored_key,
        client_t* client,
        const sa_uuid* caller_uuid) {

    if (context == NULL) {
        ERROR("NULL context");
        return SA_STATUS_NULL_PARAMETER;
    }
    *context = INVALID_HANDLE;

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return SA_STATUS_NULL_PARAMETER;
    }

    const sa_header* header = stored_key_get_header(stored_key);
    if (header == NULL) {
        ERROR("stored_key_get_header failed");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (!key_type_supports_ec(header->type, header->type_parameters.curve, header->size)) {
        ERROR("key_type_supports_ec failed");
        return SA_STATUS_BAD_KEY_TYPE;
    }

    if (client == NULL) {
        ERROR("NULL client");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (cipher_mode != SA_CIPHER_MODE_DECRYPT) {
        ERROR("Bad mode");
        return SA_STATUS_BAD_PARAMETER;
    }

    sa_status status;
    do {
        status = ec_verify_cipher(cipher_mode, stored_key);
        if (status != SA_STATUS_OK) {
            ERROR("ec_verify_cipher failed");
            break;
        }

        cipher_store_t* cipher_store = client_get_cipher_store(client);
        status = cipher_store_add_asymmetric_key(context, cipher_store, SA_CIPHER_ALGORITHM_EC_ELGAMAL, cipher_mode,
                stored_key, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("cipher_store_add_asymmetric_key failed");
            break;
        }
    } while (false);

    return status;
}

sa_status ta_sa_crypto_cipher_init(
        sa_crypto_cipher_context* context,
        sa_cipher_algorithm cipher_algorithm,
        sa_cipher_mode cipher_mode,
        sa_key key,
        void* parameters,
        ta_client client_slot,
        const sa_uuid* caller_uuid) {

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (context == NULL) {
        ERROR("NULL context");
        return SA_STATUS_NULL_PARAMETER;
    }
    *context = INVALID_HANDLE;

    if (cipher_algorithm != SA_CIPHER_ALGORITHM_AES_ECB && cipher_algorithm != SA_CIPHER_ALGORITHM_AES_ECB_PKCS7 &&
            cipher_algorithm != SA_CIPHER_ALGORITHM_AES_CBC && cipher_algorithm != SA_CIPHER_ALGORITHM_AES_CBC_PKCS7 &&
            cipher_algorithm != SA_CIPHER_ALGORITHM_AES_CTR && cipher_algorithm != SA_CIPHER_ALGORITHM_AES_GCM &&
            cipher_algorithm != SA_CIPHER_ALGORITHM_CHACHA20 &&
            cipher_algorithm != SA_CIPHER_ALGORITHM_CHACHA20_POLY1305 &&
            cipher_algorithm != SA_CIPHER_ALGORITHM_RSA_PKCS1V15 && cipher_algorithm != SA_CIPHER_ALGORITHM_RSA_OAEP &&
            cipher_algorithm != SA_CIPHER_ALGORITHM_EC_ELGAMAL) {
        ERROR("Bad algorithm");
        return SA_STATUS_BAD_PARAMETER;
    }

    if (cipher_mode != SA_CIPHER_MODE_ENCRYPT && cipher_mode != SA_CIPHER_MODE_DECRYPT) {
        ERROR("Bad mode");
        return SA_STATUS_BAD_PARAMETER;
    }

    sa_status status;
    client_store_t* client_store = client_store_global();
    client_t* client = NULL;
    stored_key_t* stored_key = NULL;
    do {
        status = client_store_acquire(&client, client_store, client_slot, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("client_store_acquire failed");
            break;
        }

        key_store_t* key_store = client_get_key_store(client);
        status = key_store_unwrap(&stored_key, key_store, key, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("key_store_unwrap failed");
            break;
        }

        const sa_header* header = stored_key_get_header(stored_key);
        if (header == NULL) {
            ERROR("stored_key_get_header failed");
            status = SA_STATUS_NULL_PARAMETER;
            break;
        }

        if (cipher_mode == SA_CIPHER_MODE_ENCRYPT) {
            if (!rights_allowed_encrypt(&header->rights, header->type)) {
                ERROR("rights_allowed_encrypt failed");
                status = SA_STATUS_OPERATION_NOT_ALLOWED;
                break;
            }
        } else if (cipher_mode == SA_CIPHER_MODE_DECRYPT) {
            if (!rights_allowed_decrypt(&header->rights, header->type)) {
                ERROR("rights_allowed_decrypt failed");
                status = SA_STATUS_OPERATION_NOT_ALLOWED;
                break;
            }
        } else {
            ERROR("Unknown cipher mode encountered");
            status = SA_STATUS_BAD_PARAMETER;
            break;
        }

        if (cipher_algorithm == SA_CIPHER_ALGORITHM_AES_ECB || cipher_algorithm == SA_CIPHER_ALGORITHM_AES_ECB_PKCS7) {
            status = ta_sa_crypto_cipher_init_aes_ecb(context, cipher_algorithm, cipher_mode, stored_key, client,
                    caller_uuid);
            if (status != SA_STATUS_OK) {
                ERROR("ta_sa_crypto_cipher_init_aes_ecb failed");
                break;
            }
        } else if (cipher_algorithm == SA_CIPHER_ALGORITHM_AES_CBC ||
                   cipher_algorithm == SA_CIPHER_ALGORITHM_AES_CBC_PKCS7) {
            status = ta_sa_crypto_cipher_init_aes_cbc(context, cipher_algorithm, cipher_mode, stored_key,
                    (sa_cipher_parameters_aes_cbc*) parameters, client, caller_uuid);
            if (status != SA_STATUS_OK) {
                ERROR("ta_sa_crypto_cipher_init_aes_cbc failed");
                break;
            }
        } else if (cipher_algorithm == SA_CIPHER_ALGORITHM_AES_CTR) {
            status = ta_sa_crypto_cipher_init_aes_ctr(context, cipher_mode, stored_key,
                    (sa_cipher_parameters_aes_ctr*) parameters, client, caller_uuid);
            if (status != SA_STATUS_OK) {
                ERROR("ta_sa_crypto_cipher_init_aes_ctr failed");
                break;
            }
        } else if (cipher_algorithm == SA_CIPHER_ALGORITHM_AES_GCM) {
            status = ta_sa_crypto_cipher_init_aes_gcm(context, cipher_mode, stored_key,
                    (sa_cipher_parameters_aes_gcm*) parameters, client, caller_uuid);
            if (status != SA_STATUS_OK) {
                ERROR("ta_sa_crypto_cipher_init_aes_gcm failed");
                break;
            }
        } else if (cipher_algorithm == SA_CIPHER_ALGORITHM_CHACHA20) {
            status = ta_sa_crypto_cipher_init_chacha20(context, cipher_mode, stored_key,
                    (sa_cipher_parameters_chacha20*) parameters, client, caller_uuid);
            if (status != SA_STATUS_OK) {
                ERROR("ta_sa_crypto_cipher_init_chacha20 failed");
                break;
            }
        } else if (cipher_algorithm == SA_CIPHER_ALGORITHM_CHACHA20_POLY1305) {
            status = ta_sa_crypto_cipher_init_chacha20_poly1305(context, cipher_mode, stored_key,
                    (sa_cipher_parameters_chacha20_poly1305*) parameters, client, caller_uuid);
            if (status != SA_STATUS_OK) {
                ERROR("ta_sa_crypto_cipher_init_chacha20_poly1305 failed");
                break;
            }
        } else if (cipher_algorithm == SA_CIPHER_ALGORITHM_RSA_PKCS1V15 ||
                   cipher_algorithm == SA_CIPHER_ALGORITHM_RSA_OAEP) {
            status = ta_sa_crypto_cipher_init_rsa(context, cipher_algorithm, cipher_mode, stored_key, client,
                    caller_uuid);
            if (status != SA_STATUS_OK) {
                ERROR("ta_sa_crypto_cipher_init_rsa failed");
                break;
            }
        } else { // cipher_algorithm == SA_CIPHER_ALGORITHM_EC_ELGAMAL
            status = ta_sa_crypto_cipher_init_ec(context, cipher_mode, stored_key, client, caller_uuid);
            if (status != SA_STATUS_OK) {
                ERROR("ta_sa_crypto_cipher_init_ec failed");
                break;
            }
        }

        // stored key is now owned by cipher store
        stored_key = NULL;
    } while (false);

    stored_key_free(stored_key);
    client_store_release(client_store, client_slot, client, caller_uuid);
    return status;
}
