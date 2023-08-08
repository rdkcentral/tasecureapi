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

#include "cipher_store.h" // NOLINT
#include "log.h"
#include "porting/memory.h"
#include "symmetric.h"
#include <memory.h>
#include <threads.h>

struct cipher_s {
    sa_cipher_algorithm cipher_algorithm;
    sa_cipher_mode cipher_mode;
    symmetric_context_t* symmetric_context;
    stored_key_t* stored_key;
    sa_digest_algorithm oaep_digest_algorithm;
    sa_digest_algorithm oaep_mgf1_digest_algorithm;
    void* oaep_label;
    size_t oaep_label_length;
    mtx_t mutex;
};

sa_cipher_algorithm cipher_get_algorithm(const cipher_t* cipher) {
    if (cipher == NULL) {
        ERROR("NULL cipher");
        return -1;
    }

    return cipher->cipher_algorithm;
}

sa_cipher_mode cipher_get_mode(const cipher_t* cipher) {
    if (cipher == NULL) {
        ERROR("NULL cipher");
        return -1;
    }

    return cipher->cipher_mode;
}

symmetric_context_t* cipher_get_symmetric_context(const cipher_t* cipher) {
    if (cipher == NULL) {
        ERROR("NULL cipher");
        return NULL;
    }

    return cipher->symmetric_context;
}

const stored_key_t* cipher_get_stored_key(const cipher_t* cipher) {
    if (cipher == NULL) {
        ERROR("NULL cipher");
        return NULL;
    }

    return cipher->stored_key;
}

size_t cipher_get_key_size(const cipher_t* cipher) {
    if (cipher == NULL) {
        ERROR("NULL cipher");
        return 0;
    }

    const sa_header* header = stored_key_get_header(cipher->stored_key);
    if (header == NULL) {
        ERROR("stored_key_get_header failed");
        return 0;
    }

    return header->size;
}

const sa_rights* cipher_get_key_rights(const cipher_t* cipher) {
    if (cipher == NULL) {
        ERROR("NULL cipher");
        return NULL;
    }

    const sa_header* header = stored_key_get_header(cipher->stored_key);
    if (header == NULL) {
        ERROR("stored_key_get_header failed");
        return 0;
    }

    return &header->rights;
}

sa_status cipher_set_oaep_parameters(
        cipher_t* cipher,
        sa_digest_algorithm digest_algorithm,
        sa_digest_algorithm mgf1_digest_algorithm,
        void* label,
        size_t label_length) {

    if (cipher == NULL) {
        ERROR("NULL cipher");
        return SA_STATUS_NULL_PARAMETER;
    }

    cipher->oaep_digest_algorithm = digest_algorithm;
    cipher->oaep_mgf1_digest_algorithm = mgf1_digest_algorithm;

    if (label != NULL) {
        cipher->oaep_label = memory_secure_alloc(label_length);
        if (cipher->oaep_label == NULL) {
            ERROR("memory_secure_alloc failed");
            return SA_STATUS_INTERNAL_ERROR;
        }

        memcpy(cipher->oaep_label, label, label_length);
    } else {
        cipher->oaep_label = NULL;
    }

    cipher->oaep_label_length = label_length;
    return SA_STATUS_OK;
}

sa_status cipher_get_oaep_parameters(
        const cipher_t* cipher,
        sa_digest_algorithm* digest_algorithm,
        sa_digest_algorithm* mgf1_digest_algorithm,
        const void** label,
        size_t* label_length) {

    if (cipher == NULL) {
        ERROR("NULL cipher");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (digest_algorithm == NULL) {
        ERROR("NULL digest_algorithm");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (mgf1_digest_algorithm == NULL) {
        ERROR("NULL mgf1_digest_algorithm");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (label == NULL) {
        ERROR("NULL label");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (label_length == NULL) {
        ERROR("NULL label_length");
        return SA_STATUS_NULL_PARAMETER;
    }

    *digest_algorithm = cipher->oaep_digest_algorithm;
    *mgf1_digest_algorithm = cipher->oaep_mgf1_digest_algorithm;
    *label = cipher->oaep_label;
    *label_length = cipher->oaep_label_length;
    return SA_STATUS_OK;
}

static cipher_t* cipher_alloc() {
    bool status = false;
    cipher_t* cipher = NULL;
    do {
        cipher = memory_internal_alloc(sizeof(cipher_t));
        if (cipher == NULL) {
            ERROR("memory_internal_alloc failed");
            break;
        }

        memory_memset_unoptimizable(cipher, 0, sizeof(cipher_t));

        if (mtx_init(&cipher->mutex, mtx_recursive)) {
            ERROR("mtx_init failed");
            break;
        }

        status = true;
    } while (false);

    if (!status) {
        memory_internal_free(cipher);
        cipher = NULL;
    }

    return cipher;
}

static void cipher_free(void* object) {
    if (object == NULL) {
        return;
    }

    cipher_t* cipher = (cipher_t*) object;

    symmetric_context_free(cipher->symmetric_context);
    stored_key_free(cipher->stored_key);
    if (cipher->oaep_label != NULL)
        memory_secure_free(cipher->oaep_label);

    mtx_destroy(&cipher->mutex);

    memory_memset_unoptimizable(cipher, 0, sizeof(cipher_t));
    memory_internal_free(cipher);
}

static bool cipher_lock(cipher_t* cipher) {
    if (cipher == NULL) {
        return false;
    }

    if (mtx_lock(&cipher->mutex) != thrd_success) {
        ERROR("mtx_lock failed");
        return false;
    }

    return true;
}

static void cipher_unlock(cipher_t* cipher) {
    if (cipher == NULL) {
        return;
    }

    if (mtx_unlock(&cipher->mutex) != thrd_success) {
        ERROR("mtx_unlock failed");
    }
}

cipher_store_t* cipher_store_init(size_t size) {
    cipher_store_t* store = object_store_init(cipher_free, size, "cipher");
    if (store == NULL) {
        ERROR("object_store_init failed");
        return NULL;
    }

    return store;
}

void cipher_store_shutdown(cipher_store_t* store) {
    if (store == NULL) {
        return;
    }

    object_store_shutdown(store);
}

sa_status cipher_store_add_symmetric_context(
        sa_crypto_cipher_context* context,
        cipher_store_t* store,
        sa_cipher_algorithm cipher_algorithm,
        sa_cipher_mode cipher_mode,
        symmetric_context_t* symmetric_context,
        stored_key_t* stored_key,
        const sa_uuid* caller_uuid) {

    if (context == NULL) {
        ERROR("NULL context");
        return SA_STATUS_NULL_PARAMETER;
    }
    *context = INVALID_HANDLE;

    if (store == NULL) {
        ERROR("NULL store");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (symmetric_context == NULL) {
        ERROR("NULL symmetric_context");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (cipher_algorithm != SA_CIPHER_ALGORITHM_AES_ECB && cipher_algorithm != SA_CIPHER_ALGORITHM_AES_ECB_PKCS7 &&
            cipher_algorithm != SA_CIPHER_ALGORITHM_AES_CBC && cipher_algorithm != SA_CIPHER_ALGORITHM_AES_CBC_PKCS7 &&
            cipher_algorithm != SA_CIPHER_ALGORITHM_AES_CTR && cipher_algorithm != SA_CIPHER_ALGORITHM_AES_GCM &&
            cipher_algorithm != SA_CIPHER_ALGORITHM_CHACHA20 &&
            cipher_algorithm != SA_CIPHER_ALGORITHM_CHACHA20_POLY1305) {
        ERROR("Non symmetric algorithm encountered");
        return SA_STATUS_INTERNAL_ERROR;
    }

    if (cipher_mode != SA_CIPHER_MODE_ENCRYPT && cipher_mode != SA_CIPHER_MODE_DECRYPT) {
        ERROR("Invalid mode");
        return SA_STATUS_INVALID_PARAMETER;
    }

    sa_status status = SA_STATUS_INTERNAL_ERROR;
    cipher_t* cipher = NULL;
    do {
        cipher = cipher_alloc();
        if (cipher == NULL) {
            ERROR("cipher_alloc failed");
            break;
        }

        cipher->cipher_algorithm = cipher_algorithm;
        cipher->cipher_mode = cipher_mode;
        cipher->symmetric_context = symmetric_context;
        cipher->stored_key = stored_key;
        if (cipher->stored_key == NULL) {
            ERROR("stored_key_copy failed");
            break;
        }

        status = object_store_add(context, store, cipher, caller_uuid);
        if (status != SA_STATUS_OK) {
            // Let the caller free the symmetric_context and stored_key to avoid a crash.
            cipher->symmetric_context = NULL;
            cipher->stored_key = NULL;
            ERROR("object_store_add failed");
            break;
        }

        // cipher is now owned by the store
        cipher = NULL;
    } while (false);

    cipher_free(cipher);

    return status;
}

sa_status cipher_store_add_asymmetric_key(
        sa_crypto_cipher_context* context,
        cipher_store_t* store,
        sa_cipher_algorithm cipher_algorithm,
        sa_cipher_mode cipher_mode,
        stored_key_t* stored_key,
        const sa_uuid* caller_uuid) {

    if (context == NULL) {
        ERROR("NULL context");
        return SA_STATUS_NULL_PARAMETER;
    }
    *context = INVALID_HANDLE;

    if (store == NULL) {
        ERROR("NULL store");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (cipher_algorithm != SA_CIPHER_ALGORITHM_RSA_OAEP && cipher_algorithm != SA_CIPHER_ALGORITHM_RSA_PKCS1V15 &&
            cipher_algorithm != SA_CIPHER_ALGORITHM_EC_ELGAMAL) {
        ERROR("Non asymmetric algorithm encountered");
        return SA_STATUS_INTERNAL_ERROR;
    }

    if (cipher_mode != SA_CIPHER_MODE_DECRYPT) {
        ERROR("Invalid mode encountered");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status = SA_STATUS_INTERNAL_ERROR;
    cipher_t* cipher = NULL;
    do {
        cipher = cipher_alloc();
        if (cipher == NULL) {
            ERROR("cipher_alloc failed");
            break;
        }

        cipher->cipher_algorithm = cipher_algorithm;
        cipher->cipher_mode = cipher_mode;
        cipher->stored_key = stored_key;
        if (cipher->stored_key == NULL) {
            ERROR("cipher_alloc failed");
            break;
        }

        status = object_store_add(context, store, cipher, caller_uuid);
        if (status != SA_STATUS_OK) {
            // Let the caller free the stored_key to avoid a crash.
            cipher->stored_key = NULL;
            ERROR("object_store_add failed");
            break;
        }

        // cipher is now owned by the store
        cipher = NULL;
    } while (false);

    cipher_free(cipher);

    return status;
}

sa_status cipher_store_remove(
        cipher_store_t* store,
        sa_crypto_cipher_context context,
        const sa_uuid* caller_uuid) {

    if (store == NULL) {
        ERROR("NULL store");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status = object_store_remove(store, context, caller_uuid);
    if (status != SA_STATUS_OK) {
        ERROR("object_store_remove failed");
        return status;
    }

    return SA_STATUS_OK;
}

sa_status cipher_store_acquire_exclusive(
        cipher_t** cipher,
        cipher_store_t* store,
        sa_crypto_cipher_context context,
        const sa_uuid* caller_uuid) {

    if (cipher == NULL) {
        ERROR("NULL cipher");
        return SA_STATUS_NULL_PARAMETER;
    }
    *cipher = NULL;

    if (store == NULL) {
        ERROR("NULL store");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_NULL_PARAMETER;
    }

    void* object = NULL;
    sa_status status = object_store_acquire(&object, store, context, caller_uuid);
    if (status != SA_STATUS_OK) {
        ERROR("object_store_acquire failed");
        return status;
    }

    *cipher = object;

    if (!cipher_lock(*cipher)) {
        ERROR("cipher_lock failed");
        return SA_STATUS_INTERNAL_ERROR;
    }

    return SA_STATUS_OK;
}

sa_status cipher_store_release_exclusive(
        cipher_store_t* store,
        sa_crypto_cipher_context context,
        cipher_t* cipher,
        const sa_uuid* caller_uuid) {

    if (store == NULL) {
        ERROR("NULL store");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (cipher == NULL) {
        ERROR("NULL cipher");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_NULL_PARAMETER;
    }

    cipher_unlock(cipher);

    sa_status status = object_store_release(store, context, cipher, caller_uuid);
    if (status != SA_STATUS_OK) {
        ERROR("object_store_release failed");
        return status;
    }

    return SA_STATUS_OK;
}
