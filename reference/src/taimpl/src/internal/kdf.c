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

#include "kdf.h" // NOLINT
#include "cmac_context.h"
#include "common.h"
#include "digest.h"
#include "digest_util.h"
#include "hmac_internal.h"
#include "log.h"
#include "porting/memory.h"
#include "stored_key_internal.h"
#include <memory.h>

sa_status kdf_hkdf_hmac(
        stored_key_t** stored_key_derived,
        const sa_rights* rights,
        sa_kdf_parameters_hkdf* parameters,
        const stored_key_t* stored_key_parent) {

    if (stored_key_derived == NULL) {
        ERROR("NULL stored_key_derived");
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

    if (parameters->salt == NULL && parameters->salt_length > 0) {
        ERROR("NULL salt");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (parameters->info == NULL && parameters->info_length > 0) {
        ERROR("NULL info");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (stored_key_parent == NULL) {
        ERROR("NULL stored_key_parent");
        return SA_STATUS_NULL_PARAMETER;
    }

    size_t hash_length = digest_length(parameters->digest_algorithm);
    if (hash_length > DIGEST_MAX_LENGTH) {
        ERROR("Invalid digest");
        return SA_STATUS_INVALID_PARAMETER;
    }

    bool status = SA_STATUS_INTERNAL_ERROR;
    uint8_t* derived = NULL;
    uint8_t* prk = NULL;
    size_t prk_length = DIGEST_MAX_LENGTH;
    uint8_t* tag = NULL;
    size_t tag_length = DIGEST_MAX_LENGTH;
    do {
        derived = memory_secure_alloc(parameters->key_length);
        if (derived == NULL) {
            ERROR("memory_secure_alloc failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        prk = memory_secure_alloc(prk_length);
        if (prk == NULL) {
            ERROR("memory_secure_alloc failed");
            break;
        }

        tag = memory_secure_alloc(tag_length);
        if (tag == NULL) {
            ERROR("memory_secure_alloc failed");
            break;
        }

        // extract
        const void* key = stored_key_get_key(stored_key_parent);
        if (key == NULL) {
            ERROR("stored_key_get_key failed");
            break;
        }

        size_t key_length = stored_key_get_length(stored_key_parent);
        if (!hmac_internal(prk, &prk_length, parameters->digest_algorithm, key, key_length, NULL, 0, NULL, 0,
                    parameters->salt, parameters->salt_length)) {
            ERROR("hmac_internal failed");
            break;
        }

        // expand
        uint8_t* derived_bytes = derived;
        size_t remainder = parameters->key_length % hash_length;
        size_t r = parameters->key_length / hash_length + (remainder ? 1 : 0);
        if (r > 0xff) {
            ERROR("Invalid derived_length: %d", parameters->key_length);
            break;
        }

        bool hmac_failed = false;
        for (size_t i = 1; i <= r; i++) {
            uint8_t loop = i;
            if (!hmac_internal(tag, &tag_length, parameters->digest_algorithm, tag, (i == 1) ? 0 : tag_length,
                        parameters->info, parameters->info_length, &loop, 1, prk, prk_length)) {
                ERROR("hmac_internal failed");
                hmac_failed = true;
                break;
            }

            size_t copy_length = (i == r && remainder > 0) ? remainder : tag_length;
            memcpy(derived_bytes, tag, copy_length);
            derived_bytes += copy_length;
        }

        if (hmac_failed)
            break;

        const sa_header* header = stored_key_get_header(stored_key_parent);
        if (header == NULL) {
            ERROR("stored_key_get_header failed");
            break;
        }

        sa_type_parameters type_parameters;
        memory_memset_unoptimizable(&type_parameters, 0, sizeof(sa_type_parameters));
        status = stored_key_create(stored_key_derived, rights, &header->rights, SA_KEY_TYPE_SYMMETRIC, &type_parameters,
                parameters->key_length, derived, parameters->key_length);
        if (status != SA_STATUS_OK) {
            ERROR("stored_key_create failed");
            break;
        }

        status = SA_STATUS_OK;
    } while (false);

    if (prk != NULL) {
        memory_memset_unoptimizable(prk, 0, prk_length);
        memory_secure_free(prk);
    }

    if (tag != NULL) {
        memory_memset_unoptimizable(tag, 0, tag_length);
        memory_secure_free(tag);
    }

    if (derived != NULL) {
        memory_memset_unoptimizable(derived, 0, parameters->key_length);
        memory_secure_free(derived);
    }

    return status;
}

sa_status kdf_concat_kdf(
        stored_key_t** stored_key_derived,
        const sa_rights* rights,
        sa_kdf_parameters_concat* parameters,
        const stored_key_t* stored_key_parent) {

    if (stored_key_derived == NULL) {
        ERROR("NULL stored_key_derived");
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

    if (parameters->info == NULL && parameters->info_length > 0) {
        ERROR("NULL info");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (stored_key_parent == NULL) {
        ERROR("NULL stored_key_parent");
        return SA_STATUS_NULL_PARAMETER;
    }

    size_t hash_length = digest_length(parameters->digest_algorithm);
    if (hash_length > DIGEST_MAX_LENGTH) {
        ERROR("Invalid digest");
        return SA_STATUS_INVALID_PARAMETER;
    }

    bool status = SA_STATUS_INTERNAL_ERROR;
    uint8_t* derived = NULL;
    uint8_t* hash = NULL;
    do {
        derived = memory_secure_alloc(parameters->key_length);
        if (derived == NULL) {
            ERROR("memory_secure_alloc failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        hash = memory_secure_alloc(hash_length);
        if (hash == NULL) {
            ERROR("memory_secure_alloc failed");
            break;
        }

        const void* key = stored_key_get_key(stored_key_parent);
        if (key == NULL) {
            ERROR("stored_key_get_key failed");
            break;
        }

        size_t key_length = stored_key_get_length(stored_key_parent);

        // expand
        uint8_t* derived_bytes = derived;
        size_t remainder = parameters->key_length % hash_length;
        size_t r = parameters->key_length / hash_length + (remainder ? 1 : 0);
        if (r > 0xff) {
            ERROR("Invalid derived_length: %d", parameters->key_length);
            break;
        }

        uint8_t counter[4] = {0, 0, 0, 0};
        bool digest_sha_failed = false;
        for (size_t i = 1; i <= r; ++i) {
            counter[3] = i;
            if (!digest_sha(hash, &hash_length, parameters->digest_algorithm, counter, sizeof(counter), key, key_length,
                        parameters->info, parameters->info_length)) {
                ERROR("digest_sha failed");
                digest_sha_failed = true;
                break;
            }

            size_t copy_length = (i == r && remainder) ? remainder : hash_length;
            memcpy(derived_bytes, hash, copy_length);
            derived_bytes += copy_length;
        }

        if (digest_sha_failed)
            break;

        const sa_header* header = stored_key_get_header(stored_key_parent);
        if (header == NULL) {
            ERROR("stored_key_get_header failed");
            break;
        }

        sa_type_parameters type_parameters;
        memory_memset_unoptimizable(&type_parameters, 0, sizeof(sa_type_parameters));
        status = stored_key_create(stored_key_derived, rights, &header->rights, SA_KEY_TYPE_SYMMETRIC, &type_parameters,
                parameters->key_length, derived, parameters->key_length);
        if (status != SA_STATUS_OK) {
            ERROR("stored_key_create failed");
            break;
        }
    } while (false);

    if (hash != NULL) {
        memory_memset_unoptimizable(hash, 0, hash_length);
        memory_secure_free(hash);
    }

    if (derived != NULL) {
        memory_memset_unoptimizable(derived, 0, parameters->key_length);
        memory_secure_free(derived);
    }

    return status;
}

sa_status kdf_ansi_x963(
        stored_key_t** stored_key_derived,
        const sa_rights* rights,
        sa_kdf_parameters_ansi_x963* parameters,
        const stored_key_t* stored_key_parent) {

    if (stored_key_derived == NULL) {
        ERROR("NULL stored_key_derived");
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

    if (parameters->info == NULL && parameters->info_length > 0) {
        ERROR("NULL info");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (stored_key_parent == NULL) {
        ERROR("NULL stored_key_parent");
        return SA_STATUS_NULL_PARAMETER;
    }

    size_t hash_length = digest_length(parameters->digest_algorithm);
    if (hash_length > DIGEST_MAX_LENGTH) {
        ERROR("Invalid digest");
        return SA_STATUS_INVALID_PARAMETER;
    }

    bool status = SA_STATUS_INTERNAL_ERROR;
    uint8_t* derived = NULL;
    uint8_t* hash = NULL;
    do {
        derived = memory_secure_alloc(parameters->key_length);
        if (derived == NULL) {
            ERROR("memory_secure_alloc failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        hash = memory_secure_alloc(hash_length);
        if (hash == NULL) {
            ERROR("memory_secure_alloc failed");
            break;
        }

        const void* key = stored_key_get_key(stored_key_parent);
        if (key == NULL) {
            ERROR("stored_key_get_key failed");
            break;
        }

        size_t key_length = stored_key_get_length(stored_key_parent);

        // expand
        uint8_t* derived_bytes = derived;
        size_t remainder = parameters->key_length % hash_length;
        size_t r = parameters->key_length / hash_length + (remainder ? 1 : 0);
        if (r > 0xff) {
            ERROR("Invalid derived_length: %d", parameters->key_length);
            break;
        }

        uint8_t counter[4] = {0, 0, 0, 0};
        bool digest_sha_failed = false;
        for (size_t i = 1; i <= r; ++i) {
            counter[3] = i;
            if (!digest_sha(hash, &hash_length, parameters->digest_algorithm, key, key_length, counter, sizeof(counter),
                        parameters->info, parameters->info_length)) {
                ERROR("digest_sha failed");
                digest_sha_failed = true;
                break;
            }

            size_t copy_length = (i == r && remainder) ? remainder : hash_length;
            memcpy(derived_bytes, hash, copy_length);
            derived_bytes += copy_length;
        }

        if (digest_sha_failed)
            break;

        const sa_header* header = stored_key_get_header(stored_key_parent);
        if (header == NULL) {
            ERROR("stored_key_get_header failed");
            break;
        }

        sa_type_parameters type_parameters;
        memory_memset_unoptimizable(&type_parameters, 0, sizeof(sa_type_parameters));
        status = stored_key_create(stored_key_derived, rights, &header->rights, SA_KEY_TYPE_SYMMETRIC, &type_parameters,
                parameters->key_length, derived, parameters->key_length);
        if (status != SA_STATUS_OK) {
            ERROR("stored_key_create failed");
            break;
        }
    } while (false);

    if (hash != NULL) {
        memory_memset_unoptimizable(hash, 0, hash_length);
        memory_secure_free(hash);
    }

    if (derived != NULL) {
        memory_memset_unoptimizable(derived, 0, parameters->key_length);
        memory_secure_free(derived);
    }

    return status;
}

sa_status kdf_ctr_cmac(
        stored_key_t** stored_key_derived,
        const sa_rights* rights,
        sa_kdf_parameters_cmac* parameters,
        const stored_key_t* stored_key_parent) {

    if (stored_key_derived == NULL) {
        ERROR("NULL stored_key_derived");
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

    if ((parameters->key_length % SYM_128_KEY_SIZE) != 0) {
        ERROR("Invalid key_length: %d", parameters->key_length);
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (parameters->other_data == NULL && parameters->other_data_length > 0) {
        ERROR("NULL other_data");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (parameters->counter < 1 || parameters->counter > 4) {
        ERROR("Invalid counter: %d", parameters->counter);
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (parameters->key_length / SYM_128_KEY_SIZE > (size_t) (5 - parameters->counter)) {
        ERROR("Invalid derived_length, counter combo: %d, %d", parameters->key_length, parameters->counter);
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (stored_key_parent == NULL) {
        ERROR("NULL stored_key_parent");
        return SA_STATUS_NULL_PARAMETER;
    }

    bool status = SA_STATUS_INTERNAL_ERROR;
    uint8_t* full_key = NULL;
    size_t full_key_length = 4 * (size_t) AES_BLOCK_SIZE;
    uint8_t* derived = NULL;
    do {
        derived = memory_secure_alloc(parameters->key_length);
        if (derived == NULL) {
            ERROR("memory_secure_alloc failed");
            break;
        }

        full_key = memory_secure_alloc(full_key_length);
        if (full_key == NULL) {
            ERROR("memory_secure_alloc failed");
            break;
        }

        bool inner_loop_failed = false;
        for (uint8_t i = 1; i <= 4; ++i) {
            if (!cmac(full_key + (i - 1) * (ptrdiff_t) AES_BLOCK_SIZE, &i, 1, parameters->other_data,
                        parameters->other_data_length, NULL, 0, stored_key_parent)) {
                ERROR("cmac failed");
                inner_loop_failed = true;
                break;
            }
        }
        if (inner_loop_failed) {
            break;
        }

        // copy desired slice of the full key
        memcpy(derived, full_key + (parameters->counter - 1) * (ptrdiff_t) AES_BLOCK_SIZE, parameters->key_length);

        const sa_header* header = stored_key_get_header(stored_key_parent);
        if (header == NULL) {
            ERROR("stored_key_get_header failed");
            break;
        }

        sa_type_parameters type_parameters;
        memory_memset_unoptimizable(&type_parameters, 0, sizeof(sa_type_parameters));
        status = stored_key_create(stored_key_derived, rights, &header->rights, SA_KEY_TYPE_SYMMETRIC, &type_parameters,
                parameters->key_length, derived, parameters->key_length);
        if (status != SA_STATUS_OK) {
            ERROR("stored_key_create failed");
            break;
        }
    } while (false);

    if (full_key != NULL) {
        memory_memset_unoptimizable(full_key, 0, full_key_length);
        memory_secure_free(full_key);
    }

    if (derived != NULL) {
        memory_memset_unoptimizable(derived, 0, parameters->key_length);
        memory_secure_free(derived);
    }

    return status;
}
