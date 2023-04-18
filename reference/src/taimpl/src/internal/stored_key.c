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

#include "stored_key.h" // NOLINT
#include "key_type.h"
#include "log.h"
#include "porting/memory.h"
#include "rights.h"
#include "stored_key_internal.h"
#include <memory.h>

struct stored_key_s {
    sa_header header;
    size_t key_length;
    void* key;
};

#define KEY_ONLY_MASK (~SA_USAGE_BIT_MASK(SA_USAGE_FLAG_UNWRAP) & SA_KEY_USAGE_MASK)

static void restrict_child_rights(sa_rights* rights, const sa_rights* rootrights) {
    if (rights == NULL) {
        ERROR("NULL rights");
        return;
    }

    if (rootrights == NULL) {
        return;
    }

    if ((rootrights->usage_flags & KEY_ONLY_MASK) || (rootrights->child_usage_flags == 0)) {
        uint64_t disallowed = ~rootrights->usage_flags & SA_USAGE_OUTPUT_PROTECTIONS_MASK;
        rights->usage_flags &= ~disallowed;
    } else {
        uint64_t disallowed = ~rootrights->child_usage_flags & SA_KEY_USAGE_MASK;
        rights->usage_flags &= ~disallowed;
    }
}

const void* stored_key_get_key(const stored_key_t* stored_key) {
    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return NULL;
    }

    return stored_key->key;
}

size_t stored_key_get_length(const stored_key_t* stored_key) {
    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return 0;
    }

    return stored_key->key_length;
}

const sa_header* stored_key_get_header(const stored_key_t* stored_key) {
    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return NULL;
    }

    return &stored_key->header;
}

sa_status stored_key_import(
        stored_key_t** stored_key,
        const sa_rights* rights,
        sa_key_type key_type,
        const sa_type_parameters* type_parameters,
        size_t size,
        const void* in,
        size_t in_length) {
    return stored_key_create(stored_key, rights, NULL, key_type, type_parameters, size, in, in_length);
}

sa_status stored_key_create(
        stored_key_t** stored_key,
        const sa_rights* rights,
        const sa_rights* parent_rights,
        sa_key_type key_type,
        const sa_type_parameters* type_parameters,
        size_t size,
        const void* in,
        size_t in_length) {

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return SA_STATUS_NULL_PARAMETER;
    }
    *stored_key = NULL;

    if (rights == NULL) {
        ERROR("NULL rights");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (in == NULL) {
        ERROR("NULL in");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (!key_type_supports_any(key_type, type_parameters->curve, size)) {
        ERROR("key_type_supports_any failed");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (!rights_validate_format(rights)) {
        ERROR("rights_validate_format failed");
        return SA_STATUS_INVALID_PARAMETER;
    }

    sa_status status = SA_STATUS_INTERNAL_ERROR;
    stored_key_t* new_stored_key = NULL;
    do {
        new_stored_key = memory_secure_alloc(sizeof(stored_key_t));
        if (new_stored_key == NULL) {
            ERROR("memory_secure_alloc failed");
            break;
        }
        memory_memset_unoptimizable(new_stored_key, 0, sizeof(stored_key_t));

        // copy key data
        new_stored_key->key = memory_secure_alloc(in_length);
        if (new_stored_key->key == NULL) {
            ERROR("memory_secure_alloc failed");
            break;
        }
        memcpy(new_stored_key->key, in, in_length);
        new_stored_key->key_length = in_length;

        // fill key_header - implementations don't need to store sa_header as is, it can be optimized for space.
        static const char MAGIC[NUM_MAGIC] = {'s', 'a', 'k', '0'};
        memcpy(new_stored_key->header.magic, MAGIC, sizeof(MAGIC));
        memcpy(&new_stored_key->header.rights, rights, sizeof(sa_rights));
        new_stored_key->header.type = key_type;
        memcpy(&new_stored_key->header.type_parameters, type_parameters, sizeof(sa_type_parameters));
        new_stored_key->header.size = size;

        restrict_child_rights(&new_stored_key->header.rights, parent_rights);

        *stored_key = new_stored_key;
        new_stored_key = NULL;
        status = SA_STATUS_OK;
    } while (false);

    stored_key_free(new_stored_key);

    return status;
}

void stored_key_free(stored_key_t* stored_key) {
    if (stored_key == NULL) {
        return;
    }

    if (stored_key->key != NULL) {
        memory_memset_unoptimizable(stored_key->key, 0, stored_key->key_length);
        memory_secure_free(stored_key->key);
    }

    memory_memset_unoptimizable(stored_key, 0, sizeof(stored_key_t));
    memory_secure_free(stored_key);
}
