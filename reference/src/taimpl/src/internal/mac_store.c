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

#include "mac_store.h" // NOLINT
#include "log.h"
#include "porting/memory.h"
#include <threads.h>

struct mac_s {
    sa_mac_algorithm mac_algorithm;
    hmac_context_t* hmac_context;
    cmac_context_t* cmac_context;
    mtx_t mutex;
};

sa_mac_algorithm mac_get_algorithm(const mac_t* mac) {
    if (mac == NULL) {
        ERROR("NULL mac");
        return -1;
    }

    return mac->mac_algorithm;
}

hmac_context_t* mac_get_hmac_context(const mac_t* mac) {
    if (mac == NULL) {
        ERROR("NULL mac");
        return NULL;
    }

    return mac->hmac_context;
}

cmac_context_t* mac_get_cmac_context(const mac_t* mac) {
    if (mac == NULL) {
        ERROR("NULL mac");
        return NULL;
    }

    return mac->cmac_context;
}

static mac_t* mac_allocate() {
    bool status = false;
    mac_t* mac = NULL;
    do {
        mac = memory_internal_alloc(sizeof(mac_t));
        if (mac == NULL) {
            ERROR("memory_internal_alloc failed");
            break;
        }

        memory_memset_unoptimizable(mac, 0, sizeof(mac_t));

        if (mtx_init(&mac->mutex, mtx_recursive)) {
            ERROR("mtx_init failed");
            break;
        }

        status = true;
    } while (false);

    if (!status) {
        memory_internal_free(mac);
        mac = NULL;
    }

    return mac;
}

static void mac_free(void* object) {
    if (object == NULL) {
        return;
    }

    mac_t* mac = (mac_t*) object;

    hmac_context_free(mac->hmac_context);
    cmac_context_free(mac->cmac_context);

    mtx_destroy(&mac->mutex);

    memory_memset_unoptimizable(mac, 0, sizeof(mac_t));
    memory_internal_free(mac);
}

static bool mac_lock(mac_t* mac) {
    if (mac == NULL) {
        return false;
    }

    if (mtx_lock(&mac->mutex) != thrd_success) {
        ERROR("mtx_lock failed");
        return false;
    }

    return true;
}

static void mac_unlock(mac_t* mac) {
    if (mac == NULL) {
        return;
    }

    if (mtx_unlock(&mac->mutex) != thrd_success) {
        ERROR("mtx_unlock failed");
    }
}

mac_store_t* mac_store_init(size_t size) {
    mac_store_t* store = object_store_init(mac_free, size, "mac");
    if (store == NULL) {
        ERROR("object_store_init failed");
        return NULL;
    }

    return store;
}

void mac_store_shutdown(mac_store_t* store) {
    if (store == NULL) {
        return;
    }

    object_store_shutdown(store);
}

sa_status mac_store_add_hmac_context(
        sa_crypto_mac_context* context,
        mac_store_t* store,
        hmac_context_t* hmac_context,
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

    if (hmac_context == NULL) {
        ERROR("NULL hmac_context");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_NULL_PARAMETER;
    }

    mac_t* mac = NULL;
    sa_status status = SA_STATUS_INTERNAL_ERROR;
    do {
        mac = mac_allocate();
        if (mac == NULL) {
            ERROR("mac_allocate failed");
            break;
        }

        mac->mac_algorithm = SA_MAC_ALGORITHM_HMAC;
        mac->hmac_context = hmac_context;

        status = object_store_add(context, store, mac, caller_uuid);
        if (status != SA_STATUS_OK) {
            // Let the caller free the hmac_context to avoid a crash.
            mac->hmac_context = NULL;
            ERROR("object_store_add failed");
            break;
        }

        // ownership has been transferred to store
        mac = NULL;
    } while (false);

    mac_free(mac);

    return status;
}

sa_status mac_store_add_cmac_context(
        sa_crypto_mac_context* context,
        mac_store_t* store,
        cmac_context_t* cmac_context,
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

    if (cmac_context == NULL) {
        ERROR("NULL cmac_context");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_NULL_PARAMETER;
    }

    mac_t* mac = NULL;
    sa_status status = SA_STATUS_INTERNAL_ERROR;
    do {
        mac = mac_allocate();
        if (mac == NULL) {
            ERROR("mac_allocate failed");
            break;
        }

        mac->mac_algorithm = SA_MAC_ALGORITHM_CMAC;
        mac->cmac_context = cmac_context;

        status = object_store_add(context, store, mac, caller_uuid);
        if (status != SA_STATUS_OK) {
            // Let the caller free the cmac_context to avoid a crash.
            mac->cmac_context = NULL;
            ERROR("object_store_add failed");
            break;
        }

        // ownership has been transferred to store
        mac = NULL;
    } while (false);

    mac_free(mac);

    return status;
}

sa_status mac_store_remove(
        mac_store_t* store,
        sa_crypto_mac_context context,
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

sa_status mac_store_acquire_exclusive(
        mac_t** mac,
        mac_store_t* store,
        size_t slot,
        const sa_uuid* caller_uuid) {

    if (mac == NULL) {
        ERROR("NULL mac");
        return SA_STATUS_NULL_PARAMETER;
    }
    *mac = NULL;

    if (store == NULL) {
        ERROR("NULL store");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_NULL_PARAMETER;
    }

    void* object = NULL;
    sa_status status = object_store_acquire(&object, store, slot, caller_uuid);
    if (status != SA_STATUS_OK) {
        ERROR("object_store_acquire failed");
        return status;
    }

    *mac = object;

    if (!mac_lock(*mac)) {
        ERROR("mac_lock failed");
        return SA_STATUS_INTERNAL_ERROR;
    }

    return SA_STATUS_OK;
}

sa_status mac_store_release_exclusive(
        mac_store_t* store,
        sa_crypto_mac_context context,
        mac_t* mac,
        const sa_uuid* caller_uuid) {

    if (store == NULL) {
        ERROR("NULL store");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (mac == NULL) {
        ERROR("NULL mac");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_NULL_PARAMETER;
    }

    mac_unlock(mac);

    sa_status status = object_store_release(store, context, mac, caller_uuid);
    if (status != SA_STATUS_OK) {
        ERROR("object_store_release failed");
        return status;
    }

    return SA_STATUS_OK;
}
