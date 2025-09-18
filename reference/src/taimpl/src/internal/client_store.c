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

#include "client_store.h"
#include "log.h"
#include "porting/memory.h"
#include <stdlib.h>
#include <threads.h>

#define NUM_CLIENT_SLOTS 256
#define NUM_KEY_SLOTS 256
#define NUM_CIPHER_SLOTS 256
#define NUM_MAC_SLOTS 256
#define NUM_SVP_SLOTS 256

static once_flag flag = ONCE_FLAG_INIT;
static mtx_t mutex;
static bool global_shutdown = false;

struct client_s {
    key_store_t* key_store;
    cipher_store_t* cipher_store;
    mac_store_t* mac_store;
#ifndef DISABLE_SVP
    svp_store_t* svp_store;
#endif // DISABLE_SVP
};

key_store_t* client_get_key_store(const client_t* client) {
    if (client == NULL) {
        ERROR("NULL client");
        return NULL;
    }

    return client->key_store;
}

cipher_store_t* client_get_cipher_store(const client_t* client) {
    if (client == NULL) {
        ERROR("NULL client");
        return NULL;
    }

    return client->cipher_store;
}

mac_store_t* client_get_mac_store(const client_t* client) {
    if (client == NULL) {
        ERROR("NULL client");
        return NULL;
    }

    return client->mac_store;
}

#ifndef DISABLE_SVP
svp_store_t* client_get_svp_store(const client_t* client) {
    if (client == NULL) {
        ERROR("NULL client");
        return NULL;
    }

    return client->svp_store;
}
#endif // DISABLE_SVP

static void client_free(void* object) {
    if (object == NULL) {
        return;
    }

    client_t* client = (client_t*) object;

    key_store_shutdown(client->key_store);
    cipher_store_shutdown(client->cipher_store);
    mac_store_shutdown(client->mac_store);
#ifndef DISABLE_SVP
    svp_store_shutdown(client->svp_store);
#endif // DISABLE_SVP
    memory_internal_free(client);
}
#ifndef DISABLE_SVP
static client_t* client_init(
        const sa_uuid* uuid,
        size_t key_store_size,
        size_t cipher_store_size,
        size_t mac_store_size,
        size_t svp_store_size) {
#else
static client_t* client_init(
        const sa_uuid* uuid,
        size_t key_store_size,
        size_t cipher_store_size,
        size_t mac_store_size) {
#endif // DISABLE_SVP
    if (uuid == NULL) {
        ERROR("NULL uuid");
        return NULL;
    }

    client_t* client = NULL;
    bool status = false;
    do {
        client = memory_internal_alloc(sizeof(client_t));
        if (client == NULL) {
            ERROR("memory_internal_alloc failed");
            break;
        }
        memory_memset_unoptimizable(client, 0, sizeof(client_t));

        client->key_store = key_store_init(key_store_size);
        if (client->key_store == NULL) {
            ERROR("key_store_init failed");
            break;
        }

        client->cipher_store = cipher_store_init(cipher_store_size);
        if (client->cipher_store == NULL) {
            ERROR("cipher_store_init failed");
            break;
        }

        client->mac_store = mac_store_init(mac_store_size);
        if (client->mac_store == NULL) {
            ERROR("mac_store_init failed");
            break;
        }
#ifndef DISABLE_SVP
        client->svp_store = svp_store_init(svp_store_size);
        if (client->svp_store == NULL) {
            ERROR("svp_store_init failed");
            break;
        }
#endif // DISABLE_SVP
        status = true;
    } while (false);

    if (!status) {
        client_free(client);
        client = NULL;
    }

    return client;
}

static client_store_t* client_store_init(size_t size) {
    client_store_t* store = object_store_init(client_free, size, "client");
    if (store == NULL) {
        ERROR("object_store_init failed");
        return NULL;
    }

    return store;
}

static void client_store_shutdown(client_store_t* store) {
    if (store == NULL) {
        return;
    }

    object_store_shutdown(store);
}

static void client_store_global_shutdown() {
    client_store_shutdown(client_store_global());
    global_shutdown = true;
}

static void client_store_global_create() {
    if (mtx_init(&mutex, mtx_recursive) != thrd_success) {
        ERROR("mtx_init failed");
        return;
    }

    atexit(client_store_global_shutdown);
}

client_store_t* client_store_global() {
    static client_store_t* global = NULL;

    if (global != NULL) {
        if (global_shutdown)
            return NULL;

        return global;
    }

    call_once(&flag, client_store_global_create);

    if (mtx_lock(&mutex) != thrd_success) {
        ERROR("mtx_lock failed");
        return NULL;
    }

    do {
        // someone may have created an instance underneath us
        if (global != NULL) {
            break;
        }

        global = client_store_init(NUM_CLIENT_SLOTS);
        if (global == NULL) {
            ERROR("client_store_init failed");
            break;
        }
    } while (false);

    if (mtx_unlock(&mutex) != thrd_success) {
        ERROR("mtx_unlock failed");
    }

    return global;
}

sa_status client_store_add(
        ta_client* client_slot,
        client_store_t* store,
        const sa_uuid* caller_uuid) {

    if (client_slot == NULL) {
        ERROR("NULL client_slot");
        return SA_STATUS_NULL_PARAMETER;
    }
    *client_slot = INVALID_HANDLE;

    if (store == NULL) {
        ERROR("NULL store");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status = SA_STATUS_INTERNAL_ERROR;
    client_t* client = NULL;
    do {
#ifndef DISABLE_SVP
        client = client_init(caller_uuid, NUM_KEY_SLOTS, NUM_CIPHER_SLOTS, NUM_MAC_SLOTS, NUM_SVP_SLOTS);
#else
        client = client_init(caller_uuid, NUM_KEY_SLOTS, NUM_CIPHER_SLOTS, NUM_MAC_SLOTS);
#endif // DISABLE_SVP
        if (client == NULL) {
            ERROR("client_init failed");
            break;
        }

        status = object_store_add(client_slot, store, client, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("object_store_add failed");
            break;
        }

        // now the store owns the client
        client = NULL;
    } while (false);

    client_free(client);

    return status;
}

sa_status client_store_remove(
        client_store_t* store,
        ta_client client_slot,
        const sa_uuid* caller_uuid) {

    if (global_shutdown) {
        return SA_STATUS_NO_AVAILABLE_RESOURCE_SLOT;
    }

    if (store == NULL) {
        ERROR("NULL store");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status = object_store_remove(store, client_slot, caller_uuid);
    if (status != SA_STATUS_OK) {
        ERROR("object_store_remove failed");
        return status;
    }

    return SA_STATUS_OK;
}

sa_status client_store_acquire(
        client_t** client,
        client_store_t* store,
        ta_client client_slot,
        const sa_uuid* caller_uuid) {

    if (global_shutdown) {
        return SA_STATUS_NO_AVAILABLE_RESOURCE_SLOT;
    }

    if (client == NULL) {
        ERROR("NULL client");
        return SA_STATUS_NULL_PARAMETER;
    }
    *client = NULL;

    if (store == NULL) {
        ERROR("NULL store");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_NULL_PARAMETER;
    }

    void* object = NULL;
    sa_status status = object_store_acquire(&object, store, client_slot, caller_uuid);
    if (status != SA_STATUS_OK) {
        ERROR("object_store_acquire failed");
        return status;
    }
    *client = object;

    return SA_STATUS_OK;
}

sa_status client_store_release(
        client_store_t* store,
        ta_client client_slot,
        client_t* client,
        const sa_uuid* caller_uuid) {

    if (store == NULL) {
        ERROR("NULL store");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (client == NULL) {
        ERROR("NULL client");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status = object_store_release(store, client_slot, client, caller_uuid);
    if (status != SA_STATUS_OK) {
        ERROR("object_store_release failed");
        return status;
    }

    return SA_STATUS_OK;
}
