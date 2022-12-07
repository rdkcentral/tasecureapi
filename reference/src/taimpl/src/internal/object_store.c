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

#include "object_store.h" // NOLINT
#include "log.h"
#include "porting/memory.h"
#include "slots.h"
#include <inttypes.h>
#include <memory.h>
#include <threads.h>
#include <unistd.h>

typedef struct {
    void* object;
    size_t reference_count;
    sa_uuid owner_uuid;
} store_object_t;

struct object_store_s {
    mtx_t mutex;
    object_free_function object_free;
    slots_t* slots;
    store_object_t* objects;
    size_t slot_count;
    // store is in the process of shutting down
    bool is_shutting_down;
    // track how many release operations are currently running
    size_t release_count;
};

object_store_t* object_store_init(
        object_free_function object_free,
        size_t count) {

    if (object_free == NULL) {
        ERROR("NULL object_free");
        return NULL;
    }

    if (count % (sizeof(int) * 8)) {
        ERROR("Number of objects has to be a multiple of int bit length");
        return NULL;
    }

    bool status = false;
    slots_t* slots = NULL;
    store_object_t* objects = NULL;
    object_store_t* store = NULL;
    do {
        slots = slots_init(count);
        if (slots == NULL) {
            ERROR("slots_init failed");
            break;
        }

        objects = memory_internal_alloc(sizeof(store_object_t) * count);
        if (objects == NULL) {
            ERROR("memory_internal_alloc failed");
            break;
        }

        memory_memset_unoptimizable(objects, 0, sizeof(store_object_t) * count);
        store = memory_internal_alloc(sizeof(object_store_t));
        if (store == NULL) {
            ERROR("memory_internal_alloc failed");
            break;
        }

        store->object_free = object_free;
        store->slots = slots;
        store->objects = objects;
        store->slot_count = count;
        store->is_shutting_down = false;
        store->release_count = 0;

        // slots and objects are not owned by the store
        slots = NULL;
        objects = NULL;

        if (mtx_init(&store->mutex, mtx_recursive) != thrd_success) {
            ERROR("mtx_init failed");
            break;
        }

        status = true;
    } while (false);

    slots_shutdown(slots);
    memory_internal_free(objects);

    if (!status) {
        memory_internal_free(store);
        store = NULL;
    }

    return store;
}

static bool increment_release_count(object_store_t* store) {
    if (store == NULL) {
        return false;
    }

    bool status = false;
    if (mtx_lock(&store->mutex) != thrd_success) {
        ERROR("mtx_lock failed");
        return false;
    }

    do {
        if (store->is_shutting_down) {
            WARN("Store is shutting down");
            break;
        }

        store->release_count += 1;

        status = true;
    } while (false);

    if (mtx_unlock(&store->mutex) != thrd_success) {
        ERROR("mtx_unlock failed");
    }

    return status;
}

static void decrement_release_count(object_store_t* store) {
    if (store == NULL) {
        return;
    }

    if (mtx_lock(&store->mutex) != thrd_success) {
        ERROR("mtx_lock failed");
        return;
    }

    store->release_count -= 1;
    if (mtx_unlock(&store->mutex) != thrd_success) {
        ERROR("mtx_unlock failed");
    }
}

static sa_status store_remove(
        object_store_t* store,
        slot_t slot,
        const sa_uuid* caller_uuid) {

    if (store == NULL) {
        ERROR("NULL store");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (slot >= store->slot_count) {
        ERROR("Invalid slot");
        return SA_STATUS_INVALID_PARAMETER;
    }

    bool is_shutting_down = (!caller_uuid);

    // Check if shut down is happening. Ignore this request if it is not part of the shutdown
    // procedure.
    if (!is_shutting_down) {
        if (!increment_release_count(store)) {
            WARN("Ignoring release. Store is shutting down.");
            return SA_STATUS_OK;
        }
    }

    sa_status status;
    void* object_to_free = NULL;
    do {
        if (mtx_lock(&store->mutex) != thrd_success) {
            ERROR("mtx_lock failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        store_object_t* store_object = &store->objects[slot];

        if (store_object->object == NULL) {
            // empty slot, nothing to do
            status = SA_STATUS_INVALID_PARAMETER;
            break;
        }

        if (!is_shutting_down &&
                (memory_memcmp_constant(&store_object->owner_uuid, caller_uuid, sizeof(sa_uuid)) != 0)) {
            ERROR("TA UUID does not match");
            status = SA_STATUS_OPERATION_NOT_ALLOWED;
            break;
        }

        if (store_object->reference_count == 0) {
            if (is_shutting_down) {
                WARN("Releasing object %" PRIu32 " from the store %p on shutdown", slot, store);
            }

            // reference count is 0, ok to delete
            object_to_free = store_object->object;
            store_object->object = NULL;
            slots_free(store->slots, slot);

            status = SA_STATUS_OK;
            break;
        }

        if (mtx_unlock(&store->mutex) != thrd_success) {
            ERROR("mtx_unlock failed");
        }

        // we are waiting for reference count to go to 0, sleep to allow other threads to release
        // the resource.
        sleep(0); // NOLINT
    } while (true);

    if (mtx_unlock(&store->mutex) != thrd_success) {
        ERROR("mtx_unlock failed");
    }

    // decrement the reference count if not shutting down
    if (!is_shutting_down) {
        decrement_release_count(store);
    }

    // free the resource
    if (object_to_free != NULL) {
        store->object_free(object_to_free);
    }

    return status;
}

void object_store_shutdown(object_store_t* store) {
    if (store == NULL) {
        return;
    }

    // indicate that the store is shutting down, so all future requests will fail
    if (mtx_lock(&store->mutex) != thrd_success) {
        ERROR("mtx_lock failed");
        return;
    }

    store->is_shutting_down = true;
    if (mtx_unlock(&store->mutex) != thrd_success) {
        ERROR("mtx_unlock failed");
    }

    // wait for release count to go to 0 before freeing all objects
    // release count is the number of non-shutdown release calls that are still processing.
    do {
        if (mtx_lock(&store->mutex) != thrd_success) {
            ERROR("mtx_lock failed");
            break;
        }

        size_t release_count = store->release_count;
        if (mtx_unlock(&store->mutex) != thrd_success) {
            ERROR("mtx_unlock failed");
        }

        if (release_count == 0) {
            break;
        }

        sleep(0); // NOLINT
    } while (true);

    // free keys that are still in the store
    for (size_t i = 0; i < store->slot_count; ++i) {
        store_remove(store, i, NULL);
    }

    slots_shutdown(store->slots);
    store->slots = NULL;
    memory_internal_free(store->objects);
    store->objects = NULL;

    mtx_destroy(&store->mutex);

    memory_internal_free(store);
}

sa_status object_store_add(
        slot_t* slot,
        object_store_t* store,
        void* object,
        const sa_uuid* caller_uuid) {

    if (slot == NULL) {
        ERROR("NULL slot");
        return SA_STATUS_NULL_PARAMETER;
    }
    *slot = SLOT_INVALID;

    if (store == NULL) {
        ERROR("NULL store");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (object == NULL) {
        ERROR("NULL object");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (mtx_lock(&store->mutex) != thrd_success) {
        ERROR("mtx_lock failed");
        return SA_STATUS_INTERNAL_ERROR;
    }

    sa_status status = SA_STATUS_INTERNAL_ERROR;
    do {
        if (store->is_shutting_down) {
            ERROR("Store is shutting down");
            break;
        }

        *slot = slots_allocate(store->slots);
        if (*slot == SLOT_INVALID) {
            ERROR("slots_allocate failed");
            status = SA_STATUS_NO_AVAILABLE_RESOURCE_SLOT;
            break;
        }

        store_object_t* store_object = &store->objects[*slot];
        store_object->object = object;
        memcpy(&store_object->owner_uuid, caller_uuid, sizeof(sa_uuid));

        status = SA_STATUS_OK;
    } while (false);

    if (mtx_unlock(&store->mutex) != thrd_success) {
        ERROR("mtx_unlock failed");
    }

    return status;
}

sa_status object_store_remove(
        object_store_t* store,
        slot_t slot,
        const sa_uuid* caller_uuid) {

    if (store == NULL) {
        ERROR("NULL store");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status = store_remove(store, slot, caller_uuid);
    if (status != SA_STATUS_OK) {
        ERROR("store_remove failed");
        return status;
    }

    return SA_STATUS_OK;
}

sa_status object_store_acquire(
        void** object,
        object_store_t* store,
        slot_t slot,
        const sa_uuid* caller_uuid) {

    if (object == NULL) {
        ERROR("NULL object");
        return SA_STATUS_NULL_PARAMETER;
    }
    *object = NULL;

    if (store == NULL) {
        ERROR("NULL store");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (slot >= store->slot_count) {
        ERROR("Invalid slot");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (mtx_lock(&store->mutex) != thrd_success) {
        ERROR("mtx_lock failed");
        return SA_STATUS_INTERNAL_ERROR;
    }

    sa_status status = SA_STATUS_INTERNAL_ERROR;
    store_object_t* store_object = &store->objects[slot];
    do {
        if (store_object == NULL) {
            ERROR("No object at specified slot");
            status = SA_STATUS_NULL_PARAMETER;
            break;
        }

        if (store->is_shutting_down) {
            ERROR("Store is shutting down");
            break;
        }

        *object = store_object->object;
        if (*object == NULL) {
            ERROR("No object at specified slot");
            status = SA_STATUS_INVALID_PARAMETER;
            break;
        }

        if (memory_memcmp_constant(&store_object->owner_uuid, caller_uuid, sizeof(sa_uuid)) != 0) {
            *object = NULL;
            ERROR("TA UUID does not match");
            status = SA_STATUS_OPERATION_NOT_ALLOWED;
            break;
        }

        store_object->reference_count += 1;

        status = SA_STATUS_OK;
    } while (false);

    if (mtx_unlock(&store->mutex) != thrd_success) {
        ERROR("mtx_unlock failed");
    }

    return status;
}

sa_status object_store_release(object_store_t* store, slot_t slot, void* object, const sa_uuid* caller_uuid) {
    if (store == NULL) {
        ERROR("NULL store");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (slot >= store->slot_count) {
        ERROR("Invalid slot");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (object == NULL) {
        // silent return
        return SA_STATUS_NULL_PARAMETER;
    }

    if (mtx_lock(&store->mutex) != thrd_success) {
        ERROR("mtx_lock failed");
        return SA_STATUS_INTERNAL_ERROR;
    }

    sa_status status = SA_STATUS_INTERNAL_ERROR;
    store_object_t* store_object = &store->objects[slot];
    do {
        if (memory_memcmp_constant(&store_object->owner_uuid, caller_uuid, sizeof(sa_uuid)) != 0) {
            ERROR("TA UUID does not match");
            status = SA_STATUS_OPERATION_NOT_ALLOWED;
            break;
        }

        if (store_object->object != object) {
            ERROR("obj does not match the store entry. This can lead to resources not being freed.");
            break;
        }

        if (store_object->reference_count == 0) {
            ERROR("ref_count is already at 0");
            break;
        }

        store_object->reference_count -= 1;

        status = SA_STATUS_OK;
    } while (false);

    if (mtx_unlock(&store->mutex) != thrd_success) {
        ERROR("mtx_unlock failed");
    }

    return status;
}

size_t object_store_size(object_store_t* store) {
    if (store == NULL) {
        ERROR("NULL store");
        return 0;
    }

    return store->slot_count;
}
