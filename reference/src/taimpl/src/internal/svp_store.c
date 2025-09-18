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
#ifndef DISABLE_SVP
#include "svp_store.h" // NOLINT
#include "log.h"
#include "porting/memory.h"
#include "porting/svp.h"
#include <threads.h>

struct svp_s {
    svp_buffer_t* buffer;
    mtx_t mutex;
};
sa_status svp_supported() {
    return SA_STATUS_OK;
}
static void svp_free(void* object) {
    if (object == NULL) {
        return;
    }

    svp_t* svp = (svp_t*) object;

    mtx_destroy(&svp->mutex);

    if (svp->buffer != NULL)
        memory_internal_free(svp->buffer);

    memory_memset_unoptimizable(svp, 0, sizeof(svp_t));
    memory_internal_free(svp);
}

static svp_t* svp_create(
        void* buffer,
        size_t size) {

    bool status = false;
    svp_t* svp = NULL;
    do {
        svp = memory_internal_alloc(sizeof(svp_t));
        if (svp == NULL) {
            ERROR("memory_internal_alloc failed");
            break;
        }

        memory_memset_unoptimizable(svp, 0, sizeof(svp_t));

        if (!svp_create_buffer(&svp->buffer, buffer, size)) {
            ERROR("svp_create failed");
            break;
        }

        if (mtx_init(&svp->mutex, mtx_recursive)) {
            ERROR("mtx_init failed");
            break;
        }

        status = true;
    } while (false);

    if (!status) {
        if (svp != NULL) {
            svp_free(svp);
            svp = NULL;
        }
    }

    return svp;
}

static bool svp_lock(svp_t* svp) {
    if (svp == NULL) {
        return false;
    }

    if (mtx_lock(&svp->mutex) != thrd_success) {
        ERROR("mtx_lock failed");
        return false;
    }

    return true;
}

static void svp_unlock(svp_t* svp) {
    if (svp == NULL) {
        return;
    }

    if (mtx_unlock(&svp->mutex) != thrd_success) {
        ERROR("mtx_unlock failed");
    }
}

svp_buffer_t* svp_get_buffer(const svp_t* svp) {
    if (svp == NULL) {
        ERROR("NULL svp");
        return NULL;
    }

    return svp->buffer;
}

svp_store_t* svp_store_init(size_t size) {
    svp_store_t* store = object_store_init(svp_free, size, "svp");
    if (store == NULL) {
        ERROR("object_store_init failed");
        return NULL;
    }

    return store;
}

void svp_store_shutdown(svp_store_t* store) {
    if (store == NULL) {
        return;
    }

    object_store_shutdown(store);
}


sa_status svp_store_create(
        sa_svp_buffer* svp_buffer,
        svp_store_t* store,
        void* svp_memory,
        size_t size,
        const sa_uuid* caller_uuid) {

    sa_status status = svp_supported();
    if (status != SA_STATUS_OK)
        return status;

    if (svp_buffer == NULL) {
        ERROR("NULL svp_buffer");
        return SA_STATUS_NULL_PARAMETER;
    }

    *svp_buffer = INVALID_HANDLE;

    if (store == NULL) {
        ERROR("NULL store");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (svp_memory == NULL) {
        ERROR("NULL svp_memory");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_NULL_PARAMETER;
    }

    svp_t* svp = NULL;
    status = SA_STATUS_INTERNAL_ERROR;
    do {
        svp = svp_create(svp_memory, size);
        if (svp == NULL) {
            ERROR("svp_create failed");
            break;
        }

        status = object_store_add(svp_buffer, store, svp, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("object_store_add failed");
            break;
        }

        // ownership has been transferred to store
        svp = NULL;
    } while (false);

    svp_free(svp);

    return status;
}

sa_status svp_store_release(
        void** svp_memory,
        size_t* size,
        svp_store_t* store,
        sa_svp_buffer svp_buffer,
        const sa_uuid* caller_uuid) {

    sa_status status = svp_supported();
    if (status != SA_STATUS_OK)
        return status;

    if (svp_memory == NULL) {
        ERROR("NULL svp_memory");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (size == NULL) {
        ERROR("NULL size");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (store == NULL) {
        ERROR("NULL store");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_NULL_PARAMETER;
    }

    svp_t* svp;
    status = svp_store_acquire_exclusive(&svp, store, svp_buffer, caller_uuid);
    if (status != SA_STATUS_OK) {
        ERROR("svp_store_acquire_exclusive failed");
        return status;
    }

    if (!svp_release_buffer(svp_memory, size, svp->buffer)) {
        ERROR("svp_release_buffer failed");
        return status;
    }

    svp->buffer = NULL;
    status = svp_store_release_exclusive(store, svp_buffer, svp, caller_uuid);
    if (status != SA_STATUS_OK) {
        ERROR("svp_store_acquire_exclusive failed");
        return status;
    }

    status = object_store_remove(store, svp_buffer, caller_uuid);
    if (status != SA_STATUS_OK) {
        ERROR("object_store_remove failed");
        return status;
    }

    return SA_STATUS_OK;
}

sa_status svp_store_acquire_exclusive(
        svp_t** svp,
        svp_store_t* store,
        sa_svp_buffer svp_buffer,
        const sa_uuid* caller_uuid) {

    sa_status status = svp_supported();
    if (status != SA_STATUS_OK)
        return status;

    if (svp == NULL) {
        ERROR("NULL svp");
        return SA_STATUS_NULL_PARAMETER;
    }
    *svp = NULL;

    if (store == NULL) {
        ERROR("NULL store");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_NULL_PARAMETER;
    }

    void* object = NULL;
    status = object_store_acquire(&object, store, svp_buffer, caller_uuid);
    if (status != SA_STATUS_OK) {
        ERROR("object_store_acquire failed");
        return status;
    }

    *svp = object;

    if (!svp_lock(*svp)) {
        ERROR("svp_lock failed");
        return SA_STATUS_INTERNAL_ERROR;
    }

    return SA_STATUS_OK;
}

sa_status svp_store_release_exclusive(
        svp_store_t* store,
        sa_svp_buffer svp_buffer,
        svp_t* svp,
        const sa_uuid* caller_uuid) {

    sa_status status = svp_supported();
    if (status != SA_STATUS_OK)
        return status;

    if (store == NULL) {
        ERROR("NULL store");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (svp == NULL) {
        ERROR("NULL svp");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_NULL_PARAMETER;
    }

    svp_unlock(svp);

    status = object_store_release(store, svp_buffer, svp, caller_uuid);
    if (status != SA_STATUS_OK) {
        ERROR("object_store_release failed");
        return status;
    }

    return SA_STATUS_OK;
}
#endif // DISABLE_SVP
