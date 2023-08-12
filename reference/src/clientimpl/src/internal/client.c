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

#include "client.h"
#include "log.h"
#include "ta_client.h"
#include <stdbool.h>
#include <stdlib.h>
#include <threads.h>

static void* session = NULL;
static once_flag mutex_flag = ONCE_FLAG_INIT;
static once_flag shutdown_flag = ONCE_FLAG_INIT;
static mtx_t mutex;

static void client_shutdown() {
    if (session != NULL) {
        ta_close_session(session);
        session = NULL;
    }
}

static void client_mutex_create() {
    if (mtx_init(&mutex, mtx_recursive) != thrd_success) {
        ERROR("mtx_init failed");
        return;
    }
}

static void client_create() {
    // Calls client_shutdown when the main thread exits.
    if (atexit(client_shutdown) != 0) {
        ERROR("atexit failed");
        return;
    }
}

void* client_session() {
    if (session != NULL) {
        return session;
    }

    call_once(&mutex_flag, client_mutex_create);

    if (mtx_lock(&mutex) != thrd_success) {
        ERROR("mtx_lock failed");
        return NULL;
    }

    do {
        // someone may have created a client underneath us
        if (session != NULL) {
            break;
        }

        sa_status status = ta_open_session(&session);
        if (status != SA_STATUS_OK) {
            ERROR("ta_sa_init failed: %d", status);
            break;
        }

        // Call after the open session so that client_shutdown handler runs after the TA handler in the reference
        // implementation.
        call_once(&shutdown_flag, client_create);
    } while (false);

    if (mtx_unlock(&mutex) != thrd_success) {
        ERROR("mtx_unlock failed");
    }

    return session;
}
