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

static thread_local void* session = NULL;
static tss_t thread_session;
static once_flag mutex_flag = ONCE_FLAG_INIT;
static once_flag shutdown_flag = ONCE_FLAG_INIT;
static mtx_t mutex;

static void client_thread_shutdown(void* client_session) {
    if (client_session != NULL) {
        ta_close_session(client_session);
    }
}

static void client_shutdown() {
    if (session != NULL) {
        client_thread_shutdown(session);
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
    // Calls client_thread_shutdown when the thread exits.
    if (tss_create(&thread_session, client_thread_shutdown) != 0) {
        ERROR("tss_create failed");
        return;
    }

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

        // Store the session in thread specific storage so that it can be cleaned up automatically when the thread
        // exits.
        void* thread_session_ptr = session;
        if (tss_set(thread_session, thread_session_ptr) != thrd_success) {
            ERROR("tss_set failed");
            break;
        }
    } while (false);

    if (mtx_unlock(&mutex) != thrd_success) {
        ERROR("mtx_unlock failed");
    }

    return session;
}
