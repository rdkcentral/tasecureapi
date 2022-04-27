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

#include "client.h"
#include "ta_client.h"
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <threads.h>

static thread_local void* session = NULL;
static tss_t thread_session;
static once_flag flag = ONCE_FLAG_INIT;
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

static void client_create() {
    if (mtx_init(&mutex, mtx_recursive) != thrd_success) {
        ERROR("mtx_init failed");
        return;
    }

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

    call_once(&flag, client_create);

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

void client_log_entry(
        const char* file,
        int line,
        const char* function,
        const char* format,
        ...) {

    // get current time
    time_t current_time = time(NULL);
    struct tm local_time;
    localtime_r(&current_time, &local_time);

    // compose new format line with timestamp, log level, file and line numbers
    char new_format[320];
    strftime(new_format, sizeof(new_format), "%D %H:%M:%S ", &local_time);
    snprintf(new_format + 18, sizeof(new_format) - 18, "ERROR %.96s:%d (%.32s): %.128s\n", file, line, function,
            format);

    // forward to vfprintf
    va_list args;
    va_start(args, format);
    vfprintf(stderr, new_format, args);
    va_end(args);
    fflush(stderr);
}
