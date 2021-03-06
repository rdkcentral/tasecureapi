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

/**
 * @section Description
 * @file ta_client.h
 *
 * This file contains functions that implements the REE -> TA interface and the TA -> TA interface. SOC vendors must
 * provide client implementations of the functions ta_open_session, ta_close_session, and ta_invoke_command that makes
 * calls into a TA (i.e., ta_client.c should be replaced).
 */

#ifndef TA_CLIENT_H
#define TA_CLIENT_H

#include "sa_ta_types.h"
#ifdef __cplusplus

#include <cmemory>
#include <cstddef>
#include <cstdint>
#include <cstdlib>

extern "C" {
#else

#include <memory.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#endif

#define NUM_TA_PARAMS 4

#ifdef USE_SHARED_MEMORY

#define CREATE_COMMAND(type, command) \
    command = ta_alloc_shared_memory(sizeof(type))

#define RELEASE_COMMAND(command) \
    ta_free_shared_memory(command)

#define CREATE_PARAM(param, input, size) \
    param = ta_alloc_shared_memory(size); \
    if ((param) != NULL) \
    memcpy(param, input, size)

#define CREATE_OUT_PARAM(param, output, size) \
    param = ta_alloc_shared_memory(size)

#define COPY_OUT_PARAM(output, param, size) \
    memcpy(output, param, size)

#define RELEASE_PARAM(param) \
    ta_free_shared_memory(param)

#else

#define CREATE_COMMAND(type, command) \
    command = malloc(sizeof(type))

#define RELEASE_COMMAND(command) \
    if ((command) != NULL) \
    free(command)

#define CREATE_PARAM(param, input, size) \
    param = input

#define CREATE_OUT_PARAM(param, output, size) \
    param = output

// NOOP
#define COPY_OUT_PARAM(output, param, size) \
    do { \
    } while (0)

// NOOP
#define RELEASE_PARAM(param) \
    do { \
    } while (0)

#endif

/**
 * Opens a session on the TA.
 *
 * @param session_context the opaque session context.
 * @return a result.
 */
sa_status ta_open_session(void** session_context);

/**
 * Closes a session on the TA.
 *
 * @param session_context the opaque session context.
 */
void ta_close_session(void* session_context);

/**
 * Invokes a command on the TA.
 *
 * @param session_context the opaque session context returned from an open session command.
 * @param command_id the id of the command to invoke.
 * @param parameters_types the types of the 4 parameters.
 * @param parameters the 4 command parameters.
 * @return the status of the command.
 */
sa_status ta_invoke_command(
        void* session_context,
        SA_COMMAND_ID command_id,
        const ta_param_type param_types[NUM_TA_PARAMS],
        ta_param params[NUM_TA_PARAMS]);

/**
 * Allocates shared memory that can be accessed by both the REE and TA.
 *
 * @param size the size of the memory block to allocate.
 * @return the shared memory buffer. NULL if the shared memory buffer could not be allocated.
 */
void* ta_alloc_shared_memory(size_t size);

/**
 * Frees a shared memory block.
 *
 * @param buffer the shared memory buffer to free.
 */
void ta_free_shared_memory(void* buffer);

#ifdef __cplusplus
}
#endif

#endif // TA_CLIENT_H
