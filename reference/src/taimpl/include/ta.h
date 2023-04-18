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

/**
 * @section Description
 * @file ta.h
 *
 * This file contains declarations for functions that implement the TA handling code. SOC vendors should write
 * functions that call ta_open_session_handler, ta_close_session_handler, ta_invoke_command_handler.
 */

#ifndef TA_H
#define TA_H

#include "sa_ta_types.h"

#define NUM_TA_PARAMS 4

/**
 * Implements open session on the TA.
 *
 * @param session_context the opaque session context.
 * @return a result.
 */
sa_status ta_open_session_handler(void** session_context);

/**
 * Implements close session on the TA.
 *
 * @param session_context the opaque session context.
 */
void ta_close_session_handler(void* session_context);

/**
 * Implements the invocation of a command on the TA.
 *
 * @param session_context the opaque session context returned from an open session command.
 * @param command_id the id of the command to invoke.
 * @param parameters the 4 command parameters.
 * @return the status of the command.
 */
sa_status ta_invoke_command_handler(
        void* session_context,
        SA_COMMAND_ID command_id,
        ta_param params[NUM_TA_PARAMS]);

#ifdef __cplusplus
}
#endif

#endif // TA_H
