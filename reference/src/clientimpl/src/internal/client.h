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

#ifndef CLIENT_H
#define CLIENT_H

#include "sa_types.h"

#ifdef __cplusplus
#include <cstdio>
extern "C" {
#else
#include <stdio.h>
#endif

#define ERROR(...) client_log_entry(__FILE__, __LINE__, __func__, __VA_ARGS__)

/**
 * Returns a session for the thread. On first call, the client opens a session with the SecApi TA. Client session is
 * released automatically on thread exit.
 *
 * @return client session context.
 */
void* client_session();

/**
 * Create a log entry.
 *
 * @param[in] file source file.
 * @param[in] line source line number.
 * @param[in] function function name.
 * @param[in] format format string.
 * @param[in] ... data.
 */
void client_log_entry(
        const char* file,
        int line,
        const char* function,
        const char* format,
        ...);

#ifdef __cplusplus
}
#endif

#endif // CLIENT_H
