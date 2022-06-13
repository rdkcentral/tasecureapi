/**
 * Copyright 2022 Comcast Cable Communications Management, LLC
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

#ifndef SA_LOG_H
#define SA_LOG_H

#ifdef __cplusplus
extern "C" {
#endif

#define ERROR(...) sa_log_entry(__FILE__, __LINE__, __func__, __VA_ARGS__)

/**
 * Create a log entry.
 *
 * @param[in] file source file.
 * @param[in] line source line number.
 * @param[in] function function name.
 * @param[in] format format string.
 * @param[in] ... data.
 */
void sa_log_entry(
        const char* file,
        int line,
        const char* function,
        const char* format,
        ...);

#ifdef __cplusplus
}
#endif

#endif //SA_LOG_H
