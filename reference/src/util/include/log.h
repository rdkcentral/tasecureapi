/*
 * Copyright 2019-2023 Comcast Cable Communications Management, LLC
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

/** @section Description
 * @file log.h
 *
 * This file contains the functions and structures providing logging support.
 */

#ifndef LOG_H
#define LOG_H

#ifdef __cplusplus
#include <cstddef>
extern "C" {
#else
#include <stddef.h>
#endif

typedef enum {
    LOG_LEVEL_TRACE = 0,
    LOG_LEVEL_DEBUG,
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARN,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_FATAL
} log_level_e;

#define TRACE(...) log_entry(LOG_LEVEL_TRACE, __FILE__, __LINE__, __func__, __VA_ARGS__)
#define DEBUG(...) log_entry(LOG_LEVEL_DEBUG, __FILE__, __LINE__, __func__, __VA_ARGS__)
#define INFO(...) log_entry(LOG_LEVEL_INFO, __FILE__, __LINE__, __func__, __VA_ARGS__)
#define WARN(...) log_entry(LOG_LEVEL_WARN, __FILE__, __LINE__, __func__, __VA_ARGS__)
#define ERROR(...) log_entry(LOG_LEVEL_ERROR, __FILE__, __LINE__, __func__, __VA_ARGS__)
#define FATAL(...) log_entry(LOG_LEVEL_FATAL, __FILE__, __LINE__, __func__, __VA_ARGS__)

/**
 * Set minimum log level to output.
 *
 * @param[in] level log level.
 */
void log_set_level(size_t level);

/**
 * Create a log entry.
 *
 * @param[in] level log level.
 * @param[in] file source file.
 * @param[in] line source line number.
 * @param[in] function function name.
 * @param[in] format format string.
 * @param[in] ... data.
 */
void log_entry(
        log_level_e level,
        const char* file,
        int line,
        const char* function,
        const char* format,
        ...);

#ifdef __cplusplus
}
#endif

#endif // LOG_H
