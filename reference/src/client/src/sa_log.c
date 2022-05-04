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

#include "sa_log.h"
#include <stdarg.h>
#include <stdio.h>
#include <time.h>

void sa_log_entry(
        const char* file,
        int line,
        const char* function,
        const char* format,
        ...) {

    // get current time
    time_t current_time = time(NULL);
    struct tm local_time = {};
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
