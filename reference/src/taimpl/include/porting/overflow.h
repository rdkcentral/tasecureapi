/**
 * Copyright 2023 Comcast Cable Communications Management, LLC
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
 * @file overflow.h
 *
 * This file contains the functions and structures that check the addition operation for overflow.
 */

#ifndef OVERFLOW_H
#define OVERFLOW_H

#ifdef __cplusplus

#include <cstdbool>

extern "C" {
#else
#include <stdbool.h>
#endif

/**
 * Adds to unsigned long values together and checks for overflow. The result is placed in res.
 *
 * @param[in] a left value to add.
 * @param[in] b right value to add
 * @param[out] res result of addition if no overflow occurs.
 * @return false if no overflow and true if there is.
 */
bool add_overflow(
        unsigned long a,
        unsigned long b,
        unsigned long* result);

#ifdef __cplusplus
}
#endif

#endif // OVERFLOW_H
