/**
 * Copyright 2019-2021 Comcast Cable Communications Management, LLC
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
 * @file typej.h
 *
 * This file contains the functions and structures implementing Type-J key container unwrapping.
 */

#ifndef TYPEJ_H
#define TYPEJ_H

#include "sa_types.h"
#include "stored_key.h"

#ifdef __cplusplus

#include <cstddef>

extern "C" {
#else
#include <stddef.h>
#endif

/**
 * Unwrap Type-J key container
 *
 * @param[out] stored_key the stored key from the key container.
 * @param[in] in input data for Type-J container.
 * @param[in] in_length input data length.
 * @param[in] stored_key_mac integrity key.
 * @param[in] stored_key_encryption encryption key.
 * @return status of the operation.
 */
sa_status typej_unwrap(
        stored_key_t** stored_key,
        const void* in,
        size_t in_length,
        const stored_key_t* stored_key_mac,
        const stored_key_t* stored_key_encryption);

#ifdef __cplusplus
}
#endif

#endif // TYPEJ_H
