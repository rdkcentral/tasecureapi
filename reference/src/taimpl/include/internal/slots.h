/**
 * Copyright 2020-2021 Comcast Cable Communications Management, LLC
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
 * @file slots.h
 *
 * This file contains the functions and structures implementing slot management.
 */

#ifndef SLOTS_H
#define SLOTS_H

#ifdef __cplusplus

#include <climits>
#include <cstddef>
#include <cstdint>

extern "C" {
#else
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#endif

typedef unsigned long slot_t;

#define SLOT_INVALID ((slot_t) ULONG_MAX)

typedef struct slots_s slots_t;

/**
 * Create and initialize slots object.
 *
 * @param[in] count number of slots.
 * @return created slots instance.
 */
slots_t* slots_init(size_t count);

/**
 * Release the slots instance.
 *
 * @param[in] slots slots instance.
 */
void slots_shutdown(slots_t* slots);

/**
 * Allocate a slot from the slots list.
 *
 * @param[in] slots slots instance.
 * @return allocated slot. SLOT_INVALID is there are no available slots.
 */
slot_t slots_allocate(slots_t* slots);

/**
 * Release a slot.
 *
 * @param[in] slots slots instance.
 * @param[in] slot slot to release.
 */
void slots_free(
        slots_t* slots,
        slot_t slot);

#ifdef __cplusplus
}
#endif

#endif // SLOTS_H
