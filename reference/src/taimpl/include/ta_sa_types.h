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
 * @file ta_sa_types.h
 *
 * This file contains the TA specific structures and constants.
 */

#ifndef TA_SA_TYPES_H
#define TA_SA_TYPES_H

#include "sa_types.h"

#ifdef __cplusplus

#include <cstddef>
#include <cstdint>

extern "C" {
#else
#include <stddef.h>
#include <stdint.h>
#endif

#define SYM_MAX_SIZE 512

/**
 * The client slot ID.
 */
typedef sa_handle ta_client;

#ifdef __cplusplus
}
#endif

#endif // TA_SA_TYPES_H
