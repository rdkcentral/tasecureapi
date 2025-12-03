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
 * @file init.h
 *
 * This file contains functions that should be run on SecApi TA initialization.
 */

#ifndef INIT_H
#define INIT_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialize the mbedTLS allocator to use the secure memory heap functions memory_secure_* 
 * for all internal allocations and de-allocations.
 */
void init_mbedtls_allocator();

#ifdef __cplusplus
}
#endif

#endif // INIT_H
