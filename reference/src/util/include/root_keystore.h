/*
 * Copyright 2025-2026 Comcast Cable Communications Management, LLC
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

#ifndef ROOT_KEYSTORE_H
#define ROOT_KEYSTORE_H

#include <stddef.h>
#include <stdint.h>

#define DEFAULT_ROOT_KEYSTORE_PASSWORD "password01234567"
#define COMMON_ROOT_NAME "commonroot"

/// A PKCS#12 container containing a secret key encrypted with the
/// `DEFAULT_ROOT_KEYSTORE_PASSWORD`.
extern const uint8_t default_root_keystore[];

/// Size of the `default_root_keystore`
extern const size_t default_root_keystore_size;

#endif /* ROOT_KEYSTORE_H */
