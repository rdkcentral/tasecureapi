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

#ifndef PKCS12_MBEDTLS_H
#define PKCS12_MBEDTLS_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Load a secret key from a PKCS#12 file using mbedTLS APIs only.
 *
 * This is a pure mbedTLS implementation that replaces OpenSSL's PKCS#12 parsing.
 * Compatible with OpenSSL's load_pkcs12_secret_key() interface.
 *
 * @param key           Buffer to store the extracted key
 * @param key_length    [in/out] Size of key buffer / actual key length
 * @param name          [in/out] Input: name pattern to match (e.g., "commonroot")
 *                               Output: extracted key's friendly name
 * @param name_length   [in/out] Size of name buffer / actual name length
 *
 * @return              true on success, false on failure
 */
bool load_pkcs12_secret_key_mbedtls(
        void* key,
        size_t* key_length,
        char* name,
        size_t* name_length);

#ifdef __cplusplus
}
#endif

#endif /* PKCS12_MBEDTLS_H */
