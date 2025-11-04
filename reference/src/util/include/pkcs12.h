/*
 * Copyright 2022-2023 Comcast Cable Communications Management, LLC
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
 * @file pkcs12.h
 *
 * This file contains the functions and structures providing PKCS12 processing.
 */

#ifndef PKCS12_H
#define PKCS12_H

#include <openssl/pkcs12.h>

// Include mbedTLS PKCS#12 header if enabled
#ifdef USE_MBEDTLS
#include "pkcs12_mbedtls.h"
#endif

#ifdef __cplusplus
#include <cstdint>
extern "C" {
#else
#include <stdint.h>
#endif

/**
 * Loads a secret key from a PKCS12 file identified at the ROOT_KEYSTORE environment variable. The password to the
 * keystore is in the ROOT_KEYSTORE_PASSWORD environment variable. If neither is defined, it looks for the file
 * root_keystore.p12 in the working directory with a default password.
 *
 * @param[out] key the key to load.
 * @param[in,out] key_length the length of the loaded key.
 * @param[out] name
 * @param[in,out] name_length
 * @return true if successful and false if not.
 */
#ifdef USE_MBEDTLS
// When USE_MBEDTLS is defined, redirect to mbedTLS implementation
#define load_pkcs12_secret_key load_pkcs12_secret_key_mbedtls
#else
// OpenSSL implementation
bool load_pkcs12_secret_key(
        void* key,
        size_t* key_length,
        char* name,
        size_t* name_length);
#endif

#ifdef __cplusplus
}
#endif

#endif // PKCS12_H
