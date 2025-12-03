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
 * @file pkcs8.h
 *
 * This file contains the functions and structures providing PKCS8 processing using OpenSSL.
 */

#ifndef PKCS8_OPENSSL_H
#define PKCS8_OPENSSL_H

#include <openssl/evp.h>

#ifdef __cplusplus
#include <cstdbool>
extern "C" {
#else
#include <stdbool.h>
#endif

/**
 * Converts an EVP_PKEY private key into a OneAsymmetricKey (PKCS 8) structure.
 *
 * @param[out] out the encoded private key.
 * @param[in/out] out_length the length of the encoded key.
 * @param evp_pkey the private key to convert.
 * @return true if successful, false if not.
 */
bool evp_pkey_to_pkcs8(
        void* out,
        size_t* out_length,
        EVP_PKEY* evp_pkey);

/**
 * Converts a OneAsymmetricKey (PKCS 8) structure into EVP_PKEY private key.
 *
 * @param[in] type the type of the key.
 * @param[in] in the encoded private key.
 * @param[in] in_length the length of the encoded key.
 * @return the private key or NULL if not successful. Caller must free with EVP_PKEY_free().
 */
EVP_PKEY* evp_pkey_from_pkcs8(
        int type,
        const void* in,
        size_t in_length);

#ifdef __cplusplus
}
#endif

#endif //PKCS8_OPENSSL_H
