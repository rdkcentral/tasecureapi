/**
 * Copyright 2020-2023 Comcast Cable Communications Management, LLC
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
 * @file digest.h
 *
 * This file contains the functions implementing internal digest algorithms.
 */

#ifndef DIGEST_UTIL_H
#define DIGEST_UTIL_H

#include "sa_types.h"
#include <openssl/ossl_typ.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Converts a digest algorithm into an OpenSSL mechanism.
 * @param[in] digest_algorithm the digest algorithm to convert.
 * @return the OpenSSL mechanism.
 */
const EVP_MD* digest_mechanism(sa_digest_algorithm digest_algorithm);

/**
 * Returns the digest name as a string.
 *
 * @param[in] digest_algorithm the digest algorithm to lookup.
 * @return the string identifying the digest.
 */
const char* digest_string(sa_digest_algorithm digest_algorithm);

/**
 * Obtain digest length for specified algorithm.
 *
 * @param[in] digest_algorithm digest algorithm.
 * @return length required to store the digest value. Returns (size_t) -1 if invalid digest
 * algorithm is specified.
 */
size_t digest_length(sa_digest_algorithm digest_algorithm);

/**
 * Retrieves the digest algorithm from the OpenSSL message digest.
 *
 * @param[in] evp_md the OpenSSL message digest.
 * @return the digest algorithm.
 */
sa_digest_algorithm digest_algorithm_from_md(const EVP_MD* evp_md);

/**
 * Returns the digest algorithm based on the algorithm name.
 *
 * @param[in] name the name of the digest algorithm.
 * @return the digest algorithm.
 */
sa_digest_algorithm digest_algorithm_from_name(const char* name);

#ifdef __cplusplus
}
#endif

#endif // DIGEST_UTIL_H
