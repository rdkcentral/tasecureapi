/*
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

#ifndef DIGEST_MECHANISM_H
#define DIGEST_MECHANISM_H

#include "sa_types.h"
#include <openssl/evp.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Returns the OpenSSL digest mechanism (EVP_MD) for the given digest algorithm.
 *
 * @param[in] digest_algorithm the digest algorithm.
 * @return the OpenSSL EVP_MD pointer, or NULL if invalid.
 */
const EVP_MD* digest_mechanism(sa_digest_algorithm digest_algorithm);

/**
 * Retrieves the digest algorithm from the OpenSSL EVP_MD type.
 * This function is used by the OpenSSL engine/provider code in the client library.
 *
 * @param[in] evp_md the OpenSSL EVP_MD pointer.
 * @return the digest algorithm.
 */
sa_digest_algorithm digest_algorithm_from_evp_md(const EVP_MD* evp_md);

#ifdef __cplusplus
}
#endif

#endif // DIGEST_MECHANISM_H
