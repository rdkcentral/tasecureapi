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

/** @section Description
 * @file digest_util_mbedtls.h
 *
 * This file contains mbedTLS-specific digest utility functions for taimpl.
 */

#ifndef DIGEST_UTIL_MBEDTLS_H
#define DIGEST_UTIL_MBEDTLS_H

#include "digest_util.h"
#include "mbedtls_header.h"
#include "pkcs12_mbedtls.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Converts a digest algorithm into an mbedTLS mechanism.
 * @param[in] digest_algorithm the digest algorithm to convert.
 * @return the mbedTLS mechanism.
 */
mbedtls_md_type_t digest_mechanism_mbedtls(sa_digest_algorithm digest_algorithm);

/**
 * Retrieves the digest algorithm from the mbedTLS message digest type.
 *
 * @param[in] md_type the mbedTLS message digest type.
 * @return the digest algorithm.
 */
sa_digest_algorithm digest_algorithm_from_md(mbedtls_md_type_t md_type);

#ifdef __cplusplus
}
#endif

#endif // DIGEST_UTIL_MBEDTLS_H
