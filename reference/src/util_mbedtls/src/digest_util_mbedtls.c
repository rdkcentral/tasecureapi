/*
 * Copyright 2023-2025 Comcast Cable Communications Management, LLC
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

#include "digest_util_mbedtls.h"
#include "log.h"
#include "pkcs12_mbedtls.h"

sa_digest_algorithm digest_algorithm_from_md(mbedtls_md_type_t md_type) {
    switch (md_type) {
        case MBEDTLS_MD_SHA1:
            return SA_DIGEST_ALGORITHM_SHA1;

        case MBEDTLS_MD_SHA256:
            return SA_DIGEST_ALGORITHM_SHA256;

        case MBEDTLS_MD_SHA384:
            return SA_DIGEST_ALGORITHM_SHA384;

        case MBEDTLS_MD_SHA512:
            return SA_DIGEST_ALGORITHM_SHA512;

        default:
            return UINT32_MAX;
    }
}

mbedtls_md_type_t digest_mechanism_mbedtls(sa_digest_algorithm digest_algorithm) {
    switch (digest_algorithm) {
        case SA_DIGEST_ALGORITHM_SHA1:
            return MBEDTLS_MD_SHA1;

        case SA_DIGEST_ALGORITHM_SHA256:
            return MBEDTLS_MD_SHA256;

        case SA_DIGEST_ALGORITHM_SHA384:
            return MBEDTLS_MD_SHA384;

        case SA_DIGEST_ALGORITHM_SHA512:
            return MBEDTLS_MD_SHA512;

        default:
            ERROR("Unknown digest encountered");
            return MBEDTLS_MD_NONE;
    }
}
