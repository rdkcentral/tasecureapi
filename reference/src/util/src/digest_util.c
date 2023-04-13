/**
 * Copyright 2023 Comcast Cable Communications Management, LLC
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

#include "digest_util.h"
#include "common.h"
#include "log.h"
#include <openssl/evp.h>
#include <string.h>

sa_digest_algorithm digest_algorithm_from_md(const EVP_MD* evp_md) {
    if (evp_md != NULL) {
        switch (EVP_MD_nid(evp_md)) {
            case NID_sha1:
                return SA_DIGEST_ALGORITHM_SHA1;

            case NID_sha256:
                return SA_DIGEST_ALGORITHM_SHA256;

            case NID_sha384:
                return SA_DIGEST_ALGORITHM_SHA384;

            case NID_sha512:
                return SA_DIGEST_ALGORITHM_SHA512;
        }
    }

    return UINT32_MAX;
}

const EVP_MD* digest_mechanism(sa_digest_algorithm digest_algorithm) {
    switch (digest_algorithm) {
        case SA_DIGEST_ALGORITHM_SHA1:
            return EVP_sha1();

        case SA_DIGEST_ALGORITHM_SHA256:
            return EVP_sha256();

        case SA_DIGEST_ALGORITHM_SHA384:
            return EVP_sha384();

        case SA_DIGEST_ALGORITHM_SHA512:
            return EVP_sha512();

        default:
            ERROR("Unknown digest encountered");
            return NULL;
    }
}

const char* digest_string(sa_digest_algorithm digest_algorithm) {
    switch (digest_algorithm) {
        case SA_DIGEST_ALGORITHM_SHA1:
            return "sha1";

        case SA_DIGEST_ALGORITHM_SHA256:
            return "sha256";

        case SA_DIGEST_ALGORITHM_SHA384:
            return "sha384";

        case SA_DIGEST_ALGORITHM_SHA512:
            return "sha512";

        default:
            ERROR("Unknown digest encountered");
            return NULL;
    }
}

size_t digest_length(sa_digest_algorithm digest_algorithm) {
    switch (digest_algorithm) {
        case SA_DIGEST_ALGORITHM_SHA1:
            return SHA1_DIGEST_LENGTH;

        case SA_DIGEST_ALGORITHM_SHA256:
            return SHA256_DIGEST_LENGTH;

        case SA_DIGEST_ALGORITHM_SHA384:
            return SHA384_DIGEST_LENGTH;

        case SA_DIGEST_ALGORITHM_SHA512:
            return SHA512_DIGEST_LENGTH;

        default:
            ERROR("Unknown digest encountered");
            break;
    }

    return (size_t) -1;
}

sa_digest_algorithm digest_algorithm_from_name(const char* name) {
    if (strncmp(name, "SHA1", 4) == 0 || strncmp(name, "SHA-1", 5) == 0)
        return SA_DIGEST_ALGORITHM_SHA1;

    if (strncmp(name, "SHA256", 6) == 0 || strncmp(name, "SHA2-256", 7) == 0 || strncmp(name, "SHA-256", 7) == 0)
        return SA_DIGEST_ALGORITHM_SHA256;

    if (strncmp(name, "SHA384", 6) == 0 || strncmp(name, "SHA2-384", 7) == 0 || strncmp(name, "SHA-384", 7) == 0)
        return SA_DIGEST_ALGORITHM_SHA384;

    if (strncmp(name, "SHA512", 6) == 0 || strncmp(name, "SHA2-512", 7) == 0 || strncmp(name, "SHA-512", 7) == 0)
        return SA_DIGEST_ALGORITHM_SHA512;

    return UINT32_MAX;
}
